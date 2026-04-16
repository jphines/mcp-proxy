package proxy

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/jphines/mcp-proxy/gateway"
	"github.com/jphines/mcp-proxy/internal/approval"
)

// NewHTTPServer builds and returns the proxy HTTP server. It registers all routes:
//
//   - POST/GET /mcp          — upstream MCP (StreamableHTTP)
//   - GET      /oauth/enroll/{serviceID} — start OAuth enrollment
//   - GET      /oauth/callback           — OAuth authorization code callback
//   - POST     /approvals/slack/callback — Slack interactive component webhook
//   - GET      /metrics                  — Prometheus metrics
//   - GET      /healthz                  — liveness probe
//   - GET      /readyz                   — readiness probe
//
// The returned *http.Server is not started; call ListenAndServeTLS from main.go.
func (p *Proxy) NewHTTPServer(addr string, approvalHandler *approval.Handler) *http.Server {
	mux := http.NewServeMux()

	// MCP endpoint — handles both POST (send message) and GET (SSE receive).
	// authGate wraps the MCP handler: when requireAuth is set it returns a
	// proper HTTP 401 with WWW-Authenticate instead of the SDK's generic 400.
	// Claude Code only triggers its OAuth PKCE flow on 401/403, not 400.
	mcpHandler := mcp.NewStreamableHTTPHandler(p.GetServer, nil)
	var mcpHandlerWrapped http.Handler = mcpHandler
	if p.requireAuth {
		mcpHandlerWrapped = p.authGate(mcpHandler)
	}
	mux.Handle("/mcp", mcpHandlerWrapped)

	// OAuth Authorization Server support.
	// /.well-known/oauth-authorization-server (RFC 8414) is served whenever an
	// AS is configured; it tells Claude Code where to authenticate.
	// /.well-known/oauth-protected-resource (RFC 9728) is served so the MCP
	// client SDK can discover the authorization server via protected resource
	// metadata discovery (required for Auth0 mode; recommended always).
	// /oauth/register (stub) is served in both modes so Claude Code can
	// auto-discover the correct client_id via dynamic client registration.
	// /oauth/authorize + /oauth/token are only served in demo-jwt mode;
	// in Auth0 mode those requests go directly to Auth0.
	if p.as != nil {
		mux.HandleFunc("GET /.well-known/oauth-authorization-server", p.as.handleMetadata)
		mux.HandleFunc("GET /.well-known/oauth-protected-resource", p.as.handleProtectedResourceMeta)
		mux.HandleFunc("POST /oauth/register", p.as.handleRegister)

		// Authorize, token, and logout endpoints are served in BOTH modes.
		// In Auth0 mode the proxy acts as an intermediary AS, delegating
		// the actual login to Auth0 via a fixed callback URL.
		mux.HandleFunc("GET /oauth/authorize", p.as.handleAuthorizeGET)
		mux.HandleFunc("POST /oauth/token", p.as.handleToken)
		mux.HandleFunc("GET /oauth/logout", p.as.handleLogout)

		if p.as.auth0Issuer != "" {
			// Auth0 mode: fixed callback URL that Auth0 can allowlist.
			mux.HandleFunc("GET /oauth/auth0-callback", p.as.handleAuth0Callback)
		}
		if p.as.demoJWTURL != "" {
			// Demo mode: login form submission.
			mux.HandleFunc("POST /oauth/authorize", p.as.handleAuthorizePOST)
		}
	}

	// OAuth enrollment flow (upstream resource enrollment: Google, etc.).
	mux.HandleFunc("GET /oauth/enroll/{serviceID}", p.handleOAuthEnroll)
	mux.HandleFunc("GET /oauth/callback", p.handleOAuthCallback)

	// Slack HITL approval callback.
	if approvalHandler != nil {
		mux.Handle("POST /approvals/slack/callback", approvalHandler)
	}

	// Observability.
	mux.Handle("GET /metrics", promhttp.Handler())
	mux.HandleFunc("GET /healthz", handleHealthz)
	mux.HandleFunc("GET /readyz", handleReadyz)

	return &http.Server{
		Addr:         addr,
		Handler:      mux,
		TLSConfig:    tlsConfig(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
}

// authGate is an HTTP middleware that enforces bearer-token authentication in
// front of the MCP handler.  It returns a proper RFC 6750 401 response so that
// MCP clients (e.g. Claude Code) trigger their OAuth PKCE discovery flow.
//
// Without this gate the go-sdk StreamableHTTPHandler returns 400 Bad Request
// when GetServer returns nil, which MCP clients do not recognise as an auth
// challenge.
func (p *Proxy) authGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := extractBearerToken(r)

		if token == "" {
			// No token at all — point the client at the protected resource
			// metadata document so it can discover the authorization server.
			rmURL := p.proxyBaseURL + "/.well-known/oauth-protected-resource"
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata=%q`, rmURL))
			http.Error(w, "unauthorized: no bearer token", http.StatusUnauthorized)
			return
		}

		// Token present — validate it before handing off to the MCP handler.
		// If invalid, return 401 so the client can re-authenticate; the SDK
		// would return 400 if we let GetServer return nil instead.
		if _, err := p.deps.Authenticator.Authenticate(r.Context(), token); err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			http.Error(w, "unauthorized: "+err.Error(), http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// handleOAuthEnroll authenticates the caller and redirects to the provider's
// authorization URL to begin the enrollment flow.
func (p *Proxy) handleOAuthEnroll(w http.ResponseWriter, r *http.Request) {
	serviceID := r.PathValue("serviceID")

	token := extractBearerToken(r)
	if token == "" {
		// Fallback: accept token as a query parameter so the enrollment URL
		// works when opened in a browser (e.g. from Claude Code's error message).
		token = r.URL.Query().Get("token")
	}
	if token == "" {
		http.Error(w, "unauthorized: missing bearer token", http.StatusUnauthorized)
		return
	}
	identity, err := p.deps.Authenticator.Authenticate(r.Context(), token)
	if err != nil {
		http.Error(w, "unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	authURL, err := p.deps.OAuthEnrollment.InitiateFlow(r.Context(), identity, serviceID)
	if err != nil {
		http.Error(w, "enrollment initiation failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleOAuthCallback receives the authorization code from the provider,
// completes the PKCE exchange, and persists the refresh token.
func (p *Proxy) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" || state == "" {
		http.Error(w, "missing code or state parameter", http.StatusBadRequest)
		return
	}

	if err := p.deps.OAuthEnrollment.HandleCallback(r.Context(), code, state); err != nil {
		http.Error(w, "enrollment failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(
		"<html><body>" +
			"<h1>OAuth enrollment successful</h1>" +
			"<p>You may now close this window and return to Claude.</p>" +
			"</body></html>",
	))
}

func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func handleReadyz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready"))
}

// tlsConfig returns a *tls.Config that enforces TLS 1.3 minimum and strong cipher
// suites. The certificate is loaded by the caller via http.Server.ListenAndServeTLS.
func tlsConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
	}
}

// activeSessionsDelta adjusts the active-session gauge in MetricsCollector.
// Called by the GetServer wrapper once wired in main.go if needed.
func (p *Proxy) activeSessionsDelta(delta int) {
	p.deps.MetricsCollector.ActiveSessions(delta)
}

// Ensure Handler interface is satisfied at compile time.
var _ http.Handler = (*approval.Handler)(nil)
var _ gateway.OAuthEnrollment = (gateway.OAuthEnrollment)(nil) // interface assertion
