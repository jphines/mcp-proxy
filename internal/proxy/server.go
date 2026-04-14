package proxy

import (
	"crypto/tls"
	"net/http"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/ro-eng/mcp-proxy/gateway"
	"github.com/ro-eng/mcp-proxy/internal/approval"
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
	mcpHandler := mcp.NewStreamableHTTPHandler(p.GetServer, nil)
	mux.Handle("/mcp", mcpHandler)

	// OAuth enrollment flow.
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

// handleOAuthEnroll authenticates the caller and redirects to the provider's
// authorization URL to begin the enrollment flow.
func (p *Proxy) handleOAuthEnroll(w http.ResponseWriter, r *http.Request) {
	serviceID := r.PathValue("serviceID")

	token := extractBearerToken(r)
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
