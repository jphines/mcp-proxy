package proxy

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// oauthAS supports two operating modes:
//
// Demo-jwt mode (demoJWTURL set):
//
//	The proxy itself acts as an OAuth AS. It serves a login form at
//	/oauth/authorize, issues short-lived opaque codes, and exchanges them for
//	JWTs by calling the demo-jwt service. Used when there is no real IdP.
//
// Auth0 mode (auth0Issuer set):
//
//	The proxy acts as an OAuth intermediary. It serves its own /oauth/authorize
//	and /oauth/token endpoints to Claude Code, but delegates the actual
//	authentication to Auth0. This is necessary because Auth0 does not support
//	wildcard ports in callback URLs, and Claude Code uses random localhost ports.
//	The proxy uses a fixed callback URL (/oauth/auth0-callback) with Auth0,
//	then redirects back to Claude Code's random-port callback with a proxy
//	authorization code.
type oauthAS struct {
	proxyBaseURL string

	// demo-jwt mode fields (non-empty when in demo mode).
	demoJWTURL string

	// Auth0 mode fields (non-empty when in Auth0 mode).
	auth0Issuer   string // e.g. "https://dev-xyz.us.auth0.com/"
	auth0ClientID string // Auth0 application client ID
	auth0Audience string // Auth0 API audience for JWT aud claim

	// Shared fields.
	httpClient *http.Client
	mu         sync.Mutex
	codes      map[string]*pendingCode // proxy authorization codes → pending token
	auth0Flows map[string]*auth0Flow   // Auth0 mode: auth0State → pending flow
}

// pendingCode is a single-use proxy authorization code stored between the
// authorize redirect and the token exchange.
type pendingCode struct {
	// Demo-jwt mode fields.
	email  string
	groups string

	// Auth0 mode fields.
	auth0Token     string // the Auth0 JWT to return to Claude Code
	auth0ExpiresIn int    // Auth0 token expiry in seconds

	// Common fields.
	codeChallenge string
	redirectURI   string
	expiresAt     time.Time
}

// auth0Flow tracks an in-progress Auth0 authorization, keyed by the random
// state parameter the proxy sends to Auth0.
type auth0Flow struct {
	clientRedirectURI   string // Claude Code's random-port callback URL
	clientCodeChallenge string // Claude Code's PKCE S256 challenge
	clientState         string // Claude Code's state parameter (forwarded back)
	auth0Verifier       string // proxy's PKCE verifier for the Auth0 exchange
	expiresAt           time.Time
}

const (
	authCodeExpiry  = 5 * time.Minute
	demoTokenTTL    = "24h"
	maxRegisterBody = 64 * 1024 // 64 KiB
)

// newOAuthAS creates an oauthAS backed by the demo-jwt service.
func newOAuthAS(proxyBaseURL, demoJWTURL string) *oauthAS {
	return &oauthAS{
		proxyBaseURL: strings.TrimRight(proxyBaseURL, "/"),
		demoJWTURL:   strings.TrimRight(demoJWTURL, "/"),
		httpClient:   &http.Client{Timeout: 10 * time.Second},
		codes:        make(map[string]*pendingCode),
	}
}

// newOAuthASAuth0 creates an oauthAS that delegates auth to Auth0.
// The proxy acts as an OAuth intermediary: it serves its own authorize/token
// endpoints to Claude Code and delegates authentication to Auth0 with a fixed
// callback URL that Auth0 can allowlist.
func newOAuthASAuth0(proxyBaseURL, auth0Domain, auth0ClientID, auth0Audience string) *oauthAS {
	issuer := "https://" + strings.Trim(auth0Domain, "/") + "/"
	return &oauthAS{
		proxyBaseURL:  strings.TrimRight(proxyBaseURL, "/"),
		auth0Issuer:   issuer,
		auth0ClientID: auth0ClientID,
		auth0Audience: auth0Audience,
		httpClient:    &http.Client{Timeout: 10 * time.Second},
		codes:         make(map[string]*pendingCode),
		auth0Flows:    make(map[string]*auth0Flow),
	}
}

// handleMetadata serves GET /.well-known/oauth-authorization-server (RFC 8414).
//
// In both modes the response points Claude Code at the proxy's own AS
// endpoints. In Auth0 mode the proxy acts as an intermediary: it handles
// /oauth/authorize and /oauth/token locally, delegating the actual login to
// Auth0 via a fixed callback URL that Auth0 can allowlist.
func (as *oauthAS) handleMetadata(w http.ResponseWriter, _ *http.Request) {
	base := as.proxyBaseURL
	metadata := map[string]any{
		"issuer":                                 base,
		"authorization_endpoint":                 base + "/oauth/authorize",
		"token_endpoint":                         base + "/oauth/token",
		"registration_endpoint":                  base + "/oauth/register",
		"end_session_endpoint":                   base + "/oauth/logout",
		"response_types_supported":               []string{"code"},
		"grant_types_supported":                  []string{"authorization_code"},
		"code_challenge_methods_supported":        []string{"S256"},
		"token_endpoint_auth_methods_supported":  []string{"none"},
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(metadata)
}

// handleProtectedResourceMeta serves GET /.well-known/oauth-protected-resource
// (RFC 9728).
//
// Points MCP clients at the proxy as the authorization server in both modes.
// The MCP client SDK reads authorization_servers[0] and then fetches the AS
// metadata from that issuer to locate the authorize/token endpoints.
func (as *oauthAS) handleProtectedResourceMeta(w http.ResponseWriter, _ *http.Request) {
	meta := map[string]any{
		"resource":                 as.proxyBaseURL,
		"authorization_servers":    []string{as.proxyBaseURL},
		"bearer_methods_supported": []string{"header"},
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(meta)
}

// handleAuthorizeGET handles GET /oauth/authorize.
//
// In Auth0 mode:    stores Claude Code's PKCE state, then redirects to Auth0.
// In demo-jwt mode: renders the login / consent form.
func (as *oauthAS) handleAuthorizeGET(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	if q.Get("response_type") != "code" {
		http.Error(w, "unsupported response_type; expected code", http.StatusBadRequest)
		return
	}
	if q.Get("code_challenge_method") != "S256" {
		http.Error(w, "code_challenge_method must be S256", http.StatusBadRequest)
		return
	}
	if q.Get("code_challenge") == "" || q.Get("redirect_uri") == "" {
		http.Error(w, "missing required parameters: redirect_uri, code_challenge", http.StatusBadRequest)
		return
	}

	// Only allow redirects back to loopback addresses.
	if !isLoopbackURI(q.Get("redirect_uri")) {
		http.Error(w, "redirect_uri must be a loopback address (localhost / 127.0.0.1)", http.StatusBadRequest)
		return
	}

	if as.auth0Issuer != "" {
		as.handleAuth0Authorize(w, r, q)
		return
	}

	// Demo-jwt mode: render login form.
	data := authorizePageData{
		ClientID:      q.Get("client_id"),
		RedirectURI:   q.Get("redirect_uri"),
		State:         q.Get("state"),
		CodeChallenge: q.Get("code_challenge"),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := authorizePageTmpl.Execute(w, data); err != nil {
		slog.Error("oauth: authorize template error", slog.Any("error", err))
	}
}

// handleAuth0Authorize redirects the user to Auth0 for authentication.
// It stores Claude Code's PKCE challenge and redirect_uri, generates its own
// PKCE pair for the Auth0 exchange, and redirects with a fixed callback URL
// that Auth0 can allowlist (no random-port problem).
func (as *oauthAS) handleAuth0Authorize(w http.ResponseWriter, r *http.Request, q url.Values) {
	// Generate the proxy's own PKCE pair for the Auth0 exchange.
	verifier := generatePKCEVerifier()
	challenge := computeS256Challenge(verifier)
	auth0State := generateOpaqueCode()

	// Store the pending flow so handleAuth0Callback can retrieve it.
	as.mu.Lock()
	as.auth0Flows[auth0State] = &auth0Flow{
		clientRedirectURI:   q.Get("redirect_uri"),
		clientCodeChallenge: q.Get("code_challenge"),
		clientState:         q.Get("state"),
		auth0Verifier:       verifier,
		expiresAt:           time.Now().Add(authCodeExpiry),
	}
	as.mu.Unlock()

	// Build Auth0 authorize URL with the proxy's fixed callback.
	auth0AuthURL := strings.TrimRight(as.auth0Issuer, "/") + "/authorize"
	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {as.auth0ClientID},
		"redirect_uri":          {as.proxyBaseURL + "/oauth/auth0-callback"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {auth0State},
		"scope":                 {"openid email profile"},
	}

	slog.Info("oauth: redirecting to Auth0",
		slog.String("auth0_state", auth0State[:8]+"..."),
		slog.String("client_redirect", q.Get("redirect_uri")),
	)

	http.Redirect(w, r, auth0AuthURL+"?"+params.Encode(), http.StatusFound)
}

// handleAuth0Callback handles GET /oauth/auth0-callback.
// Auth0 redirects here after the user authenticates. The proxy exchanges the
// Auth0 authorization code for a JWT, issues its own proxy authorization code,
// and redirects back to Claude Code's random-port callback.
func (as *oauthAS) handleAuth0Callback(w http.ResponseWriter, r *http.Request) {
	// Check for Auth0 error response before looking for code/state.
	if errCode := r.URL.Query().Get("error"); errCode != "" {
		errDesc := r.URL.Query().Get("error_description")
		slog.Error("oauth: Auth0 returned error",
			slog.String("error", errCode),
			slog.String("description", errDesc),
		)
		http.Error(w, fmt.Sprintf("Auth0 error: %s — %s", errCode, errDesc), http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" || state == "" {
		http.Error(w, "missing code or state parameter from Auth0", http.StatusBadRequest)
		return
	}

	// Look up the pending flow.
	as.mu.Lock()
	flow, ok := as.auth0Flows[state]
	if ok {
		delete(as.auth0Flows, state)
	}
	as.mu.Unlock()

	if !ok || time.Now().After(flow.expiresAt) {
		http.Error(w, "invalid or expired authorization state", http.StatusBadRequest)
		return
	}

	// Exchange Auth0 authorization code for an access token.
	tokenURL := strings.TrimRight(as.auth0Issuer, "/") + "/oauth/token"
	tokenResp, err := as.httpClient.PostForm(tokenURL, url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {as.auth0ClientID},
		"code":          {code},
		"redirect_uri":  {as.proxyBaseURL + "/oauth/auth0-callback"},
		"code_verifier": {flow.auth0Verifier},
	})
	if err != nil {
		slog.Error("oauth: Auth0 token exchange failed", slog.Any("error", err))
		http.Error(w, "failed to exchange authorization code with Auth0", http.StatusBadGateway)
		return
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(tokenResp.Body, 4096))
		slog.Error("oauth: Auth0 token endpoint returned error",
			slog.Int("status", tokenResp.StatusCode),
			slog.String("body", string(body)),
		)
		http.Error(w, "Auth0 token exchange failed", http.StatusBadGateway)
		return
	}

	var auth0Token struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}
	if err := json.NewDecoder(tokenResp.Body).Decode(&auth0Token); err != nil {
		slog.Error("oauth: failed to decode Auth0 token response", slog.Any("error", err))
		http.Error(w, "failed to obtain token from Auth0", http.StatusBadGateway)
		return
	}

	// Prefer id_token (always a JWT) over access_token (opaque without audience).
	bearerToken := auth0Token.IDToken
	if bearerToken == "" {
		bearerToken = auth0Token.AccessToken
	}
	if bearerToken == "" {
		slog.Error("oauth: Auth0 returned neither id_token nor access_token")
		http.Error(w, "failed to obtain token from Auth0", http.StatusBadGateway)
		return
	}

	// Issue a proxy authorization code that maps to the Auth0 JWT.
	proxyCode := generateOpaqueCode()

	as.mu.Lock()
	as.codes[proxyCode] = &pendingCode{
		auth0Token:     bearerToken,
		auth0ExpiresIn: auth0Token.ExpiresIn,
		codeChallenge:  flow.clientCodeChallenge,
		redirectURI:    flow.clientRedirectURI,
		expiresAt:      time.Now().Add(authCodeExpiry),
	}
	as.mu.Unlock()

	// Redirect back to Claude Code's random-port callback with the proxy code.
	target, err := url.Parse(flow.clientRedirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	qp := target.Query()
	qp.Set("code", proxyCode)
	if flow.clientState != "" {
		qp.Set("state", flow.clientState)
	}
	target.RawQuery = qp.Encode()

	slog.Info("oauth: Auth0 login successful, redirecting to Claude Code",
		slog.String("proxy_code", proxyCode[:8]+"..."),
	)

	http.Redirect(w, r, target.String(), http.StatusFound)
}

// handleAuthorizePOST processes the submitted login form (demo-jwt mode only),
// issues a one-time authorization code, and redirects back to the OAuth client.
func (as *oauthAS) handleAuthorizePOST(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form data", http.StatusBadRequest)
		return
	}

	email := strings.TrimSpace(r.FormValue("email"))
	groups := strings.TrimSpace(r.FormValue("groups"))
	redirectURI := r.FormValue("redirect_uri")
	state := r.FormValue("state")
	codeChallenge := r.FormValue("code_challenge")

	if email == "" || redirectURI == "" || codeChallenge == "" {
		http.Error(w, "email, redirect_uri, and code_challenge are required", http.StatusBadRequest)
		return
	}
	if groups == "" {
		groups = "everyone"
	}

	if !isLoopbackURI(redirectURI) {
		http.Error(w, "redirect_uri must be a loopback address (localhost / 127.0.0.1)", http.StatusBadRequest)
		return
	}

	code := generateOpaqueCode()

	as.mu.Lock()
	as.codes[code] = &pendingCode{
		email:         email,
		groups:        groups,
		codeChallenge: codeChallenge,
		redirectURI:   redirectURI,
		expiresAt:     time.Now().Add(authCodeExpiry),
	}
	as.mu.Unlock()

	target, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	qp := target.Query()
	qp.Set("code", code)
	if state != "" {
		qp.Set("state", state)
	}
	target.RawQuery = qp.Encode()

	http.Redirect(w, r, target.String(), http.StatusFound)
}

// handleToken processes POST /oauth/token (authorization_code grant + PKCE S256).
// Works in both modes:
//   - Auth0: returns the Auth0 JWT that was obtained during the callback.
//   - Demo-jwt: exchanges the code for a fresh JWT from the demo-jwt service.
func (as *oauthAS) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, "invalid_request", "could not parse form body")
		return
	}

	if r.FormValue("grant_type") != "authorization_code" {
		writeOAuthError(w, "unsupported_grant_type", "only authorization_code is supported")
		return
	}

	code := r.FormValue("code")
	codeVerifier := r.FormValue("code_verifier")
	redirectURI := r.FormValue("redirect_uri")

	if code == "" || codeVerifier == "" {
		writeOAuthError(w, "invalid_request", "code and code_verifier are required")
		return
	}

	// Pop the auth code (single-use).
	as.mu.Lock()
	pending, ok := as.codes[code]
	if ok {
		delete(as.codes, code)
	}
	as.mu.Unlock()

	if !ok || time.Now().After(pending.expiresAt) {
		writeOAuthError(w, "invalid_grant", "authorization code not found or expired")
		return
	}
	if redirectURI != "" && redirectURI != pending.redirectURI {
		writeOAuthError(w, "invalid_grant", "redirect_uri mismatch")
		return
	}
	if !verifyS256(codeVerifier, pending.codeChallenge) {
		writeOAuthError(w, "invalid_grant", "PKCE code_verifier does not match code_challenge")
		return
	}

	// Auth0 mode: the access token was already obtained during the callback.
	if pending.auth0Token != "" {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": pending.auth0Token,
			"token_type":   "Bearer",
			"expires_in":   pending.auth0ExpiresIn,
		})
		return
	}

	// Demo-jwt mode: exchange for a token from the demo-jwt service.
	accessToken, expiresIn, err := as.fetchDemoToken(r.Context(), pending.email, pending.groups)
	if err != nil {
		slog.ErrorContext(r.Context(), "oauth: demo-jwt fetch failed", slog.Any("error", err))
		writeOAuthError(w, "server_error", "token issuance failed")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   expiresIn,
	})
}

// handleRegister is a stub RFC 7591 dynamic client registration endpoint.
// Claude Code calls this to register itself before the PKCE flow.
// Returns the Auth0 client_id in Auth0 mode; echoes back in demo mode.
func (as *oauthAS) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req map[string]any
	if err := json.NewDecoder(io.LimitReader(r.Body, maxRegisterBody)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	_ = r.Body.Close()

	clientID := as.auth0ClientID
	if clientID == "" {
		clientID, _ = req["client_id"].(string)
		if clientID == "" {
			clientID = "mcp-proxy"
		}
	}

	resp := map[string]any{
		"client_id":                  clientID,
		"client_secret_expires_at":   0,
		"grant_types":                []string{"authorization_code"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
	}
	if v, ok := req["client_name"]; ok {
		resp["client_name"] = v
	}
	if v, ok := req["redirect_uris"]; ok {
		resp["redirect_uris"] = v
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

// fetchDemoToken calls the demo-jwt /token endpoint and returns the access token.
func (as *oauthAS) fetchDemoToken(ctx context.Context, email, groups string) (token string, expiresIn int, err error) {
	params := url.Values{
		"user":   {email},
		"groups": {groups},
		"ttl":    {demoTokenTTL},
	}
	reqURL := as.demoJWTURL + "/token?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", 0, fmt.Errorf("building demo-jwt request: %w", err)
	}

	resp, err := as.httpClient.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("calling demo-jwt at %s: %w", as.demoJWTURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("demo-jwt returned HTTP %d", resp.StatusCode)
	}

	var body struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", 0, fmt.Errorf("decoding demo-jwt response: %w", err)
	}
	if body.AccessToken == "" {
		return "", 0, fmt.Errorf("demo-jwt returned empty access_token")
	}
	return body.AccessToken, body.ExpiresIn, nil
}

// handleLogout handles GET /oauth/logout.
//
// In Auth0 mode:    redirects to Auth0's /v2/logout endpoint, which ends the Auth0
//
//	session and then redirects back to the proxy's base URL.
//
// In demo-jwt mode: renders a simple "logged out" confirmation page. There are no
//
//	server-side sessions to invalidate; the JWT simply expires.
func (as *oauthAS) handleLogout(w http.ResponseWriter, r *http.Request) {
	if as.auth0Issuer != "" {
		// Auth0 /v2/logout clears the Auth0 session cookie and redirects
		// the user to returnTo. The returnTo URL must be registered in
		// Auth0 → Settings → Allowed Logout URLs.
		logoutURL := strings.TrimRight(as.auth0Issuer, "/") + "/v2/logout"
		params := url.Values{
			"client_id": {as.auth0ClientID},
			"returnTo":  {as.proxyBaseURL},
		}
		http.Redirect(w, r, logoutURL+"?"+params.Encode(), http.StatusFound)
		return
	}

	// Demo-jwt mode: no server-side session to clear.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(
		"<html><body>" +
			"<h1>Logged out</h1>" +
			"<p>You have been logged out of MCP Proxy. You may close this window.</p>" +
			"</body></html>",
	))
}

// --- PKCE helpers ---

// verifyS256 checks that base64url(SHA-256(verifier)) == challenge.
func verifyS256(verifier, challenge string) bool {
	h := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])
	return computed == challenge
}

// computeS256Challenge returns the base64url-encoded SHA-256 of verifier.
func computeS256Challenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// generatePKCEVerifier returns a cryptographically random PKCE verifier (43 chars).
func generatePKCEVerifier() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// isLoopbackURI reports whether rawURL has a loopback host.
func isLoopbackURI(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	h := u.Hostname()
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

// generateOpaqueCode returns a 32-byte random hex string suitable for auth codes.
func generateOpaqueCode() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// writeOAuthError writes an RFC 6749 §5.2 JSON error response.
func writeOAuthError(w http.ResponseWriter, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": desc,
	})
}

// --- Login page template ---

type authorizePageData struct {
	ClientID      string
	RedirectURI   string
	State         string
	CodeChallenge string
}

var authorizePageTmpl = template.Must(template.New("authorize").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MCP Proxy — Sign In</title>
<style>
  *, *::before, *::after { box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
    max-width: 420px; margin: 80px auto; padding: 0 24px; color: #111; background: #fafafa;
  }
  .card {
    background: #fff; border: 1px solid #e0e0e0; border-radius: 10px;
    padding: 32px; box-shadow: 0 1px 4px rgba(0,0,0,.06);
  }
  h1 { font-size: 1.35rem; font-weight: 600; margin: 0 0 6px; }
  .app { font-size: 0.85rem; color: #666; margin: 0 0 28px; }
  label { display: block; margin-top: 16px; font-size: 0.875rem; font-weight: 500; color: #333; }
  input[type=email], input[type=text] {
    display: block; width: 100%; padding: 9px 12px; margin-top: 5px;
    font-size: 0.95rem; border: 1px solid #d0d0d0; border-radius: 6px;
    outline: none; background: #fff;
  }
  input:focus { border-color: #0070f3; box-shadow: 0 0 0 2px rgba(0,112,243,.15); }
  .hint { font-size: 0.78rem; color: #888; margin-top: 4px; }
  button {
    display: block; width: 100%; margin-top: 24px; padding: 11px;
    font-size: 0.95rem; font-weight: 500;
    background: #0070f3; color: #fff; border: none; border-radius: 6px; cursor: pointer;
  }
  button:hover { background: #005ed3; }
  .footer { margin-top: 20px; font-size: 0.78rem; color: #aaa; text-align: center; }
</style>
</head>
<body>
<div class="card">
  <h1>Sign in to MCP Proxy</h1>
  <p class="app">Authorizing: <strong>{{.ClientID}}</strong></p>
  <form method="POST">
    <input type="hidden" name="redirect_uri"   value="{{.RedirectURI}}">
    <input type="hidden" name="state"           value="{{.State}}">
    <input type="hidden" name="code_challenge"  value="{{.CodeChallenge}}">
    <input type="hidden" name="client_id"       value="{{.ClientID}}">
    <label>Email
      <input type="email" name="email" placeholder="you@example.com" required autofocus>
    </label>
    <label>Groups
      <input type="text" name="groups" value="platform-eng,everyone">
      <span class="hint">Comma-separated — controls policy access in demo</span>
    </label>
    <button type="submit">Connect to MCP Proxy</button>
  </form>
</div>
<p class="footer">MCP Proxy Demo · OAuth 2.0 + PKCE</p>
</body>
</html>`))
