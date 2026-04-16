package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jphines/mcp-proxy/gateway"
	"github.com/jphines/mcp-proxy/internal/mocks"
)

// --- authGate tests ---

func TestAuthGate_NoToken_Returns401WithResourceMetadata(t *testing.T) {
	t.Parallel()

	auth := mocks.NewMockAuthenticator(t)
	deps := &gateway.Dependencies{Authenticator: auth}
	p := &Proxy{deps: deps, proxyBaseURL: "https://proxy.example.com", requireAuth: true}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler should not be called")
	})

	handler := p.authGate(inner)
	req := httptest.NewRequest("POST", "/mcp", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	wwwAuth := rec.Header().Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, "Bearer")
	assert.Contains(t, wwwAuth, "resource_metadata")
	assert.Contains(t, wwwAuth, "/.well-known/oauth-protected-resource")
}

func TestAuthGate_InvalidToken_Returns401(t *testing.T) {
	t.Parallel()

	auth := mocks.NewMockAuthenticator(t)
	auth.EXPECT().Authenticate(context.Background(), "bad-token").
		Return(nil, gateway.ErrUnauthenticated)

	deps := &gateway.Dependencies{Authenticator: auth}
	p := &Proxy{deps: deps, proxyBaseURL: "https://proxy.example.com", requireAuth: true}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler should not be called")
	})

	handler := p.authGate(inner)
	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer bad-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	wwwAuth := rec.Header().Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, `invalid_token`)
}

func TestAuthGate_ValidToken_PassesThrough(t *testing.T) {
	t.Parallel()

	identity := &gateway.Identity{Subject: "alice@example.com"}
	auth := mocks.NewMockAuthenticator(t)
	auth.EXPECT().Authenticate(context.Background(), "good-token").Return(identity, nil)

	deps := &gateway.Dependencies{Authenticator: auth}
	p := &Proxy{deps: deps, proxyBaseURL: "https://proxy.example.com", requireAuth: true}

	innerCalled := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		innerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := p.authGate(inner)
	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer good-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.True(t, innerCalled, "inner handler should be called for valid token")
	assert.Equal(t, http.StatusOK, rec.Code)
}

// --- health/readiness endpoints ---

func TestHealthz(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest("GET", "/healthz", nil)
	rec := httptest.NewRecorder()
	handleHealthz(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "ok", rec.Body.String())
}

func TestReadyz(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest("GET", "/readyz", nil)
	rec := httptest.NewRecorder()
	handleReadyz(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "ready", rec.Body.String())
}

// --- extractBearerToken ---

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		expected string
	}{
		{"valid bearer", "Bearer my-token", "my-token"},
		{"lowercase bearer rejected", "bearer my-token", ""},
		{"empty header", "", ""},
		{"no bearer prefix", "Basic dXNlcjpwYXNz", ""},
		{"bearer only", "Bearer ", ""},
		{"extra space in token preserved", "Bearer  my-token", " my-token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			assert.Equal(t, tt.expected, extractBearerToken(req))
		})
	}
}

// --- OAuth enrollment handler ---

func TestHandleOAuthEnroll_MissingToken(t *testing.T) {
	t.Parallel()

	deps := &gateway.Dependencies{}
	p := &Proxy{deps: deps}

	req := httptest.NewRequest("GET", "/oauth/enroll/google", nil)
	req.SetPathValue("serviceID", "google")
	rec := httptest.NewRecorder()

	p.handleOAuthEnroll(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestHandleOAuthEnroll_TokenFromQueryParam(t *testing.T) {
	t.Parallel()

	identity := &gateway.Identity{Subject: "alice"}
	auth := mocks.NewMockAuthenticator(t)
	auth.EXPECT().Authenticate(context.Background(), "query-token").Return(identity, nil)

	enrollment := mocks.NewMockOAuthEnrollment(t)
	enrollment.EXPECT().InitiateFlow(context.Background(), identity, "google").
		Return("https://accounts.google.com/auth?code=123", nil)

	deps := &gateway.Dependencies{Authenticator: auth, OAuthEnrollment: enrollment}
	p := &Proxy{deps: deps}

	req := httptest.NewRequest("GET", "/oauth/enroll/google?token=query-token", nil)
	req.SetPathValue("serviceID", "google")
	rec := httptest.NewRecorder()

	p.handleOAuthEnroll(rec, req)

	assert.Equal(t, http.StatusFound, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "accounts.google.com")
}

// --- OAuth callback handler ---

func TestHandleOAuthCallback_MissingParams(t *testing.T) {
	t.Parallel()

	deps := &gateway.Dependencies{}
	p := &Proxy{deps: deps}

	req := httptest.NewRequest("GET", "/oauth/callback", nil)
	rec := httptest.NewRecorder()

	p.handleOAuthCallback(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "missing code or state")
}

func TestHandleOAuthCallback_Success(t *testing.T) {
	t.Parallel()

	enrollment := mocks.NewMockOAuthEnrollment(t)
	enrollment.EXPECT().HandleCallback(context.Background(), "auth-code", "state-val").Return(nil)

	deps := &gateway.Dependencies{OAuthEnrollment: enrollment}
	p := &Proxy{deps: deps}

	req := httptest.NewRequest("GET", "/oauth/callback?code=auth-code&state=state-val", nil)
	rec := httptest.NewRecorder()

	p.handleOAuthCallback(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "enrollment successful")
}

// --- Logout handler ---

func TestHandleLogout_Auth0Mode_RedirectsToAuth0(t *testing.T) {
	t.Parallel()

	as := newOAuthASAuth0("https://proxy.example.com", "dev-test.us.auth0.com", "client123", "")

	req := httptest.NewRequest("GET", "/oauth/logout", nil)
	rec := httptest.NewRecorder()

	as.handleLogout(rec, req)

	assert.Equal(t, http.StatusFound, rec.Code)
	loc := rec.Header().Get("Location")
	assert.Contains(t, loc, "https://dev-test.us.auth0.com/v2/logout")
	assert.Contains(t, loc, "client_id=client123")
	assert.Contains(t, loc, "returnTo=https%3A%2F%2Fproxy.example.com")
}

func TestHandleLogout_DemoMode_RendersLoggedOutPage(t *testing.T) {
	t.Parallel()

	as := newOAuthAS("https://proxy.example.com", "http://demo-jwt:9999")

	req := httptest.NewRequest("GET", "/oauth/logout", nil)
	rec := httptest.NewRecorder()

	as.handleLogout(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Logged out")
	assert.Contains(t, rec.Body.String(), "You have been logged out")
}

// --- Metadata includes end_session_endpoint ---

func TestHandleMetadata_IncludesEndSessionEndpoint(t *testing.T) {
	t.Parallel()

	as := newOAuthAS("https://proxy.example.com", "http://demo-jwt:9999")

	req := httptest.NewRequest("GET", "/.well-known/oauth-authorization-server", nil)
	rec := httptest.NewRecorder()

	as.handleMetadata(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var meta map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&meta))
	assert.Equal(t, "https://proxy.example.com/oauth/logout", meta["end_session_endpoint"])
}

// --- TLS config ---

func TestTLSConfig_MinTLS13(t *testing.T) {
	t.Parallel()
	cfg := tlsConfig()
	require.NotNil(t, cfg)
	assert.Equal(t, uint16(0x0304), cfg.MinVersion) // tls.VersionTLS13
}
