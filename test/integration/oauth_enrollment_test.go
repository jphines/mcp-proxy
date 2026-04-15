package integration_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// oauthServerYAML builds a servers.yaml snippet for an OAuth-protected server.
// providerURL is the mock OAuth provider's base URL.
// fixtureURL is the fixture downstream MCP server's URL.
func oauthServerYAML(fixtureURL, providerURL string) string {
	return fmt.Sprintf(`servers:
  - id: fixture
    name: Fixture Server (OAuth)
    transport:
      type: streamable_http
      url: %s
    data_tier: 2
    auth_strategy: oauth
    oauth_provider:
      auth_url: %s/auth
      token_url: %s/token
      client_id: test-client-id
      client_secret_ref: test-secret-ref
      scopes: ["read"]
      pkce_required: true
    auth_injection:
      method: header_bearer
    allowed_groups: []
    enabled: true
    circuit_breaker:
      failure_threshold: 5
      reset_timeout: 30s
      half_open_max: 2
`, fixtureURL, providerURL, providerURL)
}

// mockOAuthProvider is a minimal OAuth 2.0 provider for integration tests.
// It accepts any code and returns a deterministic access token.
type mockOAuthProvider struct {
	srv         *httptest.Server
	accessToken string
	refreshToken string
}

func newMockOAuthProvider(t *testing.T) *mockOAuthProvider {
	t.Helper()

	p := &mockOAuthProvider{
		accessToken:  "test-access-token-" + fmt.Sprint(time.Now().UnixNano()),
		refreshToken: "test-refresh-token",
	}

	mux := http.NewServeMux()

	// /auth — returns the state param directly (mimics authorization grant).
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, "authorize here")
	})

	// /token — accepts any code and returns a static token response.
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		// Accept any code; return static token.
		resp := map[string]any{
			"access_token":  p.accessToken,
			"token_type":    "bearer",
			"expires_in":    3600,
			"refresh_token": p.refreshToken,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

func (p *mockOAuthProvider) URL() string { return p.srv.URL }

// TestOAuth_NotEnrolled verifies that calling a tool on an OAuth server without
// enrolling first returns an error (EnrollmentRequiredError surfaced in the result).
func TestOAuth_NotEnrolled(t *testing.T) {
	t.Parallel()

	mockProvider := newMockOAuthProvider(t)
	h := newHarness(t, allowAllPolicy, harnessOptions{
		serverYAML: oauthServerYAML("DOWNSTREAM_URL", mockProvider.URL()),
		// serverYAML with the real downstream URL is populated below
	})

	// Rebuild with correct downstream URL.
	h2 := newHarness(t, allowAllPolicy, harnessOptions{
		serverYAML: oauthServerYAML(h.downstream.URL(), mockProvider.URL()),
	})

	token := h2.keys.token(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Without enrollment, the credential middleware should return an error.
	result, err := h2.callTool(ctx, token, "fixture__read_data", nil)
	require.NoError(t, err) // MCP protocol level: no error
	require.NotNil(t, result)
	assert.True(t, result.IsError, "unenrolled OAuth call should return error")

	// Downstream should NOT have been called.
	assert.Zero(t, h2.downstream.Recorder().Len())
	_ = h // suppress unused warning for the placeholder harness
}

// TestOAuth_FullEnrollmentFlow tests the complete OAuth enrollment path:
//  1. Call the tool → EnrollmentRequired
//  2. GET /oauth/enroll/{serviceID} → redirect to mock OAuth provider
//  3. Extract state from auth URL
//  4. Call /oauth/callback with code + state → token stored
//  5. Call the tool again → succeeds with the stored token
func TestOAuth_FullEnrollmentFlow(t *testing.T) {
	t.Parallel()

	mockProvider := newMockOAuthProvider(t)
	h := newHarness(t, allowAllPolicy, harnessOptions{
		serverYAML: oauthServerYAML("PLACEHOLDER", mockProvider.URL()),
	})
	// Now rebuild with the real downstream URL from the harness.
	h2 := newHarness(t, allowAllPolicy, harnessOptions{
		serverYAML: oauthServerYAML(h.downstream.URL(), mockProvider.URL()),
	})

	token := h2.keys.token(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// ── Step 1: Verify unenrolled call fails ──────────────────────────────────
	result1, err := h2.callTool(ctx, token, "fixture__read_data", nil)
	require.NoError(t, err)
	assert.True(t, result1.IsError, "step 1: unenrolled call should fail")

	// ── Step 2: Initiate enrollment ───────────────────────────────────────────
	enrollURL := h2.proxyURL + "/oauth/enroll/fixture"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, enrollURL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	// Don't follow redirects; we need the Location header.
	httpClient := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusFound, resp.StatusCode, "enrollment should redirect to OAuth provider")

	authURL := resp.Header.Get("Location")
	require.NotEmpty(t, authURL, "Location header should contain the OAuth authorization URL")

	// ── Step 3: Extract state from the authorization URL ──────────────────────
	parsedAuthURL, err := url.Parse(authURL)
	require.NoError(t, err)
	state := parsedAuthURL.Query().Get("state")
	require.NotEmpty(t, state, "authorization URL must include state parameter")

	// ── Step 4: Simulate the OAuth callback ───────────────────────────────────
	callbackURL := h2.proxyURL + "/oauth/callback?" + url.Values{
		"code":  {"test-authorization-code"},
		"state": {state},
	}.Encode()

	callbackReq, err := http.NewRequestWithContext(ctx, http.MethodGet, callbackURL, nil)
	require.NoError(t, err)

	callbackResp, err := http.DefaultClient.Do(callbackReq)
	require.NoError(t, err)
	defer callbackResp.Body.Close()
	require.Equal(t, http.StatusOK, callbackResp.StatusCode, "callback should return 200 on success")

	// ── Step 5: Tool call should now succeed ──────────────────────────────────
	result2, err := h2.callTool(ctx, token, "fixture__read_data", map[string]any{"id": "enrolled"})
	require.NoError(t, err)
	assert.False(t, result2.IsError, "step 5: enrolled call should succeed")
	assert.Equal(t, 1, h2.downstream.Recorder().Len(),
		"downstream should be called exactly once after enrollment")

	_ = h
}

// TestOAuth_CallbackInvalidState verifies that a callback with a tampered state
// parameter is rejected.
func TestOAuth_CallbackInvalidState(t *testing.T) {
	t.Parallel()

	mockProvider := newMockOAuthProvider(t)
	// Use a placeholder downstream URL; this test only exercises the callback path.
	h := newHarness(t, allowAllPolicy, harnessOptions{
		serverYAML: oauthServerYAML("http://downstream.test.invalid", mockProvider.URL()),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Call callback with an invalid (unsigned) state.
	callbackURL := h.proxyURL + "/oauth/callback?" + url.Values{
		"code":  {"any-code"},
		"state": {strings.Repeat("x", 32)}, // not a valid HMAC-signed state
	}.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, callbackURL, nil)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"callback with invalid state should be rejected with 400")
}
