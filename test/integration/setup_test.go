// Package integration contains end-to-end tests that run the full proxy
// in-process against real dependencies:
//
//   - PostgreSQL 16 via testcontainers (for audit chain tests)
//   - In-process JWT/JWKS server (for auth)
//   - In-process mock MCP downstream (test/mcp_fixture)
//   - In-memory credential store (no AWS required)
//   - Real CEL policy engine
//
// Run with:
//
//	go test -v -timeout 10m ./test/integration/...
package integration_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/ro-eng/mcp-proxy/gateway"
	"github.com/ro-eng/mcp-proxy/internal/approval"
	"github.com/ro-eng/mcp-proxy/internal/audit"
	"github.com/ro-eng/mcp-proxy/internal/auth"
	"github.com/ro-eng/mcp-proxy/internal/credential"
	"github.com/ro-eng/mcp-proxy/internal/oauth"
	"github.com/ro-eng/mcp-proxy/internal/policy"
	"github.com/ro-eng/mcp-proxy/internal/proxy"
	"github.com/ro-eng/mcp-proxy/internal/registry"
	"github.com/ro-eng/mcp-proxy/internal/store"
	mcp_fixture "github.com/ro-eng/mcp-proxy/test/mcp_fixture"
)

// testDB is the shared PostgreSQL connection for audit chain tests.
// It is nil when Docker is unavailable (tests that need it are skipped).
var testDB *store.DB

const (
	testAudience   = "api://mcp-proxy-test"
	testHMACSecret = "integration-test-hmac-secret-32chars!"
)

// TestMain starts the PostgreSQL testcontainer once for the entire test run.
func TestMain(m *testing.M) {
	ctx := context.Background()

	container, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("mcpproxy"),
		tcpostgres.WithUsername("test"),
		tcpostgres.WithPassword("test"),
	)
	if err != nil {
		log.Printf("WARNING: could not start postgres container: %v — audit chain tests will be skipped", err)
	} else {
		connStr, cErr := container.ConnectionString(ctx, "sslmode=disable")
		if cErr != nil {
			log.Printf("WARNING: container connection string: %v — audit chain tests will be skipped", cErr)
		} else {
			db, openErr := store.Open(ctx, connStr)
			if openErr != nil {
				log.Printf("WARNING: opening test DB: %v — audit chain tests will be skipped", openErr)
			} else {
				testDB = db
			}
		}
	}

	code := m.Run()

	if testDB != nil {
		testDB.Close()
	}
	if container != nil {
		_ = container.Terminate(ctx)
	}

	os.Exit(code)
}

// ── JWT helpers ───────────────────────────────────────────────────────────────

// jwtKeys holds an RSA key pair + in-process JWKS server for signing test tokens.
type jwtKeys struct {
	privateKey *rsa.PrivateKey
	kid        string
	issuer     string    // JWKS server URL
	jwksSrv    *httptest.Server
}

func newJWTKeys(t *testing.T) *jwtKeys {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid := "integration-test-key"
	pubKey, err := jwk.FromRaw(priv.Public())
	require.NoError(t, err)
	require.NoError(t, pubKey.Set(jwk.KeyIDKey, kid))
	require.NoError(t, pubKey.Set(jwk.AlgorithmKey, jwa.RS256))

	keySet := jwk.NewSet()
	require.NoError(t, keySet.AddKey(pubKey))
	jwksBytes, err := json.Marshal(keySet)
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksBytes)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return &jwtKeys{
		privateKey: priv,
		kid:        kid,
		issuer:     srv.URL,
		jwksSrv:    srv,
	}
}

// token generates a signed test JWT. opts may override defaults.
func (k *jwtKeys) token(t *testing.T, opts ...func(*jwt.Builder) *jwt.Builder) string {
	t.Helper()

	b := jwt.NewBuilder().
		Issuer(k.issuer).
		Audience([]string{testAudience}).
		Subject("test-user@example.com").
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Hour)).
		Claim("groups", []string{"engineering"})

	for _, opt := range opts {
		b = opt(b)
	}

	tok, err := b.Build()
	require.NoError(t, err)

	privKey, err := jwk.FromRaw(k.privateKey)
	require.NoError(t, err)
	require.NoError(t, privKey.Set(jwk.KeyIDKey, k.kid))
	require.NoError(t, privKey.Set(jwk.AlgorithmKey, jwa.RS256))

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, privKey))
	require.NoError(t, err)
	return string(signed)
}

// ── In-memory credential store ────────────────────────────────────────────────

// memCredentialStore is a simple in-memory gateway.CredentialStore for tests.
// It returns a static API key for any lookup unless an explicit entry exists.
type memCredentialStore struct {
	mu         sync.Mutex
	entries    map[string]*gateway.Credential // key: serviceID or scope key
	defaultKey string
}

func newMemCredentialStore(defaultAPIKey string) *memCredentialStore {
	return &memCredentialStore{
		entries:    make(map[string]*gateway.Credential),
		defaultKey: defaultAPIKey,
	}
}

func scopeKey(scope gateway.CredentialScope) string {
	return fmt.Sprintf("%s/%s/%s", scope.Level, scope.OwnerID, scope.ServiceID)
}

func (s *memCredentialStore) Resolve(_ context.Context, identity *gateway.Identity, serviceID string) (*gateway.Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Prefer session-scoped entry if identity is set.
	if identity != nil {
		key := scopeKey(gateway.CredentialScope{Level: gateway.ScopeSession, OwnerID: identity.Subject, ServiceID: serviceID})
		if cred, ok := s.entries[key]; ok {
			return copyCredential(cred), nil
		}
	}
	// Fall back to org-scope entry.
	key := scopeKey(gateway.CredentialScope{Level: gateway.ScopeOrg, ServiceID: serviceID})
	if cred, ok := s.entries[key]; ok {
		return copyCredential(cred), nil
	}
	// Final fallback: default API key.
	if s.defaultKey != "" {
		return &gateway.Credential{
			Type:  gateway.CredTypeAPIKey,
			Value: []byte(s.defaultKey),
		}, nil
	}
	return nil, gateway.ErrCredentialNotFound
}

func (s *memCredentialStore) Store(_ context.Context, scope gateway.CredentialScope, cred *gateway.Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[scopeKey(scope)] = copyCredential(cred)
	return nil
}

func (s *memCredentialStore) Revoke(_ context.Context, scope gateway.CredentialScope) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, scopeKey(scope))
	return nil
}

func (s *memCredentialStore) Rotate(_ context.Context, scope gateway.CredentialScope) (*gateway.Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cred, ok := s.entries[scopeKey(scope)]; ok {
		return copyCredential(cred), nil
	}
	return nil, gateway.ErrCredentialNotFound
}

func (s *memCredentialStore) List(_ context.Context, _ *gateway.Identity) ([]gateway.CredentialScope, error) {
	return nil, nil
}

func copyCredential(c *gateway.Credential) *gateway.Credential {
	val := make([]byte, len(c.Value))
	copy(val, c.Value)
	return &gateway.Credential{
		Type:      c.Type,
		Value:     val,
		ExpiresAt: c.ExpiresAt,
		Metadata:  c.Metadata,
	}
}

// ── Noop MetricsCollector ─────────────────────────────────────────────────────

// noopMetrics is a MetricsCollector that discards all observations.
// Using the real Prometheus collector in tests would panic on duplicate registration.
type noopMetrics struct{}

func (noopMetrics) ToolCallTotal(_, _, _ string)                    {}
func (noopMetrics) ToolCallDuration(_, _ string, _ int64)           {}
func (noopMetrics) DownstreamDuration(_ string, _ int64)            {}
func (noopMetrics) CredentialResolutionDuration(_, _ string, _ int64) {}
func (noopMetrics) ApprovalWaitDuration(_ string, _ int64)          {}
func (noopMetrics) CircuitBreakerState(_ string, _ int)             {}
func (noopMetrics) ActiveSessions(_ int)                            {}
func (noopMetrics) DownstreamError(_, _, _ string)                  {}
func (noopMetrics) EnrollmentRequired(_ string)                     {}
func (noopMetrics) PolicyEvalError(_, _ string)                     {}

var _ gateway.MetricsCollector = noopMetrics{}

// ── Harness ───────────────────────────────────────────────────────────────────

// harness wires the full proxy for integration tests.
type harness struct {
	t           *testing.T
	proxyURL    string
	proxySrv    *httptest.Server
	keys        *jwtKeys
	downstream  *mcp_fixture.Server
	approvalSvc *approval.Service
	credStore   *memCredentialStore
}

// harnessOptions configures optional per-test overrides.
type harnessOptions struct {
	// serverYAML overrides the generated servers.yaml. If empty, a default
	// servers.yaml pointing to the fixture downstream is generated.
	serverYAML string
	// approvalSvc overrides the approval service (e.g., an intercepting wrapper).
	// When set, this is used as deps.ApprovalService; innerApprovalSvc is used
	// for the Slack callback handler.
	approvalSvc      gateway.ApprovalService
	innerApprovalSvc *approval.Service // handler needs concrete type for Decide
	// proxyBaseURL overrides the proxy base URL used for OAuth callbacks.
	// Defaults to the actual httptest server URL (determined at harness creation).
	proxyBaseURL string
}

// newHarness creates a full proxy harness for integration tests.
// policyYAML is the content of the policy rules file.
func newHarness(t *testing.T, policyYAML string, opts ...harnessOptions) *harness {
	t.Helper()

	var opt harnessOptions
	if len(opts) > 0 {
		opt = opts[0]
	}

	// ── 1. Downstream fixture MCP server ──────────────────────────────────────
	downstream := mcp_fixture.NewServer()
	t.Cleanup(downstream.Close)

	// ── 2. JWT keys + JWKS server ─────────────────────────────────────────────
	keys := newJWTKeys(t)

	// ── 3. Use NewUnstartedServer to know the proxy URL before starting ───────
	// This allows OAuth enrollment to be configured with the correct callback URL.
	proxySrv := httptest.NewUnstartedServer(nil) // handler set after proxy creation
	proxyURL := "http://" + proxySrv.Listener.Addr().String()
	if opt.proxyBaseURL != "" {
		proxyURL = opt.proxyBaseURL
	}

	// ── 4. Temp config directory ──────────────────────────────────────────────
	configDir := t.TempDir()

	serversContent := opt.serverYAML
	if serversContent == "" {
		serversContent = fmt.Sprintf(`servers:
  - id: fixture
    name: Fixture Server
    transport:
      type: streamable_http
      url: %s
    data_tier: 4
    auth_strategy: static
    credential_ref: test-fixture-cred
    auth_injection:
      method: header_bearer
    allowed_groups: []
    enabled: true
    circuit_breaker:
      failure_threshold: 5
      reset_timeout: 30s
      half_open_max: 2
`, downstream.URL())
	}

	require.NoError(t, os.WriteFile(filepath.Join(configDir, "servers.yaml"), []byte(serversContent), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(configDir, "policy.yaml"), []byte(policyYAML), 0644))

	// ── 5. Internal components ─────────────────────────────────────────────────
	credStore := newMemCredentialStore("test-static-api-key")

	innerApprovalSvc := opt.innerApprovalSvc
	if innerApprovalSvc == nil {
		innerApprovalSvc = approval.NewService(nil) // no Slack sender
	}
	var approvalSvcIface gateway.ApprovalService = innerApprovalSvc
	if opt.approvalSvc != nil {
		approvalSvcIface = opt.approvalSvc
	}
	approvalHandler := approval.NewHandler(approvalSvcIface, "test-slack-signing-secret")

	tokenCache := oauth.NewTokenCache(5 * time.Minute)

	// Registry must exist before enrollment (enrollment needs registry.Get).
	reg, err := registry.New(filepath.Join(configDir, "servers.yaml"), proxy.NewToolLister())
	require.NoError(t, err)
	t.Cleanup(reg.Close)

	enrollment := oauth.NewEnrollment(oauth.EnrollmentOptions{
		CredentialStore: credStore,
		ServerRegistry:  reg,
		TokenCache:      tokenCache,
		HMACSecret:      []byte(testHMACSecret),
		ProxyBaseURL:    proxyURL,
	})

	credResolver := credential.NewCompositeResolver(credStore, enrollment, nil)
	authenticator := auth.NewOktaAuthenticator(keys.issuer, testAudience)

	policyEngine, err := policy.NewEngine(filepath.Join(configDir, "policy.yaml"), "test", "us-east-1")
	require.NoError(t, err)

	// ── 6. Wire dependencies and create proxy ─────────────────────────────────
	deps := &gateway.Dependencies{
		Authenticator:      authenticator,
		PolicyEngine:       policyEngine,
		CredentialStore:    credStore,
		CredentialResolver: credResolver,
		ServerRegistry:     reg,
		AuditLogger:        &audit.NoopLogger{},
		ApprovalService:    approvalSvcIface,
		OAuthEnrollment:    enrollment,
		MetricsCollector:   noopMetrics{},
	}

	p := proxy.New(deps)

	// ── 7. Start the HTTP server ───────────────────────────────────────────────
	proxySrv.Config = p.NewHTTPServer("", approvalHandler)
	proxySrv.Start()
	t.Cleanup(proxySrv.Close)

	return &harness{
		t:           t,
		proxyURL:    proxySrv.URL,
		proxySrv:    proxySrv,
		keys:        keys,
		downstream:  downstream,
		approvalSvc: innerApprovalSvc,
		credStore:   credStore,
	}
}

// callTool creates a fresh MCP session to the proxy, calls a single tool,
// and returns the result. toolMCPName uses the proxy's __ separator convention
// (e.g., "fixture__read_data").
func (h *harness) callTool(ctx context.Context, bearerToken, toolMCPName string, args map[string]any) (*mcp.CallToolResult, error) {
	h.t.Helper()

	transport := &mcp.StreamableClientTransport{
		Endpoint: h.proxyURL + "/mcp",
		HTTPClient: &http.Client{
			Transport: &bearerRoundTripper{token: bearerToken, base: http.DefaultTransport},
		},
		DisableStandaloneSSE: true,
	}

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.0.1"}, nil)
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	defer session.Close()

	return session.CallTool(ctx, &mcp.CallToolParams{
		Name:      toolMCPName,
		Arguments: args,
	})
}

// bearerRoundTripper injects an Authorization: Bearer header on every request.
type bearerRoundTripper struct {
	token string
	base  http.RoundTripper
}

func (t *bearerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	if t.token != "" {
		r.Header.Set("Authorization", "Bearer "+t.token)
	}
	return t.base.RoundTrip(r)
}

// allowAllPolicy is a policy YAML that unconditionally allows all tool calls.
const allowAllPolicy = `rules:
  - id: allow-all
    priority: 999
    condition: "true"
    action: allow
    audit_level: standard
`
