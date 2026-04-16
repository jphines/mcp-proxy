package config_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jphines/mcp-proxy/internal/config"
)

func TestLoadFromEnv_MissingRequired(t *testing.T) {
	// Clear all config env vars.
	vars := []string{
		"OKTA_ISSUER", "OKTA_AUDIENCE", "DATABASE_URL", "CREDENTIAL_ENCRYPTION_KEY",
		"CONFIG_DIR", "PROXY_BASE_URL", "WORKSPACE", "STATE_HMAC_SECRET",
		"SLACK_WEBHOOK_URL", "SLACK_SIGNING_SECRET",
	}
	for _, v := range vars {
		t.Setenv(v, "")
	}

	_, err := config.LoadFromEnv()
	require.Error(t, err)

	errStr := err.Error()
	for _, v := range vars {
		assert.Contains(t, errStr, v, "expected error for missing %s", v)
	}
}

func TestLoadFromEnv_Valid(t *testing.T) {
	setMinimalEnv(t)
	cfg, err := config.LoadFromEnv()
	require.NoError(t, err)
	assert.Equal(t, "https://ro.okta.com/oauth2/default", cfg.OktaIssuer)
	assert.Equal(t, "production", cfg.Workspace)
}

func TestLoadFromEnv_InvalidWorkspace(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("WORKSPACE", "invalid-workspace")
	_, err := config.LoadFromEnv()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "WORKSPACE")
}

func TestLoadFromEnv_InvalidURL(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("OKTA_ISSUER", "not-a-url")
	_, err := config.LoadFromEnv()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "OKTA_ISSUER")
}

func TestLoadFromEnv_CredentialCacheTTLCap(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("CREDENTIAL_CACHE_TTL", "60s")
	_, err := config.LoadFromEnv()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CREDENTIAL_CACHE_TTL")
}

func TestLoadFromEnv_TLSPartial(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("TLS_CERT_FILE", "/path/to/cert.pem")
	// TLS_KEY_FILE not set
	_, err := config.LoadFromEnv()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TLS_KEY_FILE")
}

func TestLoadServers_Valid(t *testing.T) {
	f := writeTempFile(t, serversYAML)
	sf, err := config.LoadServers(f)
	require.NoError(t, err)
	require.Len(t, sf.Servers, 2)
	assert.Equal(t, "github", sf.Servers[0].ID)
	assert.Equal(t, "jira", sf.Servers[1].ID)
}

func TestLoadServers_DuplicateID(t *testing.T) {
	yaml := `
servers:
  - id: github
    name: GitHub
    transport:
      type: streamable_http
      url: https://github-mcp.ro.com
    auth_strategy: oauth
    oauth_provider:
      auth_url: https://github.com/login/oauth/authorize
      token_url: https://github.com/login/oauth/access_token
      client_id: abc
      client_secret_ref: proxy/github-secret
      scopes: ["repo"]
  - id: github
    name: GitHub2
    transport:
      type: streamable_http
      url: https://github2-mcp.ro.com
    auth_strategy: static
    credential_ref: proxy/github-token
`
	f := writeTempFile(t, yaml)
	_, err := config.LoadServers(f)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate server id")
}

func TestLoadServers_OAuthMissingProvider(t *testing.T) {
	yaml := `
servers:
  - id: github
    name: GitHub
    transport:
      type: streamable_http
      url: https://github-mcp.ro.com
    auth_strategy: oauth
`
	f := writeTempFile(t, yaml)
	_, err := config.LoadServers(f)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "oauth_provider is required")
}

func TestLoadServers_StaticMissingRef(t *testing.T) {
	yaml := `
servers:
  - id: clinical
    name: Clinical
    transport:
      type: streamable_http
      url: https://clinical-mcp.ro.com
    auth_strategy: static
`
	f := writeTempFile(t, yaml)
	_, err := config.LoadServers(f)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "credential_ref is required")
}

func TestLoadPolicy_Valid(t *testing.T) {
	f := writeTempFile(t, policyYAML)
	pf, err := config.LoadPolicy(f)
	require.NoError(t, err)
	require.Len(t, pf.Rules, 3)
}

func TestLoadPolicy_DuplicateID(t *testing.T) {
	yaml := `
rules:
  - id: rule-1
    priority: 1
    condition: "true"
    action: allow
  - id: rule-1
    priority: 2
    condition: "false"
    action: deny
`
	f := writeTempFile(t, yaml)
	_, err := config.LoadPolicy(f)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate rule id")
}

func TestLoadPolicy_RequireApprovalMissingBlock(t *testing.T) {
	yaml := `
rules:
  - id: needs-approval
    priority: 10
    condition: "tool.tier >= 4"
    action: require_approval
`
	f := writeTempFile(t, yaml)
	_, err := config.LoadPolicy(f)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "approval block is required")
}

// --- STS config validation ---

func TestLoadServers_STSValid(t *testing.T) {
	yaml := `
servers:
  - id: aws-bedrock
    name: AWS Bedrock
    transport:
      type: streamable_http
      url: https://bedrock-mcp.internal
    data_tier: 3
    auth_strategy: sts
    sts_config:
      role_arn: arn:aws:iam::123456789012:role/BedrockAccess
      session_name_prefix: mcp-
      duration_seconds: 900
    auth_injection:
      method: header_bearer
    enabled: true
`
	f := writeTempFile(t, yaml)
	sf, err := config.LoadServers(f)
	require.NoError(t, err)
	require.Len(t, sf.Servers, 1)
	require.NotNil(t, sf.Servers[0].STSConfig)
	assert.Equal(t, "arn:aws:iam::123456789012:role/BedrockAccess", sf.Servers[0].STSConfig.RoleARN)
}

func TestLoadServers_STSMissingConfig(t *testing.T) {
	yaml := `
servers:
  - id: aws-svc
    name: AWS Service
    transport:
      type: streamable_http
      url: https://test.internal
    auth_strategy: sts
`
	f := writeTempFile(t, yaml)
	_, err := config.LoadServers(f)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sts_config is required")
}

func TestLoadServers_STSMissingRoleARN(t *testing.T) {
	yaml := `
servers:
  - id: aws-svc
    name: AWS Service
    transport:
      type: streamable_http
      url: https://test.internal
    auth_strategy: sts
    sts_config:
      session_name_prefix: mcp-
`
	f := writeTempFile(t, yaml)
	_, err := config.LoadServers(f)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "role_arn is required")
}

func TestLoadServers_STSInvalidDuration(t *testing.T) {
	yaml := `
servers:
  - id: aws-svc
    name: AWS Service
    transport:
      type: streamable_http
      url: https://test.internal
    auth_strategy: sts
    sts_config:
      role_arn: arn:aws:iam::123456789012:role/Test
      duration_seconds: 100
`
	f := writeTempFile(t, yaml)
	_, err := config.LoadServers(f)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duration_seconds must be 900-43200")
}

// --- Credential backend config ---

func TestLoadFromEnv_CredentialBackendPostgresDefault(t *testing.T) {
	setMinimalEnv(t)
	cfg, err := config.LoadFromEnv()
	require.NoError(t, err)
	assert.Equal(t, "postgres", cfg.CredentialBackend)
}

func TestLoadFromEnv_CredentialBackendSecretsManager(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("CREDENTIAL_BACKEND", "secretsmanager")
	// secretsmanager backend doesn't require CREDENTIAL_ENCRYPTION_KEY
	t.Setenv("CREDENTIAL_ENCRYPTION_KEY", "")
	cfg, err := config.LoadFromEnv()
	require.NoError(t, err)
	assert.Equal(t, "secretsmanager", cfg.CredentialBackend)
}

func TestLoadFromEnv_CredentialBackendInvalid(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("CREDENTIAL_BACKEND", "vault")
	_, err := config.LoadFromEnv()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CREDENTIAL_BACKEND")
}

func TestLoadFromEnv_Auth0OverridesOktaFields(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("AUTH0_DOMAIN", "dev-test.us.auth0.com")
	t.Setenv("AUTH0_CLIENT_ID", "client123")
	t.Setenv("AUTH0_AUDIENCE", "")
	cfg, err := config.LoadFromEnv()
	require.NoError(t, err)
	assert.Equal(t, "https://dev-test.us.auth0.com/", cfg.OktaIssuer)
	assert.Equal(t, "client123", cfg.OktaAudience, "when Auth0Audience empty, OktaAudience = Auth0ClientID")
	assert.Equal(t, "https://mcp-proxy/groups", cfg.Auth0GroupsClaim)
}

func TestLoadFromEnv_Auth0WithAudience(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("AUTH0_DOMAIN", "dev-test.us.auth0.com")
	t.Setenv("AUTH0_CLIENT_ID", "client123")
	t.Setenv("AUTH0_AUDIENCE", "https://api/mcp-proxy")
	cfg, err := config.LoadFromEnv()
	require.NoError(t, err)
	assert.Equal(t, "https://api/mcp-proxy", cfg.OktaAudience)
}

// --- helpers ---

func setMinimalEnv(t *testing.T) {
	t.Helper()
	t.Setenv("OKTA_ISSUER", "https://ro.okta.com/oauth2/default")
	t.Setenv("OKTA_AUDIENCE", "api://mcp-proxy")
	t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/db")
	t.Setenv("CREDENTIAL_ENCRYPTION_KEY", "this-is-a-32-byte-cred-encrypt-key!")
	t.Setenv("CONFIG_DIR", "/etc/mcp-proxy")
	t.Setenv("PROXY_BASE_URL", "https://mcp-proxy.ro.com")
	t.Setenv("WORKSPACE", "production")
	t.Setenv("STATE_HMAC_SECRET", "this-is-a-32-byte-hmac-secret-ok")
	t.Setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/T000/B000/xxx")
	t.Setenv("SLACK_SIGNING_SECRET", "slack-signing-secret-value-here")
}

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "*.yaml")
	require.NoError(t, err)
	_, err = f.WriteString(content)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	return f.Name()
}

const serversYAML = `
servers:
  - id: github
    name: GitHub
    transport:
      type: streamable_http
      url: https://github-mcp.ro.com
    data_tier: 2
    auth_strategy: oauth
    oauth_provider:
      auth_url: https://github.com/login/oauth/authorize
      token_url: https://github.com/login/oauth/access_token
      client_id: Iv1.abc123
      client_secret_ref: proxy/github-oauth-secret
      scopes: ["repo", "read:org"]
      pkce_required: true
    auth_injection:
      method: header_bearer
    allowed_groups: ["engineering"]
    enabled: true

  - id: jira
    name: Jira
    transport:
      type: streamable_http
      url: https://jira-mcp.ro.com
    data_tier: 2
    auth_strategy: oauth
    oauth_provider:
      auth_url: https://auth.atlassian.com/authorize
      token_url: https://auth.atlassian.com/oauth/token
      client_id: xyz789
      client_secret_ref: proxy/jira-oauth-secret
      scopes: ["read:jira-work", "write:jira-work"]
      pkce_required: true
    auth_injection:
      method: header_bearer
    enabled: true
`

const policyYAML = `
rules:
  - id: deny-production-delete
    priority: 1
    condition: 'tool.server == "clinical" && tool.name.contains("delete") && env.workspace == "production"'
    action: deny
    reason: "Deletion of production clinical data is prohibited"
    audit_level: full

  - id: require-approval-tier4
    priority: 10
    condition: "tool.tier >= 4"
    action: require_approval
    reason: "High-impact actions require human approval"
    audit_level: full
    approval:
      channel: slack
      timeout: 5m
      require_diff: false

  - id: default-allow
    priority: 999
    condition: "true"
    action: allow
    audit_level: standard
`
