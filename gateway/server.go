package gateway

import (
	"context"
	"time"
)

// TransportType identifies the protocol used to connect to a downstream MCP server.
type TransportType string

const (
	// TransportStdio uses stdin/stdout of a child process.
	TransportStdio TransportType = "stdio"
	// TransportHTTPSSE uses HTTP with Server-Sent Events (legacy).
	TransportHTTPSSE TransportType = "http_sse"
	// TransportStreamableHTTP uses the Streamable HTTP MCP transport (preferred).
	TransportStreamableHTTP TransportType = "streamable_http"
)

// InjectionMethod controls how the resolved credential is attached to the downstream request.
type InjectionMethod string

const (
	// InjectionHeaderBearer injects as "Authorization: Bearer <value>".
	InjectionHeaderBearer InjectionMethod = "header_bearer"
	// InjectionHeaderCustom injects as a custom header with the configured name.
	InjectionHeaderCustom InjectionMethod = "header_custom"
	// InjectionQueryParam injects as a URL query parameter.
	InjectionQueryParam InjectionMethod = "query_param"
	// InjectionEnvVar injects as an environment variable (stdio servers only).
	InjectionEnvVar InjectionMethod = "env_var"
)

// TransportConfig describes how to reach a downstream MCP server.
type TransportConfig struct {
	// Type is the transport protocol.
	Type TransportType
	// URL is the base URL for HTTP-based transports.
	URL string
	// Command is the executable path for stdio servers.
	Command string
	// Args are the command-line arguments for stdio servers.
	Args []string
	// Headers are static HTTP headers to include in downstream requests.
	Headers map[string]string
}

// AuthInjection describes how to attach a resolved credential to a downstream call.
type AuthInjection struct {
	// Method determines where the credential is placed.
	Method InjectionMethod
	// Header is the custom header name (InjectionHeaderCustom only).
	Header string
	// Prefix is prepended to the credential value (e.g., "Bearer ").
	Prefix string
	// EnvVar is the environment variable name (InjectionEnvVar only).
	EnvVar string
	// QueryParam is the query parameter name (InjectionQueryParam only).
	QueryParam string
}

// OAuthProvider holds the per-service OAuth 2.0 configuration.
// The proxy uses this as a confidential client; engineers never see client secrets.
type OAuthProvider struct {
	// ServiceID matches the server registration ID.
	ServiceID string
	// AuthURL is the provider's authorization endpoint.
	AuthURL string
	// TokenURL is the provider's token endpoint.
	TokenURL string
	// RevokeURL is the provider's token revocation endpoint (optional).
	RevokeURL string
	// ClientID is the OAuth application client identifier.
	ClientID string
	// ClientSecretRef is the vault path for the OAuth client secret.
	ClientSecretRef string
	// Scopes lists the OAuth scopes to request during enrollment.
	Scopes []string
	// PKCERequired indicates PKCE must be used (always true in the proxy).
	PKCERequired bool
	// RedirectBase is the base URL for the OAuth callback (e.g., "https://mcp-proxy.ro.com").
	RedirectBase string
}

// STSConfig holds the per-server AWS STS AssumeRoleWithWebIdentity configuration.
// Used when a downstream server requires temporary AWS credentials obtained by
// exchanging the caller's validated JWT for short-lived IAM credentials.
type STSConfig struct {
	// RoleARN is the IAM role to assume (e.g. "arn:aws:iam::123456789012:role/MyRole").
	RoleARN string
	// SessionNamePrefix is prepended to the caller's subject to form the role session name.
	// Default: "mcp-proxy-". The full session name is "{prefix}{identity.Subject}".
	SessionNamePrefix string
	// DurationSeconds is the requested credential lifetime (900–3600).
	// Default: 900 (15 minutes).
	DurationSeconds int32
}

// CircuitBreakerConfig controls per-server circuit breaker behaviour.
type CircuitBreakerConfig struct {
	// FailureThreshold is the number of consecutive failures before opening the circuit.
	FailureThreshold int
	// ResetTimeout is how long to wait in Open state before allowing a probe request.
	ResetTimeout time.Duration
	// HalfOpenMax is the number of probe requests allowed in the HalfOpen state.
	HalfOpenMax int
}

// ServerConfig is the complete registration record for a downstream MCP server.
type ServerConfig struct {
	// ID is the unique server identifier used in tool namespacing (e.g., "github").
	ID string
	// Name is a human-readable display name.
	Name string
	// Transport describes how to reach the server.
	Transport TransportConfig
	// DataTier is the data classification tier (1=public … 5=red-line).
	DataTier int
	// Strategy is the credential resolution method.
	Strategy AuthStrategy
	// CredentialRef is the vault path for static-strategy credentials.
	CredentialRef string
	// OAuthProvider is set for OAuth-strategy servers.
	OAuthProvider *OAuthProvider
	// STSConfig is set for STS-strategy servers that require AssumeRoleWithWebIdentity.
	STSConfig *STSConfig
	// AuthInjection describes how to attach the resolved credential.
	AuthInjection AuthInjection
	// AllowedGroups restricts tool access to callers in these Okta groups.
	// An empty slice means all authenticated callers are allowed.
	AllowedGroups []string
	// Enabled controls whether the server is active in the catalog.
	Enabled bool
	// CircuitBreaker configures fault tolerance for this server.
	CircuitBreaker CircuitBreakerConfig
	// Tags are arbitrary labels used in policy CEL expressions.
	Tags map[string]string
}

// Tool is a namespaced tool entry in the proxy's aggregated catalog.
type Tool struct {
	// NamespacedName is "serverID::toolName" (e.g., "github::create_pull_request").
	NamespacedName string
	// ServerID is the owning server's registration ID.
	ServerID string
	// OriginalName is the bare tool name as registered on the downstream server.
	OriginalName string
	// Description is the tool's human-readable description.
	Description string
	// InputSchema is the JSON Schema for the tool's input arguments.
	InputSchema any
	// Tier is the autonomy/severity tier inherited from the server's DataTier.
	Tier int
}

// ServerFilter constrains ServerRegistry queries.
type ServerFilter struct {
	// Enabled filters by enabled status when non-nil.
	Enabled *bool
	// Strategy filters by auth strategy when non-nil.
	Strategy *AuthStrategy
	// DataTier filters to servers at or below the given tier when non-nil.
	DataTier *int
}

// ServerRegistry manages the catalog of downstream MCP servers.
type ServerRegistry interface {
	// Get returns the server configuration for the given ID.
	// Returns ErrServerNotFound when the ID is not registered.
	Get(ctx context.Context, id string) (*ServerConfig, error)

	// List returns all servers matching the optional filter.
	List(ctx context.Context, filter *ServerFilter) ([]*ServerConfig, error)

	// ToolCatalog returns the aggregated tool list visible to the given identity.
	// Tools from servers whose AllowedGroups the identity does not satisfy are excluded.
	// Results are cached with a short TTL to avoid hammering downstream servers.
	ToolCatalog(ctx context.Context, identity *Identity) ([]Tool, error)

	// Execute calls fn within the named server's circuit breaker.
	// Returns ErrCircuitOpen immediately (without calling fn) if the circuit is open.
	// The circuit breaker records fn's return value as success or failure.
	Execute(ctx context.Context, serverID string, fn func() error) error
}
