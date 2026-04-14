# Ro MCP Proxy — Internal Architecture

**Companion to:** mcp-proxy-requirements.md
**Language:** Go 1.23+
**MCP SDK:** `modelcontextprotocol/go-sdk` (official, Google co-maintained)
**Date:** April 2026

---

## 1. System Overview

The proxy is a single Go binary that acts as an MCP server to upstream clients and an MCP client to downstream tool servers. Every tool call passes through a middleware pipeline that handles authentication, policy evaluation, credential resolution, downstream dispatch, and audit — in that order.

```
                    ┌─────────────────────────────────────────────┐
                    │              MCP PROXY                       │
                    │                                             │
  Claude Code ──┐   │  ┌─────────┐                                │
  claude.ai  ───┤   │  │ MCP     │   ┌──────────────────────┐     │
  Managed    ───┤──▶│  │ Server  │──▶│  Middleware Pipeline  │     │
  Agents     ───┤   │  │ (upstream)  │                      │     │
  Custom     ───┘   │  └─────────┘   │  Auth                │     │
                    │                │  ↓                    │     │
                    │                │  Policy               │     │
                    │                │  ↓                    │     │
                    │                │  HITL (conditional)   │     │
                    │                │  ↓                    │     │
                    │                │  Credential Resolve   │     │   ┌──────────┐
                    │                │  ↓                    │──┬──┼──▶│ GitHub   │
                    │                │  Dispatch             │  │  │  │ MCP      │
                    │                │  ↓                    │  │  │  └──────────┘
                    │                │  Audit                │  │  │  ┌──────────┐
                    │                └──────────────────────┘  ├──┼──▶│ Clinical │
                    │                                          │  │  │ API      │
                    │  ┌──────────┐  ┌──────────┐  ┌────────┐ │  │  └──────────┘
                    │  │ Okta     │  │ Vault    │  │ Audit  │ │  │  ┌──────────┐
                    │  │ JWKS     │  │ Backend  │  │ Store  │ ├──┼──▶│ Jira     │
                    │  └──────────┘  └──────────┘  └────────┘ │  │  │ MCP      │
                    │                                          │  │  └──────────┘
                    └──────────────────────────────────────────┘
```

---

## 2. Core Interfaces

These are the primary abstraction boundaries. Each interface has one job. Implementations are injected at startup via constructor.

### 2.1 Authenticator

Validates inbound identity assertions and produces a canonical `Identity` that flows through the rest of the pipeline.

```go
package gateway

import "context"

// Identity represents an authenticated caller — human or agent.
// Populated by the Authenticator from the inbound token claims.
type Identity struct {
    Subject      string            // Okta sub claim — unique ID
    Type         IdentityType      // Human, Agent, Service
    Groups       []string          // Okta group memberships
    Scopes       []string          // Authorized scopes from token
    SessionID    string            // Optional — set when token carries session context
    DelegatedBy  string            // For agents: the human who initiated the delegation
    Claims       map[string]any    // Raw claims for policy evaluation via CEL
    TokenExpiry  time.Time         // When the identity assertion expires
}

type IdentityType string

const (
    IdentityHuman   IdentityType = "human"
    IdentityAgent   IdentityType = "agent"
    IdentityService IdentityType = "service"
)

// Authenticator validates inbound tokens and returns an Identity.
// The proxy doesn't care *how* the token was issued — Okta OIDC,
// XAA token exchange, service account JWT — it just needs a validated
// Identity to feed into the policy engine.
type Authenticator interface {
    // Authenticate validates the token from the request context
    // (typically from the Authorization header or MCP auth metadata)
    // and returns the authenticated Identity.
    //
    // Returns ErrUnauthenticated if the token is missing, expired,
    // or fails signature validation.
    Authenticate(ctx context.Context, token string) (*Identity, error)
}
```

### 2.2 PolicyEngine

Evaluates whether a given identity is allowed to call a given tool, and what additional actions (HITL, audit level) apply.

```go
package gateway

import "context"

// PolicyDecision is the outcome of evaluating a tool call against policy.
type PolicyDecision struct {
    Action       PolicyAction
    Reason       string              // Human-readable explanation
    Rule         string              // ID of the rule that matched
    AuditLevel   AuditLevel          // How much to log for this call
    ApprovalSpec *ApprovalSpec       // Non-nil if Action == ActionRequireApproval
}

type PolicyAction string

const (
    ActionAllow           PolicyAction = "allow"
    ActionDeny            PolicyAction = "deny"
    ActionRequireApproval PolicyAction = "require_approval"
    ActionLog             PolicyAction = "log" // Allow, but with explicit audit emphasis
)

type AuditLevel string

const (
    AuditMinimal  AuditLevel = "minimal"  // Tool name + identity + decision
    AuditStandard AuditLevel = "standard" // + arguments hash + response code
    AuditFull     AuditLevel = "full"     // + arguments (if not classified) + response body hash
)

// ApprovalSpec describes how a human approval should be requested.
type ApprovalSpec struct {
    Channel     string        // "slack", "webhook", etc.
    Timeout     time.Duration // How long to wait before auto-rejecting
    RequireDiff bool          // Whether the approver must be different from the caller
}

// PolicyEngine evaluates tool calls against pre-authored rules.
// Rules are loaded from YAML files with CEL expressions.
// The engine does not make authorization decisions about data —
// it decides whether the identity is allowed to invoke the tool.
type PolicyEngine interface {
    // Evaluate checks whether the given identity is allowed to call
    // the given tool with the given arguments.
    //
    // The engine evaluates rules in order: first matching deny short-circuits,
    // require_approval gates, log records, and allow is the default.
    Evaluate(ctx context.Context, identity *Identity, call *ToolCall) (*PolicyDecision, error)

    // Reload hot-reloads policy rules from the configured source
    // without restarting the proxy.
    Reload(ctx context.Context) error
}

// ToolCall represents the parameters of a tool invocation
// as seen by the policy engine (before credential injection).
type ToolCall struct {
    ServerID  string         // Which downstream MCP server
    ToolName  string         // The tool being invoked
    Arguments map[string]any // The arguments from the caller
    Tier      int            // 1-5 severity tier from tool registration
}
```

### 2.3 CredentialStore

Abstracted vault backend. First implementation: AWS Secrets Manager. Interface designed to support HashiCorp Vault, 1Password, or anything else.

```go
package gateway

import "context"

// CredentialScope identifies where a credential is stored in the hierarchy.
type CredentialScope struct {
    Level     ScopeLevel // Session, Agent, Org
    OwnerID   string     // Session ID, agent sub, or org identifier
    ServiceID string     // The downstream service this credential is for
}

type ScopeLevel string

const (
    ScopeSession ScopeLevel = "session"
    ScopeAgent   ScopeLevel = "agent"
    ScopeOrg     ScopeLevel = "org"
)

// Credential holds a resolved secret. It is zeroed from memory
// after the downstream call completes (30-second hard ceiling).
type Credential struct {
    Type       CredentialType
    Value      []byte            // The secret material — API key, access token, etc.
    ExpiresAt  *time.Time        // Non-nil for time-limited credentials (OAuth tokens)
    Metadata   map[string]string // Provider-specific metadata (e.g., OAuth client ID, token endpoint)
}

type CredentialType string

const (
    CredTypeAPIKey       CredentialType = "api_key"
    CredTypeOAuthAccess  CredentialType = "oauth_access_token"
    CredTypeOAuthRefresh CredentialType = "oauth_refresh_token"
    CredTypeIAMRole      CredentialType = "iam_role"
    CredTypeBearerToken  CredentialType = "bearer_token"
    CredTypeBasicAuth    CredentialType = "basic_auth"
)

// CredentialStore is the abstraction over the vault backend.
// Implementations must encrypt at rest and zero secrets from memory
// when the caller signals completion via Credential.Zero().
type CredentialStore interface {
    // Resolve returns the credential for a service, checking
    // session → agent → org scopes in order.
    // Returns ErrCredentialNotFound if no credential exists at any scope.
    Resolve(ctx context.Context, identity *Identity, serviceID string) (*Credential, error)

    // Store persists a credential at the given scope.
    // The implementation must encrypt the value before persisting.
    Store(ctx context.Context, scope CredentialScope, cred *Credential) error

    // Revoke removes a credential. If the credential is an OAuth token,
    // the implementation should also revoke it at the provider if possible.
    Revoke(ctx context.Context, scope CredentialScope) error

    // Rotate refreshes an expiring credential (e.g., OAuth access token refresh).
    // Returns the new credential, which is also persisted.
    Rotate(ctx context.Context, scope CredentialScope) (*Credential, error)

    // List returns all credential scopes for a given identity.
    // Used for session cleanup and admin views.
    List(ctx context.Context, identity *Identity) ([]CredentialScope, error)
}

// Zero securely wipes the credential value from memory.
// Must be called after the downstream call completes.
func (c *Credential) Zero() {
    for i := range c.Value {
        c.Value[i] = 0
    }
    c.Value = nil
}
```

### 2.4 ServerRegistry

Manages the catalog of downstream MCP servers, their transport configuration, data classification, and connection pooling.

```go
package gateway

import "context"

// ServerConfig describes a registered downstream MCP server.
type ServerConfig struct {
    ID             string            // Unique identifier (used as namespace prefix)
    Name           string            // Human-readable name
    Transport      TransportConfig   // How to connect to this server
    DataTier       int               // 1-5 data classification
    Strategy       AuthStrategy      // How to obtain credentials (oauth, xaa, static, sts)
    CredentialRef  string            // Service ID for static credentials (vault path)
    OAuthProvider  *OAuthProvider    // Non-nil when Strategy == AuthStrategyOAuth
    AuthInjection  AuthInjection     // How to inject the credential into downstream requests
    AllowedGroups  []string          // Okta groups permitted to access this server (empty = all)
    Enabled        bool              // Can be disabled without removing config
    CircuitBreaker CircuitBreakerConfig
    Tags           map[string]string // Arbitrary metadata (team, environment, hipaa, etc.)
}

type TransportType string

const (
    TransportStdio          TransportType = "stdio"
    TransportHTTPSSE        TransportType = "http_sse"
    TransportStreamableHTTP TransportType = "streamable_http"
)

type TransportConfig struct {
    Type    TransportType
    URL     string   // For HTTP transports
    Command string   // For stdio transport — the binary to exec
    Args    []string // For stdio transport
    Headers map[string]string // Static headers for HTTP transports
}

// AuthInjection describes how the resolved credential is inserted
// into the downstream request.
type AuthInjection struct {
    Method   InjectionMethod
    Header   string // For HeaderBearerToken and HeaderCustom
    Prefix   string // e.g., "Bearer ", "Token ", "Basic "
    EnvVar   string // For stdio servers — inject as environment variable
}

type InjectionMethod string

const (
    InjectionHeaderBearer InjectionMethod = "header_bearer"  // Authorization: Bearer <token>
    InjectionHeaderCustom InjectionMethod = "header_custom"  // X-Api-Key: <token>
    InjectionQueryParam   InjectionMethod = "query_param"    // ?api_key=<token>
    InjectionEnvVar       InjectionMethod = "env_var"        // For stdio processes
)

type CircuitBreakerConfig struct {
    FailureThreshold int           // Consecutive failures before opening
    ResetTimeout     time.Duration // How long to wait before half-open probe
    HalfOpenMax      int           // Max requests in half-open state
}

// ServerRegistry manages the catalog of downstream MCP servers.
type ServerRegistry interface {
    // Get returns a server config by ID.
    Get(ctx context.Context, id string) (*ServerConfig, error)

    // List returns all registered servers, optionally filtered.
    List(ctx context.Context, filter *ServerFilter) ([]*ServerConfig, error)

    // Register adds or updates a server config. Hot-reloadable.
    Register(ctx context.Context, config *ServerConfig) error

    // Deregister removes a server config.
    Deregister(ctx context.Context, id string) error

    // ToolCatalog returns the aggregated tool list across all
    // registered servers, filtered by the caller's identity.
    // Each tool name is prefixed with the server ID namespace.
    ToolCatalog(ctx context.Context, identity *Identity) ([]Tool, error)
}
```

### 2.5 AuditLogger

Structured, tamper-evident audit trail for every tool call.

```go
package gateway

import "context"

// AuditEvent is the structured record of a single tool call lifecycle.
type AuditEvent struct {
    // Identification
    ID          string    // Unique event ID (ULID for ordering)
    Timestamp   time.Time
    Region      string    // AWS region where this proxy instance runs
    
    // Caller
    CallerSub   string       // Identity.Subject
    CallerType  IdentityType
    CallerGroups []string
    SessionID   string
    DelegatedBy string       // The human behind an agent identity
    
    // Request
    ServerID    string    // Downstream server namespace
    ToolName    string    // Tool within that server
    ArgsHash    string    // SHA-256 of canonical JSON arguments
    
    // Decision
    Decision    PolicyAction // allow, deny, require_approval
    PolicyRule  string       // Which rule matched
    AuditLevel  AuditLevel
    
    // Approval (if HITL was triggered)
    ApprovalReq *ApprovalRecord
    
    // Execution
    CredentialRef string    // Vault reference (never the value)
    DownstreamURL string    // Where the call was routed
    StatusCode    int       // Downstream HTTP status (0 if not HTTP)
    LatencyMs     int64     // Total proxy overhead in ms
    DownstreamMs  int64     // Downstream call time in ms
    Error         string    // Non-empty if the call failed
    
    // Integrity
    PrevHash    string    // SHA-256 of the previous event (chain)
}

type ApprovalRecord struct {
    RequestedAt time.Time
    Channel     string       // "slack", "webhook"
    Outcome     string       // "approved", "rejected", "timeout", "modified"
    ApprovedBy  string       // Identity of the approver
    ResolvedAt  time.Time
    ModifiedArgs *string     // Non-nil if the approver modified arguments
}

// AuditLogger persists audit events and maintains the hash chain.
type AuditLogger interface {
    // Emit records an audit event. The implementation is responsible
    // for computing the hash chain (PrevHash) and persisting.
    Emit(ctx context.Context, event *AuditEvent) error

    // Query retrieves events matching the filter. For compliance reporting.
    Query(ctx context.Context, filter *AuditFilter) ([]*AuditEvent, error)

    // VerifyChain checks the integrity of the hash chain over a range.
    // Returns the first broken link, or nil if the chain is intact.
    VerifyChain(ctx context.Context, from, to time.Time) (*ChainBreak, error)
}

type AuditFilter struct {
    CallerSub  *string
    SessionID  *string
    ServerID   *string
    ToolName   *string
    Decision   *PolicyAction
    TimeFrom   *time.Time
    TimeTo     *time.Time
    Limit      int
}

type ChainBreak struct {
    EventID      string
    ExpectedHash string
    ActualHash   string
}
```

### 2.6 ApprovalService

Manages HITL approval workflows — sending requests, receiving decisions, handling timeouts.

```go
package gateway

import "context"

// ApprovalRequest is what gets sent to the approval channel
// when a tool call triggers a require_approval policy.
type ApprovalRequest struct {
    ID          string         // Unique request ID
    CallerSub   string         // Who triggered the call
    CallerType  IdentityType
    ServerID    string
    ToolName    string
    ArgsSummary string         // Human-readable summary of arguments
    PolicyRule  string         // Which rule triggered this
    Tier        int            // Severity tier
    ExpiresAt   time.Time      // When this request auto-rejects
}

// ApprovalDecision is the response from the approver.
type ApprovalDecision struct {
    RequestID    string
    Outcome      ApprovalOutcome
    ApprovedBy   string          // Identity of the approver
    ModifiedArgs map[string]any  // Non-nil if outcome is Modified
    Reason       string          // Optional explanation
}

type ApprovalOutcome string

const (
    OutcomeApproved ApprovalOutcome = "approved"
    OutcomeRejected ApprovalOutcome = "rejected"
    OutcomeModified ApprovalOutcome = "modified"
    OutcomeTimeout  ApprovalOutcome = "timeout"
)

// ApprovalService manages the lifecycle of HITL approval requests.
type ApprovalService interface {
    // Request sends an approval request to the configured channel
    // and blocks until a decision is received or the timeout expires.
    Request(ctx context.Context, req *ApprovalRequest) (*ApprovalDecision, error)

    // Decide is called by the approval channel adapter (e.g., Slack webhook handler)
    // when an approver makes a decision.
    Decide(ctx context.Context, decision *ApprovalDecision) error
}
```

### 2.7 OAuthEnrollment

Manages the per-user OAuth flow for SaaS tool authentication through the proxy.

```go
package gateway

import "context"

// OAuthProvider describes a downstream service's OAuth configuration.
type OAuthProvider struct {
    ServiceID     string   // Maps to ServerConfig.CredentialRef
    AuthURL       string   // Authorization endpoint
    TokenURL      string   // Token endpoint
    RevokeURL     string   // Revocation endpoint (optional)
    ClientID      string   // OAuth client ID (registered with provider)
    ClientSecret  string   // Stored in vault, resolved at runtime
    Scopes        []string // Requested OAuth scopes
    PKCERequired  bool     // Use PKCE (should always be true)
    RedirectBase  string   // Base URL for OAuth callback (proxy's own URL)
}

// OAuthEnrollment manages the per-user OAuth authorization flow.
// When an engineer first uses a tool that requires per-user OAuth,
// the proxy initiates this flow to get their consent and store
// their tokens in the vault.
type OAuthEnrollment interface {
    // InitiateFlow starts the OAuth authorization code flow.
    // Returns a URL to redirect the user to for consent.
    // The state parameter is signed and includes the identity + service ID.
    InitiateFlow(ctx context.Context, identity *Identity, serviceID string) (authURL string, err error)

    // HandleCallback processes the OAuth callback after user consent.
    // Exchanges the authorization code for tokens and stores them
    // in the CredentialStore scoped to the user.
    HandleCallback(ctx context.Context, code string, state string) error

    // IsEnrolled checks whether a user has a valid OAuth credential
    // for a given service.
    IsEnrolled(ctx context.Context, identity *Identity, serviceID string) (bool, error)

    // Revoke removes the user's OAuth credential and revokes
    // the token at the provider.
    Revoke(ctx context.Context, identity *Identity, serviceID string) error
}
```

### 2.8 TokenExchanger (XAA / ID-JAG)

Future-state credential resolution for services that support Okta's Cross-App Access protocol. When a downstream service supports XAA, credentials are derived fresh from the caller's Okta session on every call — no stored refresh tokens, no enrollment step, no consent screen.

Today (April 2026): No target service supports XAA yet. GitHub, Atlassian, Snowflake, and Mixpanel all use standard OAuth. This interface exists so the proxy is ready when adoption arrives.

```go
package gateway

import "context"

// TokenExchanger handles the XAA/ID-JAG credential derivation flow.
//
// The flow is two token exchanges:
//   1. Proxy sends caller's Okta ID token to Okta's token endpoint,
//      requesting an ID-JAG (Identity Assertion JWT) targeted at
//      the downstream service.
//   2. Proxy presents the ID-JAG to the downstream service's
//      authorization server, which validates it against Okta's
//      JWKS and issues a scoped access token.
//
// No credentials are stored. Every token is short-lived and derived
// from the Okta session. If the Okta session expires, the next call
// triggers re-authentication at the proxy level (not at each service).
type TokenExchanger interface {
    // Exchange derives an access token for the downstream service
    // from the caller's Okta identity. Returns a short-lived
    // Credential that should be used immediately and zeroed after.
    //
    // Returns ErrXAANotSupported if the service doesn't support XAA.
    Exchange(ctx context.Context, identity *Identity, serviceID string) (*Credential, error)
}
```

### 2.9 CredentialResolver (Composite)

The credential middleware doesn't call `CredentialStore`, `OAuthEnrollment`, or `TokenExchanger` directly. It calls a `CredentialResolver` that encapsulates the strategy selection based on the server's auth configuration.

```go
package gateway

import "context"

// AuthStrategy determines how credentials are obtained for a downstream service.
type AuthStrategy string

const (
    // AuthStrategyOAuth — per-user OAuth enrollment with stored refresh tokens.
    // Used for: GitHub, Jira, Mixpanel, Snowflake (current).
    AuthStrategyOAuth AuthStrategy = "oauth"

    // AuthStrategyXAA — Okta XAA/ID-JAG token exchange. No stored credentials.
    // Used for: services that adopt the XAA protocol (future).
    AuthStrategyXAA AuthStrategy = "xaa"

    // AuthStrategyStatic — API key or service account token from the vault.
    // Used for: internal APIs, agent workloads, services without OAuth.
    AuthStrategyStatic AuthStrategy = "static"

    // AuthStrategySTS — AWS IAM role assumption via STS.
    // Used for: AWS-native services (S3, Bedrock, etc.).
    AuthStrategySTS AuthStrategy = "sts"
)

// CredentialResolver selects the appropriate credential strategy
// for each downstream service and returns a ready-to-inject Credential.
type CredentialResolver interface {
    // Resolve returns a credential for the given identity + service,
    // using the strategy configured for that service.
    //
    // For OAuth: checks enrollment, resolves cached/stored token, refreshes if needed.
    // For XAA: derives a fresh token from the Okta session (no storage).
    // For Static: resolves from the vault.
    // For STS: assumes an IAM role scoped to the caller.
    //
    // Returns EnrollmentRequiredError if OAuth enrollment is needed.
    Resolve(ctx context.Context, identity *Identity, server *ServerConfig) (*Credential, error)
}
```

---

## 3. Service-Specific Auth Configurations

### Auth Pattern Summary

| Service | Auth Strategy | Per-User | Enrollment Required | Stored Credentials | Okta Federation |
|---------|--------------|----------|--------------------|--------------------|-----------------|
| GitHub | OAuth | Yes | Yes (one-time consent) | Refresh token in vault | No (GitHub's own OAuth) |
| Jira/Confluence | OAuth | Yes | Yes (one-time consent) | Refresh token in vault | No (Atlassian's own OAuth) |
| Snowflake | OAuth | Yes | Yes (one-time consent) | Refresh token in vault | Possible via `external_oauth` (future) |
| Mixpanel | OAuth | Yes | Yes (one-time consent) | Refresh token in vault | No |
| Clinical API | Static | No | No | Service token in vault | N/A (internal API) |
| AWS services | STS | No | No | None (assumed role) | Via OIDC federation |

All four external services use the same pattern today: standard OAuth through the proxy with per-user enrollment. This is deliberate — one pattern to build, test, and operate. The `TokenExchanger` interface is ready for when XAA adoption makes the zero-enrollment path viable.

### Mixpanel HIPAA Constraint

Mixpanel's MCP server explicitly does not support HIPAA, and their BAA does not cover the MCP feature. The proxy's policy engine must enforce that agents cannot send PHI-containing arguments to Mixpanel tools. In practice this is fine — Mixpanel queries return aggregate analytics data (event counts, funnel metrics, retention curves), not patient records. But the policy rule should be explicit:

```yaml
- id: mixpanel-no-phi-args
  priority: 5
  condition: >
    tool.server == "mixpanel" &&
    tool.args.exists_one(k,
      k == "patient_id" || k == "mrn" || k == "ssn"
    )
  action: deny
  reason: "Mixpanel MCP does not support HIPAA — PHI identifiers cannot be sent as arguments"
```

---

## 4. Middleware Pipeline

The proxy processes every tool call through an ordered middleware chain. Each middleware receives the request context, can short-circuit (return early), or pass to the next handler. This is a standard `http.Handler`-style chain adapted for MCP tool calls.

```go
package gateway

import "context"

// ToolCallContext carries the accumulated state through the middleware pipeline.
type ToolCallContext struct {
    // Set by the MCP server handler
    RawRequest  *mcp.CallToolRequest
    ServerID    string
    ToolName    string
    Arguments   map[string]any
    
    // Set by AuthMiddleware
    Identity    *Identity
    
    // Set by PolicyMiddleware
    Decision    *PolicyDecision
    
    // Set by CredentialMiddleware
    Credential  *Credential  // Zeroed after dispatch
    Injection   *AuthInjection
    
    // Set by DispatchMiddleware
    Response    *mcp.CallToolResult
    StatusCode  int
    LatencyMs   int64
    
    // Error at any stage
    Err         error
}

// Middleware processes one step in the tool call pipeline.
type Middleware func(ctx context.Context, tc *ToolCallContext, next MiddlewareFunc)

// MiddlewareFunc is the continuation to the next middleware.
type MiddlewareFunc func(ctx context.Context, tc *ToolCallContext)

// BuildPipeline chains middleware in order. The last middleware
// is the dispatcher that actually calls the downstream server.
func BuildPipeline(middlewares ...Middleware) MiddlewareFunc {
    if len(middlewares) == 0 {
        return func(ctx context.Context, tc *ToolCallContext) {}
    }
    return func(ctx context.Context, tc *ToolCallContext) {
        middlewares[0](ctx, tc, BuildPipeline(middlewares[1:]...))
    }
}
```

### Pipeline Order

```go
func NewProxy(deps Dependencies) *Proxy {
    p := &Proxy{deps: deps}
    
    p.pipeline = BuildPipeline(
        p.authMiddleware,       // 1. Validate token → populate Identity
        p.routeMiddleware,      // 2. Parse server::tool → resolve ServerConfig
        p.policyMiddleware,     // 3. Evaluate policy → allow/deny/require-approval
        p.approvalMiddleware,   // 4. If require-approval, block for HITL
        p.enrollmentMiddleware, // 5. If per-user OAuth needed, check enrollment
        p.credentialMiddleware, // 6. Resolve credential from vault
        p.dispatchMiddleware,   // 7. Inject credential, call downstream, stream response
        p.auditMiddleware,      // 8. Emit structured audit event
    )
    
    return p
}
```

### Middleware Implementations (Sketches)

```go
// 1. Auth: Extract and validate the Okta token.
func (p *Proxy) authMiddleware(ctx context.Context, tc *ToolCallContext, next MiddlewareFunc) {
    token := extractBearerToken(ctx)
    identity, err := p.deps.Authenticator.Authenticate(ctx, token)
    if err != nil {
        tc.Err = fmt.Errorf("authentication failed: %w", err)
        return // short-circuit — no next()
    }
    tc.Identity = identity
    next(ctx, tc)
}

// 3. Policy: Evaluate the call against rules.
func (p *Proxy) policyMiddleware(ctx context.Context, tc *ToolCallContext, next MiddlewareFunc) {
    decision, err := p.deps.PolicyEngine.Evaluate(ctx, tc.Identity, &ToolCall{
        ServerID:  tc.ServerID,
        ToolName:  tc.ToolName,
        Arguments: tc.Arguments,
        Tier:      tc.serverConfig.DataTier,
    })
    if err != nil {
        // Fail open: allow with audit warning
        tc.Decision = &PolicyDecision{Action: ActionAllow, Reason: "policy_eval_error"}
        p.deps.AuditLogger.Emit(ctx, &AuditEvent{
            Decision: ActionAllow, PolicyRule: "fail_open", Error: err.Error(),
        })
        next(ctx, tc)
        return
    }
    
    tc.Decision = decision
    
    if decision.Action == ActionDeny {
        tc.Err = fmt.Errorf("denied by policy: %s", decision.Reason)
        // Don't call next — but do fall through to audit middleware
        // (audit middleware is always invoked, even on deny)
        return
    }
    
    next(ctx, tc)
}

// 4. Approval: Block for HITL if policy requires it.
func (p *Proxy) approvalMiddleware(ctx context.Context, tc *ToolCallContext, next MiddlewareFunc) {
    if tc.Decision.Action != ActionRequireApproval {
        next(ctx, tc)
        return
    }
    
    decision, err := p.deps.ApprovalService.Request(ctx, &ApprovalRequest{
        ID:          ulid.Make().String(),
        CallerSub:   tc.Identity.Subject,
        CallerType:  tc.Identity.Type,
        ServerID:    tc.ServerID,
        ToolName:    tc.ToolName,
        ArgsSummary: summarizeArgs(tc.Arguments),
        PolicyRule:  tc.Decision.Rule,
        Tier:        tc.serverConfig.DataTier,
        ExpiresAt:   time.Now().Add(tc.Decision.ApprovalSpec.Timeout),
    })
    if err != nil || decision.Outcome == OutcomeRejected || decision.Outcome == OutcomeTimeout {
        tc.Err = fmt.Errorf("approval denied or timed out")
        return
    }
    
    if decision.Outcome == OutcomeModified {
        tc.Arguments = decision.ModifiedArgs
    }
    
    next(ctx, tc)
}

// 6. Credential: Resolve from vault, defer Zero().
func (p *Proxy) credentialMiddleware(ctx context.Context, tc *ToolCallContext, next MiddlewareFunc) {
    cred, err := p.deps.CredentialStore.Resolve(ctx, tc.Identity, tc.serverConfig.CredentialRef)
    if err != nil {
        tc.Err = fmt.Errorf("credential resolution failed: %w", err)
        return
    }
    tc.Credential = cred
    defer cred.Zero() // CRITICAL: wipe from memory after downstream call
    
    tc.Injection = &tc.serverConfig.AuthInjection
    
    next(ctx, tc)
}
```

---

## 4. Data Model (PostgreSQL)

```sql
-- Downstream MCP server registrations
CREATE TABLE servers (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    transport_type  TEXT NOT NULL,
    transport_config JSONB NOT NULL,     -- URL, command, args, headers
    data_tier       INT NOT NULL DEFAULT 1,
    credential_ref  TEXT,                -- Service ID for CredentialStore
    auth_injection  JSONB NOT NULL,      -- How to inject credentials
    allowed_groups  TEXT[],              -- Okta groups (empty = all)
    circuit_breaker JSONB,
    tags            JSONB,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Per-user OAuth enrollment state
CREATE TABLE oauth_enrollments (
    id              BIGSERIAL PRIMARY KEY,
    user_sub        TEXT NOT NULL,        -- Okta subject
    service_id      TEXT NOT NULL,        -- Maps to servers.credential_ref
    status          TEXT NOT NULL,        -- 'pending', 'active', 'revoked'
    enrolled_at     TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,
    UNIQUE (user_sub, service_id)
);

-- HITL approval requests and decisions
CREATE TABLE approval_requests (
    id              TEXT PRIMARY KEY,     -- ULID
    caller_sub      TEXT NOT NULL,
    caller_type     TEXT NOT NULL,
    server_id       TEXT NOT NULL,
    tool_name       TEXT NOT NULL,
    args_summary    TEXT,
    policy_rule     TEXT NOT NULL,
    tier            INT NOT NULL,
    status          TEXT NOT NULL,        -- 'pending', 'approved', 'rejected', 'timeout', 'modified'
    approved_by     TEXT,
    modified_args   JSONB,
    reason          TEXT,
    requested_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at     TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ NOT NULL
);

-- Audit trail with hash chain
CREATE TABLE audit_events (
    id              TEXT PRIMARY KEY,     -- ULID (time-ordered)
    region          TEXT NOT NULL,
    caller_sub      TEXT NOT NULL,
    caller_type     TEXT NOT NULL,
    caller_groups   TEXT[],
    session_id      TEXT,
    delegated_by    TEXT,
    server_id       TEXT NOT NULL,
    tool_name       TEXT NOT NULL,
    args_hash       TEXT NOT NULL,        -- SHA-256 of canonical JSON
    decision        TEXT NOT NULL,        -- allow, deny, require_approval
    policy_rule     TEXT,
    audit_level     TEXT NOT NULL,
    approval_id     TEXT REFERENCES approval_requests(id),
    credential_ref  TEXT,                 -- Vault reference (never the value)
    downstream_url  TEXT,
    status_code     INT,
    latency_ms      BIGINT,
    downstream_ms   BIGINT,
    error           TEXT,
    prev_hash       TEXT NOT NULL,        -- SHA-256 of previous event row
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_caller ON audit_events (caller_sub, created_at DESC);
CREATE INDEX idx_audit_server ON audit_events (server_id, tool_name, created_at DESC);
CREATE INDEX idx_audit_session ON audit_events (session_id, created_at DESC);
CREATE INDEX idx_audit_decision ON audit_events (decision, created_at DESC);

-- Policy rules (cached from YAML, hot-reloaded)
CREATE TABLE policy_rules (
    id              TEXT PRIMARY KEY,
    priority        INT NOT NULL,         -- Lower = evaluated first
    match_server    TEXT,                 -- Glob pattern (e.g., "clinical.*")
    match_tool      TEXT,                 -- Glob pattern
    match_identity  TEXT,                 -- CEL expression
    action          TEXT NOT NULL,        -- allow, deny, require_approval, log
    audit_level     TEXT NOT NULL DEFAULT 'standard',
    approval_spec   JSONB,               -- Channel, timeout, require_diff
    reason          TEXT,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    source_file     TEXT,                 -- Which YAML file this came from
    loaded_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

---

## 5. Dependency Injection / Constructor

```go
package gateway

// Dependencies holds all injectable components.
// Constructed once at startup, immutable after.
type Dependencies struct {
    Authenticator      Authenticator
    PolicyEngine       PolicyEngine
    CredentialResolver CredentialResolver  // Composite — delegates to store, enrollment, exchanger, STS
    CredentialStore    CredentialStore     // Used by resolver for static + OAuth stored tokens
    ServerRegistry     ServerRegistry
    AuditLogger        AuditLogger
    ApprovalService    ApprovalService
    OAuthEnrollment    OAuthEnrollment    // Used by resolver for per-user OAuth
    TokenExchanger     TokenExchanger     // Used by resolver for XAA (nil until adoption)
    MetricsCollector   MetricsCollector
}

// MetricsCollector exposes Prometheus-compatible metrics.
type MetricsCollector interface {
    ToolCallTotal(serverID, toolName, decision string)
    ToolCallLatency(serverID, toolName string, ms int64)
    CredentialResolutionLatency(serviceID string, ms int64)
    ApprovalWaitTime(serverID, toolName string, ms int64)
    CircuitBreakerState(serverID string, state string)
    ActiveSessions(count int)
}

// NewProxy creates the proxy with all dependencies wired.
func NewProxy(deps Dependencies) *Proxy {
    return &Proxy{
        deps: deps,
        pipeline: BuildPipeline(
            // ... middleware chain as above
        ),
    }
}
```

---

## 6. Configuration Schema (YAML)

### Server Registration

```yaml
# servers.yaml — registered via PR review, hot-reloaded
servers:
  # ── GitHub (Pattern A: per-user OAuth) ──────────────────────
  - id: github
    name: "GitHub"
    transport:
      type: streamable_http
      url: "https://api.githubcopilot.com/mcp/"
    data_tier: 2
    auth_strategy: oauth
    oauth_provider:
      auth_url: "https://github.com/login/oauth/authorize"
      token_url: "https://github.com/login/oauth/access_token"
      revoke_url: "https://api.github.com/applications/{client_id}/token"
      client_id: "Iv1.abc123def456"
      client_secret_ref: "proxy/github-oauth-secret"
      scopes: ["repo", "read:org"]
      pkce_required: true
    auth_injection:
      method: header_bearer
    allowed_groups: ["engineering"]
    circuit_breaker:
      failure_threshold: 5
      reset_timeout: 30s

  # ── Jira / Confluence (Pattern A: per-user OAuth) ───────────
  - id: atlassian
    name: "Jira & Confluence"
    transport:
      type: streamable_http
      url: "https://mcp.atlassian.com/v1/mcp"
    data_tier: 2
    auth_strategy: oauth
    oauth_provider:
      auth_url: "https://auth.atlassian.com/authorize"
      token_url: "https://auth.atlassian.com/oauth/token"
      client_id: "xyz789"
      client_secret_ref: "proxy/atlassian-oauth-secret"
      scopes:
        - "read:jira-work"
        - "write:jira-work"
        - "read:confluence-content.all"
        - "write:confluence-content"
        - "offline_access"
      pkce_required: true
    auth_injection:
      method: header_bearer
    allowed_groups: ["engineering", "product"]
    circuit_breaker:
      failure_threshold: 5
      reset_timeout: 30s

  # ── Snowflake (Pattern A: per-user OAuth) ───────────────────
  # Using Snowflake's native OAuth, not Okta-federated external OAuth.
  # Simpler to operate — same pattern as GitHub and Jira.
  # Can migrate to XAA (Pattern B) if Snowflake adopts ID-JAG.
  - id: snowflake
    name: "Snowflake"
    transport:
      type: streamable_http
      url: "https://ACCOUNT.snowflakecomputing.com/api/v2/databases/ANALYTICS/schemas/PUBLIC/mcp-servers/RO_MCP_SERVER"
    data_tier: 3
    auth_strategy: oauth
    oauth_provider:
      auth_url: "https://ACCOUNT.snowflakecomputing.com/oauth/authorize"
      token_url: "https://ACCOUNT.snowflakecomputing.com/oauth/token-request"
      client_id: "snowflake-mcp-client"
      client_secret_ref: "proxy/snowflake-oauth-secret"
      scopes: ["session:role:ANALYST_ROLE"]
      pkce_required: true
    auth_injection:
      method: header_bearer
    allowed_groups: ["engineering", "data-science"]
    circuit_breaker:
      failure_threshold: 3
      reset_timeout: 60s

  # ── Mixpanel (Pattern A: per-user OAuth) ────────────────────
  # IMPORTANT: Mixpanel MCP does NOT support HIPAA. Non-PHI only.
  - id: mixpanel
    name: "Mixpanel"
    transport:
      type: streamable_http
      url: "https://mcp.mixpanel.com/mcp"
    data_tier: 1   # Non-PHI analytics data only
    auth_strategy: oauth
    oauth_provider:
      # Mixpanel supports RFC 8414 / RFC 9728 discovery:
      # https://mcp.mixpanel.com/.well-known/oauth-authorization-server/mcp
      auth_url: "https://mcp.mixpanel.com/oauth/authorize"
      token_url: "https://mcp.mixpanel.com/oauth/token"
      client_id: "mixpanel-mcp-client"
      client_secret_ref: "proxy/mixpanel-oauth-secret"
      scopes: ["read:events", "read:funnels", "read:retention"]
      pkce_required: true
    auth_injection:
      method: header_bearer
    allowed_groups: ["engineering", "product", "data-science"]
    tags:
      hipaa: "false"   # Explicitly marked non-HIPAA

  # ── Clinical API (Pattern C: static service token) ──────────
  - id: clinical
    name: "Clinical Data API"
    transport:
      type: streamable_http
      url: "https://clinical-api.internal.ro.com/mcp"
    data_tier: 4
    auth_strategy: static
    credential_ref: "clinical-api-service-token"
    auth_injection:
      method: header_bearer
    allowed_groups: ["clinical-engineering", "data-science"]
    circuit_breaker:
      failure_threshold: 3
      reset_timeout: 60s

  # ── Staging DB (Pattern C: static connection string) ────────
  - id: postgres-staging
    name: "Staging DB (read-only)"
    transport:
      type: stdio
      command: "/usr/local/bin/mcp-postgres"
      args: ["--read-only"]
    data_tier: 3
    auth_strategy: static
    credential_ref: "postgres-staging-connstring"
    auth_injection:
      method: env_var
      env_var: "DATABASE_URL"
    allowed_groups: ["engineering"]
```

### Policy Rules

```yaml
# policy.yaml
rules:
  # Red line: no one deletes production data
  - id: deny-prod-delete
    priority: 1
    match_server: "clinical"
    match_tool: "*delete*"
    action: deny
    reason: "Production data deletion is prohibited via MCP"

  # Tier 4 tools require approval
  - id: tier4-approval
    priority: 10
    match_identity: "identity.type == 'agent'"
    action: require_approval
    audit_level: full
    approval_spec:
      channel: slack
      timeout: 5m
      require_diff: true  # Approver must be different from delegating human

  # Default allow for authenticated users
  - id: default-allow
    priority: 100
    action: allow
    audit_level: standard
```

---

## 7. Key Design Decisions

**Why middleware chain, not event-driven?** Tool calls are synchronous request-response. The caller is blocking, waiting for a result. A pipeline of synchronous middleware is the natural fit — each step either passes forward or short-circuits. Event-driven would add complexity without benefit for this request model.

**Why PostgreSQL for audit, not append-only log?** We need queryable audit for compliance reporting ("show me all clinical tool calls by agent X in March"). CloudWatch is the durable SIEM sink; PostgreSQL is the queryable working store. The hash chain provides tamper evidence regardless of storage backend.

**Why interfaces over concrete types?** Every external dependency (Okta, Secrets Manager, Slack, PostgreSQL) is behind an interface. This gives us three things: testability (mock every dependency in unit tests), replaceability (swap Secrets Manager for Vault without touching the pipeline), and multi-region flexibility (different implementations per region if needed).

**Why CEL over OPA/Rego?** CEL is bounded and non-Turing-complete — it's guaranteed to terminate. For a proxy in the request path, we can't afford a policy expression that loops forever. CEL also has a strong Go implementation (`google/cel-go`) and is the expression language used by Kubernetes, Envoy, and Cedar. OPA is more powerful but more operational surface area than we need for tool-call policy.

**Why fail open?** A policy engine bug or infrastructure failure should not block all tool calls company-wide. The audit trail captures every fail-open event, so security can detect and investigate. The alternative — fail closed — means a Secrets Manager blip at 2am takes down every agent workflow. The risk of a few uninspected calls is lower than the risk of a hard outage.

**Why standard OAuth for everything (not Okta-federated for Snowflake)?** Snowflake supports Okta as an external OAuth provider, which would enable a single-identity-chain flow (Okta → proxy → Snowflake, no consent screen). But this adds setup complexity (Okta custom authorization server + Snowflake `external_oauth` security integration + user mapping) for one service while the other three use standard OAuth. One pattern to build, test, and operate beats a marginally cleaner identity chain for one service. The `TokenExchanger` interface is ready for when XAA adoption makes the zero-enrollment path viable across all services simultaneously.

**Why `CredentialResolver` as a composite?** The credential middleware shouldn't know about auth strategies. It calls `Resolve(identity, server)` and gets back a `Credential`. The resolver internally checks the server's `AuthStrategy` and delegates to the right subsystem. This means adding a new strategy (XAA, STS, mTLS, whatever) is a change inside the resolver, not a change to the middleware pipeline.
