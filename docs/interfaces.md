# Gateway Interfaces

All interfaces live in `gateway/`. They are the seams between the middleware pipeline and every external system. Each interface has exactly one production implementation and is substituted with a generated mock (`internal/mocks/`) in unit tests.

## Authenticator

```go
type Authenticator interface {
    Authenticate(ctx context.Context, token string) (*Identity, error)
}
```

**Production impl**: `internal/auth.OktaAuthenticator`

Validates an Okta-issued JWT. Verifies signature against the JWKS endpoint, checks `iss`, `aud`, and `exp`. Returns an `*Identity` with:

- `Subject` — Okta sub claim (`user@example.com` or agent ID)
- `Type` — `human | agent | service` (derived from `amr` claim)
- `Groups` — Okta group memberships (used in policy CEL expressions)
- `SessionID` — `sid` claim for session-level audit correlation
- `RawToken` — the original JWT string (needed for STS `AssumeRoleWithWebIdentity`)

**Error path**: returns `ErrUnauthenticated` for missing, expired, tampered, or unrecognised-issuer tokens.

**JWKS caching**: keys cached 1 hour with background refresh. On unknown-KID error, one immediate retry with a fresh fetch before failing.

---

## PolicyEngine

```go
type PolicyEngine interface {
    Evaluate(ctx context.Context, identity *Identity, call *ToolCall) (*PolicyDecision, error)
    Reload(ctx context.Context) error
}
```

**Production impl**: `internal/policy.Engine`

Evaluates all loaded CEL rules against `(identity, call)`. Rules are evaluated in priority order (lowest number = highest priority). First matching rule wins.

**Return values**:

| Field | Meaning |
|---|---|
| `Decision.Action` | `allow \| deny \| require_approval \| log` |
| `Decision.Rule` | ID of the matching rule |
| `Decision.Reason` | Human-readable explanation |
| `Decision.ApprovalSpec` | Channel + timeout (require_approval only) |
| `Decision.AuditLevel` | `minimal \| standard \| full` |

**Fail-open**: if CEL evaluation panics or returns an error, the engine returns `ActionAllow` and a non-nil error. The proxy records the error in `tc.PolicyEvalErr` and proceeds. This preserves availability while guaranteeing audit records of all eval failures.

**Hot-reload**: `fsnotify` watches the policy YAML file. On Write/Create events, the engine recompiles all rules. If compilation fails, the existing compiled rule set is kept unchanged.

---

## CredentialStore

```go
type CredentialStore interface {
    Resolve(ctx context.Context, identity *Identity, serviceID string) (*Credential, error)
    Store(ctx context.Context, scope CredentialScope, cred *Credential) error
    Revoke(ctx context.Context, scope CredentialScope) error
    Rotate(ctx context.Context, scope CredentialScope) (*Credential, error)
    List(ctx context.Context, identity *Identity) ([]CredentialScope, error)
}
```

**Production impl**: `internal/credential/store.SecretsManagerStore`

Backed by AWS Secrets Manager with an in-process AES-256-GCM encrypted cache (30-second TTL, background zero-out on expiry).

**ARN convention**: `mcp-proxy/{scope}/{ownerID}/{serviceID}`
- `mcp-proxy/org/-/github` — org-scope API key
- `mcp-proxy/session/user@example.com/github` — session OAuth token

**Scope resolution order** (`Resolve`): session → agent → org. If `identity` is `nil`, only org-scope is checked. This `nil`-identity path is used by the proxy's own OAuth client secret lookup (`CredentialStore.Resolve(ctx, nil, clientSecretRef)`).

**Zero-on-expiry**: the encrypted cache calls `cred.Zero()` when a cached entry expires, wiping secret bytes before GC.

---

## CredentialResolver

```go
type CredentialResolver interface {
    Resolve(ctx context.Context, identity *Identity, server *ServerConfig) (*Credential, error)
}
```

**Production impl**: `internal/credential.CompositeResolver`

Routes to one of four sub-strategies based on `server.Strategy`:

| Strategy | Implementation |
|---|---|
| `oauth` | `OAuthEnrollment.AccessToken()` → cached access token |
| `static` | `CredentialStore.Resolve(ctx, nil, credentialRef)` — org-scope only |
| `sts` | `sts.AssumeRoleWithWebIdentity` using `identity.RawToken` |
| `xaa` | Returns `ErrXAANotSupported` (Phase 1 stub) |

Returns `EnrollmentRequiredError` when OAuth strategy is used but the identity has not completed enrollment.

---

## ServerRegistry

```go
type ServerRegistry interface {
    Get(ctx context.Context, id string) (*ServerConfig, error)
    List(ctx context.Context, filter *ServerFilter) ([]*ServerConfig, error)
    ToolCatalog(ctx context.Context, identity *Identity) ([]Tool, error)
    Execute(ctx context.Context, serverID string, fn func() error) error
}
```

**Production impl**: `internal/registry.YAMLRegistry`

Loads `servers.yaml`, hot-reloads on file changes.

**`ToolCatalog`**: fan-out `tools/list` concurrently across all enabled servers. Results cached 30 seconds per server. AllowedGroups filter applied per server: tools from servers whose groups the identity does not satisfy are excluded. Circuit-open servers: tools remain in catalog but calls return immediate error.

**`Execute`**: wraps `fn` in the server's `sony/gobreaker` circuit breaker. If the circuit is open, returns `ErrCircuitOpen` without calling `fn`. Default thresholds: 5 consecutive failures to open, 30-second reset timeout, 1 half-open probe request.

---

## AuditLogger

```go
type AuditLogger interface {
    Emit(ctx context.Context, event *AuditEvent) error
    VerifyChain(ctx context.Context) error
}
```

**Production impl**: `internal/audit.CloudWatchLogger`

**`Emit`**:
1. Assigns a ULID `EventID` if empty
2. Computes hash chain: `SHA-256(canonical_JSON(event with Hash=""))` with `PrevHash` from the previous event in this instance's stream
3. Enqueues to in-memory batch (flushed every 200ms or when 10,000 events accumulate)
4. If PostgreSQL is configured, also calls `store.InsertAuditEvent`

**`VerifyChain`**: queries PostgreSQL for all events in timestamp order, recomputes each hash, and verifies `event.Hash == computed`. Returns an error identifying the first broken link.

**CloudWatch batching**: up to 10,000 events per `PutLogEvents` call. On `InvalidSequenceTokenException`, the sequence token is refreshed and the batch is retried. Failed batches are prepended back to the queue.

---

## ApprovalService

```go
type ApprovalService interface {
    Request(ctx context.Context, req *ApprovalRequest) (*ApprovalDecision, error)
    Decide(ctx context.Context, decision *ApprovalDecision) error
}
```

**Production impl**: `internal/approval.Service`

**`Request`**: registers a channel keyed by `requestID`, sends a Slack Block Kit message with Approve/Reject buttons, then blocks on `select { case d := <-ch | case <-timer | case <-ctx.Done() }`. Non-blocking Slack send (failure is logged but does not fail the approval gate).

**`Decide`**: called by the Slack webhook callback handler. Sends the decision to the waiting channel. Returns an error if the `requestID` is not found (already decided or timed out) — the handler silently swallows this to prevent Slack retry storms.

**Outcome types**: `approved | rejected | modified | timed_out`. Modified outcomes carry `ModifiedArguments` which replace `tc.Arguments` before dispatch.

---

## OAuthEnrollment

```go
type OAuthEnrollment interface {
    InitiateFlow(ctx context.Context, identity *Identity, serviceID string) (authURL string, err error)
    HandleCallback(ctx context.Context, code, stateParam string) error
    IsEnrolled(ctx context.Context, identity *Identity, serviceID string) (bool, error)
    AccessToken(ctx context.Context, identity *Identity, serviceID string) (*Credential, error)
    Revoke(ctx context.Context, identity *Identity, serviceID string) error
}
```

**Production impl**: `internal/oauth.Enrollment`

PKCE flow using `oauth2.GenerateVerifier()` / `oauth2.S256ChallengeOption`. State parameter is HMAC-SHA256 signed with a 10-minute expiry to prevent CSRF.

**AccessToken fast path**: checks the in-memory `TokenCache` first. If the cached token is still valid (within `oauth2.Token.Expiry`), returns immediately. Slow path: resolves the stored refresh token, calls `oauth2.TokenSource`, updates the cache and rotates the stored refresh token.

---

## MetricsCollector

```go
type MetricsCollector interface {
    ToolCallTotal(serverID, toolName, decision string)
    ToolCallDuration(serverID, toolName string, ms int64)
    DownstreamDuration(serverID string, ms int64)
    CredentialResolutionDuration(serverID, strategy string, ms int64)
    ApprovalWaitDuration(serverID string, ms int64)
    CircuitBreakerState(serverID string, state int)
    ActiveSessions(delta int)
    DownstreamError(serverID, toolName, errType string)
    EnrollmentRequired(serverID string)
    PolicyEvalError(serverID, toolName string)
}
```

**Production impl**: `internal/metrics.PrometheusCollector`

All methods are non-blocking and safe for concurrent use. Backed by `promauto` counters, histograms (millisecond buckets), and gauges. Prometheus scraping endpoint: `GET /metrics`.

## Dependency Bundle

```go
// gateway/dependencies.go
type Dependencies struct {
    Authenticator      Authenticator
    PolicyEngine       PolicyEngine
    CredentialStore    CredentialStore
    CredentialResolver CredentialResolver
    ServerRegistry     ServerRegistry
    AuditLogger        AuditLogger
    ApprovalService    ApprovalService
    OAuthEnrollment    OAuthEnrollment
    TokenExchanger     TokenExchanger    // stub; Phase 2
    MetricsCollector   MetricsCollector
}
```

`cmd/mcp-proxy/main.go` constructs all implementations bottom-up and passes a single `*Dependencies` to `proxy.New(deps)`. This makes every dependency visible at the top level and makes the proxy easily testable by swapping any interface.
