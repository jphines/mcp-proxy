# Middleware Pipeline

## Pipeline Construction

The pipeline is a recursive closure built by `gateway.BuildPipeline`:

```go
func BuildPipeline(middlewares ...Middleware) MiddlewareFunc {
    if len(middlewares) == 0 {
        return func(_ context.Context, _ *ToolCallContext) {}
    }
    return func(ctx context.Context, tc *ToolCallContext) {
        middlewares[0](ctx, tc, BuildPipeline(middlewares[1:]...))
    }
}
```

`proxy.New` assembles the 8 stages in this exact order:

```go
p.pipeline = gateway.BuildPipeline(
    p.auditMiddleware,       // 1 — outermost; defers emit
    p.authMiddleware,        // 2
    p.routeMiddleware,       // 3
    p.policyMiddleware,      // 4
    p.approvalMiddleware,    // 5
    p.enrollmentMiddleware,  // 6
    p.credentialMiddleware,  // 7
    p.dispatchMiddleware,    // 8 — terminal; does not call next
)
```

Each middleware has the signature:

```go
type Middleware func(ctx context.Context, tc *ToolCallContext, next MiddlewareFunc)
```

**Short-circuiting**: a middleware stops the chain by setting `tc.Err` and returning without calling `next`. The outermost audit middleware always fires because it uses `defer`.

---

## Stage 1: auditMiddleware

**File**: `internal/proxy/middleware_audit.go`

```
Entry → record start time
      → call next(ctx, tc)   [entire inner chain runs]
      → DEFER: compute latency, build AuditEvent, call AuditLogger.Emit
Exit
```

Positioned outermost so that denied, timed-out, and errored calls are all recorded. The `AuditEvent` is assembled from all fields populated by the inner chain:

- `CallerSubject`, `CallerType`, `CallerGroups` from `tc.Identity`
- `ToolNamespaced` from `tc.ServerID + "::" + tc.ToolName` (or raw request name if routing failed)
- `ArgumentsHash` — SHA-256 of `tc.Arguments` JSON (never raw values)
- `Decision` — inferred: `deny` if `tc.Err != nil`, else `tc.Decision.Action`
- `DownstreamMs`, `StatusCode`, `RedactionsApplied`, `CredentialRef`

---

## Stage 2: authMiddleware

**File**: `internal/proxy/middleware_auth.go`

```
Extract bearer token from context  (placed there by handleToolCall)
If token == ""  →  tc.Err = ErrUnauthenticated, return
Call Authenticator.Authenticate(ctx, token)
If err          →  tc.Err = err, return
tc.Identity = identity
next(ctx, tc)
```

The bearer token is injected into the `context.Context` by `handleToolCall` (not extracted from the HTTP request at this stage, since HTTP middleware has already done that). This keeps the middleware testable without an HTTP server.

---

## Stage 3: routeMiddleware

**File**: `internal/proxy/middleware_route.go`

```
Parse tc.RawRequest.Name: "github__create_pr" → ("github", "create_pr")
If no server prefix  →  tc.Err = ErrServerNotFound, return
ServerRegistry.Get(ctx, serverID)
If not found or disabled  →  tc.Err, return
json.Unmarshal(tc.RawRequest.Arguments) → map[string]any
tc.ServerID = serverID
tc.ToolName = toolName
tc.Arguments = args
tc.ServerConfig = srv
next(ctx, tc)
```

**Tool name format**: upstream clients see `server__tool` (double-underscore). `fromMCPName` splits on the first `__`. Server IDs are `[a-z0-9-]+` so there is no ambiguity.

---

## Stage 4: policyMiddleware

**File**: `internal/proxy/middleware_policy.go`

```
Build ToolCall{ServerID, ToolName, Arguments, Tier, Tags}
PolicyEngine.Evaluate(ctx, tc.Identity, call)
If evalErr != nil:
  tc.PolicyEvalErr = evalErr
  MetricsCollector.PolicyEvalError(...)
  log WARN (fail-open)

tc.Decision = decision
If decision.Action == Deny:
  tc.Err = ErrPolicyDenied
  MetricsCollector.ToolCallTotal(..., "deny")
  return  ← short-circuit

next(ctx, tc)
```

**Fail-open**: a CEL evaluation error does not block the call. The error is recorded on `tc.PolicyEvalErr` and surfaced in the audit event. The proxy continues with the decision that was returned (typically `ActionAllow` on error).

**log action**: does not short-circuit. The matching rule ID is accumulated in `Decision.MatchedLogRules`. The call proceeds; the rule appears in the audit event.

---

## Stage 5: approvalMiddleware

**File**: `internal/proxy/middleware_approval.go`

```
If decision.Action != RequireApproval  →  next(ctx, tc), return

Build ApprovalRequest{RequestID, ToolNamespaced, ArgumentsSummary, ...}
  ArgumentsSummary = field names + Go types only (no values — PHI-safe)

start = time.Now()
ApprovalService.Request(ctx, req)  ← BLOCKS until human decides or timeout
MetricsCollector.ApprovalWaitDuration(...)

If outcome == Rejected   →  tc.Err = ErrApprovalRejected, return
If outcome == TimedOut   →  tc.Err = ErrApprovalTimedOut, return
If outcome == Modified   →  tc.Arguments = decision.ModifiedArguments

next(ctx, tc)
```

**Human decision flow**:
1. `Request` sends a Slack Block Kit message with Approve/Reject buttons (action IDs `approve_<requestID>` / `reject_<requestID>`).
2. Human clicks a button. Slack POSTs to `/approvals/slack/callback`.
3. `Handler.ServeHTTP` verifies HMAC-SHA256 signature, extracts the decision, calls `Service.Decide`.
4. `Decide` sends on the channel that `Request` is blocking on.
5. Pipeline continues (or short-circuits if rejected).

---

## Stage 6: enrollmentMiddleware

**File**: `internal/proxy/middleware_enrollment.go`

```
If server.Strategy != OAuth  →  next(ctx, tc), return
If tc.Identity == nil        →  tc.Err = ErrUnauthenticated, return

OAuthEnrollment.IsEnrolled(ctx, tc.Identity, tc.ServerID)
If !enrolled:
  MetricsCollector.EnrollmentRequired(tc.ServerID)
  enrollURL = OAuthEnrollment.InitiateFlow(...)  (best-effort)
  tc.Err = &EnrollmentRequiredError{..., EnrollURL: enrollURL}
  return

next(ctx, tc)
```

**EnrollmentRequiredError** is returned to the Claude client as the tool's error text. It contains the enrollment URL the engineer must visit to complete the OAuth consent flow.

---

## Stage 7: credentialMiddleware

**File**: `internal/proxy/middleware_credential.go`

```
start = time.Now()
CredentialResolver.Resolve(ctx, tc.Identity, tc.ServerConfig)
MetricsCollector.CredentialResolutionDuration(...)

If err  →  tc.Err = err, return
DEFER: cred.Zero()  ← wipes secret bytes after dispatch returns

tc.Credential = cred
tc.Injection = &tc.ServerConfig.AuthInjection

next(ctx, tc)
```

**Critical**: `defer cred.Zero()` runs when `credentialMiddleware` returns, which is after `dispatchMiddleware` has completed. Secret bytes are wiped from memory immediately after they are no longer needed.

**Injection methods** (from `ServerConfig.AuthInjection`):
- `header_bearer` → `Authorization: Bearer <value>`
- `header_custom` → `<Header>: <Prefix><value>`
- `query_param` → appended to URL query string
- `env_var` → environment variable (stdio servers only)

---

## Stage 8: dispatchMiddleware (terminal)

**File**: `internal/proxy/middleware_dispatch.go`

```
start = time.Now()

ServerRegistry.Execute(ctx, tc.ServerID, func() error {
  result, statusCode, err = p.callDownstream(ctx, tc)
  if err  →  return err
  tc.Response = result
  tc.StatusCode = statusCode
  return nil
})

tc.DownstreamMs = time.Since(start)
MetricsCollector.DownstreamDuration(...)

If err:
  tc.Err = err
  errType = "circuit_open" if errors.Is(err, ErrCircuitOpen) else "downstream_error"
  MetricsCollector.DownstreamError(...)

MetricsCollector.ToolCallTotal(...)
# next is NOT called — dispatch is terminal
```

**callDownstream** (`internal/proxy/dispatch.go`):
1. Builds an `*http.Client` with a `credInjectingTransport` (applies static headers + dynamic credential per request).
2. Creates a `mcp.StreamableClientTransport{Endpoint: url, HTTPClient: client, DisableStandaloneSSE: true}`.
3. `mcp.NewClient(...).Connect(ctx, transport, nil)` — MCP initialize handshake.
4. `session.CallTool(ctx, &mcp.CallToolParams{Name: toolName, Arguments: tc.Arguments})`.
5. `defer session.Close()`.

## Short-Circuit Summary

| Stage | Condition | Error set |
|---|---|---|
| auth | Missing or invalid token | `ErrUnauthenticated` |
| route | Unparseable name | `ErrServerNotFound` |
| route | Server disabled or unknown | `ErrServerNotFound` |
| policy | Action == deny | `ErrPolicyDenied` |
| approval | Human rejected | `ErrApprovalRejected` |
| approval | Timed out | `ErrApprovalTimedOut` |
| enrollment | Not enrolled (OAuth) | `*EnrollmentRequiredError` |
| credential | Resolution failed | (strategy-specific) |
| dispatch | Circuit open | `ErrCircuitOpen` |
| dispatch | Downstream error | (wrapped) |

All short-circuits are captured by the outermost `auditMiddleware` and appear in the audit event.
