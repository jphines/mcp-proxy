# MCP Proxy — Architecture

## Overview

MCP Proxy is a single-binary Go service that acts as a governance choke point between Claude AI surfaces (Claude Code, claude.ai, Managed Agents) and downstream MCP tool servers. Every tool call passes through a deterministic 8-stage middleware pipeline before reaching any downstream server. No Claude client is aware of the proxy's existence.

```
Claude Code / claude.ai / Agents
              │  MCP (Streamable HTTP)
              ▼
    ┌─────────────────────┐
    │      MCP Proxy      │
    │  ┌───────────────┐  │
    │  │  audit        │  │  ← outermost; defers emit until chain completes
    │  │  auth         │  │  ← Okta JWT validation
    │  │  route        │  │  ← resolve server + parse arguments
    │  │  policy       │  │  ← CEL evaluation; deny short-circuits
    │  │  approval     │  │  ← HITL Slack gate (require_approval only)
    │  │  enrollment   │  │  ← OAuth readiness check (OAuth servers only)
    │  │  credential   │  │  ← resolve + inject; defer Zero()
    │  │  dispatch     │  │  ← circuit breaker + downstream MCP call
    │  └───────────────┘  │
    └─────────────────────┘
              │  MCP (Streamable HTTP or SSE)
              ▼
    ┌────────────────────────────────────┐
    │  Downstream MCP Servers            │
    │  github  clinical  jira  salesforce│
    └────────────────────────────────────┘
```

## Component Map

```
github.com/jphines/mcp-proxy
├── cmd/mcp-proxy/        Entry point: wire deps, start server
├── gateway/              Interfaces + domain types (no logic)
└── internal/
    ├── auth/             Okta JWT validation + JWKS key cache
    ├── policy/           CEL engine, hot-reloading YAML rules
    ├── credential/       CompositeResolver: OAuth / static / STS
    │   └── store/        AES-256-GCM cache + AWS Secrets Manager
    ├── registry/         YAML server catalog + circuit breakers
    ├── audit/            SHA-256 hash chain + CloudWatch + PostgreSQL
    ├── approval/         Slack HITL service + callback handler
    ├── oauth/            PKCE enrollment, token cache, state signing
    ├── metrics/          Prometheus counters, histograms, gauges
    ├── store/            PostgreSQL pool + migrations + CRUD
    ├── config/           Env-var loader + YAML schema validation
    ├── mocks/            mockery-generated gateway mocks
    └── proxy/            Middleware pipeline + HTTP server
```

## Request Lifecycle

1. **Upstream session**: Claude calls `POST /mcp` with `Authorization: Bearer <okta-jwt>`. The `StreamableHTTPHandler` calls `GetServer(r)`, which authenticates the JWT, loads the filtered tool catalog, and returns an `mcp.Server` with all permitted tools pre-registered.

2. **Tool call**: Claude invokes a tool (e.g., `github__create_pull_request`). The SDK dispatches to the tool handler, which calls `handleToolCall(ctx, req, bearerToken)`.

3. **Pipeline execution**: `handleToolCall` creates a `ToolCallContext` and runs it through the 8-stage pipeline. Each stage populates the context and either calls `next` to continue or sets `tc.Err` to short-circuit.

4. **Downstream dispatch**: The dispatch stage calls `ServerRegistry.Execute` (circuit breaker wrapper), which connects a fresh MCP client to the downstream server and calls the tool with credential injection.

5. **Audit**: When the pipeline unwinds, the outermost audit middleware's deferred closure fires. It appends to the SHA-256 hash chain and emits to CloudWatch + PostgreSQL.

## Key Design Decisions

| # | Decision | Rationale |
|---|---|---|
| D1 | Audit is outermost, uses `defer` | Every call — including denied ones — is always recorded |
| D2 | Tool names use `__` separator | MCP only allows `[a-zA-Z0-9_-.]`; `::` is invalid |
| D3 | Policy failures are fail-open | Availability over security; audit always records eval errors |
| D4 | Tool catalog shared per server, not per user | Avoids credential injection during `tools/list`; filtered by AllowedGroups |
| D5 | Circuit-open tools remain in catalog | Better UX than disappearing tools; calls return immediate error |
| D6 | CEL `identity.groups.exists(g, g == "admin")` over custom `hasGroup` | Avoids complex CEL binding; idiomatic and testable |
| D7 | `CredentialStore.Resolve(ctx, nil, ref)` for org-scope lookup | nil identity = org-only; used by proxy's own OAuth client secret retrieval |

## Data Flow Through ToolCallContext

```
ToolCallContext fields populated stage by stage:

auditMiddleware    → (deferred) LatencyMs, emits AuditEvent
authMiddleware     → Identity
routeMiddleware    → ServerID, ToolName, Arguments, ServerConfig
policyMiddleware   → Decision, [PolicyEvalErr]
approvalMiddleware → (Arguments may be replaced by approver)
enrollmentMiddleware → (check only; no new fields)
credentialMiddleware → Credential, Injection
dispatchMiddleware → Response, StatusCode, DownstreamMs
```

## PostgreSQL Schema (abbreviated)

```sql
audit_events (
  event_id         TEXT PRIMARY KEY,
  instance_id      TEXT,               -- ECS task / instance ID
  timestamp        TIMESTAMPTZ,
  request_id       TEXT,
  caller_sub       TEXT,
  caller_type      TEXT,               -- human | agent | service
  caller_groups    TEXT[],
  tool_namespaced  TEXT,               -- "github::create_pull_request"
  arguments_hash   TEXT,               -- SHA-256 of arguments JSON
  decision         TEXT,               -- allow | deny | require_approval | log
  policy_rule      TEXT,
  prev_hash        TEXT,               -- links to previous event in chain
  hash             TEXT                -- SHA-256 of this event (excluding hash field)
)

approval_requests (request_id, tool_namespaced, caller_sub, status, ...)
sessions          (session_id, identity_sub, created_at, expires_at)
```

## Scaling Model

- **Stateless compute**: Each ECS task runs the full proxy. Per-instance hash chain segments (D3). No cross-task coordination needed.
- **Shared state**: PostgreSQL (audit + sessions + approvals), AWS Secrets Manager (credentials), CloudWatch Logs (audit stream).
- **Multi-region**: Route 53 geolocation routing → regional proxies → regional Secrets Manager + CloudWatch, shared Aurora Global Database.
- **Session affinity**: Not required. Each `tools/call` is independent (token re-validated, credential re-resolved with cache).
