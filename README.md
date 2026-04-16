# MCP Proxy

A single-binary Go service that acts as a governance choke point between Claude AI surfaces (Claude Code, claude.ai, Managed Agents) and downstream MCP tool servers. Every tool call passes through a deterministic 8-stage middleware pipeline before reaching any downstream server. No MCP client is aware of the proxy's existence — it is fully transparent.

```
Claude Code / claude.ai / Agents
              │  MCP (Streamable HTTP)
              ▼
    ┌─────────────────────┐
    │      MCP Proxy      │
    │  ┌───────────────┐  │
    │  │  audit        │  │  ← outermost; defers emit until chain completes
    │  │  auth         │  │  ← Okta JWT validation + JWKS cache
    │  │  route        │  │  ← resolve server + parse tool arguments
    │  │  policy       │  │  ← CEL evaluation; deny short-circuits
    │  │  approval     │  │  ← Slack HITL gate (require_approval rules)
    │  │  enrollment   │  │  ← OAuth readiness check (OAuth servers only)
    │  │  credential   │  │  ← resolve + inject; defer Zero()
    │  │  dispatch     │  │  ← circuit breaker + downstream MCP call
    │  └───────────────┘  │
    └─────────────────────┘
              │  MCP (Streamable HTTP)
              ▼
    ┌────────────────────────────────────┐
    │  Downstream MCP Servers            │
    │  github  clinical  jira  salesforce│
    └────────────────────────────────────┘
```

## What It Does

| Concern | How |
|---------|-----|
| **Identity validation** | Okta JWT authentication on every request; JWKS cache with background refresh |
| **Declarative policy** | CEL-based rules that can deny, require approval, or log tool calls |
| **Per-user OAuth** | PKCE enrollment flow; per-user tokens injected transparently into downstream requests |
| **Human-in-the-loop approvals** | Slack Block Kit approval messages; pipeline blocks until approved, rejected, or timed out |
| **Tamper-evident audit** | SHA-256 hash chain persisted in PostgreSQL; events streamed to CloudWatch |
| **Credential security** | AES-256-GCM encrypted in-memory cache; `defer cred.Zero()` wipes secret bytes after every call |
| **Resilience** | Per-server circuit breakers; tools remain visible when breaker is open |
| **Observability** | Prometheus metrics for every pipeline stage; structured audit events |

## Architecture

The proxy is a single Go binary (`cmd/mcp-proxy`) that implements the MCP Streamable HTTP transport. Upstream clients connect to `POST /mcp`; the proxy authenticates, filters the tool catalog, and creates a fresh `mcp.Server` per session. When a tool is invoked, the 8-stage pipeline runs synchronously.

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

See [docs/architecture.md](docs/architecture.md) for the full component map, data flow diagrams, and PostgreSQL schema.

## Prerequisites

- Go 1.23+
- Docker (for integration tests via testcontainers)
- PostgreSQL 16 (production) or testcontainers will spin one up for tests
- AWS account with Secrets Manager access (or LocalStack for local development)
- Okta tenant

## Quick Start

```bash
# Build
make build          # → bin/mcp-proxy

# Run unit tests
make test

# Run with environment variables
export OKTA_ISSUER="https://your-org.okta.com/oauth2/default"
export OKTA_AUDIENCE="api://mcp-proxy"
export DATABASE_URL="postgres://user:pass@localhost:5432/mcpproxy?sslmode=require"
export AWS_REGION="us-east-1"
export CONFIG_DIR="/etc/mcp-proxy"
export PROXY_BASE_URL="https://mcp-proxy.your-org.com"
export WORKSPACE="dev"
export STATE_HMAC_SECRET="your-32-char-or-longer-secret-key"
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
export SLACK_SIGNING_SECRET="your-slack-signing-secret"

make run
```

## Configuration

All runtime configuration is read from environment variables at startup. The proxy aggregates all validation errors before failing — you see every problem at once, not just the first.

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `OKTA_ISSUER` | Okta tenant issuer URL for JWT validation | `https://your-org.okta.com/oauth2/default` |
| `OKTA_AUDIENCE` | Expected JWT audience claim | `api://mcp-proxy` |
| `DATABASE_URL` | PostgreSQL connection string | `postgres://user:pass@host:5432/mcpproxy?sslmode=require` |
| `AWS_REGION` | AWS region for Secrets Manager and CloudWatch | `us-east-1` |
| `CONFIG_DIR` | Directory containing `servers.yaml` and `policy.yaml` | `/etc/mcp-proxy` |
| `PROXY_BASE_URL` | Public base URL (used for OAuth callbacks) | `https://mcp-proxy.your-org.com` |
| `WORKSPACE` | Deployment environment | `production`, `staging`, or `dev` |
| `STATE_HMAC_SECRET` | HMAC-SHA256 key for OAuth state params (≥32 chars) | 64-char hex string |
| `SLACK_WEBHOOK_URL` | Incoming webhook URL for approval notifications | `https://hooks.slack.com/services/...` |
| `SLACK_SIGNING_SECRET` | Slack signing secret for verifying callbacks | Slack-provided secret |

### Optional Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LISTEN_ADDR` | `:8443` | `host:port` the server binds to |
| `TLS_CERT_FILE` | — | Path to TLS certificate (both cert + key required together) |
| `TLS_KEY_FILE` | — | Path to TLS private key |
| `INSTANCE_ID` | hostname | Unique ID for audit hash chain genesis seed |
| `CREDENTIAL_CACHE_TTL` | `30s` | Max time a decrypted credential lives in memory (hard ceiling: 30s) |
| `TOOL_CATALOG_CACHE_TTL` | `30s` | How long the aggregated tool catalog is cached |
| `APPROVAL_TIMEOUT` | `5m` | Default HITL approval timeout |
| `SHUTDOWN_TIMEOUT` | `30s` | Grace period for in-flight requests during SIGTERM |

### Server Registry (`servers.yaml`)

Servers are registered in `$CONFIG_DIR/servers.yaml`. The file is hot-reloaded on change without a restart.

```yaml
servers:
  - id: github
    name: GitHub
    transport:
      type: streamable_http
      url: https://github-mcp.your-org.com
    data_tier: 2          # 1=read-only, 2=standard, 3=write, 4=destructive
    auth_strategy: oauth  # oauth | static | sts
    oauth_provider:
      auth_url: https://github.com/login/oauth/authorize
      token_url: https://github.com/login/oauth/access_token
      client_id: your-client-id
      client_secret_ref: proxy/prod/github-oauth-secret   # Secrets Manager ARN fragment
      scopes: ["repo", "read:org"]
      pkce_required: true
    auth_injection:
      method: header_bearer       # header_bearer | header_custom | query_param
    allowed_groups: ["engineering"]
    enabled: true
    circuit_breaker:
      failure_threshold: 5
      reset_timeout: 30s
      half_open_max: 2
    tags:
      team: platform

  - id: clinical
    name: Clinical Data API
    transport:
      type: streamable_http
      url: https://clinical-mcp.your-org.com
    data_tier: 4
    auth_strategy: static
    credential_ref: proxy/prod/clinical-api-key
    auth_injection:
      method: header_bearer
    allowed_groups: ["clinical-engineering", "data-science"]
    enabled: true
    tags:
      hipaa: "true"
```

**Authentication strategies:**

| Strategy | Description | `credential_ref` field |
|----------|-------------|----------------------|
| `oauth` | Per-user PKCE OAuth flow | Not used (client secret in `oauth_provider.client_secret_ref`) |
| `static` | Static API key from Secrets Manager | ARN fragment: `proxy/{scope}/{serviceID}` |
| `sts` | AWS `AssumeRoleWithWebIdentity` | IAM role ARN |

### Policy Rules (`policy.yaml`)

Policy rules live in `$CONFIG_DIR/policy.yaml` and are hot-reloaded on change. CEL compile errors at reload keep the existing rule set in place — the proxy never transitions to an invalid policy state.

```yaml
rules:
  # Hard deny: agents cannot write clinical data
  - id: deny-agents-clinical-write
    priority: 5
    condition: >
      tool.server == "clinical" &&
      identity.type == "agent" &&
      (tool.name.contains("update") || tool.name.contains("write"))
    action: deny
    reason: "Agents may not write to clinical data sources"
    audit_level: full

  # Tier-4 actions require Slack approval
  - id: require-approval-tier4
    priority: 100
    condition: "tool.tier >= 4"
    action: require_approval
    reason: "High-impact actions require human approval"
    audit_level: full
    approval:
      channel: slack
      timeout: 5m

  # Default allow
  - id: default-allow
    priority: 999
    condition: "true"
    action: allow
    audit_level: standard
```

Rules are evaluated in priority order (lowest number first). The first matching rule wins. For the full CEL variable reference and expression guide, see [docs/policy-authoring.md](docs/policy-authoring.md).

**Available actions:** `deny` · `require_approval` · `log` · `allow`

**Key CEL variables:**

| Variable | Type | Description |
|----------|------|-------------|
| `identity.subject` | string | JWT `sub` claim |
| `identity.type` | string | `human`, `agent`, or `service` |
| `identity.groups` | list | Okta group memberships |
| `tool.server` | string | Server ID from servers.yaml |
| `tool.name` | string | Tool name (without server prefix) |
| `tool.tier` | int | Server's `data_tier` |
| `env.workspace` | string | `production`, `staging`, or `dev` |

## OAuth Enrollment

When a user calls a tool on an OAuth-protected server for the first time, the proxy returns an `EnrollmentRequiredError` with a redirect URL. The user visits the URL, completes the OAuth flow, and subsequent tool calls proceed automatically.

```
User calls github__create_pull_request
    ↓
Proxy: "not enrolled" → 403 with enrollment URL
    ↓
User visits: GET /oauth/enroll/github
    ↓
Redirect to GitHub authorization page
    ↓
GitHub redirects to: GET /oauth/callback?code=...&state=...
    ↓
Proxy exchanges code, stores token in encrypted cache
    ↓
Subsequent calls: token injected into downstream requests automatically
```

Tokens are cached in-memory (encrypted, AES-256-GCM) and in PostgreSQL (for persistence across restarts). Refresh tokens are rotated on use. See [docs/oauth-enrollment.md](docs/oauth-enrollment.md) for the complete flow.

## Tool Naming

MCP tool names must match `[a-zA-Z0-9_-.]` — colons are not valid. The proxy uses double underscores as the server/tool separator:

```
github::create_pull_request  →  github__create_pull_request
clinical::get_patient_labs   →  clinical__get_patient_labs
```

Claude calls `github__create_pull_request`; the proxy splits on `__`, resolves the `github` server, and calls `create_pull_request` on the downstream server.

## Human-in-the-Loop Approvals

When a policy rule uses `action: require_approval`, the pipeline blocks and sends a Slack message with **Approve** / **Reject** buttons. The approval request includes:

- Identity (user or agent subject)
- Server ID and tool name
- Argument field names and types (never values — PHI-safe)
- Reason from the policy rule

The pipeline resumes once a Slack user clicks a button or the timeout elapses. Modified arguments submitted via the approval response replace the original call arguments.

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/mcp` | `POST`, `GET` | MCP Streamable HTTP transport (tool calls + SSE) |
| `/oauth/enroll/{serviceID}` | `GET` | Initiate OAuth enrollment for a service |
| `/oauth/callback` | `GET` | OAuth authorization code callback |
| `/approvals/slack/callback` | `POST` | Slack interactive component callback |
| `/metrics` | `GET` | Prometheus metrics (text format) |
| `/healthz` | `GET` | Liveness check: `200 OK` |
| `/readyz` | `GET` | Readiness check: requires DB + registry loaded |

## Development

```bash
make build              # Compile binary to bin/mcp-proxy
make test               # Unit tests with race detector + coverage profile
make lint               # golangci-lint (errcheck, staticcheck, govet, exhaustive)
make generate           # Re-generate mockery mocks (run after changing gateway interfaces)
make policy-test        # Run TestPolicyFixtures against testdata/policy/tests/*.yaml
make integration-test   # Full integration tests (requires Docker for testcontainers)
make check-coverage     # Fail if coverage drops below 80%
make docker-build       # Build mcp-proxy:dev Docker image
make validate-policy    # Syntax-check policy.yaml only (no infra required)
make tidy               # go mod tidy
make clean              # Remove bin/ and coverage.out
```

### Adding a New Gateway Interface

1. Add the interface to `gateway/`
2. Run `make generate` to create the mock
3. Reference the mock in unit tests via `internal/mocks/`

### Adding a New Middleware

1. Create `internal/proxy/middleware_<name>.go`
2. Add the `Middleware` function (signature: `func(ctx context.Context, tc *gateway.ToolCallContext, next gateway.MiddlewareFunc)`)
3. Insert it into the pipeline in `internal/proxy/proxy.go` — remember audit is always outermost
4. Add tests in `internal/proxy/proxy_test.go`

## Testing

### Unit Tests

```bash
make test
# or
go test -race -coverprofile=coverage.out ./internal/...
```

All unit tests are table-driven with `t.Parallel()`. Integration points are mocked via the generated `internal/mocks/` package. Real implementations are tested without mocks: `policy.Engine` (real CEL + YAML), `audit.Chain` (real SHA-256), `credential.EncryptedCache` (real AES-GCM).

### Policy Fixture Tests

```bash
make policy-test
```

Policy tests live in `testdata/policy/tests/*.yaml` and use a declarative fixture format:

```yaml
suite: "Clinical data access"
setup:
  policy_dir: "../base"
cases:
  - name: "human in clinical-engineering can read"
    identity: { subject: "jane@example.com", type: human, groups: ["clinical-engineering"] }
    call: { server_id: clinical, tool_name: get_patient_labs, tier: 2 }
    expect: { action: allow }

  - name: "agent denied clinical write"
    identity: { subject: "agent-rx", type: agent, groups: ["clinical-engineering"] }
    call: { server_id: clinical, tool_name: update_prescription, tier: 3 }
    expect: { action: deny, rule: deny-agents-clinical-write }
```

To validate policy YAML syntax without running test cases:

```bash
make validate-policy
```

### Integration Tests

```bash
make integration-test
```

Integration tests use [testcontainers-go](https://testcontainers.com/guides/getting-started-with-testcontainers-for-go/) to spin up PostgreSQL 16 and LocalStack. They test the full proxy in-process: auth flows, policy enforcement, OAuth enrollment, and audit chain verification.

### Mock MCP Server

`test/mcp_fixture` provides an in-process mock MCP downstream server used by integration tests:

```go
srv := mcp_fixture.NewServer(t)
defer srv.Close()

// srv.URL() is the endpoint; srv.Recorder() captures calls for assertion
calls := srv.Recorder().CallsFor("read_data")
```

The fixture exposes 4 tools at data tiers 1–4: `read_data`, `search`, `write_data`, `delete_data`.

## Deployment

### Docker

```dockerfile
FROM golang:1.23-alpine AS builder
RUN go build -trimpath -ldflags="-s -w" -o mcp-proxy ./cmd/mcp-proxy

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /build/mcp-proxy /mcp-proxy
EXPOSE 8443
ENTRYPOINT ["/mcp-proxy"]
```

```bash
make docker-build       # builds mcp-proxy:dev
docker run -e OKTA_ISSUER=... -e DATABASE_URL=... mcp-proxy:dev
```

### AWS ECS

The proxy is designed to run as an ECS Fargate service. Key considerations:

- **Secrets**: mount all env vars via ECS Secrets (referencing AWS Secrets Manager ARNs)
- **TLS**: terminate TLS at the proxy using `TLS_CERT_FILE` / `TLS_KEY_FILE`, or terminate at ALB/NLB and run HTTP internally
- **PostgreSQL**: use RDS PostgreSQL 16 in the same VPC with `sslmode=require`
- **IAM role**: the task role needs `secretsmanager:GetSecretValue` (for credentials) and `logs:PutLogEvents` (for CloudWatch audit)

For a complete ECS task definition template, see [docs/deployment.md](docs/deployment.md).

### Graceful Shutdown

The proxy handles `SIGTERM` and `SIGINT`. On signal:
1. Stop accepting new connections
2. Wait up to `SHUTDOWN_TIMEOUT` (default 30s) for in-flight requests to complete
3. Flush any buffered CloudWatch log events
4. Close the PostgreSQL connection pool
5. Exit 0

### Health Checks

```
GET /healthz   → 200 OK            (liveness: process is running)
GET /readyz    → 200 OK / 503      (readiness: DB connected, registry loaded)
```

Use `/readyz` for ECS health checks and ALB target group health; use `/healthz` for container-level liveness.

## Audit Trail

Every tool call — including denied ones — produces an `AuditEvent`. Events are:

1. **Hashed** into a SHA-256 chain (each event includes the hash of the previous event)
2. **Streamed** to CloudWatch Logs in the `mcp-proxy` log group
3. **Persisted** to PostgreSQL for chain integrity verification

To verify the chain has not been tampered with:

```bash
# From the runbook
psql $DATABASE_URL -c "SELECT verify_chain('instance-id-here')"
```

Any modification to a historical event breaks the chain and is detected by `VerifyChain`. See [docs/audit-chain.md](docs/audit-chain.md) for the full algorithm.

## Metrics

The proxy exposes Prometheus metrics at `GET /metrics`:

| Metric | Type | Description |
|--------|------|-------------|
| `mcp_proxy_tool_calls_total` | Counter | Tool calls by server, tool, status, identity type |
| `mcp_proxy_pipeline_duration_seconds` | Histogram | End-to-end latency including all middleware |
| `mcp_proxy_downstream_duration_seconds` | Histogram | Downstream MCP server latency only |
| `mcp_proxy_policy_eval_errors_total` | Counter | Policy evaluation errors (fail-open events) |
| `mcp_proxy_approval_wait_seconds` | Histogram | Time spent waiting for Slack approval |
| `mcp_proxy_circuit_breaker_state` | Gauge | Circuit breaker state per server (0=closed, 1=half-open, 2=open) |
| `mcp_proxy_credential_cache_hits_total` | Counter | Credential cache hits (AES-GCM cache) |
| `mcp_proxy_credential_cache_misses_total` | Counter | Credential cache misses (Secrets Manager fetches) |
| `mcp_proxy_auth_failures_total` | Counter | JWT authentication failures |
| `mcp_proxy_enrollment_required_total` | Counter | OAuth enrollment redirects issued |

Alert recommendations:
- `mcp_proxy_policy_eval_errors_total > 0` → investigate CEL errors
- `mcp_proxy_circuit_breaker_state == 2` → downstream server unavailable
- `mcp_proxy_pipeline_duration_seconds p95 > 2s` → investigate latency

## Documentation

| Document | Description |
|----------|-------------|
| [docs/architecture.md](docs/architecture.md) | Component map, request lifecycle, data flow through ToolCallContext, PostgreSQL schema |
| [docs/interfaces.md](docs/interfaces.md) | All 10 gateway interfaces with method signatures and contracts |
| [docs/middleware-pipeline.md](docs/middleware-pipeline.md) | Per-stage behavior, short-circuit conditions, error handling |
| [docs/policy-authoring.md](docs/policy-authoring.md) | Full CEL variable reference, action semantics, example rules, test harness |
| [docs/oauth-enrollment.md](docs/oauth-enrollment.md) | Enrollment flow, token refresh, revocation, per-service configuration |
| [docs/credential-management.md](docs/credential-management.md) | CompositeResolver strategies, AES-GCM cache, `defer Zero()` lifecycle |
| [docs/audit-chain.md](docs/audit-chain.md) | SHA-256 hash chain algorithm, CloudWatch layout, chain verification |
| [docs/api-reference.md](docs/api-reference.md) | All HTTP endpoints, request/response formats, error codes |
| [docs/deployment.md](docs/deployment.md) | Docker, ECS task definition, multi-region, rolling updates, TLS |
| [docs/runbook.md](docs/runbook.md) | Failure modes and remediation procedures |
| [docs/adr/001-fail-open.md](docs/adr/001-fail-open.md) | Why policy evaluation failures are fail-open |
| [docs/adr/002-cel-over-rego.md](docs/adr/002-cel-over-rego.md) | Why CEL instead of OPA/Rego |
| [docs/adr/003-mcp-sdk-selection.md](docs/adr/003-mcp-sdk-selection.md) | Why the official `modelcontextprotocol/go-sdk` |

## Key Design Decisions

**Audit is outermost, uses `defer`.** Every tool call — including hard denials at the auth stage — is unconditionally recorded. The `defer` pattern ensures the event is emitted after the entire inner chain completes, capturing the final outcome including downstream latency.

**Policy failures are fail-open.** If the CEL engine returns an error (unexpected argument type, nil dereference in a complex expression), the call is allowed and the error is recorded in `AuditEvent.PolicyEvalError`. The rationale: the proxy is in the critical path for all Claude tool usage; a single malformed policy expression should not block all users. The audit trail and `mcp_proxy_policy_eval_errors_total` metric provide the backstop. See [ADR-001](docs/adr/001-fail-open.md).

**CEL over OPA/Rego.** CEL guarantees termination (no loops or recursion), embeds as a pure Go library with microsecond evaluation, and has familiar C/Go/JS syntax. Rego's power (module system, data policies, partial evaluation) is not needed for stateless expression evaluation against request context. See [ADR-002](docs/adr/002-cel-over-rego.md).

**Official MCP SDK.** `github.com/modelcontextprotocol/go-sdk` is used for both server-side (`StreamableHTTPHandler` with per-session `GetServer`) and client-side (`StreamableClientTransport{DisableStandaloneSSE: true}`) transport. The per-session server creation enables dynamic, per-user tool catalog filtering. See [ADR-003](docs/adr/003-mcp-sdk-selection.md).

**`defer cred.Zero()` in credential middleware.** The resolved credential byte slice is zeroed immediately after the dispatch middleware returns, before any other code in the call stack runs. This minimizes the window during which decrypted secrets live in heap memory.

## Contributing

1. Fork the repo and create a feature branch
2. Write tests — table-driven, parallel, using mocks from `internal/mocks/`
3. Run `make lint test policy-test` before opening a PR
4. For gateway interface changes, run `make generate` to regenerate mocks and commit them
5. Policy changes must include a fixture test case in `testdata/policy/tests/`
6. CI enforces 80% aggregate coverage, zero `golangci-lint` warnings, and `TestPolicyFixtures` passing

## License

See [LICENSE](LICENSE).
