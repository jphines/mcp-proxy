# Ro MCP Proxy — Requirements & Design Brief

**Project:** Self-hosted MCP proxy ("Gateway") in Go
**Reference Implementation:** Peta Core (dunialabs/peta-core)
**Status:** Requirements Gathering
**Date:** April 2026

---

## 1. Purpose

A single choke point between all Claude surfaces (Claude Code, claude.ai, Managed Agents, custom agent harnesses) and all downstream MCP servers and APIs. Every MCP tool call flows through this proxy, which enforces identity, policy, credential injection, content classification, and audit — without any MCP client needing to be aware of the governance layer.

The proxy is the runtime enforcement arm of Ro's Agentic AI Systems Framework (seven-pillar model). It operationalizes three pillars directly: Identity & Harness (Pillar 1), Tool Design (Pillar 3), and Evaluation & Observability (Pillar 6).

---

## 2. Core Architectural Principles

These are non-negotiable design constraints derived from prior work on the governance standards, Moat/Keep analysis, and Ro's healthcare context.

**P1 — Secrets never transit to the caller.** The proxy is the only component that touches downstream credentials. Agents, brains, sandboxes, and human users receive tool call results but never see auth headers, API keys, or tokens. Credential injection happens at the wire, after policy evaluation, and credentials are zeroed from memory after the downstream call completes.

**P2 — Identity is the input; policy is the enforcement.** Every request to the proxy carries an identity assertion (Okta-issued token). Policy decisions are made against identity claims, not against the request content alone. The proxy does not make authorization decisions — it evaluates pre-authored policy against caller identity and delegates to downstream services for data-level authorization.

**P3 — Redact over deny.** When a legitimate call contains sensitive content, redaction is preferred over blocking. Denial stops the workflow; redaction allows it to continue with sanitized data. Denial is reserved for policy violations and unauthorized access attempts. PHI is a normal operating condition for this proxy, not an exception — most tool calls will involve PHI.

**P4 — The Rule of Two.** The proxy represents the second independent judgment. The first judgment is the human or orchestrator who initiated the action. The policy governing what's allowed was authored at a different time by a different person (or the same person in a different mental state). The proxy holds the line even when the caller would approve anything.

**P5 — Fail open.** When policy evaluation fails (expression error, missing field, timeout), the proxy allows the call through with an audit warning. Availability and developer velocity take precedence over blocking on policy engine failures. Security is enforced by well-tested, pre-authored policy — not by failing closed on infrastructure errors.

**P6 — Build for replacement.** The proxy should be a thin, focused service with clear interfaces. If a better commercial product emerges (Runlayer ships HIPAA, Onyx ships an inline proxy), the proxy can be retired without rearchitecting the rest of the stack. Avoid building anything into the proxy that belongs in the policy engine, the identity provider, or the observability platform.

---

## 3. Functional Requirements

### 3.1 MCP Protocol Gateway

- **Transparent MCP proxying.** Act as an MCP server upstream (to Claude surfaces) and an MCP client downstream (to tool servers). No custom protocol extensions — standard MCP 2025-11-25 spec.
- **Multi-server routing.** Mount multiple downstream MCP servers behind one stable endpoint. Namespace tools by server ID (e.g., `github::create_pull_request`, `clinical::get_patient_labs`).
- **Transport support.** Upstream: Streamable HTTP (primary), HTTP+SSE (fallback). Downstream: stdio, HTTP+SSE, Streamable HTTP — whatever each MCP server requires.
- **Tool catalog aggregation.** Merge `tools/list` responses from all registered downstream servers into a single catalog, filtered by the caller's effective permissions.
- **Stream resumption.** Persist events so clients can resume via `Last-Event-ID` after disconnections.
- **Lazy server lifecycle (optional, Phase 2).** Start downstream servers on first call, shut down after idle timeout. Health checks and auto-restart for managed servers.

### 3.2 Identity & Authentication

- **Okta as identity fabric.** All callers authenticate via Okta-issued tokens. Human users present OIDC ID tokens. AI agents present workload identity tokens (ID-JAG / XAA per Okta's agentic identity framework).
- **Token validation.** Validate JWT signature against Okta JWKS endpoint, verify expiry, issuer, audience. Extract claims: `sub` (identity), `groups` (role membership), `scope` (authorized actions), `session_id` (if present).
- **Agent identity registration.** Agents are first-class identities in Okta, not service accounts. Each agent has a registered identity with declared capabilities, an owning human, and a delegation chain.
- **Delegation chains.** When a human initiates an agent session, the proxy receives a delegated token with scoped permissions — "this agent can access clinical data for patients assigned to Dr. Smith." The token inherits the user's permission boundaries.
- **Anonymous access (limited).** A `/mcp/public` endpoint for unauthenticated tool discovery only, with per-source-IP rate limits. No tool execution without authentication.

### 3.3 Credential Resolution & Injection

- **Abstract vault interface.** All credential storage and retrieval goes through a `CredentialStore` interface. The initial implementation backs this with AWS Secrets Manager, but the interface must support swapping to HashiCorp Vault, 1Password, or any other backend without changing the proxy's core logic.

```go
type CredentialStore interface {
    // Resolve returns the credential for a given service, scoped to the caller.
    // Checks session → agent → org scopes in order.
    Resolve(ctx context.Context, identity Identity, service string) (*Credential, error)
    
    // Store persists a credential (e.g., after an OAuth token exchange).
    Store(ctx context.Context, scope CredentialScope, service string, cred *Credential) error
    
    // Revoke removes a credential and, if OAuth, revokes it at the provider.
    Revoke(ctx context.Context, scope CredentialScope, service string) error
    
    // Rotate refreshes an expiring credential (e.g., OAuth access token refresh).
    Rotate(ctx context.Context, scope CredentialScope, service string) (*Credential, error)
}
```

- **Three-tier credential hierarchy.** Resolve credentials in order: session-scoped → agent-scoped → org-scoped. Session credentials (e.g., a delegated OAuth token for a specific clinical workflow) take precedence over agent-level defaults.
- **Per-user OAuth tokens.** For SaaS tools (GitHub, Jira, Slack, etc.), each engineer authenticates to the downstream service through the proxy via OAuth. The proxy stores their per-user refresh tokens in the vault backend and injects per-user access tokens into downstream calls. This provides full per-user attribution in downstream audit logs.
- **OAuth enrollment flow.** When an engineer first connects to a tool that requires per-user OAuth, the proxy initiates an OAuth authorization code + PKCE flow, redirecting the user to the downstream provider's consent screen. On callback, the proxy stores the refresh token in the vault and issues a short-lived access token for immediate use.
- **Credential translation (RFC 8693 token exchange).** The proxy's distinguishing capability vs. commercial products. Receive the caller's identity assertion (Okta ID-JAG) and exchange it for whatever the downstream MCP server expects: an OAuth access token, an API key from the vault, an STS-assumed IAM role, a SAML assertion. The downstream credential is *derived from* the caller's identity, not just injected from a store.
- **AWS STS integration.** For AWS-native services, assume IAM roles scoped to the caller's permissions via `AssumeRoleWithWebIdentity` using the Okta token.
- **OAuth token lifecycle.** Store refresh tokens encrypted via the vault interface, automatically refresh access tokens before expiry, inject only access tokens into downstream requests. Refresh tokens never leave the proxy.
- **Credential revocation on session end.** When a session is archived, revoke its delegated tokens at the provider (if OAuth), delete from the vault, and emit an audit event.
- **30-second decryption TTL.** Decrypted credentials exist in memory only for the duration of the downstream call, with a hard ceiling of 30 seconds. Zeroed from memory after use.

### 3.4 Policy Engine

- **Declarative rules, not imperative code.** Policy rules are YAML files with match conditions (tool pattern, identity claims) and actions (deny, redact, log, require-approval). Expressions use CEL (Common Expression Language) — bounded, non-Turing-complete, guaranteed to terminate.
- **Evaluation semantics.** Deny short-circuits (first matching deny ends evaluation). Redact composes (all matching redact rules run in sequence). Log is transparent (recorded but doesn't affect the call). Allow is the default when no rule matches.
- **Data classification tiers.** Every registered MCP tool has a declared data classification: `public`, `internal`, `confidential`, `phi`. Classification drives which policy rules apply and which failure posture (fail-open vs. fail-closed) is used.
- **Severity-based autonomy tiers.** Map to the Risk Taxonomy & Autonomy Policy (five-tier model from the agentic framework):
  - Tier 1 (Observe): Read-only, non-sensitive. Auto-allow.
  - Tier 2 (Assist): Read-only, potentially sensitive. Auto-allow with audit.
  - Tier 3 (Act): Write operations, reversible. Allow with enhanced audit.
  - Tier 4 (Decide): Write operations, irreversible or high-impact. Require human approval (HITL).
  - Tier 5 (Red Line): Prohibited actions. Hard deny, alert.
- **External policy engine integration (Phase 2).** Webhook to Onyx Security for behavioral analysis. Pre-call and post-call inspection. Hybrid mode: inline for PHI tools, async for non-PHI.
- **Cedar integration (Phase 2).** Evaluate tool-call authorization against Cedar policies for compatibility with AWS Bedrock AgentCore's policy model.

### 3.5 Content Safety

- **Secret detection in freeform text.** Scan tool call parameters and responses for leaked credentials (API keys, connection strings, tokens) using pattern matching. Redact with a placeholder and emit an audit alert.
- **No PHI detection at the proxy layer.** This is a healthcare proxy — PHI is the normal operating condition, not an anomaly to detect. PHI access is governed by identity and policy (does this caller have authorization to access this tool?), not by content scanning. Downstream services enforce data-level access controls. The proxy enforces tool-level access controls.

### 3.6 Human-in-the-Loop (HITL) Approvals

- **Approval workflow for Tier 4 tools.** When a tool call hits a Tier 4 policy, the proxy pauses execution and emits an approval request via the notification channel (Slack webhook initially, with extensible interface for other channels).
- **Approval request payload.** Includes: tool name, arguments summary, caller identity, policy rule that triggered, and a unique request ID.
- **Approval response.** Approve (proceed with original arguments), modify (proceed with altered arguments), or reject (return error to caller). Timeout after configurable window (default 5 minutes) → reject.
- **Audit of approval decisions.** Every approval request and its outcome (approved by whom, modified how, rejected with what reason, or timed out) is recorded in the audit trail.
- **HITL is not authentication.** The HITL approval is a policy gate for high-risk *actions*, not an authentication step. The caller is already authenticated via Okta. HITL answers "should this action proceed?" not "who is making this request?" The approver may be the caller themselves (for self-review of destructive operations) or a different human (for separation-of-duties requirements).

### 3.7 Audit Trail & Observability

- **Structured audit events for every tool call.** Fields: timestamp, request ID, caller identity (sub, groups, session_id), tool name (namespaced), arguments hash (not raw arguments for PHI tools), credential used (reference, not value), policy decision (allow/deny/redact/require-approval), downstream response code, latency, any redactions applied.
- **Tamper-evident log chain.** Each audit entry includes a SHA-256 hash of the previous entry, creating a hash chain. Broken chain = evidence of tampering.
- **SIEM integration.** Emit audit events to CloudWatch Logs in structured JSON. Onyx Security consumes the log stream for behavioral analytics, anomaly detection, and compliance reporting.
- **Metrics.** Expose Prometheus-compatible metrics: request count by tool/identity/decision, latency histograms, credential resolution time, downstream error rates, HITL approval wait times.
- **No raw secrets in logs.** Credential values are never logged. Credential references (Secrets Manager ARN, OAuth client ID) are logged. Argument values for PHI-classified tools are hashed, not logged verbatim.

### 3.8 Network Policy

- **Default-deny egress.** The proxy can only reach registered downstream MCP servers and AWS services (Secrets Manager, STS, Okta JWKS). All other egress is blocked by Cilium network policy or security group.
- **Per-agent, per-server authorization.** Beyond tool-level policy, the proxy enforces which downstream servers a given agent identity can reach at all. Agent A may be authorized for `github.*` and `jira.*` but not `clinical.*`.
- **Circuit breaking.** If a downstream MCP server returns errors or exceeds latency thresholds, the proxy circuit-breaks and returns a degraded response rather than letting agents retry into a wall. Configurable per-server: failure threshold, reset timeout, half-open probe.

### 3.9 Multi-Tenancy & Isolation

- **Session isolation.** Agent A's credentials, session state, and audit trail are invisible to Agent B, even when both transit the same proxy instance. Session state is keyed by (caller_sub, session_id) and stored in PostgreSQL.
- **Workspace scoping.** Tools, policies, and credentials can be scoped to workspaces (e.g., `production`, `staging`, `dev`). An agent authenticated against the `staging` workspace cannot reach `production` MCP servers.

---

## 4. Non-Functional Requirements

### 4.1 Performance

- **Latency budget.** < 50ms p50, < 200ms p95 proxy overhead (excluding downstream call time and Onyx inspection). Credential resolution from Secrets Manager should be cached with TTL.
- **Throughput.** Support 100+ concurrent MCP sessions with sustained tool call rates of 50 calls/second across all sessions.
- **Connection pooling.** Maintain persistent connections to high-frequency downstream MCP servers. Pool and reuse HTTP clients.

### 4.2 Reliability

- **Graceful degradation.** If PostgreSQL is unavailable, the proxy continues serving requests using in-memory state but disables audit persistence (with alert). If Secrets Manager is unavailable, cached credentials continue working until TTL expiry.
- **Zero-downtime deployment.** Rolling restarts with connection draining. Active MCP sessions are migrated or resumed via `Last-Event-ID`.

### 4.3 Security

- **Encryption at rest.** All persisted credentials encrypted with AES-256-GCM. Key derivation via PBKDF2 (100k+ iterations) or AWS KMS envelope encryption.
- **Encryption in transit.** TLS 1.3 minimum for all connections (upstream and downstream).
- **No ambient credentials.** The proxy's own AWS IAM role is scoped to Secrets Manager read + STS AssumeRole only. No admin access, no broad IAM policies.
- **Vulnerability scanning.** Go binary built with `-trimpath`, minimal dependencies, Snyk or Trivy scanning in CI.

### 4.4 Deployment

- **Target platform.** AWS ECS Fargate (primary) or EKS (secondary). Single Go binary, no runtime dependencies beyond PostgreSQL.
- **Multi-region.** Deploy proxy instances in multiple AWS regions behind a Global Accelerator or Route 53 latency-based routing. Each region has its own PostgreSQL replica for audit persistence. Credential resolution uses regional Secrets Manager endpoints. Policy config is replicated across regions via S3 or a shared config store.
- **Configuration.** Environment variables for infrastructure (database URL, AWS region, Okta issuer). YAML files for policy rules and MCP server registrations. Policy changes do not require proxy restart — hot-reload via file watch or API signal.
- **Docker.** Multi-stage build, distroless base image, non-root user, read-only filesystem.
- **HIPAA deployment.** Runs inside Ro's existing AWS BAA-covered VPC. Audit logs go to CloudWatch within the same compliance boundary.

---

## 5. What We're NOT Building (and Why)

- **A policy authoring UI.** Onyx Security provides natural-language policy authoring. We consume policies, not author them in the proxy.
- **An MCP server marketplace or catalog.** Runlayer does this. We register servers via config, not a discovery protocol.
- **A full identity provider.** Okta is the IdP. We validate tokens, not issue them.
- **LLM-level guardrails.** Bedrock Guardrails or the model provider handles prompt safety. The proxy operates at the tool-call layer, not the inference layer.
- **An agent orchestration framework.** The proxy doesn't care whether the caller is a single-turn tool call or a multi-agent swarm. It sees MCP requests with identity assertions.
- **A desktop approval app.** HITL approvals go through Slack initially. A lightweight web UI is a Phase 2 option if Slack proves insufficient.
- **PHI detection or content scanning.** PHI is the normal case. Access governance happens at the identity and policy layer, not the content layer.

---

## 6. Phased Delivery

### Phase 1 — Core Proxy (Weeks 1-8)

Core proxy loop: accept MCP connection → validate Okta JWT → evaluate YAML policy → route to downstream server → resolve credential via `CredentialStore` interface → inject credential → return response → emit audit event. Per-user OAuth enrollment flow for SaaS tools. Static server registration. CloudWatch audit logging. Prometheus metrics. Circuit breaking. Multi-region deployment with regional PostgreSQL replicas.

Includes: `CredentialStore` interface with AWS Secrets Manager implementation, CEL-based policy expressions, HITL approval workflow via Slack, credential translation (RFC 8693 token exchange with Okta), session-scoped credential lifecycle, tamper-evident audit chain.

### Phase 2 — Integration & Hardening (Weeks 9-14)

Onyx Security integration (async log consumer initially, inline for designated tool categories). Cedar policy evaluation for AgentCore compatibility. Lazy server lifecycle management (start on first call, shutdown on idle). Stream resumption. Secret detection and redaction in freeform text. Load testing and performance optimization. Additional `CredentialStore` implementations as needed.

---

## 7. Resolved Decisions

1. **Per-user OAuth tokens.** Each engineer authenticates to downstream SaaS tools through the proxy. The proxy stores per-user refresh tokens in the vault backend and injects per-user access tokens. This provides full attribution in downstream audit logs and respects the principle of individual accountability.

2. **Fail open.** If the proxy's policy engine or vault is degraded, tool calls proceed with an audit warning rather than blocking. Developer velocity takes precedence over policy engine availability. Security is enforced by well-tested policy, not by infrastructure failure modes.

3. **Abstract vault interface.** AWS Secrets Manager is the initial implementation behind a `CredentialStore` interface. The interface is designed to swap to HashiCorp Vault, 1Password, or any other backend without changing proxy core logic. No direct Secrets Manager API calls outside the adapter.

4. **Multi-region deployment.** The proxy runs in multiple AWS regions for availability and latency.

5. **No PHI detection at the proxy layer.** PHI is the normal operating condition. Access is governed by identity and policy at the tool level, not by content scanning at the proxy level.

---

## 8. Remaining Open Questions

1. **Credential caching strategy.** Resolving credentials from Secrets Manager on every tool call adds latency. Need to define TTL-based caching with cache invalidation on credential rotation events. The cache must respect the 30-second decryption TTL for in-memory secrets.

2. **Onyx inline inspection payload.** Onyx will sign a BAA and support PHI. Confirm the integration surface: do we send full tool call arguments to Onyx Guard, or a structured summary? Full arguments give Onyx the best signal for behavioral analytics; summaries reduce data transit.

### Resolved (moved from open)

- **Onyx data residency:** Onyx will support PHI and sign a BAA. No data stripping needed.
- **Server registration model:** Static YAML config, added via PR review. No self-service registration API needed.
- **Session affinity:** Not needed. Stateless proxy instances; session state in PostgreSQL is available from any region.
- **OAuth scope management:** Proxy requests minimal scopes by default. Scopes are configurable per-server in `servers.yaml`. Security team reviews scope changes as part of the server config PR.
- **Credential caching:** TTL-based in-memory cache for access tokens. Refresh tokens always resolved from vault. Cache invalidation on rotation events via vault backend notification (if supported) or TTL expiry.

---

## 9. Go MCP SDK Landscape

Research as of April 2026:

**Official SDK: `modelcontextprotocol/go-sdk`** — Maintained by the MCP project in collaboration with Google. Published March 2026, with 1,443 known importers as of April 2026. Provides typed server and client scaffolding, automatic JSON schema generation from Go structs, built-in support for stdio and command transports, and an `auth` package with OAuth primitives. Supports middleware for request/response interception. The `jsonrpc` package is exposed for custom transport implementations. License: Apache-2.0 / MIT dual license. This is the recommended foundation — it's the canonical implementation, actively maintained, and aligns with the spec directly.

**Community SDK: `mark3labs/mcp-go`** — The most popular community SDK with 1,880 importers. Supports Streamable HTTP natively via `server.NewStreamableHTTPServer()`. Lower boilerplate than the official SDK for simple cases. MIT licensed. Good for reference but the official SDK is now the better long-term bet given Google's co-maintenance.

**Community SDK: `metoro-io/mcp-golang`** — Modular design (transport / protocol / server-client split). Server-first focus. Supports stdio and SSE transports. Smaller community but clean architecture.

**Recommendation:** Use `modelcontextprotocol/go-sdk` as the foundation. It has the strongest spec compliance guarantees, Google co-maintenance, and the `jsonrpc` package gives us the hook point to implement custom transports for the proxy's bidirectional MCP proxying (upstream server + downstream client in one process). The middleware support is critical for inserting the policy evaluation and credential injection steps into the request pipeline without forking the SDK.
