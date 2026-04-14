# ADR-001: Fail-Open on Policy Evaluation Errors

**Status**: Accepted  
**Date**: 2025-01-01  
**Deciders**: Platform Engineering

## Context

The CEL policy engine evaluates rules against every tool call. CEL evaluation can fail in edge cases — unexpected argument types, nil pointer dereferences in complex expressions, or bugs in custom functions.

The system must choose between two failure modes:
- **Fail-closed**: block the tool call when the policy engine cannot evaluate
- **Fail-open**: allow the tool call and record the evaluation error

## Decision

**Fail-open**: when `PolicyEngine.Evaluate` returns a non-nil error, the proxy:
1. Sets `tc.PolicyEvalErr = evalErr`
2. Logs a `WARN` with server ID, tool name, and error
3. Increments `mcp_proxy_policy_eval_errors_total`
4. Continues the pipeline with the returned decision (typically `ActionAllow`)

The evaluation error is recorded in the `AuditEvent.PolicyEvalError` field, making it visible in every compliance review.

## Rationale

**Availability over security gate reliability**: MCP Proxy is in the critical path for all Claude tool usage. A fail-closed policy engine would mean a single malformed policy expression or unexpected argument type blocks all tool calls for all users until the issue is fixed and deployed. For a globally-used productivity tool, this is unacceptable.

**Audit as the backstop**: every fail-open call is recorded with `PolicyEvalError` in the audit trail. Security and compliance teams can query for these and investigate. The audit chain is tamper-evident, so the record cannot be retroactively removed.

**Defense in depth**: the proxy has multiple layers before the policy engine (authentication, server registry, AllowedGroups filtering). A policy evaluation failure does not grant access to unauthenticated callers or disabled servers.

**CEL is bounded**: `google/cel-go` evaluation is time-bounded and memory-bounded. Infinite loops are not possible. Failures are well-defined panics or errors, not silent incorrect results.

## Safeguards

1. **Startup fails on compile errors**: CEL expressions are compiled at startup. Syntax errors and type mismatches are caught before the proxy serves traffic.
2. **Hot-reload keeps existing rules on compile error**: a bad rule file does not replace working rules.
3. **Metrics alert**: `mcp_proxy_policy_eval_errors_total > 0` should trigger a PagerDuty alert for investigation.
4. **Audit records**: every fail-open call is permanently recorded and visible in compliance dashboards.

## Consequences

- Policy evaluation errors are non-blocking but visible
- Engineering teams must monitor `PolicyEvalError` in audit and `mcp_proxy_policy_eval_errors_total` metric
- A well-crafted input that triggers a CEL evaluation error will bypass policy — mitigated by authentication + audit
