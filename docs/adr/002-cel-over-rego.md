# ADR-002: CEL over OPA/Rego for Policy Evaluation

**Status**: Accepted  
**Date**: 2025-01-01  
**Deciders**: Platform Engineering

## Context

The proxy needs a declarative policy language that:
- Expresses conditions on identity attributes and tool call properties
- Is maintainable by engineers without a security background
- Compiles and evaluates quickly in the hot path
- Embeds cleanly in a Go binary without external process dependencies

The primary candidates evaluated were:
- **CEL** (Common Expression Language, `google/cel-go`)
- **OPA/Rego** (`open-policy-agent/opa`)
- **Custom DSL** (hand-rolled parser/evaluator)

## Decision

**CEL** (`google/cel-go`).

## Rationale

### Bounded evaluation

CEL guarantees termination. Expressions cannot contain loops or recursion — they are pure function applications on a static activation. This eliminates a class of denial-of-service attacks (malicious policies that loop forever) and makes reasoning about evaluation time straightforward.

OPA/Rego supports full Turing-complete policies with recursive rules. While OPA has timeouts, they require explicit configuration and monitoring.

### Go-native embedding

`google/cel-go` is a pure Go library. It compiles into the proxy binary with no sidecar process, Unix socket, or gRPC connection. Evaluation latency is in microseconds. OPA embeds as a library as well (`github.com/open-policy-agent/opa`), but adds ~30MB to the binary and introduces the Rego compilation pipeline.

### Expression familiarity

CEL syntax is intentionally similar to C, Go, and JavaScript. Expressions like:

```
identity.type == "agent" && call.tier >= 3 && call.tags["domain"] == "clinical"
```

are immediately readable by engineers who don't know Rego. Rego's Datalog-inspired syntax has a steeper learning curve for one-off policy authors.

### Google maintenance

`google/cel-go` is maintained by Google and used in production at scale in Kubernetes admission webhooks, Firebase Security Rules, and Google's own policy systems. Long-term maintenance risk is low.

### What CEL gives up vs Rego

| Feature | CEL | Rego |
|---|---|---|
| Data policies (querying databases) | No | Yes |
| Partial evaluation | Limited | Full |
| Module system | No | Yes |
| Test framework | External | Built-in |
| Bundle distribution | No | Yes |

For the proxy's use case — evaluating stateless expressions against request context — none of the Rego advantages are needed. Policy data (server tiers, tags) is embedded in the activation at evaluation time.

## Consequences

- Policy expressions are limited to stateless CEL expressions; no database lookups in rules
- The policy test harness is custom-built (`cmd/policy-test`), not OPA's built-in `opa test`
- Engineers write `identity.groups.exists(g, g == "admin")` instead of `"admin" in input.identity.groups` (minor ergonomic difference)
- `matchesGlob` is implemented as a custom CEL function (registered in `internal/policy/cel_env.go`)
