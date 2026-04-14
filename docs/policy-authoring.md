# Policy Authoring Guide

Policies are YAML files consumed by `internal/policy.Engine`. The engine compiles all rules at startup using `google/cel-go` and hot-reloads on file changes. A compile error in any rule aborts the reload and keeps the current rule set.

## Rule Schema

```yaml
rules:
  - id: deny-agents-clinical-write
    priority: 10                       # lower number = evaluated first
    description: Agents cannot mutate clinical data
    condition: |
      identity.type == "agent" &&
      call.tier >= 3 &&
      call.tags["domain"] == "clinical"
    action: deny
    reason: "Agents are restricted from tier-3+ clinical mutations"
    audit_level: full                  # minimal | standard | full

  - id: require-approval-high-tier
    priority: 20
    description: Humans writing tier-4+ data need approval
    condition: |
      identity.type == "human" &&
      call.tier >= 4
    action: require_approval
    approval:
      channel: slack
      timeout: 5m
      require_diff: false
    reason: "Tier-4 mutations require a second set of eyes"

  - id: log-external-calls
    priority: 50
    description: Log all calls to external-tagged servers
    condition: |
      call.tags["external"] == "true"
    action: log
    audit_level: standard

  - id: allow-all
    priority: 9999
    description: Default allow
    condition: "true"
    action: allow
```

## Actions

| Action | Effect |
|---|---|
| `deny` | Immediately short-circuit; `tc.Err = ErrPolicyDenied`; audit records denial |
| `require_approval` | Block pipeline until human decides via Slack; audit records outcome |
| `log` | Does **not** short-circuit; records matched rule ID in audit; call proceeds |
| `allow` | Permits the call; no special handling |

**Evaluation order**: rules are sorted by `priority` (ascending). The first rule whose `condition` is truthy wins. `log` rules are additive — all matching log rules are accumulated in `Decision.MatchedLogRules` before the first non-log rule fires.

## CEL Variable Reference

All variables are available in every rule's `condition` expression.

### `identity` object

| Field | Type | Description |
|---|---|---|
| `identity.subject` | `string` | Caller subject (`user@example.com`, agent ID) |
| `identity.type` | `string` | `"human"`, `"agent"`, or `"service"` |
| `identity.groups` | `list(string)` | Okta group memberships |
| `identity.session_id` | `string` | Okta session ID |

### `call` object

| Field | Type | Description |
|---|---|---|
| `call.server_id` | `string` | Registered server ID (`"github"`, `"clinical"`) |
| `call.tool_name` | `string` | Bare tool name (`"create_pull_request"`) |
| `call.tier` | `int` | Server's data tier (1–5) |
| `call.tags` | `map(string, string)` | Key-value labels from `servers.yaml` |
| `call.arguments` | `map(string, dyn)` | Decoded tool arguments |

## Common Patterns

### Deny by identity type + tier

```yaml
condition: |
  identity.type == "agent" && call.tier >= 3
action: deny
```

### Deny by server tag

```yaml
condition: |
  call.tags["env"] == "production" && call.tool_name.startsWith("delete_")
action: deny
reason: "Deletes on production require manual approval"
```

### Group membership check

CEL does not have a built-in `hasGroup` function. Use the idiomatic list exists pattern:

```yaml
condition: |
  identity.groups.exists(g, g == "clinical-engineering")
action: allow
```

To require membership in any of multiple groups:

```yaml
condition: |
  ["platform-eng", "sre", "infra"].exists(g, identity.groups.exists(m, m == g))
```

### `matchesGlob` custom function

The engine registers `matchesGlob(pattern string, value string) bool` for shell-style glob matching (`*`, `?`):

```yaml
condition: |
  matchesGlob("delete_*", call.tool_name) && call.tier >= 3
action: require_approval
```

### Argument inspection

Arguments are available as `map(string, dyn)`. CEL's dynamic type system handles this:

```yaml
condition: |
  "patient_id" in call.arguments &&
  call.tool_name == "get_patient_record"
action: log
audit_level: full
```

### Time-based rules (future)

CEL's `timestamp` functions are available if needed:

```yaml
condition: |
  timestamp(call_time).getHours("America/New_York") >= 20
action: require_approval
reason: "After-hours changes require approval"
```

(Note: `call_time` is not currently injected; this is an example of future extensibility.)

## Audit Levels

| Level | What is recorded |
|---|---|
| `minimal` | EventID, timestamp, caller subject, tool name, decision |
| `standard` | Above + arguments hash, latency, downstream status |
| `full` | Above + policy rule, policy reason, credential ref, redaction count |

Default level when not specified: `standard`.

## require_approval Configuration

```yaml
approval:
  channel: slack         # only "slack" supported in Phase 1
  timeout: 5m            # duration string; default 5m
  require_diff: false    # if true, approver must supply modified arguments
```

`require_diff: true` causes the Slack message to prompt the approver to paste modified arguments. The proxy substitutes `tc.Arguments` before dispatch.

## Startup Validation

At startup, the policy engine compiles every CEL expression. Startup fails (exit code 2) on:
- Duplicate rule IDs
- CEL compile error in any rule
- `require_approval` rule without `approval.channel`

Hot-reload errors keep the existing compiled rule set; a warning is logged.

## Testing Policies

Use the policy test harness (`cmd/policy-test`):

```bash
# Validate syntax only (no engine evaluation)
go run ./cmd/policy-test -- --validate-only --policy config/policy.yaml

# Run all fixture test cases
go run ./cmd/policy-test -- --fixtures testdata/policy/tests/ --policy config/policy.yaml
```

Fixture format:

```yaml
suite: "Clinical data access"
setup:
  policy_dir: "../../config"
cases:
  - name: "human in clinical-engineering can read"
    identity:
      subject: "jane@ro.com"
      type: human
      groups: ["clinical-engineering"]
    call:
      server_id: clinical
      tool_name: get_patient_labs
      tier: 2
    expect:
      action: allow

  - name: "agent denied tier-3 clinical write"
    identity:
      subject: "agent-rx"
      type: agent
      groups: ["clinical-engineering"]
    call:
      server_id: clinical
      tool_name: update_prescription
      tier: 3
    expect:
      action: deny
      rule: deny-agents-clinical-write
```
