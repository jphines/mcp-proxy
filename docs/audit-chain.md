# Audit Trail & Hash Chain

## Purpose

The tamper-evident hash chain provides cryptographic evidence that audit records have not been modified, deleted, or reordered after the fact. It is designed for security audits and compliance reviews where log integrity must be provable.

## Algorithm

```
event_input = canonical_JSON(AuditEvent) with Hash="" and PrevHash=<prevHash>
event.Hash  = hex(SHA-256(event_input))
```

**Canonical JSON** uses `encoding/json.Marshal` with the struct field order fixed by the struct definition. Map keys (`CallerGroups`, `Metadata`) are sorted alphabetically by the Go JSON encoder. There is no extra whitespace.

**Chain linkage**: each event's `PrevHash` equals the previous event's `Hash`. The first event in each instance's stream uses the genesis seed as `PrevHash`.

### Go implementation

```go
func ComputeHash(event *gateway.AuditEvent, prevHash string) {
    event.PrevHash = prevHash
    event.Hash = ""              // excluded from its own hash input

    data, _ := json.Marshal(event)
    sum := sha256.Sum256(data)
    event.Hash = hex.EncodeToString(sum[:])
}
```

The `Hash` field is set to `""` before marshalling so it is included in the JSON as `"Hash":""` (a deterministic zero-value). This avoids the chicken-and-egg problem of hashing a field that contains the hash.

## Genesis Seed

At startup, the proxy:
1. Queries `store.UpsertChainGenesis(instanceID)` — inserts a row with a random UUID as the genesis hash if none exists for this instance ID, or returns the existing one.
2. Uses this hash as `prevHash` for the first event emitted from this process.

Each ECS task has a unique `instanceID` (the ECS task ARN). This means chain segments are per-instance, not cross-instance. Verification is performed per-instance.

## Verification

```go
// AuditLogger.VerifyChain(ctx) — called by runbook/ops tooling
func (l *CloudWatchLogger) VerifyChain(ctx context.Context) error {
    // Query all events for this instance_id, ordered by timestamp ASC
    // Walk events, recomputing hash at each step
    // Compare computed hash to stored hash
    // Return error identifying first broken link
}
```

To test chain integrity after a tampering attempt:

```bash
# 1. Emit 10 tool calls through the proxy
# 2. Verify chain (should pass)
go run ./cmd/policy-test -- --verify-chain --instance-id <id>

# 3. Manually update one row:
# UPDATE audit_events SET decision = 'allow' WHERE event_id = 'evt-xxx';

# 4. Verify chain (should fail at that event)
go run ./cmd/policy-test -- --verify-chain --instance-id <id>
# Error: chain break at event evt-xxx (position 7): computed hash abc123 != stored hash def456
```

## AuditEvent Fields

```go
type AuditEvent struct {
    EventID           string         // ULID — assigned by CloudWatchLogger.Emit
    Timestamp         time.Time
    RequestID         string         // correlation ID from tc.RequestID
    InstanceID        string         // ECS task ARN or hostname

    CallerSubject     string
    CallerType        IdentityType
    CallerGroups      []string
    CallerSessionID   string

    ToolNamespaced    string         // "github::create_pull_request"
    ArgumentsHash     string         // SHA-256 of arguments JSON
    CredentialRef     string         // vault path of resolved credential

    Decision          PolicyAction   // allow | deny | require_approval | log
    PolicyRule        string
    PolicyReason      string
    PolicyEvalError   string         // non-empty on fail-open path

    Workspace         string
    DownstreamStatus  int
    LatencyMs         int64
    DownstreamMs      int64
    RedactionsApplied int

    PrevHash          string         // links to previous event
    Hash              string         // SHA-256 of this event (Hash="")
}
```

## PostgreSQL Persistence

Events are written to the `audit_events` table synchronously (in the CloudWatch flush goroutine, not the hot path). The flush goroutine batches events and writes them together.

`store.DB.VerifyChain` queries events for a given `instance_id` ordered by `timestamp`, then walks them calling `audit.RowHash(row, prevHash)` at each step. This uses the same `ComputeHash` algorithm so the verification is reproducible independently of the in-process state.

## CloudWatch Log Format

Each audit event is JSON-serialised and written as a single CloudWatch log event. The log group and stream are configured via `CloudWatchOptions`:

```
LogGroupName:  "mcp-proxy/audit"
LogStreamName: "{workspace}/{instanceID}"
```

Retention policy should be set to at least 90 days for compliance. CloudWatch Insights can be used to query across events:

```
fields @timestamp, CallerSubject, ToolNamespaced, Decision, PolicyRule
| filter Decision = "deny"
| sort @timestamp desc
| limit 100
```

## Redaction

The proxy does not store raw argument values. It stores `ArgumentsHash` — the SHA-256 of the JSON-serialised arguments. PHI and secrets are never written to the audit trail. If a response contains secrets (e.g., a tool that returns an API key), the `RedactionsApplied` counter tracks how many patterns were detected and redacted.
