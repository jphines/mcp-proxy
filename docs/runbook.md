# Operations Runbook

## Health Endpoints

| Endpoint | Purpose | Expected response |
|---|---|---|
| `GET /healthz` | Liveness | `200 OK`, body `ok` |
| `GET /readyz` | Readiness | `200 OK`, body `ready` |
| `GET /metrics` | Prometheus scrape | `200 OK`, Prometheus text format |

## Common Failure Modes

### 1. Policy Hot-Reload Failure

**Symptom**: Log contains `policy: hot-reload error; keeping existing rules`

**Cause**: Syntax error in updated `policy.yaml`, or CEL compile error.

**Impact**: Existing policy rules remain active. No enforcement gap.

**Remediation**:
```bash
# Validate the new policy file locally
go run ./cmd/policy-test -- --validate-only --policy /path/to/new-policy.yaml

# Check logs for the specific compile error
aws logs filter-log-events \
  --log-group-name /mcp-proxy/app \
  --filter-pattern "hot-reload error"
```

### 2. Credential Not Found

**Symptom**: Tool calls to a specific server fail with `"credential not found"`

**Cause**: Missing secret in Secrets Manager, wrong ARN convention, or IAM permission denied.

**Remediation**:
```bash
# Check the server's credential_ref in servers.yaml
# Expected ARN format: mcp-proxy/{scope}/{ownerID}/{serviceID}

# Verify the secret exists
aws secretsmanager get-secret-value \
  --secret-id mcp-proxy/org/-/github-api-key \
  --region us-east-1

# Check IAM permissions
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::123:role/mcp-proxy-task \
  --action-names secretsmanager:GetSecretValue \
  --resource-arns arn:aws:secretsmanager:us-east-1:123:secret:mcp-proxy/org/-/github-api-key
```

### 3. CloudWatch Log Delivery Failure

**Symptom**: Log contains `cloudwatch: PutLogEvents error`, audit events not appearing in CloudWatch.

**Cause**: IAM permission denied, sequence token out of sync, or throttling.

**Impact**: Audit events are buffered in memory. If the process restarts, buffered events are lost. PostgreSQL events (if configured) are unaffected.

**Remediation**:
```bash
# Check CloudWatch IAM permissions
# Check for InvalidSequenceTokenException (auto-handled by the logger)
# Check for ThrottlingException (increase flush interval)

# To check buffer depth:
curl https://mcp-proxy.internal:8443/metrics | grep cloudwatch_buffer
```

### 4. Circuit Breaker Open

**Symptom**: Tool calls to a server return `"circuit breaker open"`. Metric: `mcp_proxy_circuit_breaker_state{server_id="github"} 1`.

**Cause**: 5 consecutive failures to the downstream server (connection refused, 5xx errors, timeouts).

**Impact**: All calls to that server are immediately rejected with a structured error. Tools remain visible in the catalog (D5).

**Remediation**:
```bash
# Check downstream server health
curl -v https://github-mcp.internal:8443/healthz

# The circuit breaker auto-resets after the configured reset_timeout (default 30s)
# A successful probe request transitions it back to closed

# If the downstream is healthy, the breaker will self-heal
# Monitor: watch -n 5 'curl -s .../metrics | grep circuit_breaker'
```

### 5. Slack Approval Timeout

**Symptom**: Tool calls requiring approval fail with `"approval request timed out"`.

**Cause**: Approver did not respond within the configured timeout (default 5 minutes).

**Impact**: The tool call is rejected. The engineer must retry.

**Remediation**:
- Verify the Slack webhook URL is reachable from the ECS task
- Verify the `SLACK_SIGNING_SECRET` matches the Slack app configuration
- Check `internal/approval/slack.go` for Slack API errors in logs
- If approvers are unreachable (holiday, incident), temporarily adjust policy to `allow` for the affected rule

### 6. OAuth Enrollment Flow Broken

**Symptom**: Engineers get `EnrollmentRequiredError` with an enrollment URL, but visiting the URL returns an error.

**Causes and checks**:
- `PROXY_BASE_URL` env var not set or incorrect (redirect URL mismatch at provider)
- `OAUTH_STATE_SECRET` not set (state signing fails silently)
- OAuth provider `client_secret_ref` points to a non-existent or expired secret
- Clock skew: state expires in 10 minutes; check NTP sync on ECS task

```bash
# Test enrollment URL manually
curl -H "Authorization: Bearer $(cat /tmp/test-jwt)" \
  https://mcp-proxy.internal:8443/oauth/enroll/github
# Should return 302 to GitHub authorization page
```

### 7. Policy Evaluation Error (Fail-Open)

**Symptom**: Log contains `policy: evaluation error (fail-open)`. Metric: `mcp_proxy_policy_eval_errors_total > 0`.

**Cause**: Unexpected value in arguments causing CEL evaluation panic, or nil pointer in activation.

**Impact**: Call proceeds (fail-open). Error recorded in audit event `PolicyEvalError` field.

**Remediation**:
```bash
# Find affected calls
aws logs filter-log-events \
  --log-group-name /mcp-proxy/audit \
  --filter-pattern '{ $.PolicyEvalError != "" }'

# The error message identifies which rule and which field caused the panic
# Fix the CEL expression to handle the edge case (e.g., add exists() checks)
```

## Metrics Alerts (Recommended)

```yaml
# Policy denials spike
- alert: PolicyDenialSpike
  expr: rate(mcp_proxy_tool_calls_total{decision="deny"}[5m]) > 10
  annotations:
    summary: "Unusual policy denial rate — check for misconfiguration or attack"

# Circuit breaker open
- alert: DownstreamCircuitOpen
  expr: mcp_proxy_circuit_breaker_state == 1
  for: 2m
  annotations:
    summary: "Circuit breaker open for {{ $labels.server_id }}"

# Audit delivery lag
- alert: AuditDeliveryLag
  expr: mcp_proxy_cloudwatch_buffer_depth > 1000
  annotations:
    summary: "CloudWatch audit delivery backlog"

# High credential resolution latency
- alert: CredentialSlowResolve
  expr: histogram_quantile(0.95, mcp_proxy_credential_resolution_duration_ms_bucket) > 500
  annotations:
    summary: "Credential resolution p95 latency > 500ms"
```

## Log Queries

**All denied tool calls in the last hour**:
```
fields @timestamp, CallerSubject, ToolNamespaced, PolicyRule, PolicyReason
| filter Decision = "deny"
| sort @timestamp desc
```

**Calls by a specific user**:
```
fields @timestamp, ToolNamespaced, Decision, LatencyMs
| filter CallerSubject = "user@example.com"
| sort @timestamp desc
| limit 50
```

**Hash chain verification**:
```bash
go run ./cmd/policy-test -- --verify-chain \
  --instance-id <ecs-task-arn> \
  --database-url $DATABASE_URL
```

**Approval request audit trail**:
```
fields @timestamp, RequestID, CallerSubject, ToolNamespaced, Decision
| filter Decision = "require_approval"
| sort @timestamp desc
```

## Graceful Shutdown

The process handles `SIGTERM` and `SIGINT`:
1. HTTP server stops accepting new connections
2. 30-second drain period for in-flight requests
3. CloudWatch logger flushes remaining audit events
4. PostgreSQL connection pool closed
5. Process exits 0

ECS sends `SIGTERM` before force-killing the task. The 30-second drain window should be sufficient for in-flight tool calls (p99 << 5s under normal conditions).
