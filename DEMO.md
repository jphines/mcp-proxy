# MCP Proxy — Demo Walkthrough

This guide runs a self-contained docker-compose demo that shows the proxy's
governance pipeline end-to-end: JWT auth, CEL policy, HITL approval, credential
injection, circuit breaking, and a live audit trail.

## Prerequisites

- Docker Desktop (or Rancher Desktop) with Compose v2
- `curl` and `jq` (optional but recommended)
- A Google Cloud project with Calendar, Drive, and Docs APIs enabled (for the Google steps — see below)

## Start the demo

### Option A — simulated tools only (no Google account required)

```bash
make demo
```

### Option B — full demo including real Google Calendar + Docs

```bash
GOOGLE_CLIENT_ID=your_client_id \
GOOGLE_CLIENT_SECRET=your_client_secret \
make demo
```

See [Google OAuth setup](#google-oauth-setup) below for how to obtain these credentials.

This builds and starts seven containers:

| Service            | Port       | Role                                                 |
|--------------------|------------|------------------------------------------------------|
| `postgres`         | (internal) | Audit + credential database                          |
| `demo-jwt`         | 9999       | Local JWT issuer — no Okta account required          |
| `demo-server`      | (internal) | 6-tool simulated MCP server                          |
| `google-server`    | (internal) | 7-tool MCP server for real Google Calendar + Docs    |
| `seed-credentials` | (none)     | One-shot init: seeds Google OAuth secret into DB     |
| `proxy`            | 8080       | The mcp-proxy (plain HTTP, dev mode)                 |
| `dashboard`        | 9090       | Live audit dashboard + Slack auto-approver           |

Open the dashboard: <http://localhost:9090>

---

## Step 1 — Get a JWT

The demo-jwt service issues signed RS256 tokens without needing a real Okta tenant.

```bash
# Human user in the platform-eng group
TOKEN=$(curl -s 'http://localhost:9999/token?user=alice@example.com&groups=platform-eng,everyone' \
  | jq -r .access_token)
echo "Token: ${TOKEN:0:40}..."
```

Query parameters:

| Param    | Values                        | Default                   |
|----------|-------------------------------|---------------------------|
| `user`   | any email                     | `demo-user@example.com`   |
| `groups` | comma-separated group names   | `everyone`                |
| `type`   | `human`, `agent`, `service`   | `human`                   |

---

## Step 2 — Call a tool (allow path)

The `tools__get_weather` tool is tier-2, always allowed.

```bash
curl -s http://localhost:8080/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0","id":1,"method":"tools/call",
    "params":{"name":"tools__get_weather","arguments":{"city":"Berlin"}}
  }' | jq .
```

Watch the dashboard — you should see a green **allow** event appear within
a few seconds.

---

## Step 3 — Trigger the deny rule

The `infra__delete_records` tool is denied for callers outside the
`data-platform` group.

```bash
# alice is in platform-eng but NOT data-platform — this is denied.
curl -s http://localhost:8080/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0","id":2,"method":"tools/call",
    "params":{"name":"infra__delete_records","arguments":{"table":"users","filter":"inactive=true"}}
  }' | jq .result.content[0].text
```

The dashboard shows a red **deny** badge. The downstream server was never called.

Now try with the right group:

```bash
TOKEN_DP=$(curl -s 'http://localhost:9999/token?user=bob@example.com&groups=data-platform,platform-eng' \
  | jq -r .access_token)

curl -s http://localhost:8080/mcp \
  -H "Authorization: Bearer $TOKEN_DP" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0","id":3,"method":"tools/call",
    "params":{"name":"infra__delete_records","arguments":{"table":"sessions","filter":"expired=true"}}
  }' | jq .
```

This one goes through.

---

## Step 4 — HITL approval (scale_service)

`infra__scale_service` requires human approval. In the demo, the dashboard's
built-in mock-Slack handler auto-approves after **4 seconds**.

```bash
# This call will block for ~4 seconds while the proxy waits for approval.
time curl -s http://localhost:8080/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0","id":4,"method":"tools/call",
    "params":{"name":"infra__scale_service","arguments":{"service":"api-gateway","replicas":3}}
  }' | jq .
```

The dashboard shows an **approval** badge, then the result arrives once the
auto-approver fires.

---

## Step 5 — Deny for agents

Agents (`type=agent`) cannot call tier-4 destructive tools.

```bash
AGENT_TOKEN=$(curl -s 'http://localhost:9999/token?user=agent-rx&type=agent&groups=platform-eng,data-platform' \
  | jq -r .access_token)

curl -s http://localhost:8080/mcp \
  -H "Authorization: Bearer $AGENT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0","id":5,"method":"tools/call",
    "params":{"name":"infra__delete_records","arguments":{"table":"events","filter":"test=true"}}
  }' | jq .result.content[0].text
```

Denied. The proxy never contacted the downstream.

---

## Step 6 — Browse the audit trail

The PostgreSQL audit table stores every call with a tamper-evident SHA-256
hash chain. Query it directly:

```bash
docker compose -f docker-compose.demo.yml exec postgres \
  psql -U mcpproxy -d mcpproxy -c \
  "SELECT timestamp::time, caller_sub, tool_namespaced, decision, policy_rule FROM audit_events ORDER BY timestamp DESC LIMIT 10;"
```

---

## Step 7 — Google Calendar (requires Option B)

### 7a — Enroll your Google account

The proxy's OAuth enrollment flow exchanges your Google credentials for an
access token and stores it (encrypted) in PostgreSQL. Open this URL in your
browser:

```
http://localhost:8080/oauth/enroll/google?token=<YOUR_JWT>
```

Where `<YOUR_JWT>` is the token from Step 1. You will be redirected to
Google's consent screen. After approving, the token is stored and you are
redirected back to the proxy.

### 7b — List upcoming events

```bash
curl -s http://localhost:8080/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0","id":10,"method":"tools/call",
    "params":{"name":"google__list_events","arguments":{"days_ahead":7}}
  }' | jq .
```

### 7c — Create an event

```bash
curl -s http://localhost:8080/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0","id":11,"method":"tools/call",
    "params":{"name":"google__create_event","arguments":{
      "summary":"MCP Proxy Demo",
      "start_time":"2025-06-01T10:00:00-07:00",
      "end_time":"2025-06-01T11:00:00-07:00",
      "description":"Created via the mcp-proxy demo",
      "time_zone":"America/Los_Angeles"
    }}
  }' | jq .
```

The event appears immediately in Google Calendar. The dashboard shows a
**log** badge (policy rule `log-google-writes` fired).

---

## Step 8 — Google Docs (requires Option B)

### 8a — List recent documents

```bash
curl -s http://localhost:8080/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0","id":20,"method":"tools/call",
    "params":{"name":"google__list_documents","arguments":{"max_results":5}}
  }' | jq .
```

### 8b — Create a new document

```bash
curl -s http://localhost:8080/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0","id":21,"method":"tools/call",
    "params":{"name":"google__create_document","arguments":{
      "title":"My MCP Proxy Doc",
      "content":"This document was created via mcp-proxy.\n\nThe proxy injected a Google OAuth token automatically — no credentials were ever exposed to the MCP client."
    }}
  }' | jq .
```

The response includes the document URL. The doc is visible in Google Drive.

### 8c — Append to a document (allowed without approval)

```bash
DOC_ID="<document_id from 8b>"

curl -s http://localhost:8080/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"jsonrpc\":\"2.0\",\"id\":22,\"method\":\"tools/call\",
    \"params\":{\"name\":\"google__update_document\",\"arguments\":{
      \"document_id\":\"$DOC_ID\",
      \"content\":\"\n\nAppended at $(date -u +%H:%M:%S) UTC\",
      \"mode\":\"append\"
    }}
  }" | jq .
```

### 8d — Replace document content (triggers approval)

Replacing an entire document requires human approval (policy rule
`require-approval-google-doc-replace`). The auto-approver fires after 4s.

```bash
time curl -s http://localhost:8080/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"jsonrpc\":\"2.0\",\"id\":23,\"method\":\"tools/call\",
    \"params\":{\"name\":\"google__update_document\",\"arguments\":{
      \"document_id\":\"$DOC_ID\",
      \"content\":\"Replaced via approved HITL workflow.\",
      \"mode\":\"replace\"
    }}
  }" | jq .
```

Watch the dashboard — an **approval** badge appears, then the result arrives
after the auto-approver fires.

---

## Cleanup

```bash
make demo-down
```

This stops all containers and deletes the `pgdata` volume.

---

## Google OAuth setup

To use Steps 7–8 you need a Google Cloud project:

1. Go to [console.cloud.google.com](https://console.cloud.google.com) and create a project.
2. Enable these APIs: **Google Calendar API**, **Google Drive API**, **Google Docs API**.
3. Go to **APIs & Services → Credentials → Create Credentials → OAuth 2.0 Client ID**.
4. Application type: **Web application**.
5. Add this redirect URI: `http://localhost:8080/oauth/callback`
6. Copy the **Client ID** and **Client Secret**.
7. Start the demo with those values:

```bash
GOOGLE_CLIENT_ID=your_client_id \
GOOGLE_CLIENT_SECRET=your_client_secret \
docker compose -f docker-compose.demo.yml up --build
```

The client ID is passed to the proxy via `GOOGLE_CLIENT_ID` env var and is
expanded into `testdata/demo/servers.yaml` at load time. The client secret
is encrypted and stored in PostgreSQL by the `seed-credentials` init service.
Neither value is logged or written to any file.

---

## Demo architecture

```
┌────────────────────────────────────────────────────────────┐
│                     docker-compose network                 │
│                                                            │
│  ┌──────────┐   JWT      ┌───────────────────────────────┐ │
│  │ demo-jwt │◄──────────│           proxy               │ │
│  │ :9999    │  JWKS      │                               │ │
│  └──────────┘            │  audit → auth → route         │ │
│                          │  → policy → approval          │ │
│  ┌──────────────────┐    │  → credential → dispatch      │ │
│  │ demo-server :3000│◄───│                               │ │
│  │  get_weather     │    └───────────────┬───────────────┘ │
│  │  search_repos    │                    │ audit events     │
│  │  write_report    │    ┌───────────────▼───────────────┐ │
│  │  query_db        │    │         postgres              │ │
│  │  scale_service   │    │         audit_events table    │ │
│  │  delete_records  │    └───────────────┬───────────────┘ │
│  └──────────────────┘                    │ poll            │
│                          ┌───────────────▼───────────────┐ │
│  Slack webhooks          │         dashboard :9090       │ │
│  ──────────────────────► │  live feed + mock-slack       │ │
│  auto-approve callbacks  │  auto-approver                │ │
│  ◄─────────────────────  └───────────────────────────────┘ │
└────────────────────────────────────────────────────────────┘

Host browser:
  http://localhost:9090   ← dashboard
  http://localhost:8080   ← proxy
  http://localhost:9999   ← JWT issuer
```

---

## Customising the demo

### Change policy rules

Edit `testdata/demo/policy.yaml` — changes take effect on the **next tool call**
(the proxy hot-reloads policy via fsnotify; no restart needed).

### Add a new server

Add an entry to `testdata/demo/servers.yaml`. Point it at `demo-server:3000`
or any other MCP endpoint. Restart only the proxy:

```bash
docker compose -f docker-compose.demo.yml restart proxy
```

### Extend approval timeout

Change `timeout: 30s` in the `require-approval-scale` rule.
Adjust `AUTO_APPROVE_DELAY` in `docker-compose.demo.yml` to match.
