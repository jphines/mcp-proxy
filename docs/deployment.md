# Deployment Guide

## Docker Build

Multi-stage build producing a minimal distroless image:

```dockerfile
FROM golang:1.23-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -trimpath -ldflags="-s -w" -o mcp-proxy ./cmd/mcp-proxy

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /build/mcp-proxy /mcp-proxy
EXPOSE 8443
ENTRYPOINT ["/mcp-proxy"]
```

```bash
docker build -t mcp-proxy:latest .
docker run -p 8443:8443 \
  -e OKTA_ISSUER=https://your-tenant.okta.com \
  -e OKTA_AUDIENCE=https://mcp-proxy.example.com \
  # ... (see Environment Variables below)
  mcp-proxy:latest
```

## Environment Variables

All configuration is loaded from environment variables at startup. Missing required variables cause a non-zero exit (code 2) with all errors reported before exiting.

### Required

| Variable | Description |
|---|---|
| `OKTA_ISSUER` | Okta tenant URL (`https://your-tenant.okta.com`) |
| `OKTA_AUDIENCE` | JWT audience claim expected in tokens |
| `SERVERS_FILE` | Path to `servers.yaml` |
| `POLICY_FILE` | Path to `policy.yaml` |
| `AWS_REGION` | AWS region for Secrets Manager + CloudWatch |
| `CLOUDWATCH_LOG_GROUP` | CloudWatch log group name |
| `CLOUDWATCH_LOG_STREAM` | CloudWatch log stream name |

### Optional

| Variable | Default | Description |
|---|---|---|
| `LISTEN_ADDR` | `:8443` | HTTP server listen address |
| `TLS_CERT_FILE` | — | TLS certificate PEM path (required if not using ACME) |
| `TLS_KEY_FILE` | — | TLS private key PEM path |
| `DATABASE_URL` | — | PostgreSQL connection string (`postgres://...`); disables hash chain if unset |
| `WORKSPACE` | `default` | Logical workspace name (multi-tenant deployments) |
| `INSTANCE_ID` | hostname | Used in audit chain + CloudWatch stream naming |
| `SLACK_SIGNING_SECRET` | — | Slack app signing secret (required if using require_approval policy rules) |
| `OAUTH_STATE_SECRET` | — | HMAC key for OAuth state signing (32+ random bytes, base64-encoded) |
| `PROXY_BASE_URL` | — | Base URL for OAuth callbacks (e.g., `https://mcp-proxy.example.com`) |
| `POLICY_RELOAD_ENABLED` | `true` | Enable fsnotify hot-reload for policy file |
| `SERVERS_RELOAD_ENABLED` | `true` | Enable fsnotify hot-reload for servers file |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |

## ECS Task Definition (excerpt)

```json
{
  "family": "mcp-proxy",
  "taskRoleArn": "arn:aws:iam::123456789012:role/mcp-proxy-task",
  "executionRoleArn": "arn:aws:iam::123456789012:role/mcp-proxy-execution",
  "networkMode": "awsvpc",
  "containerDefinitions": [{
    "name": "mcp-proxy",
    "image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/mcp-proxy:latest",
    "portMappings": [{"containerPort": 8443, "protocol": "tcp"}],
    "environment": [
      {"name": "OKTA_ISSUER", "value": "https://your-tenant.okta.com"},
      {"name": "OKTA_AUDIENCE", "value": "https://mcp-proxy.example.com"},
      {"name": "AWS_REGION", "value": "us-east-1"},
      {"name": "CLOUDWATCH_LOG_GROUP", "value": "/mcp-proxy/audit"},
      {"name": "WORKSPACE", "value": "production"}
    ],
    "secrets": [
      {"name": "DATABASE_URL", "valueFrom": "arn:aws:secretsmanager:us-east-1:...:secret:mcp-proxy/db-url"},
      {"name": "SLACK_SIGNING_SECRET", "valueFrom": "arn:aws:secretsmanager:us-east-1:...:secret:mcp-proxy/slack-signing-secret"},
      {"name": "OAUTH_STATE_SECRET", "valueFrom": "arn:aws:secretsmanager:us-east-1:...:secret:mcp-proxy/oauth-state-secret"}
    ],
    "logConfiguration": {
      "logDriver": "awslogs",
      "options": {
        "awslogs-group": "/mcp-proxy/app",
        "awslogs-region": "us-east-1",
        "awslogs-stream-prefix": "ecs"
      }
    },
    "healthCheck": {
      "command": ["CMD-SHELL", "wget -q -O- http://localhost:8443/healthz || exit 1"],
      "interval": 30,
      "timeout": 5,
      "retries": 3
    }
  }]
}
```

## IAM Permissions

The task role needs:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["secretsmanager:GetSecretValue"],
      "Resource": "arn:aws:secretsmanager:*:*:secret:mcp-proxy/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogStreams"
      ],
      "Resource": "arn:aws:logs:*:*:log-group:/mcp-proxy/*"
    },
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Resource": "*",
      "Condition": {
        "StringLike": {"sts:RoleSessionName": "mcp-proxy-*"}
      }
    }
  ]
}
```

## TLS Configuration

The server enforces TLS 1.3 minimum. Two certificate options:

**Option 1: Certificate files** (recommended for internal/ECS deployments)
```
TLS_CERT_FILE=/etc/certs/mcp-proxy.crt
TLS_KEY_FILE=/etc/certs/mcp-proxy.key
```

**Option 2: ACM Certificate Manager** (via ALB in front of ECS)
- Terminate TLS at the ALB, use HTTP internally between ALB and ECS task on port 8080
- Set `LISTEN_ADDR=:8080` and remove TLS cert env vars

## Rolling Update Procedure

1. Build and push new image to ECR
2. Update the ECS task definition with the new image tag
3. `aws ecs update-service --cluster mcp-proxy --service mcp-proxy --task-definition mcp-proxy:NEW`
4. ECS replaces tasks one-by-one (minimum healthy percent: 50%, maximum percent: 200%)
5. Each new task:
   - Starts and passes health checks (`/healthz`)
   - Receives traffic from ALB
   - Old task is drained and stopped

In-flight MCP sessions are terminated when the old task stops. Claude Code clients will re-establish sessions automatically (next tool call).

## Multi-Region Setup

```
Route 53 (geolocation/latency routing)
    │
    ├── us-east-1  →  ALB  →  ECS (mcp-proxy)  →  Secrets Manager (us-east-1)
    │                                           →  CloudWatch (us-east-1)
    │                                           →  Aurora Global (writer)
    │
    └── eu-west-1  →  ALB  →  ECS (mcp-proxy)  →  Secrets Manager (eu-west-1)
                                                →  CloudWatch (eu-west-1)
                                                →  Aurora Global (reader replica)
```

Hash chain segments are per-instance (per ECS task). Cross-region chain verification is not required — each region's audit stream is independently verifiable.

## servers.yaml Deployment

`servers.yaml` should be stored in AWS Parameter Store or S3, and synced to the ECS container via an init container or ECS volume mount. The fsnotify hot-reload detects file changes and reloads without restart.

```bash
# Update servers.yaml (hot-reload; no restart needed)
aws s3 cp servers.yaml s3://mcp-proxy-config/servers.yaml
# ECS sidecar syncs the file to the shared volume
# fsnotify detects the write event and reloads
```
