# Credential Management

## Overview

The proxy resolves credentials on every tool call, never storing them in `ToolCallContext` beyond the lifetime of a single request. `defer cred.Zero()` in `credentialMiddleware` wipes secret bytes from memory immediately after `dispatchMiddleware` returns.

## Credential Resolution Strategies

### Static (API Keys)

Org-scope credentials retrieved from AWS Secrets Manager. Used for shared API keys that do not vary per user (e.g., a Jira API key used by all Claude surfaces).

```yaml
servers:
  - id: jira
    strategy: static
    credential_ref: "mcp-proxy/org/-/jira-api-key"
    auth_injection:
      method: header_bearer
```

Resolution flow:

```
CredentialResolver.resolveStatic(ctx, server)
  └── CredentialStore.Resolve(ctx, nil, "mcp-proxy/org/-/jira-api-key")
        ├── Cache hit (AES-256-GCM, 30s TTL)?  →  return decrypted credential
        └── SecretsManager.GetSecretValue(ctx, arn)
              → decrypt
              → store in encrypted cache
              → return
```

### OAuth (Per-User Access Tokens)

Per-user access tokens obtained via OAuth 2.0 PKCE flow. Used for services where actions should be traceable to the individual engineer (e.g., GitHub PRs appear as authored by `user@example.com`).

See [OAuth Enrollment](oauth-enrollment.md) for the full enrollment flow.

Resolution fast path per tool call:

```
AccessToken(ctx, identity, serviceID)
  ├── TokenCache.Get(subject, serviceID)?  →  return access token
  └── CredentialStore.Resolve(ctx, identity, serviceID)
        → fetch refresh token from Secrets Manager
        → oauth2.TokenSource.Token()  →  new access token
        → TokenCache.Set(new access token)
        → CredentialStore.Store(new refresh token if rotated)
        → return access token
```

### STS (AWS Temporary Credentials)

For AWS-native tools. The proxy calls `sts:AssumeRoleWithWebIdentity` using the caller's Okta JWT as the web identity token. Returns temporary IAM credentials.

```yaml
servers:
  - id: aws-data
    strategy: sts
    credential_ref: "arn:aws:iam::123456789012:role/mcp-proxy-data-role"
    auth_injection:
      method: env_var   # injects AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN
```

The returned `Credential.Metadata` contains:
- `access_key_id`
- `secret_access_key`
- `session_token`

The dispatch middleware (Phase 2) injects these as environment variables for stdio-transport servers, or as `Authorization: AWS4-HMAC-SHA256 ...` for HTTP-transport servers.

**Session name**: `mcp-proxy-{identity.Subject}`, truncated to 64 characters. This makes CloudTrail logs traceable back to the individual engineer.

### XAA (Phase 2)

RFC 8693 token exchange using the caller's Okta ID token to obtain a service-scoped token from a third-party token exchange endpoint. Not implemented in Phase 1; returns `ErrXAANotSupported`.

## Secrets Manager ARN Convention

```
mcp-proxy/{scope}/{ownerID}/{serviceID}

Examples:
  mcp-proxy/org/-/github-client-secret     ← org scope, no owner
  mcp-proxy/org/-/jira-api-key             ← org scope API key
  mcp-proxy/session/user@example.com/github ← session OAuth refresh token
  mcp-proxy/agent/agent-rx/salesforce       ← agent scope OAuth token
```

## Encrypted In-Process Cache

`internal/credential/store.encryptedCache` caches resolved credentials in memory for 30 seconds. Entries are encrypted at rest in RAM using AES-256-GCM with a per-process random key. This protects against memory dumps reading plaintext secrets.

```
Key generation (once at startup):
  key = make([]byte, 32)
  io.ReadFull(rand.Reader, key)   ← CSPRNG
  cipher, _ = aes.NewCipher(key)
  gcm, _ = cipher.NewGCM(gcm)
  // key is discarded after gcm is created

Cache set:
  nonce = 12 random bytes
  ciphertext = gcm.Seal(nonce, nonce, plaintext, nil)
  map[cacheKey] = ciphertextWithTTL

Cache get:
  ciphertext = map[cacheKey]
  if expired: cred.Zero(); delete(map, key); return nil
  plaintext = gcm.Open(...)
  return plaintext
```

Cache TTL: 30 seconds. Background goroutine runs every 60 seconds to evict expired entries and call `Zero()` on them.

## Injection Methods

| Method | Header/Parameter | Example |
|---|---|---|
| `header_bearer` | `Authorization: Bearer <value>` | GitHub, most REST APIs |
| `header_custom` | `<Header>: <Prefix><value>` | Custom APIs with `X-Api-Key: <value>` |
| `query_param` | URL query parameter | Legacy APIs: `?api_key=<value>` |
| `env_var` | Env variable (stdio only) | AWS credentials as env vars |

## Secret Lifecycle Audit Trail

1. `credentialMiddleware` calls `CredentialResolver.Resolve(ctx, identity, server)` — start timer
2. Timer recorded in `MetricsCollector.CredentialResolutionDuration`
3. `tc.Credential = cred` — pointer stored in context
4. `defer cred.Zero()` registered — runs when `credentialMiddleware` stack frame pops
5. `dispatchMiddleware` runs — builds `credInjectingTransport` with pointer to `cred`
6. `credInjectingTransport.RoundTrip` — `string(cred.Value)` extracted once per HTTP request
7. `dispatchMiddleware` returns — control returns to `credentialMiddleware`
8. `defer cred.Zero()` fires — `cred.Value` bytes set to 0, slice nilled
9. `tc.Credential` now points to a zeroed struct — no secret bytes remain in process heap

The `CredentialRef` (vault path, not the secret value) is recorded in the audit event for traceability.
