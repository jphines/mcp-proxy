# OAuth Enrollment

## Overview

When a downstream MCP server uses the `oauth` auth strategy, each engineer must complete a one-time authorization flow before their tool calls can be dispatched. After enrollment, credential refresh is transparent — the proxy exchanges the stored refresh token for access tokens automatically.

```
Engineer's browser
      │
      │  1. GET /oauth/enroll/{serviceID}  (Bearer: okta-jwt)
      │
      ▼
  MCP Proxy
      │  → Authenticates engineer
      │  → oauth.Enrollment.InitiateFlow(identity, serviceID)
      │     └── generates PKCE verifier + code_challenge
      │     └── signs state = HMAC-SHA256({subject, serviceID, verifier, exp})
      │
      │  302 Redirect ──────────────────────────────────────────────────────►
      │                                                           OAuth Provider
      │                                              (GitHub, Google, Salesforce…)
      │                                                           (user consents)
      │                                              ◄──────── GET /oauth/callback
      │                                                         ?code=XXX&state=YYY
      │  → oauth.Enrollment.HandleCallback(code, state)
      │     └── VerifyState: check HMAC + expiry
      │     └── oauth2.Exchange(code, VerifierOption(verifier)) — PKCE exchange
      │     └── CredentialStore.Store(session scope, refresh_token)
      │     └── TokenCache.Set(access_token)
      │
      │  200 "Enrollment successful — you may close this window"
```

## PKCE Flow Details

The proxy always uses PKCE (RFC 7636) regardless of whether the provider requires it. This prevents authorization code interception attacks.

```go
verifier := oauth2.GenerateVerifier()          // 32 random bytes, base64url-encoded
challenge := oauth2.S256ChallengeOption(verifier)  // SHA-256(verifier), base64url
// ...authorization URL includes code_challenge + code_challenge_method=S256

// At callback:
token, err := cfg.Exchange(ctx, code, oauth2.VerifierOption(verifier))
// Exchange includes code_verifier in the token request body
```

## State Parameter

The OAuth state parameter is HMAC-SHA256 signed to prevent CSRF:

```
state = base64url(payload) + "." + base64url(HMAC-SHA256(secret, base64url(payload)))

payload = JSON{
  "sub":      identity.Subject,
  "svc":      serviceID,
  "verifier": pkceVerifier,
  "exp":      unix_timestamp + 600   // 10-minute window
}
```

`VerifyState` splits on the last `.`, re-computes the MAC, and checks expiry.

## Token Storage

| Token type | Scope | Location | TTL |
|---|---|---|---|
| Access token | In-memory `TokenCache` | Per `(subject, serviceID)` key | Token's own expiry |
| Refresh token | AWS Secrets Manager | `mcp-proxy/session/{subject}/{serviceID}` | Until revoked |

The refresh token is the long-lived secret. It is stored encrypted in Secrets Manager and accessed only via `CredentialStore`.

## Access Token Resolution (per tool call)

```
credentialMiddleware calls CredentialResolver.Resolve(ctx, identity, server)
  └── CompositeResolver.resolveOAuth(ctx, identity, server)
        └── OAuthEnrollment.AccessToken(ctx, identity, serviceID)
              ├── Cache hit?  →  return access token immediately
              └── Cache miss: CredentialStore.Resolve(ctx, identity, serviceID)
                              → get refresh token from Secrets Manager
                              → oauth2.TokenSource(ctx, &Token{RefreshToken: rt})
                              → new access token + (possibly) new refresh token
                              → TokenCache.Set(new access token)
                              → CredentialStore.Store(new refresh token if rotated)
                              → return access token
```

## Revocation

```bash
# Engineer can revoke via the API (or proxy admin can revoke on their behalf)
# POST /oauth/revoke/{serviceID}  (not yet implemented in Phase 1)
```

Revocation calls:
1. `OAuthEnrollment.Revoke(ctx, identity, serviceID)`
2. Deletes the `TokenCache` entry
3. Calls the provider's revoke endpoint (`OAuthProvider.RevokeURL`) with the access token
4. Calls `CredentialStore.Revoke(ctx, sessionScope)` to delete the stored refresh token

## Server Configuration

```yaml
servers:
  - id: github
    name: "GitHub MCP Server"
    strategy: oauth
    oauth_provider:
      service_id: github
      auth_url: "https://github.com/login/oauth/authorize"
      token_url: "https://github.com/login/oauth/access_token"
      revoke_url: "https://github.com/settings/connections/applications/{client_id}"
      client_id: "Ov23liXXXXXXXXXXXXXX"
      client_secret_ref: "mcp-proxy/org/-/github-client-secret"
      scopes: ["repo", "read:org"]
      pkce_required: true
      redirect_base: "https://mcp-proxy.example.com"
    auth_injection:
      method: header_bearer
    transport:
      type: streamable_http
      url: "https://github-mcp.internal:8443/mcp"
```

`client_secret_ref` is a Secrets Manager ARN or path. The proxy resolves it using `CredentialStore.Resolve(ctx, nil, ref)` (nil identity = org scope), keeping the client secret out of the binary and config files.

## Security Properties

- **No secret in URL**: PKCE verifier is never sent as a URL parameter
- **CSRF protection**: HMAC-signed state with 10-minute expiry
- **Refresh token isolation**: stored at `session` scope; one user's token cannot be accessed by another user's `nil`-identity lookup
- **Access token lifetime**: short-lived; lost access tokens expire quickly
- **Revocation propagation**: revoke at provider, Secrets Manager, and in-memory cache simultaneously
