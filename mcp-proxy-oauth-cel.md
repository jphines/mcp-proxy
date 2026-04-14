# Ro MCP Proxy — OAuth Enrollment & CEL Policy Evaluation

**Companion to:** mcp-proxy-architecture.md
**Date:** April 2026

---

## Part 1: OAuth Enrollment Flow

### The Problem

An engineer runs Claude Code and calls `github::create_pull_request`. The proxy needs to make that GitHub API call *as that engineer* — not with a shared bot token. This means the engineer must have previously authorized the proxy to act on their behalf with GitHub. That authorization step is the enrollment flow.

### Design Constraints

- **One-time setup per engineer per service.** After enrollment, credentials are stored in the vault and refreshed automatically. The engineer shouldn't think about auth again.
- **Minimal scopes by default.** The proxy requests the minimum scopes needed for the registered tools. Scopes are configurable per-server in `servers.yaml`.
- **PKCE always.** Every enrollment uses authorization code + PKCE, even though the proxy is a confidential client with a client secret. Belt and suspenders — PKCE protects against code interception regardless.
- **The proxy holds the client secret.** The engineer never sees the OAuth client ID/secret pair registered with GitHub (or Jira, or Slack). Those live in the vault. The engineer only sees a consent screen.

### Flow Architecture

```
Engineer                  Proxy                    GitHub (OAuth Provider)
   │                        │                            │
   ├─ calls github::list ──▶│                            │
   │                        │                            │
   │    ┌───────────────────┤                            │
   │    │ enrollmentMiddleware                           │
   │    │ detects: no OAuth  │                           │
   │    │ token for this user│                           │
   │    │ + this service     │                           │
   │    └───────────────────┤                            │
   │                        │                            │
   │◀── MCP error response ─┤                            │
   │    "OAuth required.     │                            │
   │     Visit: https://     │                            │
   │     mcp-proxy.ro.com/  │                            │
   │     oauth/enroll/       │                            │
   │     github?token=..."   │                            │
   │                        │                            │
   ├── opens browser ──────▶│                            │
   │                        │                            │
   │                        ├─ generate code_verifier ──▶│
   │                        │  generate code_challenge   │
   │                        │  sign state (user+service  │
   │                        │  +verifier+nonce)          │
   │                        │                            │
   │                        ├─ 302 redirect ────────────▶│
   │                        │  /authorize?               │
   │                        │    client_id=...            │
   │                        │    redirect_uri=proxy/cb    │
   │                        │    scope=repo,read:org      │
   │                        │    state=<signed>           │
   │                        │    code_challenge=<hash>    │
   │                        │    code_challenge_method=S256
   │                        │                            │
   │◀──────────────── GitHub consent screen ─────────────┤
   │                        │                            │
   ├── user clicks Allow ──▶│                            │
   │                        │                            │
   │                        │◀── 302 callback ───────────┤
   │                        │   /oauth/callback?          │
   │                        │     code=AUTH_CODE           │
   │                        │     state=<signed>           │
   │                        │                            │
   │                        ├─ verify state signature     │
   │                        │  extract user + service     │
   │                        │  extract code_verifier      │
   │                        │                            │
   │                        ├─ POST /token ──────────────▶│
   │                        │   grant_type=authorization_code
   │                        │   code=AUTH_CODE             │
   │                        │   code_verifier=<verifier>   │
   │                        │   client_id + client_secret  │
   │                        │                            │
   │                        │◀── access_token + ─────────┤
   │                        │    refresh_token            │
   │                        │                            │
   │                        ├─ store refresh_token        │
   │                        │  in CredentialStore         │
   │                        │  scope: (user, github)      │
   │                        │                            │
   │                        ├─ cache access_token         │
   │                        │  in memory (TTL = expiry)   │
   │                        │                            │
   │◀── "Enrolled! You can  │                            │
   │     close this tab."   │                            │
   │                        │                            │
   ├─ retries github::list ▶│                            │
   │                        │                            │
   │                        ├─ credentialMiddleware       │
   │                        │  resolves cached token      │
   │                        │  injects Authorization hdr  │
   │                        │                            │
   │◀── tool result ────────┤                            │
```

### Interface Implementation

```go
package oauth

import (
    "context"
    "crypto/hmac"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "net/http"
    "time"

    "golang.org/x/oauth2"

    "github.com/ro-eng/mcp-proxy/gateway"
)

// enrollment implements gateway.OAuthEnrollment
type enrollment struct {
    credStore   gateway.CredentialStore
    registry    gateway.ServerRegistry
    stateSecret []byte // HMAC key for signing state params
    proxyBase   string // e.g., "https://mcp-proxy.internal.ro.com"
    cache       *tokenCache
}

// enrollmentState is signed and encoded into the OAuth state parameter.
// It binds the callback to a specific user + service + PKCE verifier.
type enrollmentState struct {
    UserSub      string    `json:"sub"`
    ServiceID    string    `json:"svc"`
    CodeVerifier string    `json:"cv"`
    Nonce        string    `json:"n"`
    ExpiresAt    time.Time `json:"exp"`
}

func (e *enrollment) InitiateFlow(
    ctx context.Context,
    identity *gateway.Identity,
    serviceID string,
) (string, error) {
    // Look up the OAuth provider config for this service
    server, err := e.registry.Get(ctx, serviceID)
    if err != nil {
        return "", fmt.Errorf("unknown service %q: %w", serviceID, err)
    }
    provider := server.OAuthProvider
    if provider == nil {
        return "", fmt.Errorf("service %q does not use per-user OAuth", serviceID)
    }

    // Resolve the client secret from the vault (the proxy's own secret,
    // NOT the user's — users never see this)
    clientSecret, err := e.credStore.Resolve(ctx, nil, provider.ClientSecretRef)
    if err != nil {
        return "", fmt.Errorf("cannot resolve client secret: %w", err)
    }
    defer clientSecret.Zero()

    // Generate PKCE verifier
    verifier := oauth2.GenerateVerifier()

    // Build signed state
    state := enrollmentState{
        UserSub:      identity.Subject,
        ServiceID:    serviceID,
        CodeVerifier: verifier,
        Nonce:        randomString(16),
        ExpiresAt:    time.Now().Add(10 * time.Minute),
    }
    signedState, err := e.signState(state)
    if err != nil {
        return "", err
    }

    // Build OAuth2 config
    conf := &oauth2.Config{
        ClientID:     provider.ClientID,
        ClientSecret: string(clientSecret.Value),
        Scopes:       provider.Scopes,
        Endpoint: oauth2.Endpoint{
            AuthURL:  provider.AuthURL,
            TokenURL: provider.TokenURL,
        },
        RedirectURL: e.proxyBase + "/oauth/callback",
    }

    // Generate authorization URL with PKCE
    authURL := conf.AuthCodeURL(
        signedState,
        oauth2.AccessTypeOffline, // Request refresh token
        oauth2.S256ChallengeOption(verifier),
    )

    return authURL, nil
}

func (e *enrollment) HandleCallback(
    ctx context.Context,
    code string,
    stateParam string,
) error {
    // Verify and decode state
    state, err := e.verifyState(stateParam)
    if err != nil {
        return fmt.Errorf("invalid state: %w", err)
    }
    if time.Now().After(state.ExpiresAt) {
        return fmt.Errorf("enrollment flow expired")
    }

    // Look up provider config
    server, err := e.registry.Get(ctx, state.ServiceID)
    if err != nil {
        return err
    }
    provider := server.OAuthProvider

    // Resolve client secret
    clientSecret, err := e.credStore.Resolve(ctx, nil, provider.ClientSecretRef)
    if err != nil {
        return err
    }
    defer clientSecret.Zero()

    conf := &oauth2.Config{
        ClientID:     provider.ClientID,
        ClientSecret: string(clientSecret.Value),
        Endpoint: oauth2.Endpoint{
            AuthURL:  provider.AuthURL,
            TokenURL: provider.TokenURL,
        },
        RedirectURL: e.proxyBase + "/oauth/callback",
    }

    // Exchange code for tokens, providing the PKCE verifier
    token, err := conf.Exchange(
        ctx, code,
        oauth2.VerifierOption(state.CodeVerifier),
    )
    if err != nil {
        return fmt.Errorf("token exchange failed: %w", err)
    }

    // Store refresh token in vault (encrypted at rest)
    if token.RefreshToken != "" {
        err = e.credStore.Store(ctx, gateway.CredentialScope{
            Level:     gateway.ScopeAgent, // Per-user, not per-session
            OwnerID:   state.UserSub,
            ServiceID: state.ServiceID,
        }, &gateway.Credential{
            Type:  gateway.CredTypeOAuthRefresh,
            Value: []byte(token.RefreshToken),
            Metadata: map[string]string{
                "token_url":  provider.TokenURL,
                "client_id":  provider.ClientID,
                "secret_ref": provider.ClientSecretRef,
                "scopes":     joinScopes(provider.Scopes),
            },
        })
        if err != nil {
            return fmt.Errorf("failed to store refresh token: %w", err)
        }
    }

    // Cache the access token in memory (short-lived)
    e.cache.Set(state.UserSub, state.ServiceID, token)

    return nil
}

func (e *enrollment) IsEnrolled(
    ctx context.Context,
    identity *gateway.Identity,
    serviceID string,
) (bool, error) {
    // Check in-memory cache first
    if e.cache.Has(identity.Subject, serviceID) {
        return true, nil
    }
    // Check vault for a stored refresh token
    _, err := e.credStore.Resolve(ctx, identity, serviceID)
    if err != nil {
        return false, nil // Not enrolled, not an error
    }
    return true, nil
}
```

### How the Enrollment Middleware Uses This

```go
func (p *Proxy) enrollmentMiddleware(
    ctx context.Context,
    tc *gateway.ToolCallContext,
    next gateway.MiddlewareFunc,
) {
    server := tc.ServerConfig
    if server.OAuthProvider == nil {
        // Not an OAuth service — skip
        next(ctx, tc)
        return
    }

    enrolled, err := p.deps.OAuthEnrollment.IsEnrolled(ctx, tc.Identity, server.ID)
    if err != nil {
        tc.Err = fmt.Errorf("enrollment check failed: %w", err)
        return
    }

    if !enrolled {
        // Return an MCP error with the enrollment URL.
        // Claude will surface this to the engineer.
        enrollURL, _ := p.deps.OAuthEnrollment.InitiateFlow(ctx, tc.Identity, server.ID)
        tc.Err = &EnrollmentRequiredError{
            ServiceID:  server.ID,
            ServiceName: server.Name,
            EnrollURL:  enrollURL,
            Message: fmt.Sprintf(
                "You need to authorize access to %s. Visit: %s",
                server.Name, enrollURL,
            ),
        }
        return
    }

    next(ctx, tc)
}
```

### Token Refresh in the Credential Middleware

Once enrolled, the credential middleware handles automatic refresh:

```go
func (p *Proxy) credentialMiddleware(
    ctx context.Context,
    tc *gateway.ToolCallContext,
    next gateway.MiddlewareFunc,
) {
    server := tc.ServerConfig

    // Try to resolve an access token (from cache or vault)
    cred, err := p.deps.CredentialStore.Resolve(ctx, tc.Identity, server.CredentialRef)
    if err != nil {
        tc.Err = fmt.Errorf("credential resolution failed: %w", err)
        return
    }

    // If it's a refresh token (no cached access token), rotate it
    if cred.Type == gateway.CredTypeOAuthRefresh {
        rotated, err := p.deps.CredentialStore.Rotate(ctx, gateway.CredentialScope{
            Level:     gateway.ScopeAgent,
            OwnerID:   tc.Identity.Subject,
            ServiceID: server.CredentialRef,
        })
        if err != nil {
            tc.Err = fmt.Errorf("token refresh failed: %w", err)
            return
        }
        cred = rotated
    }

    // Check if access token is near expiry (< 60s remaining)
    if cred.ExpiresAt != nil && time.Until(*cred.ExpiresAt) < 60*time.Second {
        rotated, err := p.deps.CredentialStore.Rotate(ctx, gateway.CredentialScope{
            Level:     gateway.ScopeAgent,
            OwnerID:   tc.Identity.Subject,
            ServiceID: server.CredentialRef,
        })
        if err != nil {
            // Use the existing token — it's close to expiry but not dead yet
            p.deps.AuditLogger.Emit(ctx, &gateway.AuditEvent{
                Error: "token refresh failed, using expiring token",
            })
        } else {
            cred = rotated
        }
    }

    tc.Credential = cred
    defer cred.Zero()

    tc.Injection = &server.AuthInjection

    next(ctx, tc)
}
```

### Scope Configuration

Scopes are declared per-server in `servers.yaml`, defaulting to minimal:

```yaml
servers:
  - id: github
    name: "GitHub"
    oauth_provider:
      auth_url: "https://github.com/login/oauth/authorize"
      token_url: "https://github.com/login/oauth/access_token"
      revoke_url: "https://api.github.com/applications/{client_id}/token"
      client_id: "Iv1.abc123"
      client_secret_ref: "proxy/github-oauth-secret"  # Vault reference
      scopes:
        - "repo"         # Read/write access to repos
        - "read:org"     # Read org membership (for team-based policy)
      pkce_required: true
    # ... rest of server config

  - id: jira
    name: "Jira"
    oauth_provider:
      auth_url: "https://auth.atlassian.com/authorize"
      token_url: "https://auth.atlassian.com/oauth/token"
      client_id: "xyz789"
      client_secret_ref: "proxy/jira-oauth-secret"
      scopes:
        - "read:jira-work"
        - "write:jira-work"
      pkce_required: true
```

---

## Part 2: CEL Policy Evaluation

### Why CEL

CEL (Common Expression Language) is the right choice for tool-call policy because it's designed exactly for this: evaluating security policies in the request path with near-zero latency. Key properties:

- **Non-Turing-complete.** Guaranteed to terminate. No loops, no recursion, no unbounded computation. You can't write a policy expression that hangs the proxy.
- **Nanosecond evaluation.** CEL compiles expressions to an AST at load time and evaluates in nanoseconds. The policy evaluation cost is negligible vs. the downstream call.
- **Type-safe.** Expressions are type-checked at compile time against a declared environment. A policy rule that references `identity.groups` gets a type error if `groups` isn't declared as `list(string)`.
- **Native Go implementation.** `google/cel-go` is the canonical implementation, maintained by Google, used in Kubernetes admission webhooks, Envoy RBAC, and Firebase security rules.

### CEL Environment

The proxy declares a CEL environment that exposes the identity and tool call as typed variables. Every policy expression evaluates against this environment.

```go
package policy

import (
    "fmt"

    "github.com/google/cel-go/cel"
    "github.com/google/cel-go/common/types"
    "github.com/google/cel-go/common/types/ref"

    "github.com/ro-eng/mcp-proxy/gateway"
)

// NewCELEnv builds the CEL environment with the variables and
// custom functions available to policy expressions.
func NewCELEnv() (*cel.Env, error) {
    return cel.NewEnv(
        // Identity variables
        cel.Variable("identity.sub", cel.StringType),
        cel.Variable("identity.type", cel.StringType),        // "human", "agent", "service"
        cel.Variable("identity.groups", cel.ListType(cel.StringType)),
        cel.Variable("identity.scopes", cel.ListType(cel.StringType)),
        cel.Variable("identity.delegated_by", cel.StringType),
        cel.Variable("identity.session_id", cel.StringType),
        cel.Variable("identity.claims", cel.MapType(cel.StringType, cel.DynType)),

        // Tool call variables
        cel.Variable("tool.server", cel.StringType),          // "github", "clinical"
        cel.Variable("tool.name", cel.StringType),            // "create_pull_request"
        cel.Variable("tool.tier", cel.IntType),               // 1-5
        cel.Variable("tool.args", cel.MapType(cel.StringType, cel.DynType)),
        cel.Variable("tool.tags", cel.MapType(cel.StringType, cel.StringType)),

        // Environment variables
        cel.Variable("env.workspace", cel.StringType),        // "production", "staging"
        cel.Variable("env.region", cel.StringType),

        // Custom functions
        cel.Function("hasGroup",
            cel.Overload("hasGroup_string",
                []*cel.Type{cel.StringType},
                cel.BoolType,
                cel.UnaryBinding(func(val ref.Val) ref.Val {
                    // Convenience: hasGroup("admin") is sugar for
                    // identity.groups.exists(g, g == "admin")
                    return types.Bool(false) // actual impl checks identity.groups
                }),
            ),
        ),
        cel.Function("matchesGlob",
            cel.Overload("matchesGlob_string_string",
                []*cel.Type{cel.StringType, cel.StringType},
                cel.BoolType,
                cel.BinaryBinding(func(lhs, rhs ref.Val) ref.Val {
                    // Glob matching for tool names: matchesGlob(tool.name, "*delete*")
                    return types.Bool(false) // actual impl does glob match
                }),
            ),
        ),
    )
}

// BuildActivation creates the CEL activation (variable bindings)
// from an identity and tool call, for evaluation.
func BuildActivation(
    identity *gateway.Identity,
    call *gateway.ToolCall,
    workspace string,
    region string,
) map[string]any {
    return map[string]any{
        "identity.sub":          identity.Subject,
        "identity.type":         string(identity.Type),
        "identity.groups":       identity.Groups,
        "identity.scopes":       identity.Scopes,
        "identity.delegated_by": identity.DelegatedBy,
        "identity.session_id":   identity.SessionID,
        "identity.claims":       identity.Claims,

        "tool.server": call.ServerID,
        "tool.name":   call.ToolName,
        "tool.tier":   call.Tier,
        "tool.args":   call.Arguments,
        "tool.tags":   call.Tags,

        "env.workspace": workspace,
        "env.region":    region,
    }
}
```

### Policy Rule Schema

Policy rules are authored in YAML and compiled to CEL ASTs at load time. They are evaluated top-down with first-match-wins for `deny` and `require_approval`. `log` actions compose (all matching log rules fire).

```yaml
# policy.yaml — the source of truth, lives in git
rules:
  # ── DENY rules (evaluated first, short-circuit) ─────────────

  - id: red-line-delete-production
    priority: 1
    condition: >
      tool.server == "clinical" &&
      matchesGlob(tool.name, "*delete*") &&
      env.workspace == "production"
    action: deny
    reason: "Deletion of production clinical data is prohibited"
    audit_level: full

  - id: deny-agents-clinical-write
    priority: 2
    condition: >
      identity.type == "agent" &&
      tool.server == "clinical" &&
      tool.tier >= 3
    action: deny
    reason: "Agents cannot perform write operations on clinical data"
    audit_level: full

  # ── REQUIRE APPROVAL rules ─────────────────────────────────

  - id: tier4-human-approval
    priority: 10
    condition: >
      tool.tier >= 4 &&
      identity.type == "human"
    action: require_approval
    approval:
      channel: slack
      timeout: 5m
      require_diff: false  # Humans can self-approve tier 4
    audit_level: full

  - id: tier3-agent-approval
    priority: 11
    condition: >
      tool.tier >= 3 &&
      identity.type == "agent"
    action: require_approval
    approval:
      channel: slack
      timeout: 5m
      require_diff: true   # Agent's delegating human must approve
    audit_level: full

  # ── LOG rules (compose, don't short-circuit) ────────────────

  - id: log-all-clinical
    priority: 50
    condition: >
      tool.server == "clinical"
    action: log
    audit_level: full

  - id: log-staging-writes
    priority: 51
    condition: >
      env.workspace == "staging" &&
      tool.tier >= 3
    action: log
    audit_level: standard

  # ── GROUP-BASED ACCESS ──────────────────────────────────────

  - id: restrict-clinical-to-team
    priority: 20
    condition: >
      tool.server == "clinical" &&
      !identity.groups.exists(g,
        g == "clinical-engineering" || g == "data-science"
      )
    action: deny
    reason: "Clinical tools are restricted to clinical-engineering and data-science groups"

  - id: restrict-infra-tools
    priority: 21
    condition: >
      tool.server == "infrastructure" &&
      !identity.groups.exists(g, g == "platform-engineering")
    action: deny
    reason: "Infrastructure tools are restricted to platform-engineering"

  # ── DEFAULT ALLOW (implicit, but explicit for clarity) ──────

  - id: default-allow
    priority: 999
    condition: "true"
    action: allow
    audit_level: standard
```

### Policy Engine Implementation

```go
package policy

import (
    "context"
    "fmt"
    "os"
    "sort"
    "sync"

    "github.com/google/cel-go/cel"
    "gopkg.in/yaml.v3"

    "github.com/ro-eng/mcp-proxy/gateway"
)

// compiledRule is a policy rule with its CEL expression pre-compiled.
type compiledRule struct {
    ID           string
    Priority     int
    Program      cel.Program   // Compiled CEL expression — eval in nanoseconds
    Action       gateway.PolicyAction
    Reason       string
    AuditLevel   gateway.AuditLevel
    ApprovalSpec *gateway.ApprovalSpec
}

// engine implements gateway.PolicyEngine
type engine struct {
    mu        sync.RWMutex
    rules     []compiledRule   // Sorted by priority
    env       *cel.Env
    configDir string           // Directory to watch for YAML changes
    workspace string
    region    string
}

func NewEngine(configDir, workspace, region string) (gateway.PolicyEngine, error) {
    celEnv, err := NewCELEnv()
    if err != nil {
        return nil, fmt.Errorf("failed to create CEL environment: %w", err)
    }

    e := &engine{
        env:       celEnv,
        configDir: configDir,
        workspace: workspace,
        region:    region,
    }

    if err := e.Reload(context.Background()); err != nil {
        return nil, err
    }

    return e, nil
}

func (e *engine) Evaluate(
    ctx context.Context,
    identity *gateway.Identity,
    call *gateway.ToolCall,
) (*gateway.PolicyDecision, error) {
    e.mu.RLock()
    rules := e.rules
    e.mu.RUnlock()

    activation := BuildActivation(identity, call, e.workspace, e.region)

    var logRules []string

    for _, rule := range rules {
        result, _, err := rule.Program.Eval(activation)
        if err != nil {
            // Fail open: skip this rule, log the error
            continue
        }

        matched, ok := result.Value().(bool)
        if !ok || !matched {
            continue
        }

        // Rule matched — apply action
        switch rule.Action {
        case gateway.ActionDeny:
            // First matching deny wins. Short-circuit.
            return &gateway.PolicyDecision{
                Action:     gateway.ActionDeny,
                Reason:     rule.Reason,
                Rule:       rule.ID,
                AuditLevel: rule.AuditLevel,
            }, nil

        case gateway.ActionRequireApproval:
            // First matching approval wins. Short-circuit.
            return &gateway.PolicyDecision{
                Action:       gateway.ActionRequireApproval,
                Reason:       rule.Reason,
                Rule:         rule.ID,
                AuditLevel:   rule.AuditLevel,
                ApprovalSpec: rule.ApprovalSpec,
            }, nil

        case gateway.ActionLog:
            // Log rules compose — record and continue
            logRules = append(logRules, rule.ID)
            // Don't return, keep evaluating

        case gateway.ActionAllow:
            // Explicit allow — return with any accumulated log rules
            return &gateway.PolicyDecision{
                Action:     gateway.ActionAllow,
                Reason:     rule.Reason,
                Rule:       rule.ID,
                AuditLevel: highestAuditLevel(rule.AuditLevel, logRules),
            }, nil
        }
    }

    // No rule matched — default allow
    return &gateway.PolicyDecision{
        Action:     gateway.ActionAllow,
        Reason:     "default",
        Rule:       "implicit_allow",
        AuditLevel: gateway.AuditStandard,
    }, nil
}

func (e *engine) Reload(ctx context.Context) error {
    // Parse all YAML files in configDir
    raw, err := loadRulesFromDir(e.configDir)
    if err != nil {
        return fmt.Errorf("failed to load policy files: %w", err)
    }

    // Compile each rule's CEL expression
    var compiled []compiledRule
    for _, r := range raw {
        ast, issues := e.env.Compile(r.Condition)
        if issues != nil && issues.Err() != nil {
            return fmt.Errorf("rule %q: CEL compile error: %w", r.ID, issues.Err())
        }

        // Type-check: condition must return bool
        if !ast.OutputType().IsExactType(cel.BoolType) {
            return fmt.Errorf(
                "rule %q: condition must return bool, got %s",
                r.ID, ast.OutputType(),
            )
        }

        prg, err := e.env.Program(ast)
        if err != nil {
            return fmt.Errorf("rule %q: CEL program error: %w", r.ID, err)
        }

        compiled = append(compiled, compiledRule{
            ID:           r.ID,
            Priority:     r.Priority,
            Program:      prg,
            Action:       gateway.PolicyAction(r.Action),
            Reason:       r.Reason,
            AuditLevel:   gateway.AuditLevel(r.AuditLevel),
            ApprovalSpec: parseApprovalSpec(r.Approval),
        })
    }

    // Sort by priority (lower = first)
    sort.Slice(compiled, func(i, j int) bool {
        return compiled[i].Priority < compiled[j].Priority
    })

    // Swap under write lock — zero downtime
    e.mu.Lock()
    e.rules = compiled
    e.mu.Unlock()

    return nil
}
```

### Hot Reload

The proxy watches the policy directory for changes and reloads without restart:

```go
func (e *engine) WatchAndReload(ctx context.Context) error {
    watcher, err := fsnotify.NewWatcher()
    if err != nil {
        return err
    }
    defer watcher.Close()

    if err := watcher.Add(e.configDir); err != nil {
        return err
    }

    for {
        select {
        case <-ctx.Done():
            return nil
        case event := <-watcher.Events:
            if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
                if err := e.Reload(ctx); err != nil {
                    // Log but don't crash — keep existing rules
                    log.Printf("policy reload failed: %v", err)
                } else {
                    log.Printf("policy reloaded from %s", e.configDir)
                }
            }
        case err := <-watcher.Errors:
            log.Printf("policy watcher error: %v", err)
        }
    }
}
```

### Policy Testing

Policy rules can be validated offline before deployment using a test harness:

```go
// policy_test.go — example test cases for the policy rules
func TestPolicyRules(t *testing.T) {
    engine, _ := NewEngine("testdata/policy", "production", "us-east-1")

    tests := []struct {
        name     string
        identity *gateway.Identity
        call     *gateway.ToolCall
        want     gateway.PolicyAction
    }{
        {
            name: "human can read clinical data",
            identity: &gateway.Identity{
                Subject: "jane@ro.com",
                Type:    gateway.IdentityHuman,
                Groups:  []string{"clinical-engineering"},
            },
            call: &gateway.ToolCall{
                ServerID: "clinical",
                ToolName: "get_patient_labs",
                Tier:     2,
            },
            want: gateway.ActionAllow,
        },
        {
            name: "agent denied clinical writes",
            identity: &gateway.Identity{
                Subject: "agent-rx-checker",
                Type:    gateway.IdentityAgent,
                Groups:  []string{"clinical-engineering"},
            },
            call: &gateway.ToolCall{
                ServerID: "clinical",
                ToolName: "update_prescription",
                Tier:     3,
            },
            want: gateway.ActionDeny,
        },
        {
            name: "wrong group denied clinical access",
            identity: &gateway.Identity{
                Subject: "bob@ro.com",
                Type:    gateway.IdentityHuman,
                Groups:  []string{"marketing"},
            },
            call: &gateway.ToolCall{
                ServerID: "clinical",
                ToolName: "get_patient_labs",
                Tier:     2,
            },
            want: gateway.ActionDeny,
        },
        {
            name: "tier 4 requires approval for humans",
            identity: &gateway.Identity{
                Subject: "jane@ro.com",
                Type:    gateway.IdentityHuman,
                Groups:  []string{"platform-engineering"},
            },
            call: &gateway.ToolCall{
                ServerID: "infrastructure",
                ToolName: "scale_down_cluster",
                Tier:     4,
            },
            want: gateway.ActionRequireApproval,
        },
        {
            name: "production clinical delete is red-lined",
            identity: &gateway.Identity{
                Subject: "jane@ro.com",
                Type:    gateway.IdentityHuman,
                Groups:  []string{"clinical-engineering"},
            },
            call: &gateway.ToolCall{
                ServerID: "clinical",
                ToolName: "delete_observation",
                Tier:     5,
            },
            want: gateway.ActionDeny,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            decision, err := engine.Evaluate(context.Background(), tt.identity, tt.call)
            if err != nil {
                t.Fatalf("unexpected error: %v", err)
            }
            if decision.Action != tt.want {
                t.Errorf("got %s, want %s (rule: %s, reason: %s)",
                    decision.Action, tt.want, decision.Rule, decision.Reason)
            }
        })
    }
}
```

This makes policy changes a PR review exercise: write the rule in YAML, add test cases, get approval from security/platform, merge, proxy hot-reloads.
