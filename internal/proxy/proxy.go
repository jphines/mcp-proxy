// Package proxy assembles the MCP proxy server: upstream MCP listener + middleware pipeline.
package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/oklog/ulid/v2"

	"github.com/jphines/mcp-proxy/gateway"
)

// toolNameSep is the separator used between serverID and toolName in MCP tool names
// presented to upstream clients (e.g., "github__create_pr").
// Double-underscore is chosen because server IDs are [a-z0-9-]+ and never contain "__".
const toolNameSep = "__"

// contextKey is an unexported key type for context values set by the proxy.
type contextKey int

const (
	bearerTokenCtxKey contextKey = iota
)

// Options configures optional Proxy features beyond the core gateway.Dependencies.
type Options struct {
	// ProxyBaseURL is the public base URL of this proxy instance
	// (e.g. "http://localhost:8080"). Required when DemoJWTURL or Auth0Domain is set.
	ProxyBaseURL string

	// DemoJWTURL, when non-empty, enables the built-in demo OAuth AS.
	// Set to the URL of the demo-jwt service (e.g. "http://demo-jwt:9999").
	// Mutually exclusive with Auth0Domain.
	DemoJWTURL string

	// Auth0Domain, when non-empty, enables Auth0 as the OAuth AS.
	// The proxy serves only RFC 8414 metadata pointing at Auth0; Auth0 handles
	// the full PKCE flow and issues the JWTs the proxy then validates.
	// Mutually exclusive with DemoJWTURL.
	Auth0Domain string

	// Auth0ClientID is the Auth0 application client ID returned to Claude Code
	// via the dynamic client registration stub endpoint.
	Auth0ClientID string

	// Auth0Audience is the Auth0 API audience. Sent in the Auth0 authorize
	// request so Auth0 issues a JWT with the correct aud claim.
	Auth0Audience string
}

// Proxy orchestrates the MCP proxy: it serves upstream MCP sessions and routes
// tool calls through the middleware pipeline to downstream MCP servers.
type Proxy struct {
	deps         *gateway.Dependencies
	pipeline     gateway.MiddlewareFunc
	as           *oauthAS // non-nil only when an OAuth AS is configured
	requireAuth  bool     // true when an OAuth AS is configured; gate middleware returns 401
	proxyBaseURL string   // public base URL, used in WWW-Authenticate discovery headers
}

// New creates a Proxy wired with the full 8-stage middleware pipeline.
// Pipeline order: audit → auth → route → policy → approval → enrollment → credential → dispatch.
func New(deps *gateway.Dependencies, opts Options) *Proxy {
	p := &Proxy{
		deps:         deps,
		proxyBaseURL: strings.TrimRight(opts.ProxyBaseURL, "/"),
	}
	switch {
	case opts.Auth0Domain != "":
		p.as = newOAuthASAuth0(opts.ProxyBaseURL, opts.Auth0Domain, opts.Auth0ClientID, opts.Auth0Audience)
		p.requireAuth = true
	case opts.DemoJWTURL != "":
		p.as = newOAuthAS(opts.ProxyBaseURL, opts.DemoJWTURL)
		p.requireAuth = true
	}
	p.pipeline = gateway.BuildPipeline(
		p.auditMiddleware,
		p.authMiddleware,
		p.routeMiddleware,
		p.policyMiddleware,
		p.approvalMiddleware,
		p.enrollmentMiddleware,
		p.credentialMiddleware,
		p.dispatchMiddleware,
	)
	return p
}

// GetServer is passed to mcp.NewStreamableHTTPHandler. It authenticates the
// inbound request, fetches the tool catalog for the identity, and returns an
// MCP Server with all permitted tools pre-registered.
// Returning nil rejects the session (the SDK responds with HTTP 400).
//
// Note: unauthenticated and invalid-token requests are rejected with proper
// HTTP 401 responses by the authGate middleware before reaching this function.
// GetServer only sees requests that either carry a token (authenticated) or
// are from an open (no OAuth AS configured) deployment.
func (p *Proxy) GetServer(r *http.Request) *mcp.Server {
	ctx := r.Context()

	token := extractBearerToken(r)
	var identity *gateway.Identity
	if token != "" {
		var err error
		identity, err = p.deps.Authenticator.Authenticate(ctx, token)
		if err != nil {
			return nil // token present but invalid — authGate already handled this case
		}
	}

	tools, _ := p.deps.ServerRegistry.ToolCatalog(ctx, identity)

	srv := mcp.NewServer(&mcp.Implementation{
		Name:    "mcp-proxy",
		Version: "1.0.0",
	}, &mcp.ServerOptions{
		Capabilities: &mcp.ServerCapabilities{
			Tools: &mcp.ToolCapabilities{ListChanged: true},
		},
	})

	for _, catalogTool := range tools {
		catalogTool := catalogTool // capture
		mcpName := toMCPName(catalogTool.NamespacedName)
		schema := catalogTool.InputSchema
		if schema == nil {
			schema = map[string]any{"type": "object"}
		}

		bearerToken := token // capture for handler closure
		srv.AddTool(&mcp.Tool{
			Name:        mcpName,
			Description: catalogTool.Description,
			InputSchema: schema,
		}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return p.handleToolCall(ctx, req, bearerToken)
		})
	}

	return srv
}

// handleToolCall runs a single tools/call request through the full middleware pipeline.
func (p *Proxy) handleToolCall(ctx context.Context, req *mcp.CallToolRequest, bearerToken string) (*mcp.CallToolResult, error) {
	tc := &gateway.ToolCallContext{
		RawRequest: req.Params,
		RequestID:  ulid.Make().String(),
	}

	// Inject the bearer token into the context so authMiddleware can retrieve it.
	ctx = context.WithValue(ctx, bearerTokenCtxKey, bearerToken)

	p.pipeline(ctx, tc)

	if tc.Err != nil {
		return errorResult(tc.Err.Error()), nil // tool-level errors are not protocol errors
	}
	if tc.Response != nil {
		return tc.Response, nil
	}
	return &mcp.CallToolResult{}, nil
}

// --- helpers ---

// toMCPName converts "github::create_pr" → "github__create_pr".
func toMCPName(namespacedName string) string {
	return strings.Replace(namespacedName, "::", toolNameSep, 1)
}

// fromMCPName converts "github__create_pr" → ("github", "create_pr").
func fromMCPName(mcpName string) (serverID, toolName string) {
	parts := strings.SplitN(mcpName, toolNameSep, 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return "", mcpName
}

// extractBearerToken parses "Authorization: Bearer <token>".
func extractBearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return ""
	}
	return h[len(prefix):]
}

// hashArguments returns the SHA-256 hex digest of the JSON-encoded arguments.
func hashArguments(args map[string]any) string {
	data, _ := json.Marshal(args)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// errorResult wraps a plain-text error message into an MCP CallToolResult with IsError.
func errorResult(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}
}
