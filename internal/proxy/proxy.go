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

	"github.com/ro-eng/mcp-proxy/gateway"
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

// Proxy orchestrates the MCP proxy: it serves upstream MCP sessions and routes
// tool calls through the middleware pipeline to downstream MCP servers.
type Proxy struct {
	deps     *gateway.Dependencies
	pipeline gateway.MiddlewareFunc
}

// New creates a Proxy wired with the full 8-stage middleware pipeline.
// Pipeline order: audit → auth → route → policy → approval → enrollment → credential → dispatch.
func New(deps *gateway.Dependencies) *Proxy {
	p := &Proxy{deps: deps}
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
// Returning nil rejects the session (the SDK responds with HTTP 401).
func (p *Proxy) GetServer(r *http.Request) *mcp.Server {
	ctx := r.Context()

	token := extractBearerToken(r)
	var identity *gateway.Identity
	if token != "" {
		var err error
		identity, err = p.deps.Authenticator.Authenticate(ctx, token)
		if err != nil {
			return nil // unauthenticated → reject session
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
