package proxy

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ro-eng/mcp-proxy/gateway"
)

// routeMiddleware parses the namespaced tool name from the MCP request,
// resolves the ServerConfig from the registry, and populates tc.ServerID,
// tc.ToolName, tc.Arguments, and tc.ServerConfig.
func (p *Proxy) routeMiddleware(ctx context.Context, tc *gateway.ToolCallContext, next gateway.MiddlewareFunc) {
	if tc.RawRequest == nil {
		tc.Err = fmt.Errorf("route: nil RawRequest")
		return
	}

	mcpName := tc.RawRequest.Name
	serverID, toolName := fromMCPName(mcpName)
	if serverID == "" {
		tc.Err = fmt.Errorf("%w: cannot parse server from tool name %q", gateway.ErrServerNotFound, mcpName)
		return
	}

	srv, err := p.deps.ServerRegistry.Get(ctx, serverID)
	if err != nil {
		tc.Err = err
		return
	}
	if !srv.Enabled {
		tc.Err = fmt.Errorf("%w: server %q is disabled", gateway.ErrServerNotFound, serverID)
		return
	}

	// Decode raw JSON arguments into map[string]any.
	var args map[string]any
	if len(tc.RawRequest.Arguments) > 0 {
		if err := json.Unmarshal(tc.RawRequest.Arguments, &args); err != nil {
			tc.Err = fmt.Errorf("route: decoding arguments: %w", err)
			return
		}
	}

	tc.ServerID = serverID
	tc.ToolName = toolName
	tc.Arguments = args
	tc.ServerConfig = srv

	next(ctx, tc)
}
