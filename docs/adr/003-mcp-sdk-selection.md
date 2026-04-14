# ADR-003: MCP SDK Selection

**Status**: Accepted  
**Date**: 2025-01-01  
**Deciders**: Platform Engineering

## Context

The proxy needs to:
1. **Serve** upstream MCP clients (Claude Code, claude.ai) via the Streamable HTTP transport
2. **Call** downstream MCP servers as a client

The Go MCP ecosystem has two primary libraries:
- **`github.com/modelcontextprotocol/go-sdk`** — the official SDK maintained by Anthropic
- **`github.com/mark3labs/mcp-go`** — a community SDK

A key constraint: the proxy cannot pre-register downstream tools at startup because:
- Tools are loaded dynamically from multiple downstream servers
- Tool sets can change at runtime (servers added, removed, or their tools changed)
- Per-user AllowedGroups filtering means different callers see different catalogs

## Decision

**`github.com/modelcontextprotocol/go-sdk`** (official SDK) using `mcp.NewStreamableHTTPHandler` for server-side and `mcp.StreamableClientTransport` + `mcp.NewClient` for client-side.

## Rationale

### Official SDK provides dynamic tool registration

`mcp.Server.AddTool` can be called multiple times before the server handles any session, and `NewStreamableHTTPHandler` calls `GetServer(*http.Request)` per session. This means:

```go
func (p *Proxy) GetServer(r *http.Request) *mcp.Server {
    // Authenticate, load catalog, create server, register all tools for this identity
    srv := mcp.NewServer(...)
    for _, tool := range tools {
        srv.AddTool(tool, handler)
    }
    return srv  // fresh server per session with the caller's filtered tool set
}
```

Per-session server creation allows the catalog to be fully personalized. Each session's `*mcp.Server` is independent.

### Streamable HTTP client transport

`mcp.StreamableClientTransport` handles the MCP initialize handshake, session ID management, and SSE stream management transparently. The proxy creates a fresh transport per tool call:

```go
session, err := mcpClient.Connect(ctx, &mcp.StreamableClientTransport{
    Endpoint:             server.Transport.URL,
    HTTPClient:           credInjectingClient,
    DisableStandaloneSSE: true,  // request-response only; no server push needed
}, nil)
defer session.Close()
result, err := session.CallTool(ctx, &mcp.CallToolParams{...})
```

`DisableStandaloneSSE: true` avoids establishing a persistent SSE connection for downstream calls, since the proxy only needs request-response for tool calls.

### Tool listing with pagination

`ClientSession.Tools(ctx, nil)` returns `iter.Seq2[*Tool, error]`, an iterator that handles pagination automatically. Used by `NewToolLister()` in `dispatch.go`.

### Official maintenance

The official SDK tracks the MCP specification directly. As the specification evolves (new transport versions, new protocol features), the official SDK is the first to implement changes. Community forks risk falling behind.

## Alternative Considered: mark3labs/mcp-go

`mark3labs/mcp-go` was the dominant community library before the official SDK was released. It has a simpler API but:
- Uses a different server model that requires pre-registering tools before handling any request
- Does not support per-session `GetServer` callbacks in the same way
- No SSE client transport for calling downstream servers
- Community-maintained with no Anthropic commitment

## Consequences

- Tool handler signature is `func(context.Context, *CallToolRequest) (*CallToolResult, error)` where `CallToolRequest = ServerRequest[*CallToolParamsRaw]`
- Arguments arrive as `json.RawMessage`; routeMiddleware decodes them to `map[string]any`
- Per-call MCP session creation (connect + initialize + call + close) adds ~1 round trip of overhead vs a persistent connection pool
- `DisableStandaloneSSE: true` is set on all client transports; server-push notifications from downstream are not received

## Future: Connection Pooling

Per-tool-call session creation is simple but adds latency. A connection pool (persistent sessions per downstream server, reused across calls) would reduce this to the `CallTool` round trip only. This optimization is deferred to Phase 2 pending load test results.
