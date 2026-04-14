package mcp_fixture

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Tool names for the four fixture tools. Use these constants in tests to
// avoid typo-prone string literals.
const (
	ToolReadData   = "read_data"   // tier 1 — observe / read-only
	ToolSearch     = "search"      // tier 2 — read / query
	ToolWriteData  = "write_data"  // tier 3 — write / mutate
	ToolDeleteData = "delete_data" // tier 4 — destructive / delete
)

// Server is an in-process MCP downstream server for integration tests.
// It registers four tools (one per autonomy tier) and records every call
// via an embedded Recorder.
type Server struct {
	http     *httptest.Server
	recorder *Recorder
}

// NewServer creates and starts the fixture server. Call Close() when done.
func NewServer() *Server {
	rec := NewRecorder()

	mcpSrv := mcp.NewServer(&mcp.Implementation{
		Name:    "fixture",
		Version: "1.0.0",
	}, nil)

	// tier 1 — read-only
	mcpSrv.AddTool(&mcp.Tool{
		Name:        ToolReadData,
		Description: "Read fixture data (tier 1 – observe)",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{
			"id": map[string]any{"type": "string"},
		}},
	}, makeHandler(rec, ToolReadData, map[string]any{"tier": 1, "result": "fixture-read"}))

	// tier 2 — search / query
	mcpSrv.AddTool(&mcp.Tool{
		Name:        ToolSearch,
		Description: "Search fixture data (tier 2 – read)",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{
			"query": map[string]any{"type": "string"},
		}},
	}, makeHandler(rec, ToolSearch, map[string]any{"tier": 2, "result": "fixture-search"}))

	// tier 3 — write / mutate
	mcpSrv.AddTool(&mcp.Tool{
		Name:        ToolWriteData,
		Description: "Write fixture data (tier 3 – write)",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{
			"payload": map[string]any{"type": "string"},
		}},
	}, makeHandler(rec, ToolWriteData, map[string]any{"tier": 3, "result": "fixture-write"}))

	// tier 4 — destructive
	mcpSrv.AddTool(&mcp.Tool{
		Name:        ToolDeleteData,
		Description: "Delete fixture data (tier 4 – destructive)",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{
			"id": map[string]any{"type": "string"},
		}},
	}, makeHandler(rec, ToolDeleteData, map[string]any{"tier": 4, "result": "fixture-delete"}))

	httpHandler := mcp.NewStreamableHTTPHandler(
		func(_ *http.Request) *mcp.Server { return mcpSrv },
		nil,
	)

	return &Server{
		http:     httptest.NewServer(httpHandler),
		recorder: rec,
	}
}

// URL returns the base URL of the fixture server (e.g. "http://127.0.0.1:PORT").
func (s *Server) URL() string {
	return s.http.URL
}

// Recorder returns the call recorder for assertion in tests.
func (s *Server) Recorder() *Recorder {
	return s.recorder
}

// Close shuts down the fixture server and its underlying HTTP listener.
func (s *Server) Close() {
	s.http.Close()
}

// makeHandler returns a ToolHandler that records the call and returns a
// JSON text result. The response payload is the fixed map r.
func makeHandler(rec *Recorder, toolName string, response map[string]any) mcp.ToolHandler {
	return func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := decodeArgs(req.Params.Arguments)
		rec.record(toolName, args)

		responseJSON, _ := json.Marshal(response)
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: string(responseJSON)}},
		}, nil
	}
}

// decodeArgs unmarshals json.RawMessage arguments into map[string]any.
// Returns nil when the raw message is empty or cannot be decoded.
func decodeArgs(raw json.RawMessage) map[string]any {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil
	}
	return m
}
