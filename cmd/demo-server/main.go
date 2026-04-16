// Command demo-server is a standalone MCP server that exposes six demo tools
// across three autonomy tiers. It is used exclusively by the docker-compose demo
// environment; it is not part of the production proxy.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":3000"
	}

	srv := mcp.NewServer(&mcp.Implementation{
		Name:    "demo",
		Version: "1.0.0",
	}, nil)

	registerTools(srv)

	mcpHandler := mcp.NewStreamableHTTPHandler(
		func(_ *http.Request) *mcp.Server { return srv },
		nil,
	)

	mux := http.NewServeMux()
	mux.Handle("/", mcpHandler)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	fmt.Fprintf(os.Stderr, "demo-server listening on %s\n", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintf(os.Stderr, "demo-server: %v\n", err)
		os.Exit(1)
	}
}

func registerTools(srv *mcp.Server) {
	// ── Tier 1: public read-only ───────────────────────────────────────────────
	srv.AddTool(&mcp.Tool{
		Name:        "get_weather",
		Description: "Get current weather conditions for a city.",
		InputSchema: schema(
			map[string]any{"city": prop("string", "City name (e.g. 'San Francisco')")},
			"city",
		),
	}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := args(req)
		city, _ := args["city"].(string)
		if city == "" {
			city = "San Francisco"
		}
		conditions := []string{"sunny", "partly cloudy", "overcast", "rainy", "windy"}
		return jsonResult(map[string]any{
			"city":        city,
			"temperature": rand.Intn(25) + 8,
			"unit":        "celsius",
			"conditions":  conditions[rand.Intn(len(conditions))],
			"humidity":    rand.Intn(40) + 40,
			"wind_mph":    rand.Intn(20) + 3,
			"fetched_at":  time.Now().UTC().Format(time.RFC3339),
		}), nil
	})

	// ── Tier 2: query / search ─────────────────────────────────────────────────
	srv.AddTool(&mcp.Tool{
		Name:        "search_repos",
		Description: "Search GitHub repositories by keyword.",
		InputSchema: schema(
			map[string]any{
				"query": prop("string", "Search keywords"),
				"limit": prop("integer", "Max results (default 5, max 20)"),
			},
			"query",
		),
	}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := args(req)
		query, _ := args["query"].(string)
		limit := 5
		if l, ok := args["limit"].(float64); ok && l > 0 {
			limit = int(l)
			if limit > 20 {
				limit = 20
			}
		}
		langs := []string{"Go", "Python", "TypeScript", "Rust", "Java"}
		repos := make([]map[string]any, limit)
		for i := range repos {
			repos[i] = map[string]any{
				"name":  fmt.Sprintf("%s-repo-%d", query, i+1),
				"stars": rand.Intn(12000),
				"lang":  langs[rand.Intn(len(langs))],
				"url":   fmt.Sprintf("https://github.com/demo/%s-repo-%d", query, i+1),
			}
		}
		return jsonResult(map[string]any{"repos": repos, "total_count": limit}), nil
	})

	// ── Tier 2: write ──────────────────────────────────────────────────────────
	srv.AddTool(&mcp.Tool{
		Name:        "write_report",
		Description: "Save a named report with markdown content.",
		InputSchema: schema(
			map[string]any{
				"title":   prop("string", "Report title"),
				"content": prop("string", "Report body in markdown"),
			},
			"title", "content",
		),
	}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := args(req)
		title, _ := args["title"].(string)
		return jsonResult(map[string]any{
			"status":    "saved",
			"report_id": fmt.Sprintf("RPT-%04d", rand.Intn(9999)+1),
			"title":     title,
			"saved_at":  time.Now().UTC().Format(time.RFC3339),
		}), nil
	})

	// ── Tier 3: database query ─────────────────────────────────────────────────
	srv.AddTool(&mcp.Tool{
		Name:        "query_db",
		Description: "Execute a read-only SQL query against the analytics database.",
		InputSchema: schema(
			map[string]any{"sql": prop("string", "SQL SELECT statement")},
			"sql",
		),
	}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := args(req)
		sql, _ := args["sql"].(string)
		n := rand.Intn(8) + 1
		rows := make([]map[string]any, n)
		for i := range rows {
			rows[i] = map[string]any{
				"id":    i + 1,
				"value": rand.Intn(10000),
				"label": fmt.Sprintf("record_%d", rand.Intn(999)+1),
			}
		}
		return jsonResult(map[string]any{
			"query":       sql,
			"rows":        rows,
			"row_count":   n,
			"duration_ms": rand.Intn(45) + 5,
		}), nil
	})

	// ── Tier 3: infrastructure mutation ───────────────────────────────────────
	srv.AddTool(&mcp.Tool{
		Name:        "scale_service",
		Description: "Scale an ECS service to a new desired-count.",
		InputSchema: schema(
			map[string]any{
				"service":  prop("string", "ECS service name"),
				"replicas": prop("integer", "Desired replica count (1-20)"),
			},
			"service", "replicas",
		),
	}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := args(req)
		service, _ := args["service"].(string)
		replicas := 2
		if r, ok := args["replicas"].(float64); ok {
			replicas = int(r)
		}
		return jsonResult(map[string]any{
			"service":      service,
			"old_replicas": rand.Intn(3) + 1,
			"new_replicas": replicas,
			"status":       "UPDATING",
			"request_id":   fmt.Sprintf("ecs-%08x", rand.Int31()),
			"updated_at":   time.Now().UTC().Format(time.RFC3339),
		}), nil
	})

	// ── Tier 4: destructive ────────────────────────────────────────────────────
	srv.AddTool(&mcp.Tool{
		Name:        "delete_records",
		Description: "Permanently delete records from the specified table.",
		InputSchema: schema(
			map[string]any{
				"table":  prop("string", "Table name"),
				"filter": prop("string", "WHERE clause (e.g. 'created_at < 2024-01-01')"),
			},
			"table", "filter",
		),
	}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		a := args(req)
		table, _ := a["table"].(string)
		filter, _ := a["filter"].(string)
		return jsonResult(map[string]any{
			"table":        table,
			"filter":       filter,
			"rows_deleted": rand.Intn(500) + 1,
			"status":       "COMMITTED",
			"deleted_at":   time.Now().UTC().Format(time.RFC3339),
		}), nil
	})
}

// ── helpers ───────────────────────────────────────────────────────────────────

func jsonResult(v any) *mcp.CallToolResult {
	b, _ := json.MarshalIndent(v, "", "  ")
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(b)}},
	}
}

func args(req *mcp.CallToolRequest) map[string]any {
	var m map[string]any
	if len(req.Params.Arguments) > 0 {
		_ = json.Unmarshal(req.Params.Arguments, &m)
	}
	return m
}

func prop(typ, desc string) map[string]any {
	return map[string]any{"type": typ, "description": desc}
}

func schema(props map[string]any, required ...string) map[string]any {
	return map[string]any{
		"type":       "object",
		"properties": props,
		"required":   required,
	}
}
