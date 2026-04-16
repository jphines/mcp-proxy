// Command dashboard is the demo observability dashboard for mcp-proxy.
// It serves a live audit-event feed and handles the demo approval flow by
// acting as a mock Slack incoming-webhook endpoint that auto-approves requests.
//
// Environment variables:
//
//	DATABASE_URL        — PostgreSQL connection string
//	LISTEN_ADDR         — address:port to bind (default ":9090")
//	PROXY_INTERNAL_URL  — internal URL of the proxy for approval callbacks (default "http://proxy:8080")
//	SLACK_SIGNING_SECRET — must match the proxy's SLACK_SIGNING_SECRET
//	AUTO_APPROVE_DELAY  — delay before auto-approving (default "4s")
package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed static
var staticFiles embed.FS

var (
	dbPool         *pgxpool.Pool
	proxyURL       string
	signingSecret  string
	autoApproveDelay time.Duration
)

func main() {
	addr := envOr("LISTEN_ADDR", ":9090")
	proxyURL = envOr("PROXY_INTERNAL_URL", "http://proxy:8080")
	signingSecret = os.Getenv("SLACK_SIGNING_SECRET")
	autoApproveDelay = 4 * time.Second
	if d, err := time.ParseDuration(envOr("AUTO_APPROVE_DELAY", "4s")); err == nil {
		autoApproveDelay = d
	}

	// Connect to PostgreSQL (graceful degradation: show empty feed if unavailable).
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var err error
		dbPool, err = pgxpool.New(ctx, dbURL)
		if err != nil {
			slog.Warn("dashboard: PostgreSQL unavailable; event feed will be empty",
				slog.String("error", err.Error()))
		} else {
			slog.Info("dashboard: PostgreSQL connected")
		}
	}

	// Serve static files (embedded).
	staticSub, _ := fs.Sub(staticFiles, "static")
	staticHandler := http.FileServer(http.FS(staticSub))

	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.StripPrefix("/static/", staticHandler))
	mux.HandleFunc("GET /", serveIndex)
	mux.HandleFunc("GET /api/events", handleEvents)
	mux.HandleFunc("GET /api/stats", handleStats)
	mux.HandleFunc("GET /health", handleHealth)

	// Mock Slack incoming-webhook: receives Block Kit messages and auto-approves.
	mux.HandleFunc("POST /mock-slack", handleMockSlack)

	slog.Info("dashboard listening", slog.String("addr", addr))
	if err := http.ListenAndServe(addr, mux); err != nil {
		slog.Error("dashboard exiting", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

// serveIndex serves the embedded index.html.
func serveIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		http.Error(w, "index.html not found", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

// handleHealth is the liveness probe.
func handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("ok"))
}

// auditRow is the subset of audit_events fields shown in the dashboard.
type auditRow struct {
	EventID        string    `json:"event_id"`
	Timestamp      time.Time `json:"timestamp"`
	CallerSub      string    `json:"caller_sub"`
	CallerType     string    `json:"caller_type"`
	ToolNamespaced string    `json:"tool_namespaced"`
	Decision       string    `json:"decision"`
	PolicyRule     string    `json:"policy_rule"`
	PolicyReason   string    `json:"policy_reason"`
	LatencyMs      int64     `json:"latency_ms"`
	DownstreamMs   int64     `json:"downstream_ms"`
}

// handleEvents returns the 100 most recent audit events as JSON.
func handleEvents(w http.ResponseWriter, r *http.Request) {
	if dbPool == nil {
		writeJSON(w, []auditRow{})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	rows, err := dbPool.Query(ctx, `
		SELECT event_id, timestamp, caller_sub, caller_type,
		       tool_namespaced, decision, policy_rule, policy_reason,
		       latency_ms, downstream_ms
		FROM audit_events
		ORDER BY timestamp DESC
		LIMIT 100
	`)
	if err != nil {
		http.Error(w, "query failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var events []auditRow
	for rows.Next() {
		var e auditRow
		if err := rows.Scan(
			&e.EventID, &e.Timestamp, &e.CallerSub, &e.CallerType,
			&e.ToolNamespaced, &e.Decision, &e.PolicyRule, &e.PolicyReason,
			&e.LatencyMs, &e.DownstreamMs,
		); err != nil {
			continue
		}
		events = append(events, e)
	}
	if events == nil {
		events = []auditRow{}
	}
	writeJSON(w, events)
}

// handleStats returns policy decision counts for the last 1000 events.
func handleStats(w http.ResponseWriter, r *http.Request) {
	if dbPool == nil {
		writeJSON(w, map[string]int{"allow": 0, "deny": 0, "require_approval": 0, "log": 0})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	rows, err := dbPool.Query(ctx, `
		SELECT decision, COUNT(*) AS cnt
		FROM (SELECT decision FROM audit_events ORDER BY timestamp DESC LIMIT 1000) sub
		GROUP BY decision
	`)
	if err != nil {
		http.Error(w, "stats query failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	stats := map[string]int{"allow": 0, "deny": 0, "require_approval": 0, "log": 0}
	for rows.Next() {
		var decision string
		var count int
		if err := rows.Scan(&decision, &count); err == nil {
			stats[decision] = count
		}
	}
	writeJSON(w, stats)
}

// slackMessage is the minimal shape of the Block Kit message the proxy sends.
type slackMessage struct {
	Blocks []struct {
		Type     string `json:"type"`
		Elements []struct {
			ActionID string `json:"action_id"`
			Value    string `json:"value"`
		} `json:"elements"`
	} `json:"blocks"`
}

// handleMockSlack receives a Slack Block Kit webhook, extracts the approval
// requestID, and fires an auto-approval to the proxy after autoApproveDelay.
func handleMockSlack(w http.ResponseWriter, r *http.Request) {
	var msg slackMessage
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}

	// Extract requestID from the approve button's value.
	var requestID string
	for _, block := range msg.Blocks {
		if block.Type == "actions" {
			for _, el := range block.Elements {
				if strings.HasPrefix(el.ActionID, "approve_") && el.Value != "" {
					requestID = el.Value
					break
				}
			}
		}
		if requestID != "" {
			break
		}
	}

	if requestID == "" {
		slog.Warn("dashboard: mock-slack: no requestID found in webhook")
		w.WriteHeader(http.StatusOK)
		return
	}

	slog.Info("dashboard: mock-slack: auto-approving",
		slog.String("request_id", requestID),
		slog.Duration("delay", autoApproveDelay),
	)

	// Fire auto-approval in background after the configured delay.
	go func() {
		time.Sleep(autoApproveDelay)
		if err := sendApprovalCallback(requestID); err != nil {
			slog.Warn("dashboard: approval callback failed",
				slog.String("request_id", requestID),
				slog.String("error", err.Error()),
			)
		} else {
			slog.Info("dashboard: approval delivered", slog.String("request_id", requestID))
		}
	}()

	w.WriteHeader(http.StatusOK)
}

// sendApprovalCallback POSTs a signed Slack interactive callback to the proxy
// approval endpoint, mimicking a real Slack click-to-approve action.
func sendApprovalCallback(requestID string) error {
	// Build the interactive payload Slack would send.
	payload := map[string]any{
		"type": "block_actions",
		"user": map[string]string{
			"id":   "U_DEMO",
			"name": "demo-approver",
		},
		"actions": []map[string]string{
			{
				"action_id": "approve_" + requestID,
				"value":     requestID,
			},
		},
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshalling payload: %w", err)
	}

	// Slack sends the payload as URL-encoded form data.
	body := "payload=" + url.QueryEscape(string(payloadJSON))
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	// Compute Slack-compatible HMAC signature.
	baseStr := "v0:" + timestamp + ":" + body
	mac := hmac.New(sha256.New, []byte(signingSecret))
	mac.Write([]byte(baseStr))
	sig := "v0=" + hex.EncodeToString(mac.Sum(nil))

	callbackURL := proxyURL + "/approvals/slack/callback"
	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		callbackURL,
		bytes.NewBufferString(body),
	)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Slack-Request-Timestamp", timestamp)
	req.Header.Set("X-Slack-Signature", sig)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("posting callback: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("proxy returned %d for approval callback", resp.StatusCode)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
