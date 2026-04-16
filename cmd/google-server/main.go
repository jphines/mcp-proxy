// Command google-server is a downstream MCP server that exposes Google Calendar
// and Google Docs/Drive tools. It is used by the docker-compose demo environment.
//
// The MCP proxy injects the caller's Google OAuth access token as an
// Authorization: Bearer header on every request. Each incoming MCP session
// creates a fresh *mcp.Server with the token captured in the tool closures,
// so the token never leaks between sessions.
//
// Tools exposed:
//
//	Calendar: list_events, create_event, delete_event
//	Docs:     list_documents, read_document, create_document, update_document
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	calendarBase = "https://www.googleapis.com/calendar/v3"
	driveBase    = "https://www.googleapis.com/drive/v3"
	docsBase     = "https://docs.googleapis.com/v1"
)

func main() {
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":4000"
	}

	mcpHandler := mcp.NewStreamableHTTPHandler(
		func(r *http.Request) *mcp.Server {
			return buildServer(extractBearer(r))
		},
		nil,
	)

	mux := http.NewServeMux()
	mux.Handle("/", mcpHandler)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	fmt.Fprintf(os.Stderr, "google-server listening on %s\n", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintf(os.Stderr, "google-server: %v\n", err)
		os.Exit(1)
	}
}

func extractBearer(r *http.Request) string {
	v := r.Header.Get("Authorization")
	if strings.HasPrefix(v, "Bearer ") {
		return strings.TrimPrefix(v, "Bearer ")
	}
	return ""
}

// buildServer constructs a per-session MCP server with the token baked into
// each tool handler via closure. No global state is shared between sessions.
func buildServer(token string) *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{Name: "google-workspace", Version: "1.0.0"}, nil)
	registerCalendarTools(srv, token)
	registerDocsTools(srv, token)
	return srv
}

// ── Calendar ──────────────────────────────────────────────────────────────────

func registerCalendarTools(srv *mcp.Server, token string) {
	srv.AddTool(&mcp.Tool{
		Name:        "list_events",
		Description: "List upcoming events from your primary Google Calendar.",
		InputSchema: schema(
			map[string]any{
				"days_ahead": prop("integer", "Number of days to look ahead (default 7, max 30)"),
			},
		),
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		days := intArg(req, "days_ahead", 7)
		if days > 30 {
			days = 30
		}
		now := time.Now().UTC()
		timeMin := now.Format(time.RFC3339)
		timeMax := now.AddDate(0, 0, days).Format(time.RFC3339)

		params := url.Values{
			"timeMin":      {timeMin},
			"timeMax":      {timeMax},
			"singleEvents": {"true"},
			"orderBy":      {"startTime"},
			"maxResults":   {"20"},
		}
		resp, err := googleGET(ctx, token, calendarBase+"/calendars/primary/events?"+params.Encode())
		if err != nil {
			return errResult(err), nil
		}

		var result struct {
			Items []calendarEvent `json:"items"`
		}
		if err := json.Unmarshal(resp, &result); err != nil {
			return errResult(err), nil
		}

		out := make([]map[string]any, 0, len(result.Items))
		for _, e := range result.Items {
			out = append(out, map[string]any{
				"id":          e.ID,
				"summary":     e.Summary,
				"start":       firstNonEmpty(e.Start.DateTime, e.Start.Date),
				"end":         firstNonEmpty(e.End.DateTime, e.End.Date),
				"description": e.Description,
				"html_link":   e.HTMLLink,
				"attendees":   attendeeEmails(e.Attendees),
			})
		}
		return jsonResult(map[string]any{"events": out, "count": len(out)}), nil
	})

	srv.AddTool(&mcp.Tool{
		Name:        "create_event",
		Description: "Create a new event in your primary Google Calendar.",
		InputSchema: schema(
			map[string]any{
				"summary":     prop("string", "Event title"),
				"start_time":  prop("string", "Start time in RFC3339 format (e.g. 2025-01-15T10:00:00-08:00)"),
				"end_time":    prop("string", "End time in RFC3339 format"),
				"description": prop("string", "Optional event description"),
				"attendees":   prop("string", "Optional comma-separated attendee email addresses"),
				"time_zone":   prop("string", "Time zone (e.g. America/Los_Angeles). Default: UTC"),
			},
			"summary", "start_time", "end_time",
		),
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		summary := stringArg(req, "summary")
		startTime := stringArg(req, "start_time")
		endTime := stringArg(req, "end_time")
		description := stringArg(req, "description")
		attendeesRaw := stringArg(req, "attendees")
		tz := stringArg(req, "time_zone")
		if tz == "" {
			tz = "UTC"
		}

		event := map[string]any{
			"summary":     summary,
			"description": description,
			"start":       map[string]string{"dateTime": startTime, "timeZone": tz},
			"end":         map[string]string{"dateTime": endTime, "timeZone": tz},
		}
		if attendeesRaw != "" {
			var attendees []map[string]string
			for _, email := range strings.Split(attendeesRaw, ",") {
				email = strings.TrimSpace(email)
				if email != "" {
					attendees = append(attendees, map[string]string{"email": email})
				}
			}
			event["attendees"] = attendees
		}

		body, _ := json.Marshal(event)
		resp, err := googlePOST(ctx, token, calendarBase+"/calendars/primary/events", body)
		if err != nil {
			return errResult(err), nil
		}

		var created calendarEvent
		if err := json.Unmarshal(resp, &created); err != nil {
			return errResult(err), nil
		}
		return jsonResult(map[string]any{
			"status":    "created",
			"id":        created.ID,
			"summary":   created.Summary,
			"start":     firstNonEmpty(created.Start.DateTime, created.Start.Date),
			"end":       firstNonEmpty(created.End.DateTime, created.End.Date),
			"html_link": created.HTMLLink,
		}), nil
	})

	srv.AddTool(&mcp.Tool{
		Name:        "delete_event",
		Description: "Permanently delete a Google Calendar event by its ID.",
		InputSchema: schema(
			map[string]any{
				"event_id": prop("string", "The Google Calendar event ID to delete"),
			},
			"event_id",
		),
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		eventID := stringArg(req, "event_id")
		if eventID == "" {
			return errResult(fmt.Errorf("event_id is required")), nil
		}
		endpoint := calendarBase + "/calendars/primary/events/" + url.PathEscape(eventID)
		if err := googleDELETE(ctx, token, endpoint); err != nil {
			return errResult(err), nil
		}
		return jsonResult(map[string]any{"status": "deleted", "event_id": eventID}), nil
	})
}

// ── Docs / Drive ──────────────────────────────────────────────────────────────

func registerDocsTools(srv *mcp.Server, token string) {
	srv.AddTool(&mcp.Tool{
		Name:        "list_documents",
		Description: "List recent Google Docs documents from your Drive.",
		InputSchema: schema(
			map[string]any{
				"max_results": prop("integer", "Maximum number of documents to return (default 10, max 50)"),
				"query":       prop("string", "Optional search query to filter documents by name"),
			},
		),
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		maxResults := intArg(req, "max_results", 10)
		if maxResults > 50 {
			maxResults = 50
		}
		q := "mimeType='application/vnd.google-apps.document' and trashed=false"
		if extra := stringArg(req, "query"); extra != "" {
			q += " and name contains '" + strings.ReplaceAll(extra, "'", "\\'") + "'"
		}

		params := url.Values{
			"q":        {q},
			"fields":   {"files(id,name,modifiedTime,webViewLink,owners)"},
			"orderBy":  {"modifiedTime desc"},
			"pageSize": {fmt.Sprintf("%d", maxResults)},
		}
		resp, err := googleGET(ctx, token, driveBase+"/files?"+params.Encode())
		if err != nil {
			return errResult(err), nil
		}

		var result struct {
			Files []driveFile `json:"files"`
		}
		if err := json.Unmarshal(resp, &result); err != nil {
			return errResult(err), nil
		}

		out := make([]map[string]any, 0, len(result.Files))
		for _, f := range result.Files {
			out = append(out, map[string]any{
				"id":            f.ID,
				"name":          f.Name,
				"modified_time": f.ModifiedTime,
				"web_view_link": f.WebViewLink,
			})
		}
		return jsonResult(map[string]any{"documents": out, "count": len(out)}), nil
	})

	srv.AddTool(&mcp.Tool{
		Name:        "read_document",
		Description: "Read the text content of a Google Doc by its document ID.",
		InputSchema: schema(
			map[string]any{
				"document_id": prop("string", "The Google Docs document ID (from the URL or list_documents)"),
			},
			"document_id",
		),
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		docID := stringArg(req, "document_id")
		if docID == "" {
			return errResult(fmt.Errorf("document_id is required")), nil
		}

		resp, err := googleGET(ctx, token, docsBase+"/documents/"+url.PathEscape(docID))
		if err != nil {
			return errResult(err), nil
		}

		var doc googleDoc
		if err := json.Unmarshal(resp, &doc); err != nil {
			return errResult(err), nil
		}

		text := extractDocText(&doc)
		return jsonResult(map[string]any{
			"document_id": docID,
			"title":       doc.Title,
			"content":     text,
			"char_count":  len(text),
		}), nil
	})

	srv.AddTool(&mcp.Tool{
		Name:        "create_document",
		Description: "Create a new Google Doc with optional initial content.",
		InputSchema: schema(
			map[string]any{
				"title":   prop("string", "Document title"),
				"content": prop("string", "Optional initial text content"),
			},
			"title",
		),
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		title := stringArg(req, "title")
		content := stringArg(req, "content")
		if title == "" {
			return errResult(fmt.Errorf("title is required")), nil
		}

		// Create the document.
		createBody, _ := json.Marshal(map[string]string{"title": title})
		resp, err := googlePOST(ctx, token, docsBase+"/documents", createBody)
		if err != nil {
			return errResult(err), nil
		}

		var created struct {
			DocumentID string `json:"documentId"`
			Title      string `json:"title"`
		}
		if err := json.Unmarshal(resp, &created); err != nil {
			return errResult(err), nil
		}

		// Insert content if provided.
		if content != "" {
			if err := insertDocText(ctx, token, created.DocumentID, content); err != nil {
				// Non-fatal: doc was created, just content insertion failed.
				return jsonResult(map[string]any{
					"status":      "created_empty",
					"document_id": created.DocumentID,
					"title":       created.Title,
					"warning":     "content insertion failed: " + err.Error(),
					"web_link":    "https://docs.google.com/document/d/" + created.DocumentID,
				}), nil
			}
		}

		return jsonResult(map[string]any{
			"status":      "created",
			"document_id": created.DocumentID,
			"title":       created.Title,
			"web_link":    "https://docs.google.com/document/d/" + created.DocumentID,
		}), nil
	})

	srv.AddTool(&mcp.Tool{
		Name:        "update_document",
		Description: "Append or replace text content in a Google Doc.",
		InputSchema: schema(
			map[string]any{
				"document_id": prop("string", "The Google Docs document ID"),
				"content":     prop("string", "Text content to write"),
				"mode":        prop("string", "Write mode: 'append' (default) adds to end, 'replace' clears first"),
			},
			"document_id", "content",
		),
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		docID := stringArg(req, "document_id")
		content := stringArg(req, "content")
		mode := stringArg(req, "mode")
		if mode == "" {
			mode = "append"
		}
		if docID == "" || content == "" {
			return errResult(fmt.Errorf("document_id and content are required")), nil
		}

		if mode == "replace" {
			if err := clearDocText(ctx, token, docID); err != nil {
				return errResult(fmt.Errorf("clearing document: %w", err)), nil
			}
		}

		if err := insertDocText(ctx, token, docID, content); err != nil {
			return errResult(err), nil
		}

		return jsonResult(map[string]any{
			"status":      "updated",
			"document_id": docID,
			"mode":        mode,
			"chars_written": len(content),
			"web_link":    "https://docs.google.com/document/d/" + docID,
		}), nil
	})
}

// ── Google API helpers ────────────────────────────────────────────────────────

func googleGET(ctx context.Context, token, endpoint string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return doRequest(req)
}

func googlePOST(ctx context.Context, token, endpoint string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	return doRequest(req)
}

func googleDELETE(ctx context.Context, token, endpoint string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	_, err = doRequest(req)
	return err
}

func doRequest(req *http.Request) ([]byte, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20)) // 4 MiB
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode >= 400 {
		// Try to extract the Google error message.
		var apiErr struct {
			Error struct {
				Message string `json:"message"`
				Code    int    `json:"code"`
			} `json:"error"`
		}
		if json.Unmarshal(body, &apiErr) == nil && apiErr.Error.Message != "" {
			return nil, fmt.Errorf("Google API %d: %s", apiErr.Error.Code, apiErr.Error.Message)
		}
		return nil, fmt.Errorf("Google API HTTP %d", resp.StatusCode)
	}

	return body, nil
}

// ── Docs text extraction ──────────────────────────────────────────────────────

type googleDoc struct {
	Title string  `json:"title"`
	Body  docBody `json:"body"`
}

type docBody struct {
	Content []structuralElement `json:"content"`
}

type structuralElement struct {
	Paragraph *paragraph `json:"paragraph,omitempty"`
	Table     *table     `json:"table,omitempty"`
}

type paragraph struct {
	Elements []paragraphElement `json:"elements"`
}

type paragraphElement struct {
	TextRun *textRun `json:"textRun,omitempty"`
}

type textRun struct {
	Content string `json:"content"`
}

type table struct {
	TableRows []tableRow `json:"tableRows"`
}

type tableRow struct {
	TableCells []tableCell `json:"tableCells"`
}

type tableCell struct {
	Content []structuralElement `json:"content"`
}

// extractDocText walks the Docs API response and returns plain text.
func extractDocText(doc *googleDoc) string {
	var sb strings.Builder
	for _, el := range doc.Body.Content {
		writeElement(&sb, el)
	}
	return sb.String()
}

func writeElement(sb *strings.Builder, el structuralElement) {
	if el.Paragraph != nil {
		for _, pe := range el.Paragraph.Elements {
			if pe.TextRun != nil {
				sb.WriteString(pe.TextRun.Content)
			}
		}
	}
	if el.Table != nil {
		for _, row := range el.Table.TableRows {
			for _, cell := range row.TableCells {
				for _, cel := range cell.Content {
					writeElement(sb, cel)
				}
				sb.WriteString("\t")
			}
			sb.WriteString("\n")
		}
	}
}

// insertDocText appends text at the end of the document body.
func insertDocText(ctx context.Context, token, docID, text string) error {
	// endOfSegmentLocation inserts at the very end of the body segment.
	req := map[string]any{
		"requests": []map[string]any{
			{
				"insertText": map[string]any{
					"text":                 text,
					"endOfSegmentLocation": map[string]any{},
				},
			},
		},
	}
	body, _ := json.Marshal(req)
	endpoint := docsBase + "/documents/" + url.PathEscape(docID) + ":batchUpdate"
	_, err := googlePOST(ctx, token, endpoint, body)
	return err
}

// clearDocText removes all content from the document body.
// It reads the document first to get the end index, then issues a deleteContentRange.
func clearDocText(ctx context.Context, token, docID string) error {
	resp, err := googleGET(ctx, token, docsBase+"/documents/"+url.PathEscape(docID))
	if err != nil {
		return err
	}

	// Extract the body end index from the raw response.
	var raw struct {
		Body struct {
			Content []struct {
				EndIndex int `json:"endIndex"`
			} `json:"content"`
		} `json:"body"`
	}
	if err := json.Unmarshal(resp, &raw); err != nil {
		return err
	}

	// Find the last element's end index.
	endIndex := 0
	for _, el := range raw.Body.Content {
		if el.EndIndex > endIndex {
			endIndex = el.EndIndex
		}
	}

	// Document must have at least 2 characters for a meaningful range (1-based, last char is newline).
	if endIndex <= 1 {
		return nil // already empty
	}

	req := map[string]any{
		"requests": []map[string]any{
			{
				"deleteContentRange": map[string]any{
					"range": map[string]any{
						"startIndex": 1,
						"endIndex":   endIndex - 1, // keep final newline
					},
				},
			},
		},
	}
	body, _ := json.Marshal(req)
	endpoint := docsBase + "/documents/" + url.PathEscape(docID) + ":batchUpdate"
	_, err = googlePOST(ctx, token, endpoint, body)
	return err
}

// ── Calendar API types ────────────────────────────────────────────────────────

type calendarEvent struct {
	ID          string        `json:"id"`
	Summary     string        `json:"summary"`
	Description string        `json:"description"`
	Start       calendarTime  `json:"start"`
	End         calendarTime  `json:"end"`
	HTMLLink    string        `json:"htmlLink"`
	Attendees   []attendee    `json:"attendees"`
}

type calendarTime struct {
	DateTime string `json:"dateTime"`
	Date     string `json:"date"`
}

type attendee struct {
	Email string `json:"email"`
}

// ── Drive API types ───────────────────────────────────────────────────────────

type driveFile struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	ModifiedTime string `json:"modifiedTime"`
	WebViewLink  string `json:"webViewLink"`
}

// ── Tool helpers ──────────────────────────────────────────────────────────────

func jsonResult(v any) *mcp.CallToolResult {
	b, _ := json.MarshalIndent(v, "", "  ")
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(b)}},
	}
}

func errResult(err error) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}},
	}
}

func stringArg(req *mcp.CallToolRequest, key string) string {
	var m map[string]any
	if len(req.Params.Arguments) > 0 {
		_ = json.Unmarshal(req.Params.Arguments, &m)
	}
	v, _ := m[key].(string)
	return v
}

func intArg(req *mcp.CallToolRequest, key string, def int) int {
	var m map[string]any
	if len(req.Params.Arguments) > 0 {
		_ = json.Unmarshal(req.Params.Arguments, &m)
	}
	if v, ok := m[key].(float64); ok {
		return int(v)
	}
	return def
}

func prop(typ, desc string) map[string]any {
	return map[string]any{"type": typ, "description": desc}
}

func schema(props map[string]any, required ...string) map[string]any {
	s := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func attendeeEmails(attendees []attendee) []string {
	emails := make([]string, 0, len(attendees))
	for _, a := range attendees {
		if a.Email != "" {
			emails = append(emails, a.Email)
		}
	}
	return emails
}
