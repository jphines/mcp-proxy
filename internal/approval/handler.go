package approval

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jphines/mcp-proxy/gateway"
)

// Handler handles POST /approvals/slack/callback from Slack's interactive components.
// It verifies the Slack signing secret, extracts the decision, and delivers it to Service.
type Handler struct {
	service       gateway.ApprovalService
	signingSecret string
}

// NewHandler creates a Handler.
func NewHandler(service gateway.ApprovalService, signingSecret string) *Handler {
	return &Handler{service: service, signingSecret: signingSecret}
}

// ServeHTTP handles the Slack callback payload.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1 MiB max
	if err != nil {
		http.Error(w, "reading body", http.StatusBadRequest)
		return
	}

	if err := h.verifySlackSignature(r, body); err != nil {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	payload, err := extractSlackPayload(body)
	if err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	decision, err := h.parseDecision(payload)
	if err != nil {
		http.Error(w, "parsing decision", http.StatusBadRequest)
		return
	}

	if err := h.service.Decide(r.Context(), decision); err != nil {
		// If the request is unknown (expired or already decided), return 200
		// to prevent Slack from retrying endlessly.
		_ = err
	}

	w.WriteHeader(http.StatusOK)
}

// verifySlackSignature validates the X-Slack-Signature header.
// See: https://api.slack.com/authentication/verifying-requests-from-slack
func (h *Handler) verifySlackSignature(r *http.Request, body []byte) error {
	timestamp := r.Header.Get("X-Slack-Request-Timestamp")
	if timestamp == "" {
		return fmt.Errorf("missing X-Slack-Request-Timestamp")
	}

	// Reject requests older than 5 minutes to prevent replay attacks.
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || time.Since(time.Unix(ts, 0)) > 5*time.Minute {
		return fmt.Errorf("stale or invalid timestamp")
	}

	baseStr := "v0:" + timestamp + ":" + string(body)
	mac := hmac.New(sha256.New, []byte(h.signingSecret))
	mac.Write([]byte(baseStr))
	expected := "v0=" + hex.EncodeToString(mac.Sum(nil))

	provided := r.Header.Get("X-Slack-Signature")
	if !hmac.Equal([]byte(expected), []byte(provided)) {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}

// slackInteractivePayload is the outer wrapper Slack sends for interactive components.
type slackInteractivePayload struct {
	Type    string `json:"type"`
	User    struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"user"`
	Actions []struct {
		ActionID string `json:"action_id"`
		Value    string `json:"value"`
	} `json:"actions"`
}

// extractSlackPayload URL-decodes and unmarshals the Slack form-encoded payload.
func extractSlackPayload(body []byte) (*slackInteractivePayload, error) {
	// Slack sends: payload=<url-encoded-json>
	raw := string(body)
	const prefix = "payload="
	if !strings.HasPrefix(raw, prefix) {
		// Try parsing directly as JSON.
		var p slackInteractivePayload
		if err := json.Unmarshal(body, &p); err != nil {
			return nil, fmt.Errorf("parsing payload: %w", err)
		}
		return &p, nil
	}

	jsonStr, err := urlDecode(raw[len(prefix):])
	if err != nil {
		return nil, fmt.Errorf("url-decoding payload: %w", err)
	}

	var p slackInteractivePayload
	if err := json.Unmarshal([]byte(jsonStr), &p); err != nil {
		return nil, fmt.Errorf("unmarshalling payload: %w", err)
	}
	return &p, nil
}

// parseDecision converts a Slack payload into an ApprovalDecision.
func (h *Handler) parseDecision(p *slackInteractivePayload) (*gateway.ApprovalDecision, error) {
	if len(p.Actions) == 0 {
		return nil, fmt.Errorf("no actions in Slack payload")
	}

	action := p.Actions[0]
	requestID := action.Value

	var outcome gateway.ApprovalOutcome
	if strings.HasPrefix(action.ActionID, "approve_") {
		outcome = gateway.ApprovalApproved
	} else if strings.HasPrefix(action.ActionID, "reject_") {
		outcome = gateway.ApprovalRejected
	} else {
		return nil, fmt.Errorf("unrecognised action_id: %q", action.ActionID)
	}

	return &gateway.ApprovalDecision{
		RequestID:       requestID,
		Outcome:         outcome,
		ApproverSubject: p.User.Name,
		DecidedAt:       time.Now().UTC(),
	}, nil
}

// urlDecode is a simple percent-decoder (subset of url.QueryUnescape).
func urlDecode(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '%' && i+2 < len(s) {
			h, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
			if err != nil {
				return "", fmt.Errorf("invalid percent-encoding at %d", i)
			}
			b.WriteByte(byte(h))
			i += 3
		} else if s[i] == '+' {
			b.WriteByte(' ')
			i++
		} else {
			b.WriteByte(s[i])
			i++
		}
	}
	return b.String(), nil
}

// contextKey is an unexported type for context keys to avoid collisions.
type contextKey int

const _ contextKey = iota

// contextBackground returns context.Background(); exposed to avoid the import in handler.
func contextBackground() context.Context {
	return context.Background()
}

var _ = contextBackground // suppress unused warning
