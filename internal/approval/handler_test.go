package approval_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ro-eng/mcp-proxy/gateway"
	"github.com/ro-eng/mcp-proxy/internal/approval"
)

const testSecret = "test-signing-secret"

// slackSig computes a valid X-Slack-Signature header value for the given timestamp and body.
func slackSig(secret, timestamp string, body []byte) string {
	base := "v0:" + timestamp + ":" + string(body)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(base))
	return "v0=" + hex.EncodeToString(mac.Sum(nil))
}

// nowTimestamp returns the current Unix timestamp as a string.
func nowTimestamp() string {
	return strconv.FormatInt(time.Now().Unix(), 10)
}

// slackPayload encodes an interactive payload the way Slack does (form-encoded).
func slackPayload(actionID, value, userID string) []byte {
	p := map[string]any{
		"type": "block_actions",
		"user": map[string]any{"id": userID, "name": userID},
		"actions": []map[string]any{
			{"action_id": actionID, "value": value},
		},
	}
	raw, _ := json.Marshal(p)
	// Slack form-encodes as: payload=<url-encoded-json>
	return []byte("payload=" + urlEncode(raw))
}

// urlEncode percent-encodes bytes (minimal implementation for tests).
func urlEncode(data []byte) string {
	var buf bytes.Buffer
	for _, b := range data {
		if (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') ||
			b == '-' || b == '_' || b == '.' || b == '~' {
			buf.WriteByte(b)
		} else {
			buf.WriteString(fmt.Sprintf("%%%02X", b))
		}
	}
	return buf.String()
}

// makeRequest builds an HTTP request simulating a Slack interactive callback.
func makeRequest(t *testing.T, body []byte, secret, timestamp string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/approvals/slack/callback", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("X-Slack-Request-Timestamp", timestamp)
	r.Header.Set("X-Slack-Signature", slackSig(secret, timestamp, body))
	return r
}

// makeService returns an approval.Service pre-loaded with a pending request ID.
func makeService(t *testing.T, requestID string) (*approval.Service, func() *gateway.ApprovalDecision) {
	t.Helper()
	svc := approval.NewService(nil)
	decisionCh := make(chan *gateway.ApprovalDecision, 1)

	go func() {
		d, _ := svc.Request(t.Context(), &gateway.ApprovalRequest{
			RequestID:  requestID,
			Spec:       gateway.ApprovalSpec{Timeout: 5 * time.Second},
			CreatedAt:  time.Now(),
		})
		decisionCh <- d
	}()
	time.Sleep(10 * time.Millisecond) // let goroutine register

	return svc, func() *gateway.ApprovalDecision {
		select {
		case d := <-decisionCh:
			return d
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for approval decision")
			return nil
		}
	}
}

// --- ServeHTTP happy paths ---

func TestHandler_ServeHTTP_Approve(t *testing.T) {
	t.Parallel()
	const requestID = "req-approve-1"

	svc, waitDecision := makeService(t, requestID)
	h := approval.NewHandler(svc, testSecret)

	body := slackPayload("approve_"+requestID, requestID, "approver1")
	ts := nowTimestamp()
	req := makeRequest(t, body, testSecret, ts)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	d := waitDecision()
	require.NotNil(t, d)
	assert.Equal(t, gateway.ApprovalApproved, d.Outcome)
	assert.Equal(t, requestID, d.RequestID)
}

func TestHandler_ServeHTTP_Reject(t *testing.T) {
	t.Parallel()
	const requestID = "req-reject-1"

	svc, waitDecision := makeService(t, requestID)
	h := approval.NewHandler(svc, testSecret)

	body := slackPayload("reject_"+requestID, requestID, "approver2")
	ts := nowTimestamp()
	req := makeRequest(t, body, testSecret, ts)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	d := waitDecision()
	require.NotNil(t, d)
	assert.Equal(t, gateway.ApprovalRejected, d.Outcome)
}

// --- signature verification ---

func TestHandler_ServeHTTP_WrongSecret_Returns401(t *testing.T) {
	t.Parallel()
	svc := approval.NewService(nil)
	h := approval.NewHandler(svc, testSecret)

	body := slackPayload("approve_req-1", "req-1", "attacker")
	ts := nowTimestamp()

	// Sign with a different secret.
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set("X-Slack-Request-Timestamp", ts)
	req.Header.Set("X-Slack-Signature", slackSig("wrong-secret", ts, body))

	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestHandler_ServeHTTP_StaleTimestamp_Returns401(t *testing.T) {
	t.Parallel()
	svc := approval.NewService(nil)
	h := approval.NewHandler(svc, testSecret)

	body := slackPayload("approve_req-1", "req-1", "attacker")
	// Timestamp more than 5 minutes in the past.
	staleTS := strconv.FormatInt(time.Now().Add(-6*time.Minute).Unix(), 10)

	req := makeRequest(t, body, testSecret, staleTS)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestHandler_ServeHTTP_MissingTimestamp_Returns401(t *testing.T) {
	t.Parallel()
	svc := approval.NewService(nil)
	h := approval.NewHandler(svc, testSecret)

	body := slackPayload("approve_req-1", "req-1", "u1")
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	// No X-Slack-Request-Timestamp header.
	req.Header.Set("X-Slack-Signature", "v0=anything")

	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// --- method enforcement ---

func TestHandler_ServeHTTP_WrongMethod_Returns405(t *testing.T) {
	t.Parallel()
	svc := approval.NewService(nil)
	h := approval.NewHandler(svc, testSecret)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

// --- unknown request ID ---

func TestHandler_ServeHTTP_UnknownRequestID_Returns200(t *testing.T) {
	t.Parallel()
	// No pending request registered — Decide should fail silently and return 200
	// so Slack stops retrying.
	svc := approval.NewService(nil)
	h := approval.NewHandler(svc, testSecret)

	body := slackPayload("approve_no-such-request", "no-such-request", "u1")
	ts := nowTimestamp()
	req := makeRequest(t, body, testSecret, ts)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// --- invalid payload ---

func TestHandler_ServeHTTP_InvalidPayload_Returns400(t *testing.T) {
	t.Parallel()
	svc := approval.NewService(nil)
	h := approval.NewHandler(svc, testSecret)

	body := []byte("payload=notvalidjson")
	ts := nowTimestamp()
	req := makeRequest(t, body, testSecret, ts)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandler_ServeHTTP_EmptyActions_Returns400(t *testing.T) {
	t.Parallel()
	svc := approval.NewService(nil)
	h := approval.NewHandler(svc, testSecret)

	p := map[string]any{
		"type":    "block_actions",
		"user":    map[string]any{"id": "u1", "name": "u1"},
		"actions": []map[string]any{},
	}
	raw, _ := json.Marshal(p)
	body := []byte("payload=" + urlEncode(raw))
	ts := nowTimestamp()
	req := makeRequest(t, body, testSecret, ts)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandler_ServeHTTP_UnrecognisedActionID_Returns400(t *testing.T) {
	t.Parallel()
	svc := approval.NewService(nil)
	h := approval.NewHandler(svc, testSecret)

	body := slackPayload("unknown_action", "req-1", "u1")
	ts := nowTimestamp()
	req := makeRequest(t, body, testSecret, ts)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- direct JSON payload (no form-encoding) ---

func TestHandler_ServeHTTP_DirectJSONPayload(t *testing.T) {
	t.Parallel()
	const requestID = "req-json-1"

	svc, waitDecision := makeService(t, requestID)
	h := approval.NewHandler(svc, testSecret)

	// Send the JSON payload directly (not form-encoded).
	payload := map[string]any{
		"type": "block_actions",
		"user": map[string]any{"id": "u1", "name": "u1"},
		"actions": []map[string]any{
			{"action_id": "approve_" + requestID, "value": requestID},
		},
	}
	body, _ := json.Marshal(payload)
	ts := nowTimestamp()
	req := makeRequest(t, body, testSecret, ts)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	d := waitDecision()
	require.NotNil(t, d)
	assert.Equal(t, gateway.ApprovalApproved, d.Outcome)
}
