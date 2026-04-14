package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/ro-eng/mcp-proxy/gateway"
)

// auditMiddleware is the OUTERMOST middleware. It defers audit emission so that
// every call — including denied ones — is always recorded.
func (p *Proxy) auditMiddleware(ctx context.Context, tc *gateway.ToolCallContext, next gateway.MiddlewareFunc) {
	start := time.Now()

	defer func() {
		tc.LatencyMs = time.Since(start).Milliseconds()

		event := buildAuditEvent(tc)
		_ = p.deps.AuditLogger.Emit(ctx, event)
	}()

	next(ctx, tc)
}

func buildAuditEvent(tc *gateway.ToolCallContext) *gateway.AuditEvent {
	event := &gateway.AuditEvent{
		EventID:   tc.RequestID,
		Timestamp: time.Now().UTC(),
		RequestID: tc.RequestID,
		LatencyMs: tc.LatencyMs,
		DownstreamMs: tc.DownstreamMs,
		RedactionsApplied: tc.RedactionsApplied,
		DownstreamStatus:  tc.StatusCode,
	}

	if tc.Identity != nil {
		event.CallerSubject = tc.Identity.Subject
		event.CallerType = tc.Identity.Type
		event.CallerGroups = tc.Identity.Groups
		event.CallerSessionID = tc.Identity.SessionID
	}

	if tc.ServerID != "" || tc.ToolName != "" {
		event.ToolNamespaced = tc.ServerID + "::" + tc.ToolName
	} else if tc.RawRequest != nil {
		event.ToolNamespaced = tc.RawRequest.Name
	}

	event.ArgumentsHash = argumentsHash(tc)

	if tc.Decision != nil {
		event.Decision = tc.Decision.Action
		event.PolicyRule = tc.Decision.Rule
		event.PolicyReason = tc.Decision.Reason
	} else if tc.Err != nil {
		event.Decision = gateway.ActionDeny
	} else {
		event.Decision = gateway.ActionAllow
	}

	if tc.ServerConfig != nil {
		event.CredentialRef = tc.ServerConfig.CredentialRef
	}

	if tc.PolicyEvalErr != nil {
		event.PolicyEvalError = tc.PolicyEvalErr.Error()
	}
	if tc.Err != nil && event.PolicyEvalError == "" {
		// record the terminal error for context
		_ = tc.Err
	}

	return event
}

// argumentsHash computes the SHA-256 hex digest of tc.Arguments.
// Returns empty string if arguments are nil.
func argumentsHash(tc *gateway.ToolCallContext) string {
	if len(tc.Arguments) == 0 {
		if tc.RawRequest == nil || len(tc.RawRequest.Arguments) == 0 {
			return ""
		}
		// Hash the raw JSON bytes.
		sum := sha256.Sum256([]byte(tc.RawRequest.Arguments))
		return hex.EncodeToString(sum[:])
	}
	data, _ := json.Marshal(tc.Arguments)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
