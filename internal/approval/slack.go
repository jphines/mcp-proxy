package approval

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/jphines/mcp-proxy/gateway"
)

// SlackSender sends approval request notifications to a Slack channel
// using the Incoming Webhooks API (Block Kit message format).
type SlackSender struct {
	webhookURL string
	client     *http.Client
}

// NewSlackSender creates a SlackSender that posts to webhookURL.
func NewSlackSender(webhookURL string) *SlackSender {
	return &SlackSender{
		webhookURL: webhookURL,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// slackMessage is the JSON payload sent to the Slack Incoming Webhook.
type slackMessage struct {
	Text   string       `json:"text,omitempty"`
	Blocks []slackBlock `json:"blocks,omitempty"`
}

type slackBlock struct {
	Type string      `json:"type"`
	Text *slackText  `json:"text,omitempty"`
	Elements []slackElement `json:"elements,omitempty"`
}

type slackText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type slackElement struct {
	Type     string    `json:"type"`
	Text     *slackText `json:"text,omitempty"`
	ActionID string    `json:"action_id,omitempty"`
	Value    string    `json:"value,omitempty"`
	Style    string    `json:"style,omitempty"`
}

// Send posts a Block Kit approval notification to Slack.
func (s *SlackSender) Send(ctx context.Context, req *gateway.ApprovalRequest) error {
	callerInfo := fmt.Sprintf("*%s* (%s)", req.CallerSubject, req.CallerType)

	msg := slackMessage{
		Text: fmt.Sprintf("Approval required: %s", req.ToolNamespaced),
		Blocks: []slackBlock{
			{
				Type: "section",
				Text: &slackText{
					Type: "mrkdwn",
					Text: fmt.Sprintf("*MCP Proxy — Approval Required* :warning:\n"+
						"*Tool:* `%s`\n"+
						"*Caller:* %s\n"+
						"*Policy rule:* `%s`\n"+
						"*Reason:* %s\n"+
						"*Arguments:* %s",
						req.ToolNamespaced,
						callerInfo,
						req.PolicyRule,
						req.PolicyReason,
						req.ArgumentsSummary,
					),
				},
			},
			{
				Type: "actions",
				Elements: []slackElement{
					{
						Type:     "button",
						ActionID: "approve_" + req.RequestID,
						Value:    req.RequestID,
						Style:    "primary",
						Text:     &slackText{Type: "plain_text", Text: "Approve"},
					},
					{
						Type:     "button",
						ActionID: "reject_" + req.RequestID,
						Value:    req.RequestID,
						Style:    "danger",
						Text:     &slackText{Type: "plain_text", Text: "Reject"},
					},
				},
			},
		},
	}

	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("approval: marshalling Slack message: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("approval: creating Slack request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("approval: sending Slack notification: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("approval: Slack returned status %d", resp.StatusCode)
	}
	return nil
}
