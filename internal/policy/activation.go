package policy

import (
	"github.com/ro-eng/mcp-proxy/gateway"
)

// buildActivation constructs the map of CEL variable bindings from an Identity,
// ToolCall, workspace, and region. The maps mirror the declared CEL variable
// structure (identity.*, tool.*, env.*).
func buildActivation(identity *gateway.Identity, call *gateway.ToolCall, workspace, region string) map[string]any {
	identityMap := map[string]any{
		"sub":          safeString(identity.Subject),
		"type":         string(identity.Type),
		"groups":       stringSliceToAny(identity.Groups),
		"scopes":       stringSliceToAny(identity.Scopes),
		"delegated_by": safeString(identity.DelegatedBy),
		"session_id":   safeString(identity.SessionID),
	}
	// Flatten raw Okta claims into identity["claims"] for advanced policy rules.
	if len(identity.Claims) > 0 {
		identityMap["claims"] = identity.Claims
	} else {
		identityMap["claims"] = map[string]any{}
	}

	toolMap := map[string]any{
		"server": safeString(call.ServerID),
		"name":   safeString(call.ToolName),
		"tier":   int64(call.Tier),
	}
	if call.Arguments != nil {
		toolMap["args"] = call.Arguments
	} else {
		toolMap["args"] = map[string]any{}
	}
	if call.Tags != nil {
		toolMap["tags"] = stringMapToAny(call.Tags)
	} else {
		toolMap["tags"] = map[string]any{}
	}

	envMap := map[string]any{
		"workspace": workspace,
		"region":    region,
	}

	return map[string]any{
		"identity": identityMap,
		"tool":     toolMap,
		"env":      envMap,
	}
}

func safeString(s string) string { return s }

func stringSliceToAny(ss []string) []any {
	if ss == nil {
		return []any{}
	}
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

func stringMapToAny(m map[string]string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
