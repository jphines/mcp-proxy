package auth

import (
	"github.com/ro-eng/mcp-proxy/gateway"
)

const (
	// claimGroups is the Okta custom claim for group membership.
	claimGroups = "groups"
	// claimScopeSpaceSep is the standard OAuth "scope" claim (space-separated scopes).
	claimScope = "scp"
	// claimSessionID is the Okta session identifier.
	claimSessionID = "sid"
	// claimDelegatedBy identifies the delegating principal for agent tokens.
	claimDelegatedBy = "delegated_by"
	// claimIdentityType is a custom Okta claim that declares the caller type.
	// Falls back to amr-based detection when not present.
	claimIdentityType = "x-identity-type"
)

// extractGroups reads group membership from the "groups" claim.
func extractGroups(claims map[string]any) []string {
	raw, ok := claims[claimGroups]
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case []any:
		groups := make([]string, 0, len(v))
		for _, g := range v {
			if s, ok := g.(string); ok {
				groups = append(groups, s)
			}
		}
		return groups
	case []string:
		return v
	}
	return nil
}

// extractScopes reads the "scp" claim (may be a space-separated string or []any).
func extractScopes(claims map[string]any) []string {
	raw, ok := claims[claimScope]
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case string:
		if v == "" {
			return nil
		}
		return splitSpaces(v)
	case []any:
		scopes := make([]string, 0, len(v))
		for _, s := range v {
			if str, ok := s.(string); ok {
				scopes = append(scopes, str)
			}
		}
		return scopes
	case []string:
		return v
	}
	return nil
}

// detectIdentityType determines the caller type from claims.
// Priority: explicit x-identity-type claim → amr heuristics → default human.
func detectIdentityType(claims map[string]any) gateway.IdentityType {
	if v, ok := claims[claimIdentityType].(string); ok {
		switch gateway.IdentityType(v) {
		case gateway.IdentityHuman, gateway.IdentityAgent, gateway.IdentityService:
			return gateway.IdentityType(v)
		}
	}

	// Heuristic: service accounts and workload identities carry specific amr values.
	if amr, ok := claims["amr"].([]any); ok {
		for _, a := range amr {
			switch a.(string) {
			case "swk", "hwk": // software/hardware key — workload identity
				return gateway.IdentityService
			}
		}
	}

	return gateway.IdentityHuman
}

func splitSpaces(s string) []string {
	var out []string
	start := -1
	for i, ch := range s {
		if ch == ' ' || ch == '\t' {
			if start >= 0 {
				out = append(out, s[start:i])
				start = -1
			}
		} else if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		out = append(out, s[start:])
	}
	return out
}
