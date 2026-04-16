package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jphines/mcp-proxy/gateway"
)

// --- extractGroups ---

func TestExtractGroups_AnySlice(t *testing.T) {
	t.Parallel()
	claims := map[string]any{
		"groups": []any{"engineering", "platform-engineering"},
	}
	got := extractGroups(claims, "groups")
	assert.Equal(t, []string{"engineering", "platform-engineering"}, got)
}

func TestExtractGroups_StringSlice(t *testing.T) {
	t.Parallel()
	claims := map[string]any{
		"groups": []string{"admin"},
	}
	got := extractGroups(claims, "groups")
	assert.Equal(t, []string{"admin"}, got)
}

func TestExtractGroups_MissingClaim(t *testing.T) {
	t.Parallel()
	claims := map[string]any{}
	got := extractGroups(claims, "groups")
	assert.Nil(t, got)
}

func TestExtractGroups_NamespacedClaim(t *testing.T) {
	t.Parallel()
	claims := map[string]any{
		"https://mcp-proxy/groups": []any{"data-science"},
	}
	got := extractGroups(claims, "https://mcp-proxy/groups")
	assert.Equal(t, []string{"data-science"}, got)
}

func TestExtractGroups_NonStringElementsSkipped(t *testing.T) {
	t.Parallel()
	claims := map[string]any{
		"groups": []any{"valid", 42, true, "also-valid"},
	}
	got := extractGroups(claims, "groups")
	assert.Equal(t, []string{"valid", "also-valid"}, got)
}

func TestExtractGroups_WrongType(t *testing.T) {
	t.Parallel()
	claims := map[string]any{
		"groups": "not-a-slice",
	}
	got := extractGroups(claims, "groups")
	assert.Nil(t, got)
}

func TestExtractGroups_EmptySlice(t *testing.T) {
	t.Parallel()
	claims := map[string]any{
		"groups": []any{},
	}
	got := extractGroups(claims, "groups")
	assert.Empty(t, got)
}

// --- extractScopes ---

func TestExtractScopes_SpaceSeparatedString(t *testing.T) {
	t.Parallel()
	claims := map[string]any{
		"scp": "mcp:read mcp:write openid",
	}
	got := extractScopes(claims)
	assert.Equal(t, []string{"mcp:read", "mcp:write", "openid"}, got)
}

func TestExtractScopes_AnySlice(t *testing.T) {
	t.Parallel()
	claims := map[string]any{
		"scp": []any{"read", "write"},
	}
	got := extractScopes(claims)
	assert.Equal(t, []string{"read", "write"}, got)
}

func TestExtractScopes_StringSlice(t *testing.T) {
	t.Parallel()
	claims := map[string]any{
		"scp": []string{"profile", "email"},
	}
	got := extractScopes(claims)
	assert.Equal(t, []string{"profile", "email"}, got)
}

func TestExtractScopes_MissingClaim(t *testing.T) {
	t.Parallel()
	got := extractScopes(map[string]any{})
	assert.Nil(t, got)
}

func TestExtractScopes_EmptyString(t *testing.T) {
	t.Parallel()
	claims := map[string]any{"scp": ""}
	got := extractScopes(claims)
	assert.Nil(t, got)
}

func TestExtractScopes_NonStringElementsSkipped(t *testing.T) {
	t.Parallel()
	claims := map[string]any{
		"scp": []any{"valid", 99, "also-valid"},
	}
	got := extractScopes(claims)
	assert.Equal(t, []string{"valid", "also-valid"}, got)
}

// --- detectIdentityType ---

func TestDetectIdentityType_ExplicitHuman(t *testing.T) {
	t.Parallel()
	claims := map[string]any{"x-identity-type": "human"}
	assert.Equal(t, gateway.IdentityHuman, detectIdentityType(claims))
}

func TestDetectIdentityType_ExplicitAgent(t *testing.T) {
	t.Parallel()
	claims := map[string]any{"x-identity-type": "agent"}
	assert.Equal(t, gateway.IdentityAgent, detectIdentityType(claims))
}

func TestDetectIdentityType_ExplicitService(t *testing.T) {
	t.Parallel()
	claims := map[string]any{"x-identity-type": "service"}
	assert.Equal(t, gateway.IdentityService, detectIdentityType(claims))
}

func TestDetectIdentityType_InvalidExplicitFallsThrough(t *testing.T) {
	t.Parallel()
	claims := map[string]any{"x-identity-type": "robot"}
	assert.Equal(t, gateway.IdentityHuman, detectIdentityType(claims))
}

func TestDetectIdentityType_AMR_SoftwareKey(t *testing.T) {
	t.Parallel()
	claims := map[string]any{"amr": []any{"swk"}}
	assert.Equal(t, gateway.IdentityService, detectIdentityType(claims))
}

func TestDetectIdentityType_AMR_HardwareKey(t *testing.T) {
	t.Parallel()
	claims := map[string]any{"amr": []any{"hwk"}}
	assert.Equal(t, gateway.IdentityService, detectIdentityType(claims))
}

func TestDetectIdentityType_AMR_PasswordIsHuman(t *testing.T) {
	t.Parallel()
	claims := map[string]any{"amr": []any{"pwd", "mfa"}}
	assert.Equal(t, gateway.IdentityHuman, detectIdentityType(claims))
}

func TestDetectIdentityType_DefaultHuman(t *testing.T) {
	t.Parallel()
	claims := map[string]any{}
	assert.Equal(t, gateway.IdentityHuman, detectIdentityType(claims))
}

func TestDetectIdentityType_ExplicitTakesPrecedenceOverAMR(t *testing.T) {
	t.Parallel()
	claims := map[string]any{
		"x-identity-type": "agent",
		"amr":             []any{"swk"}, // would be service without explicit claim
	}
	assert.Equal(t, gateway.IdentityAgent, detectIdentityType(claims))
}

// --- splitSpaces ---

func TestSplitSpaces_Basic(t *testing.T) {
	t.Parallel()
	assert.Equal(t, []string{"a", "b", "c"}, splitSpaces("a b c"))
}

func TestSplitSpaces_Tabs(t *testing.T) {
	t.Parallel()
	assert.Equal(t, []string{"a", "b"}, splitSpaces("a\tb"))
}

func TestSplitSpaces_MultipleSpaces(t *testing.T) {
	t.Parallel()
	assert.Equal(t, []string{"a", "b"}, splitSpaces("a   b"))
}

func TestSplitSpaces_LeadingTrailing(t *testing.T) {
	t.Parallel()
	assert.Equal(t, []string{"a"}, splitSpaces("  a  "))
}

func TestSplitSpaces_Empty(t *testing.T) {
	t.Parallel()
	assert.Nil(t, splitSpaces(""))
}

func TestSplitSpaces_OnlySpaces(t *testing.T) {
	t.Parallel()
	assert.Nil(t, splitSpaces("   "))
}

func TestSplitSpaces_SingleWord(t *testing.T) {
	t.Parallel()
	assert.Equal(t, []string{"hello"}, splitSpaces("hello"))
}
