package policy

import (
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

// NewCELEnv builds the CEL environment used for policy rule evaluation.
// All variables available in CEL expressions are declared here.
//
// Available variables:
//
//	identity.sub        string  — Okta subject
//	identity.type       string  — "human", "agent", "service"
//	identity.groups     list    — group memberships
//	identity.scopes     list    — authorized OAuth scopes
//	identity.delegated_by string — delegating principal (empty if none)
//	identity.session_id string  — session context
//	tool.server         string  — downstream server ID
//	tool.name           string  — bare tool name
//	tool.tier           int     — severity tier (1-5)
//	tool.args           map     — tool call arguments
//	tool.tags           map     — tool metadata tags
//	env.workspace       string  — deployment workspace
//	env.region          string  — AWS region
//
// Custom functions:
//
//	matchesGlob(value, pattern string) bool — glob matching on strings
func NewCELEnv() (*cel.Env, error) {
	return cel.NewEnv(
		// identity.*
		cel.Variable("identity", cel.MapType(cel.StringType, cel.DynType)),

		// tool.*
		cel.Variable("tool", cel.MapType(cel.StringType, cel.DynType)),

		// env.*
		cel.Variable("env", cel.MapType(cel.StringType, cel.DynType)),

		// matchesGlob(value, pattern) bool
		cel.Function("matchesGlob",
			cel.Overload("matchesGlob_string_string",
				[]*cel.Type{cel.StringType, cel.StringType},
				cel.BoolType,
				cel.BinaryBinding(func(lhs, rhs ref.Val) ref.Val {
					value, ok1 := lhs.(types.String)
					pattern, ok2 := rhs.(types.String)
					if !ok1 || !ok2 {
						return types.Bool(false)
					}
					matched, err := globMatch(string(pattern), string(value))
					if err != nil {
						return types.Bool(false)
					}
					return types.Bool(matched)
				}),
			),
		),
	)
}

// globMatch performs simple glob pattern matching.
// Supported wildcards: * (any sequence), ? (single character).
func globMatch(pattern, value string) (bool, error) {
	return matchGlob(pattern, value), nil
}

// matchGlob implements non-recursive glob matching.
func matchGlob(pattern, str string) bool {
	pi, si := 0, 0
	// starIdx tracks the position after the last '*' in pattern.
	// matchIdx tracks where in str the star last matched.
	starIdx, matchIdx := -1, 0

	for si < len(str) {
		if pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == str[si]) {
			pi++
			si++
		} else if pi < len(pattern) && pattern[pi] == '*' {
			starIdx = pi
			matchIdx = si
			pi++
		} else if starIdx != -1 {
			pi = starIdx + 1
			matchIdx++
			si = matchIdx
		} else {
			return false
		}
	}

	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}
