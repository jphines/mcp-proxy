// Package policy implements the CEL-based policy engine for the MCP proxy.
package policy

import "time"

// rawRule is the YAML schema for a single policy rule, before CEL compilation.
type rawRule struct {
	ID         string       `yaml:"id"`
	Priority   int          `yaml:"priority"`
	Condition  string       `yaml:"condition"`
	Action     string       `yaml:"action"`
	Reason     string       `yaml:"reason"`
	AuditLevel string       `yaml:"audit_level"`
	Approval   *rawApproval `yaml:"approval,omitempty"`
}

// rawApproval is the YAML schema for the approval block within a rule.
type rawApproval struct {
	Channel     string `yaml:"channel"`
	Timeout     string `yaml:"timeout"`
	RequireDiff bool   `yaml:"require_diff"`
}

// rawFile is the YAML schema for a single policy YAML file.
type rawFile struct {
	Rules []rawRule `yaml:"rules"`
}

// defaultApprovalTimeout is used when the rule does not specify a timeout.
const defaultApprovalTimeout = 5 * time.Minute
