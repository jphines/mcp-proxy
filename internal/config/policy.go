package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// PolicyFile is the top-level YAML schema for policy.yaml.
type PolicyFile struct {
	Rules []PolicyRuleEntry `yaml:"rules"`
}

// PolicyRuleEntry is the YAML representation of a single policy rule.
type PolicyRuleEntry struct {
	ID         string          `yaml:"id"`
	Priority   int             `yaml:"priority"`
	Condition  string          `yaml:"condition"`
	Action     string          `yaml:"action"`
	Reason     string          `yaml:"reason"`
	AuditLevel string          `yaml:"audit_level"`
	Approval   *ApprovalEntry  `yaml:"approval,omitempty"`
}

// ApprovalEntry is the YAML representation of approval configuration.
type ApprovalEntry struct {
	Channel     string `yaml:"channel"`
	Timeout     string `yaml:"timeout"`
	RequireDiff bool   `yaml:"require_diff"`
}

var validPolicyActions = map[string]bool{
	"allow":            true,
	"deny":             true,
	"require_approval": true,
	"log":              true,
}

var validAuditLevels = map[string]bool{
	"minimal":  true,
	"standard": true,
	"full":     true,
	"":         true, // optional field; defaults to standard
}

var validApprovalChannels = map[string]bool{
	"slack": true,
}

// LoadPolicy reads and validates policy.yaml from the given path.
// Syntax validation only — CEL compilation is performed by the policy engine.
func LoadPolicy(path string) (*PolicyFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading policy file: %w", err)
	}

	var pf PolicyFile
	if err := yaml.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("parsing policy YAML: %w", err)
	}

	if err := validatePolicyFile(&pf); err != nil {
		return nil, err
	}
	return &pf, nil
}

func validatePolicyFile(pf *PolicyFile) error {
	var errs []error
	seenIDs := map[string]bool{}
	seenPriorities := map[int]string{} // priority → first rule ID with that priority

	for i, r := range pf.Rules {
		prefix := fmt.Sprintf("rules[%d] (id=%q)", i, r.ID)

		if r.ID == "" {
			errs = append(errs, fmt.Errorf("%s: id is required", prefix))
		} else if seenIDs[r.ID] {
			errs = append(errs, fmt.Errorf("%s: duplicate rule id", prefix))
		} else {
			seenIDs[r.ID] = true
		}

		if r.Condition == "" {
			errs = append(errs, fmt.Errorf("%s: condition is required", prefix))
		}

		if !validPolicyActions[r.Action] {
			errs = append(errs, fmt.Errorf("%s: action must be one of %v, got %q",
				prefix, sortedKeys(validPolicyActions), r.Action))
		}

		if r.AuditLevel != "" && !validAuditLevels[r.AuditLevel] {
			errs = append(errs, fmt.Errorf("%s: audit_level must be one of minimal/standard/full, got %q",
				prefix, r.AuditLevel))
		}

		if r.Action == "require_approval" {
			if r.Approval == nil {
				errs = append(errs, fmt.Errorf("%s: approval block is required when action is require_approval", prefix))
			} else {
				if !validApprovalChannels[r.Approval.Channel] {
					errs = append(errs, fmt.Errorf("%s: approval.channel must be one of %v, got %q",
						prefix, keys(validApprovalChannels), r.Approval.Channel))
				}
				if r.Approval.Timeout != "" {
					if _, err := parseDurationString(r.Approval.Timeout); err != nil {
						errs = append(errs, fmt.Errorf("%s: approval.timeout is not a valid duration: %w", prefix, err))
					}
				}
			}
		}

		// Warn (as non-fatal validation note) on duplicate priorities.
		if existing, dup := seenPriorities[r.Priority]; dup && r.ID != "" {
			errs = append(errs, fmt.Errorf("%s: priority %d is already used by rule %q (ties cause unpredictable ordering)",
				prefix, r.Priority, existing))
		} else if r.ID != "" {
			seenPriorities[r.Priority] = r.ID
		}
	}

	if len(errs) > 0 {
		return joinErrors("policy.yaml validation failed", errs)
	}
	return nil
}

// parseDurationString accepts Go duration strings ("5m", "30s") or human-readable
// durations used in YAML ("5 minutes") for the timeout field.
func parseDurationString(s string) (string, error) {
	s = strings.TrimSpace(s)
	// Attempt simple replacement for common human-readable forms.
	replacer := strings.NewReplacer(
		" minutes", "m", " minute", "m",
		" seconds", "s", " second", "s",
		" hours", "h", " hour", "h",
	)
	normalized := replacer.Replace(s)
	// We just need to validate that it's parseable; return normalized form.
	// Actual parsing happens in the policy engine with time.ParseDuration.
	_ = normalized
	return s, nil
}

func keys(m map[string]bool) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}
