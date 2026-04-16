package policy

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/google/cel-go/cel"

	"github.com/jphines/mcp-proxy/gateway"
)

// compiledRule is a policy rule whose CEL condition has been compiled to a Program.
type compiledRule struct {
	id         string
	priority   int
	program    cel.Program
	action     gateway.PolicyAction
	reason     string
	auditLevel gateway.AuditLevel
	approval   *gateway.ApprovalSpec
}

// engine implements gateway.PolicyEngine using CEL expressions.
type engine struct {
	mu        sync.RWMutex
	rules     []compiledRule // sorted by priority (ascending)
	celEnv    *cel.Env
	configPath string
	workspace string
	region    string
}

// NewEngine creates a PolicyEngine that loads rules from configPath.
// configPath may be a single YAML file or a directory of YAML files.
// All CEL expressions are compiled at load time; startup fails if any expression
// is invalid. This is a configuration error, not a runtime failure.
func NewEngine(configPath, workspace, region string) (gateway.PolicyEngine, error) {
	celEnv, err := NewCELEnv()
	if err != nil {
		return nil, fmt.Errorf("creating CEL environment: %w", err)
	}

	e := &engine{
		celEnv:    celEnv,
		configPath: configPath,
		workspace: workspace,
		region:    region,
	}

	if err := e.Reload(context.Background()); err != nil {
		return nil, fmt.Errorf("loading policy rules: %w", err)
	}

	return e, nil
}

// Evaluate assesses a tool call against all loaded policy rules.
// Evaluation semantics:
//   - Rules are evaluated in priority order (lowest number first).
//   - ActionDeny and ActionRequireApproval short-circuit immediately.
//   - ActionLog rules compose: all matching log rules are accumulated.
//   - ActionAllow short-circuits (prevents further rule evaluation).
//   - If no rule matches, allow is the default.
//
// Fail-open: CEL evaluation errors skip the rule and continue.
func (e *engine) Evaluate(ctx context.Context, identity *gateway.Identity, call *gateway.ToolCall) (*gateway.PolicyDecision, error) {
	e.mu.RLock()
	rules := e.rules
	e.mu.RUnlock()

	activation, err := buildCELActivation(e.celEnv, identity, call, e.workspace, e.region)
	if err != nil {
		// Fail open: if we can't build the activation, allow through with warning.
		slog.WarnContext(ctx, "policy activation build failed; allowing through (fail-open)",
			slog.Any("error", err),
			slog.String("tool", call.ServerID+"::"+call.ToolName),
		)
		return &gateway.PolicyDecision{
			Action:     gateway.ActionAllow,
			Reason:     "fail-open: activation build error",
			AuditLevel: gateway.AuditFull,
		}, err
	}

	var loggedRules []string
	var evalErr error

	for _, rule := range rules {
		out, _, err := rule.program.ContextEval(ctx, activation)
		if err != nil {
			// Fail open: skip this rule and continue.
			slog.WarnContext(ctx, "policy rule evaluation error; skipping rule (fail-open)",
				slog.String("rule", rule.id),
				slog.Any("error", err),
			)
			evalErr = err
			continue
		}

		matched, ok := out.Value().(bool)
		if !ok || !matched {
			continue
		}

		switch rule.action {
		case gateway.ActionDeny:
			return &gateway.PolicyDecision{
				Action:          gateway.ActionDeny,
				Reason:          rule.reason,
				Rule:            rule.id,
				AuditLevel:      rule.auditLevel,
				MatchedLogRules: loggedRules,
			}, evalErr

		case gateway.ActionRequireApproval:
			return &gateway.PolicyDecision{
				Action:          gateway.ActionRequireApproval,
				Reason:          rule.reason,
				Rule:            rule.id,
				AuditLevel:      rule.auditLevel,
				ApprovalSpec:    rule.approval,
				MatchedLogRules: loggedRules,
			}, evalErr

		case gateway.ActionLog:
			// Log rules compose; continue evaluating.
			loggedRules = append(loggedRules, rule.id)

		case gateway.ActionAllow:
			return &gateway.PolicyDecision{
				Action:          gateway.ActionAllow,
				Reason:          rule.reason,
				Rule:            rule.id,
				AuditLevel:      rule.auditLevel,
				MatchedLogRules: loggedRules,
			}, evalErr
		}
	}

	// No rule matched; default allow.
	return &gateway.PolicyDecision{
		Action:          gateway.ActionAllow,
		Reason:          "no matching rule; default allow",
		AuditLevel:      gateway.AuditStandard,
		MatchedLogRules: loggedRules,
	}, evalErr
}

// Reload re-reads and recompiles the policy configuration.
// On success, the new rule set is atomically swapped in.
// On failure, the existing compiled rule set is retained unchanged.
func (e *engine) Reload(ctx context.Context) error {
	rawRules, err := loadRulesFromPath(e.configPath)
	if err != nil {
		return fmt.Errorf("loading rules: %w", err)
	}

	compiled, err := compileRules(e.celEnv, rawRules)
	if err != nil {
		return err
	}

	// Sort by priority (lower number = evaluated first).
	sort.Slice(compiled, func(i, j int) bool {
		return compiled[i].priority < compiled[j].priority
	})

	e.mu.Lock()
	e.rules = compiled
	e.mu.Unlock()

	slog.InfoContext(ctx, "policy rules loaded", slog.Int("count", len(compiled)))
	return nil
}

// compileRules compiles all raw rules into CEL programs.
// Returns an error if any rule's CEL expression fails to compile or type-check.
func compileRules(env *cel.Env, rawRules []rawRule) ([]compiledRule, error) {
	compiled := make([]compiledRule, 0, len(rawRules))

	for _, r := range rawRules {
		ast, issues := env.Compile(r.Condition)
		if issues != nil && issues.Err() != nil {
			return nil, fmt.Errorf("rule %q: CEL compile error: %w", r.ID, issues.Err())
		}

		// Type-check: condition must return bool.
		if ast.OutputType() != cel.BoolType {
			return nil, fmt.Errorf("rule %q: condition must return bool, got %s", r.ID, ast.OutputType())
		}

		prog, err := env.Program(ast)
		if err != nil {
			return nil, fmt.Errorf("rule %q: CEL program error: %w", r.ID, err)
		}

		cr := compiledRule{
			id:         r.ID,
			priority:   r.Priority,
			program:    prog,
			action:     gateway.PolicyAction(r.Action),
			reason:     r.Reason,
			auditLevel: auditLevelOrDefault(r.AuditLevel),
		}

		if r.Approval != nil {
			cr.approval = &gateway.ApprovalSpec{
				Channel:     r.Approval.Channel,
				Timeout:     parseApprovalTimeout(r.Approval.Timeout),
				RequireDiff: r.Approval.RequireDiff,
			}
		}

		compiled = append(compiled, cr)
	}

	return compiled, nil
}

// buildCELActivation constructs a cel.Activation from the request context.
func buildCELActivation(env *cel.Env, identity *gateway.Identity, call *gateway.ToolCall, workspace, region string) (map[string]any, error) {
	return buildActivation(identity, call, workspace, region), nil
}

func auditLevelOrDefault(s string) gateway.AuditLevel {
	switch gateway.AuditLevel(s) {
	case gateway.AuditMinimal, gateway.AuditStandard, gateway.AuditFull:
		return gateway.AuditLevel(s)
	}
	return gateway.AuditStandard
}

func parseApprovalTimeout(s string) time.Duration {
	if s == "" {
		return defaultApprovalTimeout
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return defaultApprovalTimeout
	}
	return d
}

var _ gateway.PolicyEngine = (*engine)(nil)
