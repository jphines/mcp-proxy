package policy_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/jphines/mcp-proxy/gateway"
	"github.com/jphines/mcp-proxy/internal/policy"
)

const (
	testWorkspace = "production"
	testRegion    = "us-east-1"
)

// mustLoadEngine is a test helper that loads the given policy file and fails the test on error.
func mustLoadEngine(t *testing.T, policyPath string) gateway.PolicyEngine {
	t.Helper()
	e, err := policy.NewEngine(policyPath, testWorkspace, testRegion)
	require.NoError(t, err)
	return e
}

// --- Unit tests for policy engine ---

func TestEvaluate_DefaultAllow(t *testing.T) {
	t.Parallel()
	e := mustLoadEngine(t, "../../testdata/policy/base.yaml")

	dec, err := e.Evaluate(context.Background(),
		&gateway.Identity{Subject: "user@ro.com", Type: gateway.IdentityHuman, Groups: []string{"engineering"}},
		&gateway.ToolCall{ServerID: "github", ToolName: "list_repos", Tier: 1},
	)
	require.NoError(t, err)
	assert.Equal(t, gateway.ActionAllow, dec.Action)
}

func TestEvaluate_DenyProductionDelete(t *testing.T) {
	t.Parallel()
	// Production engine with workspace=production.
	e, err := policy.NewEngine("../../testdata/policy/base.yaml", "production", testRegion)
	require.NoError(t, err)

	dec, err := e.Evaluate(context.Background(),
		&gateway.Identity{Subject: "admin@ro.com", Type: gateway.IdentityHuman, Groups: []string{"clinical-engineering"}},
		&gateway.ToolCall{ServerID: "clinical", ToolName: "delete_patient_record", Tier: 4},
	)
	require.NoError(t, err)
	assert.Equal(t, gateway.ActionDeny, dec.Action)
	assert.Equal(t, "red-line-delete-production-clinical", dec.Rule)
}

func TestEvaluate_DenyAgentClinicalWrite(t *testing.T) {
	t.Parallel()
	e := mustLoadEngine(t, "../../testdata/policy/base.yaml")

	dec, err := e.Evaluate(context.Background(),
		&gateway.Identity{Subject: "agent-rx", Type: gateway.IdentityAgent, Groups: []string{"clinical-engineering"}},
		&gateway.ToolCall{ServerID: "clinical", ToolName: "update_prescription", Tier: 3},
	)
	require.NoError(t, err)
	assert.Equal(t, gateway.ActionDeny, dec.Action)
	assert.Equal(t, "deny-agents-clinical-write", dec.Rule)
}

func TestEvaluate_RestrictClinicalToTeam(t *testing.T) {
	t.Parallel()
	e := mustLoadEngine(t, "../../testdata/policy/base.yaml")

	dec, err := e.Evaluate(context.Background(),
		&gateway.Identity{Subject: "user@ro.com", Type: gateway.IdentityHuman, Groups: []string{"engineering"}},
		&gateway.ToolCall{ServerID: "clinical", ToolName: "get_patient_labs", Tier: 2},
	)
	require.NoError(t, err)
	assert.Equal(t, gateway.ActionDeny, dec.Action)
	assert.Equal(t, "restrict-clinical-to-team", dec.Rule)
}

func TestEvaluate_RequireApprovalTier4(t *testing.T) {
	t.Parallel()
	e, err := policy.NewEngine("../../testdata/policy/base.yaml", "staging", testRegion)
	require.NoError(t, err)

	dec, err := e.Evaluate(context.Background(),
		&gateway.Identity{Subject: "jane@ro.com", Type: gateway.IdentityHuman, Groups: []string{"clinical-engineering"}},
		&gateway.ToolCall{ServerID: "clinical", ToolName: "archive_patient_data", Tier: 4},
	)
	require.NoError(t, err)
	assert.Equal(t, gateway.ActionRequireApproval, dec.Action)
	assert.Equal(t, "require-approval-tier4", dec.Rule)
	require.NotNil(t, dec.ApprovalSpec)
	assert.Equal(t, "slack", dec.ApprovalSpec.Channel)
}

func TestEvaluate_LogTier3(t *testing.T) {
	t.Parallel()
	e := mustLoadEngine(t, "../../testdata/policy/base.yaml")

	dec, err := e.Evaluate(context.Background(),
		&gateway.Identity{Subject: "user@ro.com", Type: gateway.IdentityHuman, Groups: []string{"engineering"}},
		&gateway.ToolCall{ServerID: "github", ToolName: "create_pull_request", Tier: 3},
	)
	require.NoError(t, err)
	// Log rule composes and then default-allow fires.
	assert.Equal(t, gateway.ActionAllow, dec.Action)
	assert.Contains(t, dec.MatchedLogRules, "log-tier3-writes")
}

func TestEvaluate_MatchesGlob(t *testing.T) {
	t.Parallel()
	// Write a temp policy that uses matchesGlob.
	policyYAML := `
rules:
  - id: deny-delete-glob
    priority: 1
    condition: 'matchesGlob(tool.name, "*delete*")'
    action: deny
    reason: "Glob: no deletes"
    audit_level: full
  - id: default-allow
    priority: 999
    condition: "true"
    action: allow
`
	f, err := os.CreateTemp(t.TempDir(), "*.yaml")
	require.NoError(t, err)
	_, err = f.WriteString(policyYAML)
	require.NoError(t, err)
	f.Close()

	e := mustLoadEngine(t, f.Name())

	tests := []struct {
		toolName string
		want     gateway.PolicyAction
	}{
		{"delete_patient", gateway.ActionDeny},
		{"soft_delete_record", gateway.ActionDeny},
		{"get_patient", gateway.ActionAllow},
	}
	for _, tt := range tests {
		t.Run(tt.toolName, func(t *testing.T) {
			t.Parallel()
			dec, err := e.Evaluate(context.Background(),
				&gateway.Identity{Type: gateway.IdentityHuman},
				&gateway.ToolCall{ToolName: tt.toolName, Tier: 1},
			)
			require.NoError(t, err)
			assert.Equal(t, tt.want, dec.Action)
		})
	}
}

func TestEngine_ReloadInvalidYAML(t *testing.T) {
	t.Parallel()
	// Valid initial policy.
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "policy.yaml")
	require.NoError(t, os.WriteFile(policyFile, []byte(`
rules:
  - id: default-allow
    priority: 999
    condition: "true"
    action: allow
`), 0o644))

	e, err := policy.NewEngine(policyFile, testWorkspace, testRegion)
	require.NoError(t, err)

	// Write invalid YAML.
	require.NoError(t, os.WriteFile(policyFile, []byte(`not: valid: yaml:`), 0o644))
	err = e.Reload(context.Background())
	require.Error(t, err)

	// Engine still works with the old rules.
	dec, evalErr := e.Evaluate(context.Background(),
		&gateway.Identity{Type: gateway.IdentityHuman},
		&gateway.ToolCall{ToolName: "anything", Tier: 1},
	)
	require.NoError(t, evalErr)
	assert.Equal(t, gateway.ActionAllow, dec.Action)
}

func TestEngine_InvalidCELExpressionFailsStartup(t *testing.T) {
	t.Parallel()
	f, err := os.CreateTemp(t.TempDir(), "*.yaml")
	require.NoError(t, err)
	_, err = f.WriteString(`
rules:
  - id: bad-rule
    priority: 1
    condition: "not valid cel $$$ expression"
    action: deny
`)
	require.NoError(t, err)
	f.Close()

	_, err = policy.NewEngine(f.Name(), testWorkspace, testRegion)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bad-rule")
}

// --- TestPolicyFixtures: offline policy harness ---

// fixtureCase is the YAML schema for a single test case in a policy fixture file.
type fixtureCase struct {
	Name     string          `yaml:"name"`
	Identity fixtureIdentity `yaml:"identity"`
	Call     fixtureCall     `yaml:"call"`
	Env      fixtureEnv      `yaml:"env"`
	Expect   fixtureExpect   `yaml:"expect"`
}

type fixtureIdentity struct {
	Subject     string   `yaml:"subject"`
	Type        string   `yaml:"type"`
	Groups      []string `yaml:"groups"`
	Scopes      []string `yaml:"scopes"`
	DelegatedBy string   `yaml:"delegated_by"`
}

type fixtureCall struct {
	ServerID string         `yaml:"server_id"`
	ToolName string         `yaml:"tool_name"`
	Tier     int            `yaml:"tier"`
	Args     map[string]any `yaml:"args"`
	Tags     map[string]string `yaml:"tags"`
}

type fixtureEnv struct {
	Workspace string `yaml:"workspace"`
	Region    string `yaml:"region"`
}

type fixtureExpect struct {
	Action  string `yaml:"action"`
	Rule    string `yaml:"rule"`
	Channel string `yaml:"approval_channel"`
}

type fixtureFile struct {
	Suite string        `yaml:"suite"`
	Setup struct {
		PolicyDir string `yaml:"policy_dir"`
	} `yaml:"setup"`
	Cases []fixtureCase `yaml:"cases"`
}

// TestPolicyFixtures discovers and runs all YAML test fixture files under
// testdata/policy/tests/. This makes policy changes a pure PR review exercise:
// write a rule, add test cases, merge, proxy hot-reloads.
func TestPolicyFixtures(t *testing.T) {
	fixturesDir := "../../testdata/policy/tests"
	entries, err := os.ReadDir(fixturesDir)
	require.NoError(t, err, "testdata/policy/tests must exist")

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if filepath.Ext(entry.Name()) != ".yaml" && filepath.Ext(entry.Name()) != ".yml" {
			continue
		}

		fixturePath := filepath.Join(fixturesDir, entry.Name())
		data, err := os.ReadFile(fixturePath)
		require.NoError(t, err)

		var ff fixtureFile
		require.NoError(t, yaml.Unmarshal(data, &ff), "parsing %s", fixturePath)

		t.Run(ff.Suite, func(t *testing.T) {
			t.Parallel()

			// Resolve policy path relative to the fixture file.
			policyPath := ff.Setup.PolicyDir
			if !filepath.IsAbs(policyPath) {
				policyPath = filepath.Join(fixturesDir, policyPath)
			}

			for _, tc := range ff.Cases {
				tc := tc
				t.Run(tc.Name, func(t *testing.T) {
					t.Parallel()

					workspace := tc.Env.Workspace
					if workspace == "" {
						workspace = testWorkspace
					}
					region := tc.Env.Region
					if region == "" {
						region = testRegion
					}

					e, err := policy.NewEngine(policyPath, workspace, region)
					require.NoError(t, err, "loading engine for %s", tc.Name)

					identity := &gateway.Identity{
						Subject:     tc.Identity.Subject,
						Type:        gateway.IdentityType(tc.Identity.Type),
						Groups:      tc.Identity.Groups,
						Scopes:      tc.Identity.Scopes,
						DelegatedBy: tc.Identity.DelegatedBy,
					}
					if identity.Type == "" {
						identity.Type = gateway.IdentityHuman
					}

					call := &gateway.ToolCall{
						ServerID:  tc.Call.ServerID,
						ToolName:  tc.Call.ToolName,
						Tier:      tc.Call.Tier,
						Arguments: tc.Call.Args,
						Tags:      tc.Call.Tags,
					}

					dec, err := e.Evaluate(context.Background(), identity, call)
					require.NoError(t, err)

					assert.Equal(t, tc.Expect.Action, string(dec.Action),
						"case %q: action mismatch (rule=%s, reason=%s)", tc.Name, dec.Rule, dec.Reason)

					if tc.Expect.Rule != "" {
						assert.Equal(t, tc.Expect.Rule, dec.Rule,
							"case %q: rule mismatch", tc.Name)
					}
					if tc.Expect.Channel != "" {
						require.NotNil(t, dec.ApprovalSpec, "case %q: expected approval spec", tc.Name)
						assert.Equal(t, tc.Expect.Channel, dec.ApprovalSpec.Channel)
					}
				})
			}
		})
	}
}
