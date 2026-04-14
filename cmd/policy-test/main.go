// Command policy-test is the offline policy validation and test runner CLI.
//
// Usage:
//
//	# Validate policy YAML syntax only (no infra required):
//	policy-test --validate-only --policy /etc/mcp-proxy/policy.yaml
//
//	# Run fixture test cases against a policy file:
//	policy-test --policy /etc/mcp-proxy/policy.yaml --fixtures ./testdata/policy/tests
//
// Exit codes:
//
//	0 — all checks passed
//	1 — one or more test cases failed or an I/O error occurred
//	2 — invalid CLI usage
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/ro-eng/mcp-proxy/gateway"
	"github.com/ro-eng/mcp-proxy/internal/policy"
)

func main() {
	fs := flag.NewFlagSet("policy-test", flag.ExitOnError)
	policyPath := fs.String("policy", "", "Path to policy YAML file or directory (required)")
	fixturesDir := fs.String("fixtures", "", "Path to fixture test directory (optional)")
	validateOnly := fs.Bool("validate-only", false, "Only validate YAML syntax and CEL compilation; do not run test cases")
	workspace := fs.String("workspace", "production", "Workspace for CEL env evaluation (production|staging|dev)")
	region := fs.String("region", "us-east-1", "AWS region for CEL env evaluation")

	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}

	if *policyPath == "" {
		fmt.Fprintln(os.Stderr, "error: --policy is required")
		fs.Usage()
		os.Exit(2)
	}

	ctx := context.Background()
	failed := false

	// ── Step 1: validate / compile policy ────────────────────────────────────
	fmt.Printf("Loading policy: %s\n", *policyPath)
	eng, err := policy.NewEngine(*policyPath, *workspace, *region)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: policy compile error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("OK: policy loaded (workspace=%s, region=%s)\n", *workspace, *region)

	if *validateOnly {
		fmt.Println("Validation successful (--validate-only; no test cases run)")
		os.Exit(0)
	}

	// ── Step 2: discover and run fixture files ────────────────────────────────
	if *fixturesDir == "" {
		fmt.Println("No --fixtures directory specified; validation only.")
		os.Exit(0)
	}

	entries, err := os.ReadDir(*fixturesDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading fixtures directory %s: %v\n", *fixturesDir, err)
		os.Exit(1)
	}

	totalCases := 0
	passedCases := 0

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := filepath.Ext(entry.Name())
		if ext != ".yaml" && ext != ".yml" {
			continue
		}

		fixturePath := filepath.Join(*fixturesDir, entry.Name())
		data, err := os.ReadFile(fixturePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading %s: %v\n", fixturePath, err)
			failed = true
			continue
		}

		var ff fixtureFile
		if err := yaml.Unmarshal(data, &ff); err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: parse error in %s: %v\n", fixturePath, err)
			failed = true
			continue
		}

		fmt.Printf("\nSuite: %s (%s)\n", ff.Suite, entry.Name())

		// Load engine per suite (allows per-suite policy paths in setup.policy_dir).
		suitePolicy := *policyPath
		if ff.Setup.PolicyDir != "" {
			suitePolicy = ff.Setup.PolicyDir
			if !filepath.IsAbs(suitePolicy) {
				suitePolicy = filepath.Join(*fixturesDir, suitePolicy)
			}
		}

		suiteEng := eng
		if suitePolicy != *policyPath {
			var loadErr error
			suiteEng, loadErr = policy.NewEngine(suitePolicy, *workspace, *region)
			if loadErr != nil {
				fmt.Fprintf(os.Stderr, "  FAIL: loading suite policy %s: %v\n", suitePolicy, loadErr)
				failed = true
				continue
			}
		}

		for _, tc := range ff.Cases {
			totalCases++

			caseWorkspace := *workspace
			if tc.Env.Workspace != "" {
				caseWorkspace = tc.Env.Workspace
			}
			caseRegion := *region
			if tc.Env.Region != "" {
				caseRegion = tc.Env.Region
			}

			// If env overrides differ from suite, load a dedicated engine.
			caseEng := suiteEng
			if caseWorkspace != *workspace || caseRegion != *region {
				var loadErr error
				caseEng, loadErr = policy.NewEngine(suitePolicy, caseWorkspace, caseRegion)
				if loadErr != nil {
					fmt.Printf("  FAIL %q: engine load: %v\n", tc.Name, loadErr)
					failed = true
					continue
				}
			}

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

			dec, evalErr := caseEng.Evaluate(ctx, identity, call)
			if evalErr != nil {
				fmt.Printf("  FAIL %q: eval error: %v\n", tc.Name, evalErr)
				failed = true
				continue
			}

			pass := true
			var reasons []string

			if string(dec.Action) != tc.Expect.Action {
				pass = false
				reasons = append(reasons, fmt.Sprintf("action: got %q, want %q (rule=%s, reason=%q)",
					dec.Action, tc.Expect.Action, dec.Rule, dec.Reason))
			}
			if tc.Expect.Rule != "" && dec.Rule != tc.Expect.Rule {
				pass = false
				reasons = append(reasons, fmt.Sprintf("rule: got %q, want %q", dec.Rule, tc.Expect.Rule))
			}
			if tc.Expect.Channel != "" {
				if dec.ApprovalSpec == nil {
					pass = false
					reasons = append(reasons, "expected approval spec but got nil")
				} else if dec.ApprovalSpec.Channel != tc.Expect.Channel {
					pass = false
					reasons = append(reasons, fmt.Sprintf("approval channel: got %q, want %q",
						dec.ApprovalSpec.Channel, tc.Expect.Channel))
				}
			}

			if pass {
				passedCases++
				fmt.Printf("  PASS %q\n", tc.Name)
			} else {
				failed = true
				for _, r := range reasons {
					fmt.Printf("  FAIL %q: %s\n", tc.Name, r)
				}
				// Print the full decision as JSON to help with debugging.
				decJSON, _ := json.MarshalIndent(dec, "       ", "  ")
				fmt.Printf("       decision: %s\n", decJSON)
			}
		}
	}

	fmt.Printf("\nResults: %d/%d passed\n", passedCases, totalCases)

	if failed {
		os.Exit(1)
	}
}

// ── Fixture file schema ───────────────────────────────────────────────────────

type fixtureFile struct {
	Suite string `yaml:"suite"`
	Setup struct {
		PolicyDir string `yaml:"policy_dir"`
	} `yaml:"setup"`
	Cases []fixtureCase `yaml:"cases"`
}

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
	ServerID string            `yaml:"server_id"`
	ToolName string            `yaml:"tool_name"`
	Tier     int               `yaml:"tier"`
	Args     map[string]any    `yaml:"args"`
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
