package policy

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// loadRulesFromPath loads all policy rules from either a single YAML file or a
// directory containing YAML files. Returns an error if any rule has a duplicate ID.
func loadRulesFromPath(path string) ([]rawRule, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}

	if !info.IsDir() {
		return loadRulesFromFile(path)
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("reading policy dir %s: %w", path, err)
	}

	var all []rawRule
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := filepath.Ext(e.Name())
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		rules, err := loadRulesFromFile(filepath.Join(path, e.Name()))
		if err != nil {
			return nil, err
		}
		all = append(all, rules...)
	}

	return deduplicateCheck(all)
}

func loadRulesFromFile(path string) ([]rawRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	var f rawFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	return f.Rules, nil
}

// deduplicateCheck verifies that all rule IDs are unique across loaded files.
func deduplicateCheck(rules []rawRule) ([]rawRule, error) {
	seen := make(map[string]bool, len(rules))
	for _, r := range rules {
		if seen[r.ID] {
			return nil, fmt.Errorf("duplicate policy rule id %q", r.ID)
		}
		seen[r.ID] = true
	}
	return rules, nil
}
