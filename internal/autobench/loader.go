package autobench

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/verabase/code-verification-engine/internal/claims"
	"github.com/verabase/code-verification-engine/internal/rules"
)

// LoadDataset loads and validates a dataset manifest plus its expected files.
func LoadDataset(moduleRoot, manifestPath string) (*DatasetManifest, map[string]ExpectedCase, error) {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, nil, err
	}

	var manifest DatasetManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, nil, fmt.Errorf("parse manifest: %w", err)
	}

	expectedByCase := make(map[string]ExpectedCase)
	if err := validateManifest(moduleRoot, manifestPath, &manifest, expectedByCase); err != nil {
		return nil, nil, err
	}

	return &manifest, expectedByCase, nil
}

func validateManifest(moduleRoot, manifestPath string, manifest *DatasetManifest, expectedByCase map[string]ExpectedCase) error {
	if manifest.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported schema_version %q", manifest.SchemaVersion)
	}
	if manifest.DatasetID == "" {
		return fmt.Errorf("dataset_id is required")
	}
	if !slices.Contains([]string{ModeFrozen, ModeGenerated, ModeShadow}, manifest.Mode) {
		return fmt.Errorf("unsupported mode %q", manifest.Mode)
	}
	if len(manifest.Suites) == 0 {
		return fmt.Errorf("at least one suite is required")
	}

	if len(manifest.GatePolicy.ProtectedPaths) == 0 {
		return fmt.Errorf("gate_policy.protected_paths is required")
	}
	for trustClass, precision := range manifest.GatePolicy.MinPrecisionByTrustClass {
		if !validTrustClass(trustClass) {
			return fmt.Errorf("unsupported trust class %q in gate policy", trustClass)
		}
		if precision < 0 || precision > 1 {
			return fmt.Errorf("precision for trust class %q must be between 0 and 1", trustClass)
		}
	}

	suiteIDs := make(map[string]struct{}, len(manifest.Suites))
	caseIDs := make(map[string]struct{})
	for _, suite := range manifest.Suites {
		if suite.ID == "" {
			return fmt.Errorf("suite id is required")
		}
		if _, exists := suiteIDs[suite.ID]; exists {
			return fmt.Errorf("duplicate suite id %q", suite.ID)
		}
		suiteIDs[suite.ID] = struct{}{}

		if _, ok := rules.GetProfile(suite.Profile); !ok {
			return fmt.Errorf("suite %q references unknown profile %q", suite.ID, suite.Profile)
		}
		if suite.ClaimSet != "" {
			if _, ok := claims.GetClaimSet(suite.ClaimSet); !ok {
				return fmt.Errorf("suite %q references unknown claim set %q", suite.ID, suite.ClaimSet)
			}
		}
		if len(suite.Cases) == 0 {
			return fmt.Errorf("suite %q must contain at least one case", suite.ID)
		}

		allowedRules := suiteRuleIDs(suite)
		for _, c := range suite.Cases {
			if c.ID == "" {
				return fmt.Errorf("suite %q contains case with empty id", suite.ID)
			}
			if _, exists := caseIDs[c.ID]; exists {
				return fmt.Errorf("duplicate case id %q", c.ID)
			}
			caseIDs[c.ID] = struct{}{}
			if err := validateCase(moduleRoot, manifestPath, suite, c, allowedRules, expectedByCase); err != nil {
				return err
			}
		}
	}

	return nil
}

func validateCase(moduleRoot, manifestPath string, suite SuiteManifest, c CaseManifest, allowedRules map[string]struct{}, expectedByCase map[string]ExpectedCase) error {
	if c.RepoPath == "" || c.ExpectedPath == "" {
		return fmt.Errorf("suite %q case %q must define repo_path and expected_path", suite.ID, c.ID)
	}
	if !slices.Contains([]string{
		CasePass,
		CaseFail,
		CaseUnknown,
		CaseMixed,
		CaseFalsePositiveGuard,
		CaseFalseNegativeGuard,
		CaseEdgeCase,
	}, c.CaseType) {
		return fmt.Errorf("suite %q case %q has unsupported case_type %q", suite.ID, c.ID, c.CaseType)
	}
	if len(c.TargetRules) == 0 {
		return fmt.Errorf("suite %q case %q must target at least one rule", suite.ID, c.ID)
	}
	for _, ruleID := range c.TargetRules {
		if _, ok := allowedRules[ruleID]; !ok {
			return fmt.Errorf("suite %q case %q targets rule %q not included by profile/claim set", suite.ID, c.ID, ruleID)
		}
	}

	repoPath := filepath.Join(moduleRoot, c.RepoPath)
	if _, err := os.Stat(repoPath); err != nil {
		return fmt.Errorf("suite %q case %q repo_path %q: %w", suite.ID, c.ID, c.RepoPath, err)
	}

	expectedPath := filepath.Join(moduleRoot, c.ExpectedPath)
	data, err := os.ReadFile(expectedPath)
	if err != nil {
		return fmt.Errorf("suite %q case %q expected_path %q: %w", suite.ID, c.ID, c.ExpectedPath, err)
	}

	var expected ExpectedCase
	if err := json.Unmarshal(data, &expected); err != nil {
		return fmt.Errorf("suite %q case %q parse expected: %w", suite.ID, c.ID, err)
	}
	if err := validateExpectedCase(suite, c, expected); err != nil {
		rel, _ := filepath.Rel(filepath.Dir(manifestPath), expectedPath)
		return fmt.Errorf("suite %q case %q expected file %q: %w", suite.ID, c.ID, rel, err)
	}
	expectedByCase[c.ID] = expected
	return nil
}

func validateExpectedCase(suite SuiteManifest, c CaseManifest, expected ExpectedCase) error {
	if expected.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported schema_version %q", expected.SchemaVersion)
	}
	if expected.CaseID != c.ID {
		return fmt.Errorf("case_id %q does not match case manifest id %q", expected.CaseID, c.ID)
	}
	if expected.Profile != suite.Profile {
		return fmt.Errorf("profile %q does not match suite profile %q", expected.Profile, suite.Profile)
	}
	if expected.ClaimSet != suite.ClaimSet {
		return fmt.Errorf("claim_set %q does not match suite claim_set %q", expected.ClaimSet, suite.ClaimSet)
	}
	if len(expected.Expectations) == 0 {
		return fmt.Errorf("at least one expectation is required")
	}

	targetRules := make(map[string]struct{}, len(c.TargetRules))
	for _, ruleID := range c.TargetRules {
		targetRules[ruleID] = struct{}{}
	}

	seen := make(map[string]struct{}, len(expected.Expectations))
	for _, exp := range expected.Expectations {
		if exp.RuleID == "" {
			return fmt.Errorf("expectation rule_id is required")
		}
		if _, exists := seen[exp.RuleID]; exists {
			return fmt.Errorf("duplicate expectation for rule %q", exp.RuleID)
		}
		seen[exp.RuleID] = struct{}{}
		if _, ok := targetRules[exp.RuleID]; !ok {
			return fmt.Errorf("expectation rule %q is not listed in target_rules", exp.RuleID)
		}
		if err := validateExpectation(exp); err != nil {
			return fmt.Errorf("rule %q: %w", exp.RuleID, err)
		}
	}
	return nil
}

func validateExpectation(exp RuleExpectation) error {
	if exp.ExpectedStatus == "" && len(exp.AllowedStatuses) == 0 {
		return fmt.Errorf("expected_status or allowed_statuses is required")
	}
	if exp.ExpectedStatus != "" && !validStatus(exp.ExpectedStatus) {
		return fmt.Errorf("unsupported expected_status %q", exp.ExpectedStatus)
	}
	for _, status := range exp.AllowedStatuses {
		if !validStatus(status) {
			return fmt.Errorf("unsupported allowed_status %q", status)
		}
	}
	if exp.ExpectedTrustClass != "" && !validTrustClass(exp.ExpectedTrustClass) {
		return fmt.Errorf("unsupported expected_trust_class %q", exp.ExpectedTrustClass)
	}
	if exp.Priority == "" {
		return fmt.Errorf("priority is required")
	}
	if exp.Priority != "blocking" && exp.Priority != "advisory" {
		return fmt.Errorf("unsupported priority %q", exp.Priority)
	}
	if exp.MinimumEvidenceCount < 0 {
		return fmt.Errorf("minimum_evidence_count must be >= 0")
	}
	if exp.Rationale == "" {
		return fmt.Errorf("rationale is required")
	}
	return nil
}

func suiteRuleIDs(suite SuiteManifest) map[string]struct{} {
	allowed := make(map[string]struct{})
	profile, _ := rules.GetProfile(suite.Profile)
	for _, r := range profile.Rules {
		allowed[r.ID] = struct{}{}
	}
	if suite.ClaimSet != "" {
		if cs, ok := claims.GetClaimSet(suite.ClaimSet); ok {
			allRules := make(map[string]rules.Rule)
			for _, prof := range rules.AllProfiles() {
				for _, r := range prof.Rules {
					allRules[r.ID] = r
				}
			}
			for _, claim := range cs.Claims {
				for _, ruleID := range claim.RuleIDs {
					if _, exists := allRules[ruleID]; exists {
						allowed[ruleID] = struct{}{}
					}
				}
			}
		}
	}
	return allowed
}

func validStatus(status string) bool {
	return status == string(rules.StatusPass) ||
		status == string(rules.StatusFail) ||
		status == string(rules.StatusUnknown)
}

func validTrustClass(class string) bool {
	return class == string(rules.TrustMachineTrusted) ||
		class == string(rules.TrustAdvisory) ||
		class == string(rules.TrustHumanOrRuntimeRequired)
}
