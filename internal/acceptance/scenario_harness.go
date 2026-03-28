package acceptance

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/verabase/code-verification-engine/internal/artifactsv2"
	"github.com/verabase/code-verification-engine/internal/engine"
)

// ScenarioFixtureGolden defines the normalized trust-critical expectations for a
// proof-grade scenario fixture. It intentionally avoids unstable fields such as
// timestamps, signatures, or full artifact snapshots.
type ScenarioFixtureGolden struct {
	FixtureID                    string                           `json:"fixture_id"`
	RepoSubpath                  string                           `json:"repo_subpath,omitempty"`
	MinVerifiedClaims            int                              `json:"min_verified_claims,omitempty"`
	MinHighlights                int                              `json:"min_highlights,omitempty"`
	MaxVerifiedClaims            *int                             `json:"max_verified_claims,omitempty"`
	RequiredVerifiedClaimIDs     []string                         `json:"required_verified_claim_ids,omitempty"`
	ForbiddenVerifiedClaimIDs    []string                         `json:"forbidden_verified_claim_ids,omitempty"`
	RequireOutsourceArtifact     bool                             `json:"require_outsource_artifact,omitempty"`
	RequirePMArtifact            bool                             `json:"require_pm_artifact,omitempty"`
	RequiredOutsourceRows        []ScenarioRequirementExpectation `json:"required_outsource_rows,omitempty"`
	RequiredPMRows               []ScenarioRequirementExpectation `json:"required_pm_rows,omitempty"`
	RequireContradictionEvidence bool                             `json:"require_contradiction_evidence,omitempty"`
	ForbidProofGradeScenarioRows bool                             `json:"forbid_proof_grade_scenario_rows,omitempty"`
	ExpectedRuleClaimFamilies    map[string][]string              `json:"expected_rule_claim_families,omitempty"`
}

// ScenarioRequirementExpectation captures the stable semantic subset for a
// required scenario row.
type ScenarioRequirementExpectation struct {
	RequirementID            string   `json:"requirement_id"`
	Status                   string   `json:"status"`
	VerificationClass        string   `json:"verification_class,omitempty"`
	TrustClass               string   `json:"trust_class,omitempty"`
	RequireClaimIDs          []string `json:"require_claim_ids,omitempty"`
	MinSupportingEvidence    int      `json:"min_supporting_evidence,omitempty"`
	MinContradictoryEvidence int      `json:"min_contradictory_evidence,omitempty"`
}

type scenarioFixtureRunResult struct {
	Bundle artifactsv2.Bundle
}

func loadScenarioFixtureGolden(dir string) (ScenarioFixtureGolden, error) {
	path := filepath.Join(dir, "scenario_golden.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return ScenarioFixtureGolden{}, err
	}
	var golden ScenarioFixtureGolden
	if err := json.Unmarshal(data, &golden); err != nil {
		return ScenarioFixtureGolden{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if strings.TrimSpace(golden.FixtureID) == "" {
		return ScenarioFixtureGolden{}, fmt.Errorf("fixture_id is required in %s", path)
	}
	return golden, nil
}

func runScenarioFixture(ctx context.Context, fixtureDir string, golden ScenarioFixtureGolden) (*scenarioFixtureRunResult, error) {
	repoDir, err := initScenarioFixtureRepo(fixtureDir)
	if err != nil {
		return nil, err
	}
	repoPath := repoDir
	if strings.TrimSpace(golden.RepoSubpath) != "" {
		repoPath = filepath.Join(repoDir, golden.RepoSubpath)
	}
	result := engine.Run(engine.Config{
		Ctx:                        ctx,
		RepoPath:                   repoPath,
		Ref:                        "HEAD",
		Profile:                    "backend-api",
		OutputDir:                  filepath.Join(repoDir, ".cve-out"),
		Format:                     "json",
		Progress:                   io.Discard,
		OutsourceAcceptanceProfile: "outsource-backend-api",
		PMAcceptanceProfile:        "pm-engineering-default",
	})
	if result.ExitCode != 0 && result.ExitCode != 5 && result.ExitCode != 6 {
		return nil, fmt.Errorf("engine exit code %d: %v", result.ExitCode, result.Errors)
	}
	if result.VerifiableBundle == nil {
		return nil, fmt.Errorf("missing verifiable bundle: exit=%d errors=%v", result.ExitCode, result.Errors)
	}
	return &scenarioFixtureRunResult{Bundle: *result.VerifiableBundle}, nil
}

func initScenarioFixtureRepo(fixtureDir string) (string, error) {
	tmpDir, err := os.MkdirTemp("", "cve-scenario-fixture-")
	if err != nil {
		return "", err
	}
	if err := filepath.Walk(fixtureDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(fixtureDir, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if info.IsDir() {
			return os.MkdirAll(filepath.Join(tmpDir, rel), 0o755)
		}
		name := filepath.Base(path)
		if name == "scenario_golden.json" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		dest := filepath.Join(tmpDir, rel)
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return err
		}
		return os.WriteFile(dest, data, 0o644)
	}); err != nil {
		return "", err
	}
	for _, args := range [][]string{
		{"git", "init"},
		{"git", "config", "user.email", "test@test.com"},
		{"git", "config", "user.name", "test"},
		{"git", "add", "-A"},
		{"git", "commit", "-m", "scenario fixture"},
	} {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = tmpDir
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("%s: %w", strings.Join(args, " "), err)
		}
	}
	return tmpDir, nil
}

func assertScenarioFixtureGolden(bundle artifactsv2.Bundle, golden ScenarioFixtureGolden) error {
	if err := artifactsv2.ValidateBundle(bundle); err != nil {
		return fmt.Errorf("bundle contract: %w", err)
	}
	requiresHiringArtifacts := golden.MinVerifiedClaims > 0 ||
		golden.MinHighlights > 0 ||
		len(golden.RequiredVerifiedClaimIDs) > 0 ||
		len(golden.ForbiddenVerifiedClaimIDs) > 0
	if requiresHiringArtifacts && (bundle.Claims == nil || bundle.Profile == nil || bundle.ResumeInput == nil) {
		return fmt.Errorf("claims/profile/resume artifacts are required")
	}
	if bundle.ResumeInput != nil && bundle.Profile != nil {
		if got := len(bundle.ResumeInput.VerifiedClaims); got < golden.MinVerifiedClaims {
			return fmt.Errorf("verified claim count mismatch: got %d want >= %d", got, golden.MinVerifiedClaims)
		}
		if golden.MaxVerifiedClaims != nil && len(bundle.ResumeInput.VerifiedClaims) > *golden.MaxVerifiedClaims {
			return fmt.Errorf("verified claim count mismatch: got %d want <= %d", len(bundle.ResumeInput.VerifiedClaims), *golden.MaxVerifiedClaims)
		}
		if got := len(bundle.Profile.Highlights); got < golden.MinHighlights {
			return fmt.Errorf("highlight count mismatch: got %d want >= %d", got, golden.MinHighlights)
		}
		for _, claimID := range golden.RequiredVerifiedClaimIDs {
			if !hasResumeVerifiedClaim(bundle.ResumeInput.VerifiedClaims, claimID) {
				return fmt.Errorf("missing verified claim %q", claimID)
			}
		}
		for _, claimID := range golden.ForbiddenVerifiedClaimIDs {
			if hasResumeVerifiedClaim(bundle.ResumeInput.VerifiedClaims, claimID) {
				return fmt.Errorf("forbidden verified claim %q present", claimID)
			}
		}
	}
	if golden.RequireOutsourceArtifact {
		if bundle.OutsourceAcceptance == nil {
			return fmt.Errorf("missing outsource acceptance artifact")
		}
		for _, expected := range golden.RequiredOutsourceRows {
			if err := assertOutsourceRequirement(*bundle.OutsourceAcceptance, expected); err != nil {
				return err
			}
		}
	}
	if golden.RequirePMArtifact {
		if bundle.PMAcceptance == nil {
			return fmt.Errorf("missing PM acceptance artifact")
		}
		for _, expected := range golden.RequiredPMRows {
			if err := assertPMRequirement(*bundle.PMAcceptance, expected); err != nil {
				return err
			}
		}
	}
	if golden.RequireContradictionEvidence && !bundleHasContradictionEvidence(bundle) {
		return fmt.Errorf("expected contradictory evidence references")
	}
	if golden.ForbidProofGradeScenarioRows && bundleHasProofGradeScenarioRows(bundle) {
		return fmt.Errorf("unexpected proof-grade scenario rows present")
	}
	if err := assertExpectedRuleClaimFamilies(bundle, golden.ExpectedRuleClaimFamilies); err != nil {
		return err
	}
	if err := assertScenarioTrustSemantics(bundle); err != nil {
		return err
	}
	return nil
}

func assertOutsourceRequirement(artifact artifactsv2.OutsourceAcceptanceArtifact, expected ScenarioRequirementExpectation) error {
	for _, row := range artifact.Requirements {
		if row.RequirementID != expected.RequirementID {
			continue
		}
		if row.Status != expected.Status {
			return fmt.Errorf("outsource %s status mismatch: got %q want %q", expected.RequirementID, row.Status, expected.Status)
		}
		if expected.VerificationClass != "" && string(row.VerificationClass) != expected.VerificationClass {
			return fmt.Errorf("outsource %s verification_class mismatch: got %q want %q", expected.RequirementID, row.VerificationClass, expected.VerificationClass)
		}
		if expected.TrustClass != "" && string(row.TrustClass) != expected.TrustClass {
			return fmt.Errorf("outsource %s trust_class mismatch: got %q want %q", expected.RequirementID, row.TrustClass, expected.TrustClass)
		}
		for _, claimID := range expected.RequireClaimIDs {
			if !slices.Contains(row.ClaimIDs, claimID) {
				return fmt.Errorf("outsource %s missing claim id %q", expected.RequirementID, claimID)
			}
		}
		if len(row.SupportingEvidenceIDs) < expected.MinSupportingEvidence {
			return fmt.Errorf("outsource %s supporting evidence mismatch: got %d want >= %d", expected.RequirementID, len(row.SupportingEvidenceIDs), expected.MinSupportingEvidence)
		}
		if len(row.ContradictoryEvidenceIDs) < expected.MinContradictoryEvidence {
			return fmt.Errorf("outsource %s contradictory evidence mismatch: got %d want >= %d", expected.RequirementID, len(row.ContradictoryEvidenceIDs), expected.MinContradictoryEvidence)
		}
		return nil
	}
	return fmt.Errorf("missing outsource requirement %q", expected.RequirementID)
}

func assertPMRequirement(artifact artifactsv2.PMAcceptanceArtifact, expected ScenarioRequirementExpectation) error {
	for _, row := range artifact.EngineeringRequirements {
		if row.RequirementID != expected.RequirementID {
			continue
		}
		if row.Status != expected.Status {
			return fmt.Errorf("pm %s status mismatch: got %q want %q", expected.RequirementID, row.Status, expected.Status)
		}
		if expected.VerificationClass != "" && string(row.VerificationClass) != expected.VerificationClass {
			return fmt.Errorf("pm %s verification_class mismatch: got %q want %q", expected.RequirementID, row.VerificationClass, expected.VerificationClass)
		}
		if expected.TrustClass != "" && string(row.TrustClass) != expected.TrustClass {
			return fmt.Errorf("pm %s trust_class mismatch: got %q want %q", expected.RequirementID, row.TrustClass, expected.TrustClass)
		}
		for _, claimID := range expected.RequireClaimIDs {
			if !slices.Contains(row.ClaimIDs, claimID) {
				return fmt.Errorf("pm %s missing claim id %q", expected.RequirementID, claimID)
			}
		}
		if len(row.SupportingEvidenceIDs) < expected.MinSupportingEvidence {
			return fmt.Errorf("pm %s supporting evidence mismatch: got %d want >= %d", expected.RequirementID, len(row.SupportingEvidenceIDs), expected.MinSupportingEvidence)
		}
		if len(row.ContradictoryEvidenceIDs) < expected.MinContradictoryEvidence {
			return fmt.Errorf("pm %s contradictory evidence mismatch: got %d want >= %d", expected.RequirementID, len(row.ContradictoryEvidenceIDs), expected.MinContradictoryEvidence)
		}
		return nil
	}
	return fmt.Errorf("missing pm requirement %q", expected.RequirementID)
}

func hasResumeVerifiedClaim(claims []artifactsv2.ResumeClaimStub, claimID string) bool {
	for _, claim := range claims {
		if claim.ClaimID == claimID {
			return true
		}
	}
	return false
}

func bundleHasContradictionEvidence(bundle artifactsv2.Bundle) bool {
	if bundle.Claims != nil {
		for _, claim := range bundle.Claims.Claims {
			if len(claim.ContradictoryEvidenceIDs) > 0 {
				return true
			}
		}
	}
	if bundle.OutsourceAcceptance != nil {
		for _, row := range bundle.OutsourceAcceptance.Requirements {
			if len(row.ContradictoryEvidenceIDs) > 0 {
				return true
			}
		}
	}
	if bundle.PMAcceptance != nil {
		for _, row := range bundle.PMAcceptance.EngineeringRequirements {
			if len(row.ContradictoryEvidenceIDs) > 0 {
				return true
			}
		}
	}
	return false
}

func bundleHasProofGradeScenarioRows(bundle artifactsv2.Bundle) bool {
	if bundle.OutsourceAcceptance != nil {
		for _, row := range bundle.OutsourceAcceptance.Requirements {
			if row.VerificationClass == artifactsv2.VerificationProofGrade {
				return true
			}
		}
	}
	if bundle.PMAcceptance != nil {
		for _, row := range bundle.PMAcceptance.EngineeringRequirements {
			if row.VerificationClass == artifactsv2.VerificationProofGrade {
				return true
			}
		}
	}
	return false
}

func assertExpectedRuleClaimFamilies(bundle artifactsv2.Bundle, expected map[string][]string) error {
	if len(expected) == 0 {
		return nil
	}
	if bundle.Trace.MigrationSummary == nil {
		return fmt.Errorf("missing migration summary")
	}
	for ruleID, expectedFamilies := range expected {
		got := append([]string(nil), bundle.Trace.MigrationSummary.RuleClaimFamilies[ruleID]...)
		if !slices.Equal(got, expectedFamilies) {
			return fmt.Errorf("rule claim families mismatch for %q: got %#v want %#v", ruleID, got, expectedFamilies)
		}
	}
	return nil
}

func assertScenarioTrustSemantics(bundle artifactsv2.Bundle) error {
	if bundle.OutsourceAcceptance != nil {
		for _, row := range bundle.OutsourceAcceptance.Requirements {
			if row.TrustClass == artifactsv2.TrustClassMachineTrusted && row.VerificationClass != artifactsv2.VerificationProofGrade {
				return fmt.Errorf("outsource row %q is machine_trusted without proof_grade", row.RequirementID)
			}
		}
	}
	if bundle.PMAcceptance != nil {
		for _, row := range bundle.PMAcceptance.EngineeringRequirements {
			if row.TrustClass == artifactsv2.TrustClassMachineTrusted && row.VerificationClass != artifactsv2.VerificationProofGrade {
				return fmt.Errorf("pm row %q is machine_trusted without proof_grade", row.RequirementID)
			}
		}
	}
	return nil
}
