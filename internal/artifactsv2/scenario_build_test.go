package artifactsv2

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validClaimsArtifactForScenarioBuild() *ClaimsArtifact {
	return &ClaimsArtifact{
		SchemaVersion: ClaimsSchemaVersion,
		Repository: ClaimRepositoryRef{
			Path:   "/repo",
			Commit: "abc123",
		},
		Claims: []ClaimRecord{{
			ClaimID:               "architecture.layering",
			Title:                 "Layering exists",
			Category:              "architecture",
			ClaimType:             "architecture",
			Status:                "accepted",
			SupportLevel:          "verified",
			Confidence:            0.9,
			VerificationClass:     VerificationStructuralInference,
			SourceOrigins:         []string{"code_inferred"},
			SupportingEvidenceIDs: []string{"ev-1"},
			Reason:                "code-backed",
			ProjectionEligible:    true,
		}},
		Summary: ClaimSummary{Verified: 1},
	}
}

func scenarioClaimsArtifactWithRows() *ClaimsArtifact {
	return &ClaimsArtifact{
		SchemaVersion: ClaimsSchemaVersion,
		Repository:    ClaimRepositoryRef{Path: "/repo", Commit: "abc123"},
		Claims: []ClaimRecord{
			{
				ClaimID:               "security.hardcoded_secret_present",
				Title:                 "Hardcoded secret literals are present",
				Category:              "security",
				ClaimType:             "implementation",
				Status:                "accepted",
				SupportLevel:          "verified",
				Confidence:            0.99,
				VerificationClass:     VerificationProofGrade,
				SourceOrigins:         []string{"code_inferred"},
				SupportingEvidenceIDs: []string{"ev-secret-1"},
				Reason:                "deterministic secret evidence",
			},
			{
				ClaimID:               "testing.auth_module_tests_present",
				Title:                 "Authentication module has tests",
				Category:              "testing",
				ClaimType:             "testing_maturity",
				Status:                "accepted",
				SupportLevel:          "strongly_supported",
				Confidence:            0.9,
				VerificationClass:     VerificationStructuralInference,
				SourceOrigins:         []string{"code_inferred"},
				SupportingEvidenceIDs: []string{"ev-test-1"},
				Reason:                "module tests found",
			},
			{
				ClaimID:               "config.secret_key_sourced_from_env",
				Title:                 "Secret config comes from env reads",
				Category:              "security",
				ClaimType:             "security_maturity",
				Status:                "accepted",
				SupportLevel:          "strongly_supported",
				Confidence:            0.85,
				VerificationClass:     VerificationStructuralInference,
				SourceOrigins:         []string{"code_inferred"},
				SupportingEvidenceIDs: []string{"ev-config-1"},
				Reason:                "env-backed config reads found",
			},
		},
	}
}

func TestBuildScenarioAcceptanceArtifacts_DisabledReturnsNil(t *testing.T) {
	t.Parallel()

	outsource, pm, err := BuildScenarioAcceptanceArtifacts(ScenarioAcceptanceBuildInput{
		RepoIdentity: "github.com/acme/repo",
		Commit:       "abc123",
		TraceID:      "trace-1",
		Claims:       validClaimsArtifactForScenarioBuild(),
	})
	if err != nil {
		t.Fatalf("BuildScenarioAcceptanceArtifacts(): %v", err)
	}
	if outsource != nil || pm != nil {
		t.Fatalf("expected nil artifacts when disabled, got outsource=%v pm=%v", outsource != nil, pm != nil)
	}
}

func TestBuildScenarioAcceptanceArtifacts_EnabledReturnsEmptyArtifacts(t *testing.T) {
	t.Parallel()

	outsource, pm, err := BuildScenarioAcceptanceArtifacts(ScenarioAcceptanceBuildInput{
		RepoIdentity: "github.com/acme/repo",
		Commit:       "abc123",
		TraceID:      "trace-1",
		Claims:       validClaimsArtifactForScenarioBuild(),
		Options: ScenarioBuildOptions{
			OutsourceAcceptanceProfile: "outsource-default",
			PMAcceptanceProfile:        "pm-default",
		},
	})
	if err != nil {
		t.Fatalf("BuildScenarioAcceptanceArtifacts(): %v", err)
	}
	if outsource == nil || pm == nil {
		t.Fatalf("expected both artifacts, got outsource=%v pm=%v", outsource != nil, pm != nil)
	}
	if len(outsource.Requirements) != 0 || len(pm.EngineeringRequirements) != 0 {
		t.Fatalf("expected empty artifacts, got outsource=%d pm=%d", len(outsource.Requirements), len(pm.EngineeringRequirements))
	}
	if err := ValidateOutsourceAcceptanceArtifact(*outsource); err != nil {
		t.Fatalf("ValidateOutsourceAcceptanceArtifact(): %v", err)
	}
	if err := ValidatePMAcceptanceArtifact(*pm); err != nil {
		t.Fatalf("ValidatePMAcceptanceArtifact(): %v", err)
	}
}

func TestBuildScenarioAcceptanceArtifacts_NilClaimsReturnsNil(t *testing.T) {
	t.Parallel()

	outsource, pm, err := BuildScenarioAcceptanceArtifacts(ScenarioAcceptanceBuildInput{
		RepoIdentity: "github.com/acme/repo",
		Commit:       "abc123",
		TraceID:      "trace-1",
		Options: ScenarioBuildOptions{
			OutsourceAcceptanceProfile: "outsource-default",
			PMAcceptanceProfile:        "pm-default",
		},
	})
	if err != nil {
		t.Fatalf("BuildScenarioAcceptanceArtifacts(): %v", err)
	}
	if outsource != nil || pm != nil {
		t.Fatalf("expected nil artifacts when claims are absent, got outsource=%v pm=%v", outsource != nil, pm != nil)
	}
}

func TestBuildScenarioAcceptanceArtifacts_ProjectsFirstWaveRows(t *testing.T) {
	t.Parallel()

	outsource, pm, err := BuildScenarioAcceptanceArtifacts(ScenarioAcceptanceBuildInput{
		RepoIdentity: "github.com/acme/repo",
		Commit:       "abc123",
		TraceID:      "trace-1",
		Claims:       scenarioClaimsArtifactWithRows(),
		Options: ScenarioBuildOptions{
			OutsourceAcceptanceProfile: "outsource-default",
			PMAcceptanceProfile:        "pm-default",
		},
	})
	if err != nil {
		t.Fatalf("BuildScenarioAcceptanceArtifacts(): %v", err)
	}
	if got := len(outsource.Requirements); got != 3 {
		t.Fatalf("outsource requirements = %d, want 3", got)
	}
	if got := len(pm.EngineeringRequirements); got != 3 {
		t.Fatalf("pm requirements = %d, want 3", got)
	}
	if outsource.Requirements[0].Status != "failed" {
		t.Fatalf("expected first outsource row failed, got %q", outsource.Requirements[0].Status)
	}
	pmRows := make(map[string]PMEngineeringRequirement, len(pm.EngineeringRequirements))
	for _, row := range pm.EngineeringRequirements {
		pmRows[row.RequirementID] = row
	}
	if pmRows["pm-auth-tests-001"].Status != "partial" {
		t.Fatalf("expected auth tests PM row to be partial, got %q", pmRows["pm-auth-tests-001"].Status)
	}
	if pmRows["pm-config-001"].Status != "partial" {
		t.Fatalf("expected config PM row to be partial, got %q", pmRows["pm-config-001"].Status)
	}
	if err := ValidateOutsourceAcceptanceArtifact(*outsource); err != nil {
		t.Fatalf("ValidateOutsourceAcceptanceArtifact(): %v", err)
	}
	if err := ValidatePMAcceptanceArtifact(*pm); err != nil {
		t.Fatalf("ValidatePMAcceptanceArtifact(): %v", err)
	}
}

func TestWriteBundleOmitsScenarioArtifactsWhenNil(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	b := testBundle()
	if err := WriteBundle(dir, &b, "test-engine"); err != nil {
		t.Fatalf("WriteBundle(): %v", err)
	}
	for _, name := range []string{"outsource_acceptance.json", "pm_acceptance.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			t.Fatalf("expected %s to be omitted", name)
		}
	}
}

func TestWriteBundleWritesScenarioArtifactsAndHashes(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	b := testBundle()
	b.Claims = validClaimsArtifactForScenarioBuild()

	outsource, pm, err := BuildScenarioAcceptanceArtifacts(ScenarioAcceptanceBuildInput{
		RepoIdentity: b.Report.Repo,
		Commit:       b.Report.Commit,
		TraceID:      b.Report.TraceID,
		Claims:       b.Claims,
		Options: ScenarioBuildOptions{
			OutsourceAcceptanceProfile: "outsource-backend-api",
			PMAcceptanceProfile:        "pm-engineering-default",
		},
	})
	if err != nil {
		t.Fatalf("BuildScenarioAcceptanceArtifacts(): %v", err)
	}
	b.OutsourceAcceptance = outsource
	b.PMAcceptance = pm

	if err := WriteBundle(dir, &b, "test-engine"); err != nil {
		t.Fatalf("WriteBundle(): %v", err)
	}
	for _, name := range []string{"outsource_acceptance.json", "pm_acceptance.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("expected %s to exist: %v", name, err)
		}
	}
	if b.Signature.ArtifactHashes["outsource_acceptance.json"] == "" {
		t.Fatal("expected outsource_acceptance.json hash to be present")
	}
	if b.Signature.ArtifactHashes["pm_acceptance.json"] == "" {
		t.Fatal("expected pm_acceptance.json hash to be present")
	}
}

func TestWriteBundleEnrichesSummaryWithScenarioAndMigrationAudit(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	b := testBundle()
	b.Claims = scenarioClaimsArtifactWithRows()
	b.Evidence.Evidence = append(b.Evidence.Evidence,
		EvidenceRecord{
			ID:              "ev-secret-1",
			Kind:            "rule_assertion",
			Source:          "rule",
			ProducerID:      "rule:SEC-001",
			ProducerVersion: "1.0.0",
			Repo:            b.Report.Repo,
			Commit:          b.Report.Commit,
			BoundaryHash:    "sha256:test",
			FactQuality:     "proof",
			Locations:       []LocationRef{{RepoRelPath: "config.ts", StartLine: 1, EndLine: 1}},
			Claims:          []string{"SEC-001"},
			Payload:         map[string]any{"status": "fail"},
			CreatedAt:       b.Report.Timestamp,
		},
		EvidenceRecord{
			ID:              "ev-test-1",
			Kind:            "structural_fact",
			Source:          "rule",
			ProducerID:      "rule:TEST-001",
			ProducerVersion: "1.0.0",
			Repo:            b.Report.Repo,
			Commit:          b.Report.Commit,
			BoundaryHash:    "sha256:test",
			FactQuality:     "structural",
			Locations:       []LocationRef{{RepoRelPath: "auth_test.go", StartLine: 1, EndLine: 3}},
			Claims:          []string{"TEST-001"},
			Payload:         map[string]any{"status": "pass"},
			CreatedAt:       b.Report.Timestamp,
		},
		EvidenceRecord{
			ID:              "ev-config-1",
			Kind:            "structural_fact",
			Source:          "rule",
			ProducerID:      "rule:SEC-SECRET-002",
			ProducerVersion: "1.0.0",
			Repo:            b.Report.Repo,
			Commit:          b.Report.Commit,
			BoundaryHash:    "sha256:test",
			FactQuality:     "structural",
			Locations:       []LocationRef{{RepoRelPath: "config.ts", StartLine: 2, EndLine: 2}},
			Claims:          []string{"SEC-SECRET-002"},
			Payload:         map[string]any{"status": "pass"},
			CreatedAt:       b.Report.Timestamp,
		},
	)
	b.Trace.MigrationSummary = &RuleMigrationSummary{
		IssueNativeCount:    1,
		SeedNativeCount:     2,
		FindingBridgedCount: 3,
		RuleClaimFamilies: map[string][]string{
			"SEC-001":  {"security.hardcoded_secret_present", "security.hardcoded_secret_absent"},
			"AUTH-002": {"security.route_auth_binding"},
		},
	}
	outsource, pm, err := BuildScenarioAcceptanceArtifacts(ScenarioAcceptanceBuildInput{
		RepoIdentity: b.Report.Repo,
		Commit:       b.Report.Commit,
		TraceID:      b.Report.TraceID,
		Claims:       b.Claims,
		Options: ScenarioBuildOptions{
			OutsourceAcceptanceProfile: "outsource-backend-api",
			PMAcceptanceProfile:        "pm-engineering-default",
		},
	})
	if err != nil {
		t.Fatalf("BuildScenarioAcceptanceArtifacts(): %v", err)
	}
	b.OutsourceAcceptance = outsource
	b.PMAcceptance = pm

	if err := WriteBundle(dir, &b, "test-engine"); err != nil {
		t.Fatalf("WriteBundle(): %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "summary.md"))
	if err != nil {
		t.Fatalf("ReadFile(summary.md): %v", err)
	}
	text := string(data)
	for _, fragment := range []string{
		"## Proof-Grade Scenarios",
		"Outsource acceptance:",
		"PM acceptance:",
		"## Migration Audit",
		"### Rule to Claim Families",
		"SEC-001 -> security.hardcoded_secret_absent, security.hardcoded_secret_present",
	} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("summary.md missing fragment %q:\n%s", fragment, text)
		}
	}
}
