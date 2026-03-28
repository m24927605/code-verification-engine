package artifactsv2

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/verabase/code-verification-engine/internal/report"
	"github.com/verabase/code-verification-engine/internal/rules"
)

// -- WriteBundle: full claims/profile/resume write path --

func TestWriteBundleFullClaimsProfileResumePathVerifiesContents(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	b := testBundleWithClaims()
	if err := WriteBundle(dir, &b, "test-signer"); err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}
	for _, name := range []string{"report.json", "evidence.json", "skills.json", "trace.json", "summary.md", "signature.json", "claims.json", "profile.json", "resume_input.json"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%s missing: %v", name, err)
		}
		if info.Size() == 0 {
			t.Fatalf("%s empty", name)
		}
	}
	// Verify signature has all hashes
	var sig SignatureArtifact
	data, _ := os.ReadFile(filepath.Join(dir, "signature.json"))
	_ = json.Unmarshal(data, &sig)
	if len(sig.ArtifactHashes) < 8 {
		t.Fatalf("expected >=8 artifact hashes, got %d", len(sig.ArtifactHashes))
	}
}

// -- ValidateTrace: deeper branch coverage --

func TestValidateTraceFullValidTrace(t *testing.T) {
	t.Parallel()
	tr := testBundle().Trace
	if err := ValidateTrace(tr); err != nil {
		t.Fatalf("ValidateTrace valid: %v", err)
	}
}

func TestValidateTraceRejectsMissingFields(t *testing.T) {
	t.Parallel()
	if err := ValidateTrace(TraceArtifact{SchemaVersion: "2.0.0"}); err == nil {
		t.Fatal("expected error for missing required trace fields")
	}
}

func TestValidateTraceRulesMissingID(t *testing.T) {
	t.Parallel()
	tr := testBundle().Trace
	tr.Rules = []RuleRun{{ID: "", Version: ""}}
	if err := ValidateTrace(tr); err == nil {
		t.Fatal("expected error for rule missing ID")
	}
}

func TestValidateTraceRulesInvalidMigState(t *testing.T) {
	t.Parallel()
	tr := testBundle().Trace
	tr.Rules = []RuleRun{{ID: "R-1", Version: "1.0", MigrationState: "invalid"}}
	if err := ValidateTrace(tr); err == nil {
		t.Fatal("expected error for invalid rule migration state")
	}
}

func TestValidateTraceAgentsMissingID(t *testing.T) {
	t.Parallel()
	tr := testBundle().Trace
	tr.Agents[0].ID = ""
	if err := ValidateTrace(tr); err == nil {
		t.Fatal("expected error for agent missing ID")
	}
}

func TestValidateTraceAgentsInvalidKind(t *testing.T) {
	t.Parallel()
	tr := testBundle().Trace
	tr.Agents[0].Kind = "x"
	if err := ValidateTrace(tr); err == nil {
		t.Fatal("expected error for invalid agent kind")
	}
}

func TestValidateTraceAgentsMissingIssueType(t *testing.T) {
	t.Parallel()
	tr := testBundle().Trace
	tr.Agents[0].IssueType = ""
	if err := ValidateTrace(tr); err == nil {
		t.Fatal("expected error for missing issue type")
	}
}

func TestValidateTraceAgentsInvalidStatus(t *testing.T) {
	t.Parallel()
	tr := testBundle().Trace
	tr.Agents[0].Status = "x"
	if err := ValidateTrace(tr); err == nil {
		t.Fatal("expected error for invalid agent status")
	}
}

func TestValidateTraceAgentsNegativeMaxFiles(t *testing.T) {
	t.Parallel()
	tr := testBundle().Trace
	tr.Agents[0].MaxFiles = -1
	if err := ValidateTrace(tr); err == nil {
		t.Fatal("expected error for negative max_files")
	}
}

func TestValidateTraceContextSelectionsInvalidTriggerType(t *testing.T) {
	t.Parallel()
	tr := testBundle().Trace
	tr.ContextSelections = []ContextSelectionRecord{{ID: "c", TriggerType: "x", TriggerID: "i"}}
	if err := ValidateTrace(tr); err == nil {
		t.Fatal("expected error for invalid trigger type")
	}
}

func TestValidateTraceContextSelectionsMissingTriggerID(t *testing.T) {
	t.Parallel()
	tr := testBundle().Trace
	tr.ContextSelections = []ContextSelectionRecord{{ID: "c", TriggerType: "issue", TriggerID: ""}}
	if err := ValidateTrace(tr); err == nil {
		t.Fatal("expected error for missing trigger ID")
	}
}

func TestValidateTraceContextSelectionsNegBudget(t *testing.T) {
	t.Parallel()
	tr := testBundle().Trace
	tr.ContextSelections = []ContextSelectionRecord{{ID: "c", TriggerType: "issue", TriggerID: "i", MaxFiles: -1}}
	if err := ValidateTrace(tr); err == nil {
		t.Fatal("expected error for negative budget")
	}
}

func TestValidateTraceContextSelectionsInvalidSpan(t *testing.T) {
	t.Parallel()
	tr := testBundle().Trace
	tr.ContextSelections = []ContextSelectionRecord{{ID: "c", TriggerType: "issue", TriggerID: "i", SelectedSpans: []LocationRef{{RepoRelPath: "", StartLine: 1, EndLine: 1}}}}
	if err := ValidateTrace(tr); err == nil {
		t.Fatal("expected error for invalid span")
	}
}

func TestValidateTraceContextSelectionsValidSpanBadLines(t *testing.T) {
	t.Parallel()
	tr := testBundle().Trace
	tr.ContextSelections = []ContextSelectionRecord{{ID: "c", TriggerType: "issue", TriggerID: "i", SelectedSpans: []LocationRef{{RepoRelPath: "a.ts", StartLine: 0, EndLine: 1}}}}
	if err := ValidateTrace(tr); err == nil {
		t.Fatal("expected error for invalid line range")
	}
}

func TestValidateTraceSkippedRulesMissing(t *testing.T) {
	t.Parallel()
	tr := testBundle().Trace
	tr.SkippedRules = []SkippedRuleTrace{{ID: "", Reason: ""}}
	if err := ValidateTrace(tr); err == nil {
		t.Fatal("expected error for missing skipped rule fields")
	}
}

func TestValidateTraceAnalyzerMissingName(t *testing.T) {
	t.Parallel()
	tr := testBundle().Trace
	tr.Analyzers[0].Name = ""
	if err := ValidateTrace(tr); err == nil {
		t.Fatal("expected error for missing analyzer name")
	}
}

func TestValidateTraceAnalyzerBadStatus(t *testing.T) {
	t.Parallel()
	tr := testBundle().Trace
	tr.Analyzers[0].Status = "x"
	if err := ValidateTrace(tr); err == nil {
		t.Fatal("expected error for invalid analyzer status")
	}
}

func TestValidateTraceCalibrationEmptyBaselines(t *testing.T) {
	t.Parallel()
	tr := testBundle().Trace
	tr.ConfidenceCalibration.RuleFamilyBaselines = nil
	if err := ValidateTrace(tr); err == nil {
		t.Fatal("expected error for empty baselines")
	}
}

func TestValidateTraceCalibrationNoOrdering(t *testing.T) {
	t.Parallel()
	tr := testBundle().Trace
	tr.ConfidenceCalibration.OrderingRules = nil
	if err := ValidateTrace(tr); err == nil {
		t.Fatal("expected error for no ordering rules")
	}
}

func TestValidateTraceCalibrationEmptyFamilyKey(t *testing.T) {
	t.Parallel()
	tr := testBundle().Trace
	tr.ConfidenceCalibration.RuleFamilyBaselines[""] = 0.5
	if err := ValidateTrace(tr); err == nil {
		t.Fatal("expected error for empty family key")
	}
}

func TestValidateTraceCalibrationBadBaseline(t *testing.T) {
	t.Parallel()
	tr := testBundle().Trace
	tr.ConfidenceCalibration.RuleFamilyBaselines["sec_secret"] = 1.5
	if err := ValidateTrace(tr); err == nil {
		t.Fatal("expected error for baseline > 1")
	}
}

func TestValidateTraceCalibrationBadThreshold(t *testing.T) {
	t.Parallel()
	tr := testBundle().Trace
	tr.ConfidenceCalibration.MachineTrustedThreshold = 1.5
	if err := ValidateTrace(tr); err == nil {
		t.Fatal("expected error for threshold > 1")
	}
}

func TestValidateTraceCalibrationBadUnknownCap(t *testing.T) {
	t.Parallel()
	tr := testBundle().Trace
	tr.ConfidenceCalibration.UnknownCap = 1.5
	if err := ValidateTrace(tr); err == nil {
		t.Fatal("expected error for unknown cap > 1")
	}
}

func TestValidateTraceCalibrationBadAgentCap(t *testing.T) {
	t.Parallel()
	tr := testBundle().Trace
	tr.ConfidenceCalibration.AgentOnlyCap = -1
	if err := ValidateTrace(tr); err == nil {
		t.Fatal("expected error for agent cap < 0")
	}
}

func TestValidateTraceCalibrationVersion(t *testing.T) {
	t.Parallel()
	tr := testBundle().Trace
	tr.ConfidenceCalibration.Version = ""
	if err := ValidateTrace(tr); err == nil {
		t.Fatal("expected error for empty calibration version")
	}
}

func TestValidateTraceContextSelectionsMissingID(t *testing.T) {
	t.Parallel()
	tr := testBundle().Trace
	tr.ContextSelections = []ContextSelectionRecord{{ID: "", TriggerType: "issue", TriggerID: "i"}}
	if err := ValidateTrace(tr); err == nil {
		t.Fatal("expected error for missing context selection ID")
	}
}

// -- ValidateClaimsArtifact deeper --

func TestValidateClaimsArtifactAllValidationBranches(t *testing.T) {
	t.Parallel()

	// Invalid schema version
	if ValidateClaimsArtifact(ClaimsArtifact{SchemaVersion: "wrong"}) == nil {
		t.Fatal("expected error for wrong schema")
	}
	// Missing repo
	if ValidateClaimsArtifact(ClaimsArtifact{SchemaVersion: ClaimsSchemaVersion}) == nil {
		t.Fatal("expected error for missing repo")
	}
	// Empty claims
	if ValidateClaimsArtifact(ClaimsArtifact{SchemaVersion: ClaimsSchemaVersion, Repository: ClaimRepositoryRef{Path: "/r", Commit: "c"}}) == nil {
		t.Fatal("expected error for empty claims")
	}
	// Missing claim ID
	if ValidateClaimsArtifact(ClaimsArtifact{SchemaVersion: ClaimsSchemaVersion, Repository: ClaimRepositoryRef{Path: "/r", Commit: "c"}, Claims: []ClaimRecord{{}}}) == nil {
		t.Fatal("expected error for missing claim ID")
	}
	// Duplicate claim ID
	c := validClaimRecord("c-1")
	if ValidateClaimsArtifact(ClaimsArtifact{SchemaVersion: ClaimsSchemaVersion, Repository: ClaimRepositoryRef{Path: "/r", Commit: "c"}, Claims: []ClaimRecord{c, c}}) == nil {
		t.Fatal("expected error for dup claim ID")
	}
	// Missing title
	c2 := validClaimRecord("c-1")
	c2.Title = ""
	if ValidateClaimsArtifact(ClaimsArtifact{SchemaVersion: ClaimsSchemaVersion, Repository: ClaimRepositoryRef{Path: "/r", Commit: "c"}, Claims: []ClaimRecord{c2}}) == nil {
		t.Fatal("expected error for missing title")
	}
	// Invalid claim type
	c3 := validClaimRecord("c-1")
	c3.ClaimType = "bad"
	if ValidateClaimsArtifact(ClaimsArtifact{SchemaVersion: ClaimsSchemaVersion, Repository: ClaimRepositoryRef{Path: "/r", Commit: "c"}, Claims: []ClaimRecord{c3}}) == nil {
		t.Fatal("expected error for bad claim type")
	}
	// Invalid status
	c4 := validClaimRecord("c-1")
	c4.Status = "bad"
	if ValidateClaimsArtifact(ClaimsArtifact{SchemaVersion: ClaimsSchemaVersion, Repository: ClaimRepositoryRef{Path: "/r", Commit: "c"}, Claims: []ClaimRecord{c4}}) == nil {
		t.Fatal("expected error for bad status")
	}
	// Invalid support level
	c5 := validClaimRecord("c-1")
	c5.SupportLevel = "bad"
	if ValidateClaimsArtifact(ClaimsArtifact{SchemaVersion: ClaimsSchemaVersion, Repository: ClaimRepositoryRef{Path: "/r", Commit: "c"}, Claims: []ClaimRecord{c5}}) == nil {
		t.Fatal("expected error for bad support level")
	}
	// Invalid confidence
	c6 := validClaimRecord("c-1")
	c6.Confidence = 1.5
	if ValidateClaimsArtifact(ClaimsArtifact{SchemaVersion: ClaimsSchemaVersion, Repository: ClaimRepositoryRef{Path: "/r", Commit: "c"}, Claims: []ClaimRecord{c6}}) == nil {
		t.Fatal("expected error for bad confidence")
	}
	// Missing source origins
	c7 := validClaimRecord("c-1")
	c7.SourceOrigins = nil
	if ValidateClaimsArtifact(ClaimsArtifact{SchemaVersion: ClaimsSchemaVersion, Repository: ClaimRepositoryRef{Path: "/r", Commit: "c"}, Claims: []ClaimRecord{c7}}) == nil {
		t.Fatal("expected error for missing origins")
	}
	// Missing evidence
	c8 := validClaimRecord("c-1")
	c8.SupportingEvidenceIDs = nil
	c8.ContradictoryEvidenceIDs = nil
	if ValidateClaimsArtifact(ClaimsArtifact{SchemaVersion: ClaimsSchemaVersion, Repository: ClaimRepositoryRef{Path: "/r", Commit: "c"}, Claims: []ClaimRecord{c8}}) == nil {
		t.Fatal("expected error for missing evidence")
	}
	// Projection eligible for weak
	c9 := validClaimRecord("c-1")
	c9.SupportLevel = "weak"
	c9.ProjectionEligible = true
	if ValidateClaimsArtifact(ClaimsArtifact{SchemaVersion: ClaimsSchemaVersion, Repository: ClaimRepositoryRef{Path: "/r", Commit: "c"}, Claims: []ClaimRecord{c9}}) == nil {
		t.Fatal("expected error for projection eligible weak")
	}
}

// -- ValidateProfileArtifact deeper --

func TestValidateProfileArtifactAllBranches(t *testing.T) {
	t.Parallel()

	if ValidateProfileArtifact(ProfileArtifact{SchemaVersion: "wrong"}) == nil {
		t.Fatal("expected error for wrong schema")
	}
	if ValidateProfileArtifact(ProfileArtifact{SchemaVersion: ProfileSchemaVersion}) == nil {
		t.Fatal("expected error for missing repo")
	}
	if ValidateProfileArtifact(ProfileArtifact{SchemaVersion: ProfileSchemaVersion, Repository: ClaimRepositoryRef{Path: "/r", Commit: "c"}}) == nil {
		t.Fatal("expected error for missing claim_ids")
	}
	// Highlight missing ID
	if ValidateProfileArtifact(ProfileArtifact{SchemaVersion: ProfileSchemaVersion, Repository: ClaimRepositoryRef{Path: "/r", Commit: "c"}, ClaimIDs: []string{"c"}, Highlights: []CapabilityHighlight{{}}}) == nil {
		t.Fatal("expected error for highlight missing ID")
	}
	// Highlight bad support level
	if ValidateProfileArtifact(ProfileArtifact{SchemaVersion: ProfileSchemaVersion, Repository: ClaimRepositoryRef{Path: "/r", Commit: "c"}, ClaimIDs: []string{"c"}, Highlights: []CapabilityHighlight{{HighlightID: "h", Title: "t", SupportLevel: "x"}}}) == nil {
		t.Fatal("expected error for bad highlight level")
	}
	// Highlight supported (not verified/strongly)
	if ValidateProfileArtifact(ProfileArtifact{SchemaVersion: ProfileSchemaVersion, Repository: ClaimRepositoryRef{Path: "/r", Commit: "c"}, ClaimIDs: []string{"c"}, Highlights: []CapabilityHighlight{{HighlightID: "h", Title: "t", SupportLevel: "supported", ClaimIDs: []string{"c"}, SupportingEvidenceIDs: []string{"e"}}}}) == nil {
		t.Fatal("expected error for supported highlight")
	}
	// Highlight missing claim_ids
	if ValidateProfileArtifact(ProfileArtifact{SchemaVersion: ProfileSchemaVersion, Repository: ClaimRepositoryRef{Path: "/r", Commit: "c"}, ClaimIDs: []string{"c"}, Highlights: []CapabilityHighlight{{HighlightID: "h", Title: "t", SupportLevel: "verified"}}}) == nil {
		t.Fatal("expected error for highlight missing claim_ids")
	}
	// Area missing ID
	if ValidateProfileArtifact(ProfileArtifact{SchemaVersion: ProfileSchemaVersion, Repository: ClaimRepositoryRef{Path: "/r", Commit: "c"}, ClaimIDs: []string{"c"}, CapabilityAreas: []CapabilityArea{{}}}) == nil {
		t.Fatal("expected error for area missing ID")
	}
	// Area missing claim_ids
	if ValidateProfileArtifact(ProfileArtifact{SchemaVersion: ProfileSchemaVersion, Repository: ClaimRepositoryRef{Path: "/r", Commit: "c"}, ClaimIDs: []string{"c"}, CapabilityAreas: []CapabilityArea{{AreaID: "a", Title: "t"}}}) == nil {
		t.Fatal("expected error for area missing claim_ids")
	}
}

// -- ValidateResumeInputArtifact deeper --

func TestValidateResumeInputArtifactAllBranches(t *testing.T) {
	t.Parallel()

	if ValidateResumeInputArtifact(ResumeInputArtifact{SchemaVersion: "wrong"}) == nil {
		t.Fatal("expected error for wrong schema")
	}
	// Valid but missing verified claims support level
	b := testBundleWithClaims()
	ri := b.ResumeInput
	ri.VerifiedClaims[0].SupportLevel = "strongly_supported"
	if ValidateResumeInputArtifact(*ri) == nil {
		t.Fatal("expected error for wrong support level in verified claims")
	}
	// Strongly supported but wrong level
	ri2 := b.ResumeInput
	ri2.StronglySupportedClaims = []ResumeClaimStub{{ClaimID: "c", Title: "t", SupportLevel: "verified", Confidence: 0.9, SupportingEvidenceIDs: []string{"e"}}}
	if ValidateResumeInputArtifact(*ri2) == nil {
		t.Fatal("expected error for wrong level in strongly_supported")
	}
	// Evidence ref missing ID
	ri3 := b.ResumeInput
	ri3.EvidenceReferences = []EvidenceReference{{EvidenceID: ""}}
	if ValidateResumeInputArtifact(*ri3) == nil {
		t.Fatal("expected error for missing evidence ref ID")
	}
	// Evidence ref missing claim_ids
	ri4 := b.ResumeInput
	ri4.EvidenceReferences = []EvidenceReference{{EvidenceID: "e"}}
	if ValidateResumeInputArtifact(*ri4) == nil {
		t.Fatal("expected error for missing evidence ref claim_ids")
	}
}

// -- validateIssuePolicyConsistency deeper --

func TestValidateIssuePolicyMachineTrustedUnknownStatus(t *testing.T) {
	t.Parallel()
	iss := testBundle().Report.Issues[0]
	iss.PolicyClass = "machine_trusted"
	iss.Status = "unknown"
	if validateIssuePolicyConsistency(iss, "t") == nil {
		t.Fatal("expected error for mt + unknown")
	}
}

func TestValidateIssuePolicyMachineTrustedLowConfClass(t *testing.T) {
	t.Parallel()
	iss := testBundle().Report.Issues[0]
	iss.PolicyClass = "machine_trusted"
	iss.ConfidenceClass = "moderate"
	if validateIssuePolicyConsistency(iss, "t") == nil {
		t.Fatal("expected error for mt + moderate")
	}
}

func TestValidateIssuePolicyMachineTrustedNilBreakdown(t *testing.T) {
	t.Parallel()
	iss := testBundle().Report.Issues[0]
	iss.PolicyClass = "machine_trusted"
	iss.ConfidenceBreakdown = nil
	if validateIssuePolicyConsistency(iss, "t") == nil {
		t.Fatal("expected error for mt + nil breakdown")
	}
}

func TestValidateIssuePolicyMachineTrustedLowConf(t *testing.T) {
	t.Parallel()
	iss := testBundle().Report.Issues[0]
	iss.PolicyClass = "machine_trusted"
	iss.Confidence = 0.70
	if validateIssuePolicyConsistency(iss, "t") == nil {
		t.Fatal("expected error for mt + low confidence")
	}
}

func TestValidateIssuePolicyMachineTrustedBadBreakdown(t *testing.T) {
	t.Parallel()
	iss := testBundle().Report.Issues[0]
	iss.PolicyClass = "machine_trusted"
	iss.ConfidenceBreakdown.RuleReliability = 0.50
	if validateIssuePolicyConsistency(iss, "t") == nil {
		t.Fatal("expected error for mt + weak breakdown")
	}
}

// -- ValidateSkills deeper --

func TestValidateSkillsMissingContribIssueIDs(t *testing.T) {
	t.Parallel()
	s := testBundle().Skills
	s.Skills[0].ContributingIssueIDs = nil
	if ValidateSkills(s) == nil {
		t.Fatal("expected error for missing contributing_issue_ids")
	}
}

func TestValidateSkillsMissingContribEvIDs(t *testing.T) {
	t.Parallel()
	s := testBundle().Skills
	s.Skills[0].ContributingEvidenceIDs = nil
	if ValidateSkills(s) == nil {
		t.Fatal("expected error for missing contributing_evidence_ids")
	}
}

func TestValidateSkillsBadConfidence(t *testing.T) {
	t.Parallel()
	s := testBundle().Skills
	s.Skills[0].Confidence = 1.5
	if ValidateSkills(s) == nil {
		t.Fatal("expected error for confidence > 1")
	}
}

// -- validateCrossReferences deeper --

func TestValidateCrossRefCounterEvidence(t *testing.T) {
	t.Parallel()
	b := testBundle()
	b.Report.Issues[0].CounterEvidenceIDs = []string{"ev-missing"}
	if validateCrossReferences(b) == nil {
		t.Fatal("expected error for counter evidence ref")
	}
}

func TestValidateCrossRefSkillIssue(t *testing.T) {
	t.Parallel()
	b := testBundle()
	b.Skills.Skills[0].ContributingIssueIDs = []string{"iss-missing"}
	if validateCrossReferences(b) == nil {
		t.Fatal("expected error for skill issue ref")
	}
}

func TestValidateCrossRefSkillEvidence(t *testing.T) {
	t.Parallel()
	b := testBundle()
	b.Skills.Skills[0].ContributingEvidenceIDs = []string{"ev-missing"}
	if validateCrossReferences(b) == nil {
		t.Fatal("expected error for skill evidence ref")
	}
}

func TestValidateCrossRefAgentIssue(t *testing.T) {
	t.Parallel()
	b := testBundle()
	b.Trace.Agents[0].IssueID = "iss-missing"
	if validateCrossReferences(b) == nil {
		t.Fatal("expected error for agent issue ref")
	}
}

func TestValidateCrossRefAgentInputEv(t *testing.T) {
	t.Parallel()
	b := testBundle()
	b.Trace.Agents[0].InputEvidenceIDs = []string{"ev-missing"}
	if validateCrossReferences(b) == nil {
		t.Fatal("expected error for agent input ev ref")
	}
}

func TestValidateCrossRefAgentOutputEv(t *testing.T) {
	t.Parallel()
	b := testBundle()
	b.Trace.Agents[0].OutputEvidenceIDs = []string{"ev-missing"}
	if validateCrossReferences(b) == nil {
		t.Fatal("expected error for agent output ev ref")
	}
}

func TestValidateCrossRefDerivUnknownIssue(t *testing.T) {
	t.Parallel()
	b := testBundle()
	b.Trace.Derivations[0].IssueID = "iss-missing"
	if validateCrossReferences(b) == nil {
		t.Fatal("expected error for derivation unknown issue")
	}
}

func TestValidateCrossRefDerivMissingFP(t *testing.T) {
	t.Parallel()
	b := testBundle()
	b.Trace.Derivations[0].IssueFingerprint = ""
	if validateCrossReferences(b) == nil {
		t.Fatal("expected error for missing fingerprint")
	}
}

func TestValidateCrossRefDerivFPMismatch(t *testing.T) {
	t.Parallel()
	b := testBundle()
	b.Trace.Derivations[0].IssueFingerprint = "wrong"
	if validateCrossReferences(b) == nil {
		t.Fatal("expected error for fingerprint mismatch")
	}
}

func TestValidateCrossRefDerivUnknownEv(t *testing.T) {
	t.Parallel()
	b := testBundle()
	b.Trace.Derivations[0].DerivedFromEvidenceIDs = []string{"ev-missing"}
	if validateCrossReferences(b) == nil {
		t.Fatal("expected error for derivation unknown evidence")
	}
}

// -- buildContextBundle: file budget reached --

func TestBuildContextBundleFileBudgetReached(t *testing.T) {
	t.Parallel()
	candidate := IssueCandidate{
		ID:          "iss-1",
		EvidenceIDs: []string{"ev-1"},
	}
	evidenceIndex := map[string]EvidenceRecord{
		"ev-1": {
			ID: "ev-1",
			Locations: []LocationRef{
				{RepoRelPath: "a.ts", StartLine: 1, EndLine: 1},
				{RepoRelPath: "b.ts", StartLine: 2, EndLine: 2},
				{RepoRelPath: "c.ts", StartLine: 3, EndLine: 3},
			},
		},
	}
	b := buildContextBundle(ContextRequest{TriggerType: "issue", TriggerID: "iss-1", MaxFiles: 1, MaxSpans: 10, MaxTokens: 1200}, candidate, evidenceIndex)
	// Only 1 file allowed, so only spans from first file
	if len(b.Spans) != 1 {
		t.Fatalf("expected 1 span due to file budget, got %d", len(b.Spans))
	}
}

// -- buildContextBundle: span budget break --

func TestBuildContextBundleSpanBudgetExhaustedBreaks(t *testing.T) {
	t.Parallel()
	candidate := IssueCandidate{
		ID:          "iss-1",
		EvidenceIDs: []string{"ev-1", "ev-2"},
	}
	evidenceIndex := map[string]EvidenceRecord{
		"ev-1": {ID: "ev-1", Locations: []LocationRef{
			{RepoRelPath: "a.ts", StartLine: 1, EndLine: 1},
			{RepoRelPath: "a.ts", StartLine: 2, EndLine: 2},
		}},
		"ev-2": {ID: "ev-2", Locations: []LocationRef{
			{RepoRelPath: "a.ts", StartLine: 3, EndLine: 3},
		}},
	}
	b := buildContextBundle(ContextRequest{TriggerType: "issue", TriggerID: "iss-1", MaxFiles: 10, MaxSpans: 2, MaxTokens: 1200}, candidate, evidenceIndex)
	if len(b.Spans) != 2 {
		t.Fatalf("expected 2 spans due to span budget, got %d", len(b.Spans))
	}
}

// -- BuildCompatArtifacts with AgentExecutor that produces error result --

func TestBuildCompatArtifactsAgentExecutorFailedResult(t *testing.T) {
	t.Parallel()
	input := CompatBuildInput{
		Scan: report.ScanReport{RepoName: "r", CommitSHA: "abc123def456", ScannedAt: "2026-03-27T12:00:00Z", FileCount: 3, BoundaryMode: "repo"},
		Verification: VerificationSource{
			ReportSchemaVersion: "1.0.0",
			IssueSeeds: []IssueSeed{{RuleID: "D-1", Title: "U", Source: "rule", Category: "design", Severity: "high", Status: "unknown", Confidence: 0.62, Quality: 0.7, File: "s.ts", Symbol: "fn", StartLine: 1, EndLine: 5}},
		},
		AgentExecutor: func(task AgentTask) (AgentResult, error) { return AgentResult{Status: "completed"}, nil },
		EngineVersion: "dev",
	}
	result, err := BuildCompatArtifacts(input)
	if err != nil {
		t.Fatalf("BuildCompatArtifacts: %v", err)
	}
	if result == nil {
		t.Fatal("expected result")
	}
}

// -- validateConfidenceBreakdown --

func TestValidateConfidenceBreakdownInvalid(t *testing.T) {
	t.Parallel()
	if validateConfidenceBreakdown(ConfidenceBreakdown{Final: 1.5}, "p") == nil {
		t.Fatal("expected error for final > 1")
	}
	if validateConfidenceBreakdown(ConfidenceBreakdown{RuleReliability: -1}, "p") == nil {
		t.Fatal("expected error for negative rule reliability")
	}
}

// -- validClaimStatus and validClaimType branches --

func TestValidClaimStatusAll(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"accepted", "downgraded", "rejected", "unknown"} {
		if !validClaimStatus(s) {
			t.Errorf("expected valid for %q", s)
		}
	}
	if validClaimStatus("bad") {
		t.Fatal("expected invalid")
	}
}

func TestValidClaimTypeAll(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"implementation", "architecture", "security_maturity", "testing_maturity", "evaluation_maturity", "operational_maturity"} {
		if !validClaimType(s) {
			t.Errorf("expected valid for %q", s)
		}
	}
	if validClaimType("bad") {
		t.Fatal("expected invalid")
	}
}

// -- compatIssueStatus resolved branch --

func TestCompatIssueStatusResolved(t *testing.T) {
	t.Parallel()
	if compatIssueStatus(rules.StatusPass) != "resolved" {
		t.Fatal("expected resolved")
	}
}

// -- compatSkillWeight structural --

func TestCompatSkillWeightStructural(t *testing.T) {
	t.Parallel()
	if compatSkillWeight("structural") != 0.7 {
		t.Fatal("expected 0.7")
	}
}

// -- WriteClaimsProfileResumeArtifacts validation failure --

func TestWriteClaimsProfileResumeArtifactsValidationFail(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if WriteClaimsProfileResumeArtifacts(dir, ClaimsProjectionArtifacts{Claims: ClaimsArtifact{SchemaVersion: "wrong"}}) == nil {
		t.Fatal("expected error")
	}
}

// -- BuildClaimsProfileResumeArtifacts input validation --

func TestBuildClaimsProfileResumeArtifactsBadInput(t *testing.T) {
	t.Parallel()
	if _, err := BuildClaimsProfileResumeArtifacts(ClaimsProjectionInput{Repository: ClaimRepositoryRef{Path: "", Commit: "c"}}); err == nil {
		t.Fatal("expected error for bad input")
	}
}
