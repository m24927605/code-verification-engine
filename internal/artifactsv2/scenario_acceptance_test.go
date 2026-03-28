package artifactsv2

import (
	"encoding/json"
	"testing"
)

// --- VerificationClass tests ---

func TestVerificationClassIsValid(t *testing.T) {
	valid := []VerificationClass{
		VerificationProofGrade,
		VerificationStructuralInference,
		VerificationHeuristicAdvisory,
		VerificationHumanOrRuntimeRequired,
	}
	for _, vc := range valid {
		if !vc.IsValid() {
			t.Errorf("expected %q to be valid", vc)
		}
	}
	if VerificationClass("bogus").IsValid() {
		t.Error("expected bogus to be invalid")
	}
	if VerificationClass("").IsValid() {
		t.Error("expected empty to be invalid")
	}
}

func TestValidVerificationClassesCoversAll(t *testing.T) {
	all := ValidVerificationClasses()
	if len(all) != 4 {
		t.Fatalf("expected 4 verification classes, got %d", len(all))
	}
	for _, vc := range all {
		if !vc.IsValid() {
			t.Errorf("ValidVerificationClasses returned invalid class %q", vc)
		}
	}
}

// --- AcceptanceIntent tests ---

func TestAcceptanceIntentIsValid(t *testing.T) {
	valid := []AcceptanceIntent{
		AcceptanceIntentExistence,
		AcceptanceIntentBinding,
		AcceptanceIntentBoundary,
		AcceptanceIntentMaturity,
		AcceptanceIntentNegativeExhaustive,
	}
	for _, ai := range valid {
		if !ai.IsValid() {
			t.Errorf("expected %q to be valid", ai)
		}
	}
	if AcceptanceIntent("invalid").IsValid() {
		t.Error("expected invalid intent to be invalid")
	}
}

// --- TrustClassValue tests ---

func TestTrustClassValueIsValid(t *testing.T) {
	valid := []TrustClassValue{
		TrustClassMachineTrusted,
		TrustClassAdvisory,
		TrustClassHumanOrRuntimeRequired,
	}
	for _, tc := range valid {
		if !tc.IsValid() {
			t.Errorf("expected %q to be valid", tc)
		}
	}
	if TrustClassValue("nope").IsValid() {
		t.Error("expected nope to be invalid")
	}
}

// --- OutsourceAcceptanceArtifact validation tests ---

func validOutsourceAcceptance() OutsourceAcceptanceArtifact {
	return OutsourceAcceptanceArtifact{
		SchemaVersion:     OutsourceAcceptanceSchemaVersion,
		Repository:        AcceptanceRepositoryRef{Path: "/repo", Commit: "abc123"},
		TraceID:           "trace-001",
		AcceptanceProfile: "outsource-backend-api",
		Summary: OutsourceAcceptanceSummary{
			Passed:           1,
			Failed:           1,
			Unknown:          0,
			RuntimeRequired:  0,
			ProofGradeRows:   1,
			BlockingFailures: 1,
		},
		Requirements: []OutsourceRequirementRow{
			{
				RequirementID:            "oa-001",
				Title:                    "Auth middleware binding",
				Category:                 "security",
				Status:                   "passed",
				VerificationClass:        VerificationProofGrade,
				TrustClass:               TrustClassMachineTrusted,
				Blocking:                 true,
				AcceptanceIntent:         AcceptanceIntentBinding,
				ClaimIDs:                 []string{"security.route_auth_binding"},
				SupportingEvidenceIDs:    []string{"ev-101"},
				ContradictoryEvidenceIDs: []string{},
				Reason:                   "All protected routes bind auth middleware.",
				UnknownReasons:           []string{},
			},
			{
				RequirementID:            "oa-002",
				Title:                    "No hardcoded secrets",
				Category:                 "security",
				Status:                   "failed",
				VerificationClass:        VerificationStructuralInference,
				TrustClass:               TrustClassAdvisory,
				Blocking:                 true,
				AcceptanceIntent:         AcceptanceIntentNegativeExhaustive,
				ClaimIDs:                 []string{"security.hardcoded_secret_present"},
				SupportingEvidenceIDs:    []string{"ev-201"},
				ContradictoryEvidenceIDs: []string{},
				Reason:                   "Hardcoded secret found.",
				UnknownReasons:           []string{},
			},
		},
	}
}

func TestValidateOutsourceAcceptanceArtifact_Valid(t *testing.T) {
	a := validOutsourceAcceptance()
	if err := ValidateOutsourceAcceptanceArtifact(a); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateOutsourceAcceptanceArtifact_MissingSchemaVersion(t *testing.T) {
	a := validOutsourceAcceptance()
	a.SchemaVersion = "9.9.9"
	if err := ValidateOutsourceAcceptanceArtifact(a); err == nil {
		t.Fatal("expected error for wrong schema version")
	}
}

func TestValidateOutsourceAcceptanceArtifact_MissingRepo(t *testing.T) {
	a := validOutsourceAcceptance()
	a.Repository.Path = ""
	if err := ValidateOutsourceAcceptanceArtifact(a); err == nil {
		t.Fatal("expected error for missing repository path")
	}
}

func TestValidateOutsourceAcceptanceArtifact_MissingTraceID(t *testing.T) {
	a := validOutsourceAcceptance()
	a.TraceID = ""
	if err := ValidateOutsourceAcceptanceArtifact(a); err == nil {
		t.Fatal("expected error for missing trace_id")
	}
}

func TestValidateOutsourceAcceptanceArtifact_DuplicateRequirementID(t *testing.T) {
	a := validOutsourceAcceptance()
	a.Requirements[1].RequirementID = a.Requirements[0].RequirementID
	if err := ValidateOutsourceAcceptanceArtifact(a); err == nil {
		t.Fatal("expected error for duplicate requirement_id")
	}
}

func TestValidateOutsourceAcceptanceArtifact_SummaryMismatch(t *testing.T) {
	a := validOutsourceAcceptance()
	a.Summary.Passed = 99
	if err := ValidateOutsourceAcceptanceArtifact(a); err == nil {
		t.Fatal("expected error for summary mismatch")
	}
}

func TestValidateOutsourceAcceptanceArtifact_InvalidStatus(t *testing.T) {
	a := validOutsourceAcceptance()
	a.Requirements[0].Status = "bogus"
	if err := ValidateOutsourceAcceptanceArtifact(a); err == nil {
		t.Fatal("expected error for invalid status")
	}
}

func TestValidateOutsourceAcceptanceArtifact_InvalidVerificationClass(t *testing.T) {
	a := validOutsourceAcceptance()
	a.Requirements[0].VerificationClass = "bogus"
	if err := ValidateOutsourceAcceptanceArtifact(a); err == nil {
		t.Fatal("expected error for invalid verification_class")
	}
}

func TestValidateOutsourceAcceptanceArtifact_InvalidTrustClass(t *testing.T) {
	a := validOutsourceAcceptance()
	a.Requirements[0].TrustClass = "bogus"
	if err := ValidateOutsourceAcceptanceArtifact(a); err == nil {
		t.Fatal("expected error for invalid trust_class")
	}
}

func TestValidateOutsourceAcceptanceArtifact_InvalidAcceptanceIntent(t *testing.T) {
	a := validOutsourceAcceptance()
	a.Requirements[0].AcceptanceIntent = "bogus"
	if err := ValidateOutsourceAcceptanceArtifact(a); err == nil {
		t.Fatal("expected error for invalid acceptance_intent")
	}
}

func TestValidateOutsourceAcceptanceArtifact_MissingClaimIDs(t *testing.T) {
	a := validOutsourceAcceptance()
	a.Requirements[0].ClaimIDs = nil
	if err := ValidateOutsourceAcceptanceArtifact(a); err == nil {
		t.Fatal("expected error for missing claim_ids")
	}
}

func TestValidateOutsourceAcceptanceArtifact_MissingReason(t *testing.T) {
	a := validOutsourceAcceptance()
	a.Requirements[0].Reason = ""
	if err := ValidateOutsourceAcceptanceArtifact(a); err == nil {
		t.Fatal("expected error for missing reason")
	}
}

func TestValidateOutsourceAcceptanceArtifact_ProofPassRequiresMachineTrusted(t *testing.T) {
	a := validOutsourceAcceptance()
	a.Requirements[0].TrustClass = TrustClassAdvisory
	if err := ValidateOutsourceAcceptanceArtifact(a); err == nil {
		t.Fatal("expected error: proof_grade passed row must be machine_trusted")
	}
}

func TestValidateOutsourceAcceptanceArtifact_NonProofPassMustNotBeMachineTrusted(t *testing.T) {
	a := validOutsourceAcceptance()
	a.Requirements[0].VerificationClass = VerificationStructuralInference
	a.Requirements[0].TrustClass = TrustClassMachineTrusted
	// Fix summary for reconciliation
	a.Summary.ProofGradeRows = 0
	if err := ValidateOutsourceAcceptanceArtifact(a); err == nil {
		t.Fatal("expected error: non-proof_grade passed row must not be machine_trusted")
	}
}

func TestValidateOutsourceAcceptanceArtifact_UnknownRequiresReasons(t *testing.T) {
	a := validOutsourceAcceptance()
	a.Requirements[0].Status = "unknown"
	a.Requirements[0].VerificationClass = VerificationHumanOrRuntimeRequired
	a.Requirements[0].TrustClass = TrustClassHumanOrRuntimeRequired
	a.Requirements[0].UnknownReasons = []string{} // empty
	// Fix summary for reconciliation
	a.Summary.Passed = 0
	a.Summary.Unknown = 1
	a.Summary.ProofGradeRows = 0
	a.Summary.BlockingFailures = 0
	if err := ValidateOutsourceAcceptanceArtifact(a); err == nil {
		t.Fatal("expected error: unknown status requires unknown_reasons")
	}
}

// --- PMAcceptanceArtifact validation tests ---

func validPMAcceptance() PMAcceptanceArtifact {
	return PMAcceptanceArtifact{
		SchemaVersion:     PMAcceptanceSchemaVersion,
		Repository:        AcceptanceRepositoryRef{Path: "/repo", Commit: "abc123"},
		TraceID:           "trace-001",
		AcceptanceProfile: "pm-engineering-default",
		Summary: PMAcceptanceSummary{
			Implemented:     1,
			Partial:         0,
			Blocked:         1,
			Unknown:         0,
			RuntimeRequired: 0,
			ProofGradeRows:  1,
		},
		EngineeringRequirements: []PMEngineeringRequirement{
			{
				RequirementID:            "pm-eng-001",
				Title:                    "Auth middleware wiring",
				Category:                 "engineering_delivery",
				Status:                   "implemented",
				VerificationClass:        VerificationProofGrade,
				TrustClass:               TrustClassMachineTrusted,
				DeliveryScope:            "implemented",
				ClaimIDs:                 []string{"security.route_auth_binding"},
				SupportingEvidenceIDs:    []string{"ev-101"},
				ContradictoryEvidenceIDs: []string{},
				Reason:                   "Route graph resolved through auth middleware.",
				FollowUpAction:           "",
			},
			{
				RequirementID:            "pm-eng-002",
				Title:                    "No hardcoded secrets",
				Category:                 "engineering_delivery",
				Status:                   "blocked",
				VerificationClass:        VerificationStructuralInference,
				TrustClass:               TrustClassAdvisory,
				DeliveryScope:            "blocked",
				ClaimIDs:                 []string{"security.hardcoded_secret_present"},
				SupportingEvidenceIDs:    []string{"ev-201"},
				ContradictoryEvidenceIDs: []string{},
				Reason:                   "Hardcoded secret detected.",
				FollowUpAction:           "Remove hardcoded secret and use environment variable.",
			},
		},
	}
}

func TestValidatePMAcceptanceArtifact_Valid(t *testing.T) {
	a := validPMAcceptance()
	if err := ValidatePMAcceptanceArtifact(a); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidatePMAcceptanceArtifact_MissingSchemaVersion(t *testing.T) {
	a := validPMAcceptance()
	a.SchemaVersion = "wrong"
	if err := ValidatePMAcceptanceArtifact(a); err == nil {
		t.Fatal("expected error for wrong schema version")
	}
}

func TestValidatePMAcceptanceArtifact_MissingRepo(t *testing.T) {
	a := validPMAcceptance()
	a.Repository.Commit = ""
	if err := ValidatePMAcceptanceArtifact(a); err == nil {
		t.Fatal("expected error for missing repository commit")
	}
}

func TestValidatePMAcceptanceArtifact_MissingTraceID(t *testing.T) {
	a := validPMAcceptance()
	a.TraceID = ""
	if err := ValidatePMAcceptanceArtifact(a); err == nil {
		t.Fatal("expected error for missing trace_id")
	}
}

func TestValidatePMAcceptanceArtifact_DuplicateRequirementID(t *testing.T) {
	a := validPMAcceptance()
	a.EngineeringRequirements[1].RequirementID = a.EngineeringRequirements[0].RequirementID
	if err := ValidatePMAcceptanceArtifact(a); err == nil {
		t.Fatal("expected error for duplicate requirement_id")
	}
}

func TestValidatePMAcceptanceArtifact_SummaryMismatch(t *testing.T) {
	a := validPMAcceptance()
	a.Summary.Implemented = 99
	if err := ValidatePMAcceptanceArtifact(a); err == nil {
		t.Fatal("expected error for summary mismatch")
	}
}

func TestValidatePMAcceptanceArtifact_InvalidStatus(t *testing.T) {
	a := validPMAcceptance()
	a.EngineeringRequirements[0].Status = "done"
	if err := ValidatePMAcceptanceArtifact(a); err == nil {
		t.Fatal("expected error for invalid status")
	}
}

func TestValidatePMAcceptanceArtifact_InvalidDeliveryScope(t *testing.T) {
	a := validPMAcceptance()
	a.EngineeringRequirements[0].DeliveryScope = "shipped"
	if err := ValidatePMAcceptanceArtifact(a); err == nil {
		t.Fatal("expected error for invalid delivery_scope")
	}
}

func TestValidatePMAcceptanceArtifact_MissingClaimIDs(t *testing.T) {
	a := validPMAcceptance()
	a.EngineeringRequirements[0].ClaimIDs = nil
	if err := ValidatePMAcceptanceArtifact(a); err == nil {
		t.Fatal("expected error for missing claim_ids")
	}
}

func TestValidatePMAcceptanceArtifact_MissingReason(t *testing.T) {
	a := validPMAcceptance()
	a.EngineeringRequirements[0].Reason = ""
	if err := ValidatePMAcceptanceArtifact(a); err == nil {
		t.Fatal("expected error for missing reason")
	}
}

// --- JSON serialization tests ---

func TestOutsourceAcceptanceJSON_RoundTrip(t *testing.T) {
	a := validOutsourceAcceptance()
	data, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	var decoded OutsourceAcceptanceArtifact
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if decoded.SchemaVersion != a.SchemaVersion {
		t.Errorf("schema_version mismatch: %q vs %q", decoded.SchemaVersion, a.SchemaVersion)
	}
	if len(decoded.Requirements) != len(a.Requirements) {
		t.Fatalf("requirements length mismatch")
	}
	if decoded.Requirements[0].VerificationClass != VerificationProofGrade {
		t.Errorf("expected proof_grade, got %q", decoded.Requirements[0].VerificationClass)
	}
	if decoded.Requirements[0].AcceptanceIntent != AcceptanceIntentBinding {
		t.Errorf("expected binding_check, got %q", decoded.Requirements[0].AcceptanceIntent)
	}
}

func TestPMAcceptanceJSON_RoundTrip(t *testing.T) {
	a := validPMAcceptance()
	data, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	var decoded PMAcceptanceArtifact
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if decoded.SchemaVersion != a.SchemaVersion {
		t.Errorf("schema_version mismatch")
	}
	if len(decoded.EngineeringRequirements) != len(a.EngineeringRequirements) {
		t.Fatalf("engineering_requirements length mismatch")
	}
	if decoded.EngineeringRequirements[0].DeliveryScope != "implemented" {
		t.Errorf("expected delivery_scope=implemented, got %q", decoded.EngineeringRequirements[0].DeliveryScope)
	}
}

func TestClaimRecordWithVerificationClass_JSON(t *testing.T) {
	claim := ClaimRecord{
		ClaimID:               "security.route_auth_binding",
		Title:                 "Auth route binding",
		Category:              "security_maturity",
		ClaimType:             "implementation",
		Status:                "accepted",
		SupportLevel:          "verified",
		Confidence:            0.95,
		VerificationClass:     VerificationProofGrade,
		ScenarioApplicability: &ScenarioApplicability{Hiring: true, OutsourceAcceptance: true, PMAcceptance: true},
		SourceOrigins:         []string{"rule"},
		SupportingEvidenceIDs: []string{"ev-101"},
		Reason:                "Route binding verified.",
		ProjectionEligible:    true,
	}
	data, err := json.Marshal(claim)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	var decoded ClaimRecord
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if decoded.VerificationClass != VerificationProofGrade {
		t.Errorf("expected proof_grade, got %q", decoded.VerificationClass)
	}
	if decoded.ScenarioApplicability == nil {
		t.Fatal("expected scenario_applicability to be non-nil")
	}
	if !decoded.ScenarioApplicability.Hiring {
		t.Error("expected hiring=true")
	}
}

// --- Fix 1: Evidence traceability tests ---

func TestValidateOutsourceAcceptanceArtifact_MissingEvidence(t *testing.T) {
	a := validOutsourceAcceptance()
	a.Requirements[0].SupportingEvidenceIDs = nil
	a.Requirements[0].ContradictoryEvidenceIDs = nil
	if err := ValidateOutsourceAcceptanceArtifact(a); err == nil {
		t.Fatal("expected error: row with no evidence references should fail traceability")
	}
}

func TestValidatePMAcceptanceArtifact_MissingEvidence(t *testing.T) {
	a := validPMAcceptance()
	a.EngineeringRequirements[0].SupportingEvidenceIDs = nil
	a.EngineeringRequirements[0].ContradictoryEvidenceIDs = nil
	if err := ValidatePMAcceptanceArtifact(a); err == nil {
		t.Fatal("expected error: row with no evidence references should fail traceability")
	}
}

func TestValidateOutsourceAcceptanceArtifact_ContradictoryOnlyIsValid(t *testing.T) {
	a := validOutsourceAcceptance()
	a.Requirements[1].SupportingEvidenceIDs = nil
	a.Requirements[1].ContradictoryEvidenceIDs = []string{"ev-contra-1"}
	if err := ValidateOutsourceAcceptanceArtifact(a); err != nil {
		t.Fatalf("contradictory-only evidence should be valid: %v", err)
	}
}

// --- Fix 2: ClaimRecord verification_class and scenario_applicability validation ---

func TestValidateClaimsArtifact_InvalidVerificationClass(t *testing.T) {
	a := validClaimsArtifactForScenario()
	a.Claims[0].VerificationClass = "bogus"
	if err := ValidateClaimsArtifact(a); err == nil {
		t.Fatal("expected error for invalid verification_class on claim")
	}
}

func TestValidateClaimsArtifact_EmptyScenarioApplicability(t *testing.T) {
	a := validClaimsArtifactForScenario()
	a.Claims[0].ScenarioApplicability = &ScenarioApplicability{}
	if err := ValidateClaimsArtifact(a); err == nil {
		t.Fatal("expected error: scenario_applicability with no scenario set")
	}
}

func TestValidateClaimsArtifact_ProofGradeRequiresStrongSupport(t *testing.T) {
	a := validClaimsArtifactForScenario()
	a.Claims[0].VerificationClass = VerificationProofGrade
	a.Claims[0].SupportLevel = "weak"
	a.Claims[0].ProjectionEligible = false
	if err := ValidateClaimsArtifact(a); err == nil {
		t.Fatal("expected error: proof_grade with weak support")
	}
}

func TestValidateClaimsArtifact_ValidVerificationClassAccepted(t *testing.T) {
	a := validClaimsArtifactForScenario()
	a.Claims[0].VerificationClass = VerificationStructuralInference
	if err := ValidateClaimsArtifact(a); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateClaimsArtifact_EmptyVerificationClassAllowed(t *testing.T) {
	a := validClaimsArtifactForScenario()
	a.Claims[0].VerificationClass = ""
	a.Claims[0].ScenarioApplicability = nil
	if err := ValidateClaimsArtifact(a); err != nil {
		t.Fatalf("unexpected error for backward-compatible empty fields: %v", err)
	}
}

func validClaimsArtifactForScenario() ClaimsArtifact {
	return ClaimsArtifact{
		SchemaVersion: ClaimsSchemaVersion,
		Repository:    ClaimRepositoryRef{Path: "/repo", Commit: "abc123"},
		Claims: []ClaimRecord{
			{
				ClaimID:               "security.route_auth_binding",
				Title:                 "Auth route binding",
				Category:              "security_maturity",
				ClaimType:             "implementation",
				Status:                "accepted",
				SupportLevel:          "verified",
				Confidence:            0.95,
				VerificationClass:     VerificationProofGrade,
				ScenarioApplicability: &ScenarioApplicability{Hiring: true, OutsourceAcceptance: true, PMAcceptance: true},
				SourceOrigins:         []string{"rule"},
				SupportingEvidenceIDs: []string{"ev-101"},
				Reason:                "Route binding verified.",
				ProjectionEligible:    true,
			},
		},
		Summary: ClaimSummary{Verified: 1},
	}
}

// --- Fix 3: Semantic consistency tests ---

func TestValidateOutsource_RuntimeRequiredCannotBeProofGrade(t *testing.T) {
	a := validOutsourceAcceptance()
	a.Requirements[0].Status = "runtime_required"
	a.Requirements[0].VerificationClass = VerificationProofGrade
	a.Requirements[0].TrustClass = TrustClassMachineTrusted
	// Fix summary
	a.Summary.Passed = 0
	a.Summary.RuntimeRequired = 1
	a.Summary.BlockingFailures = 0
	if err := ValidateOutsourceAcceptanceArtifact(a); err == nil {
		t.Fatal("expected error: runtime_required + proof_grade is semantically impossible")
	}
}

func TestValidateOutsource_UnknownCannotBeProofGrade(t *testing.T) {
	a := validOutsourceAcceptance()
	a.Requirements[0].Status = "unknown"
	a.Requirements[0].VerificationClass = VerificationProofGrade
	a.Requirements[0].TrustClass = TrustClassMachineTrusted
	a.Requirements[0].UnknownReasons = []string{"incomplete boundary"}
	// Fix summary
	a.Summary.Passed = 0
	a.Summary.Unknown = 1
	a.Summary.BlockingFailures = 0
	if err := ValidateOutsourceAcceptanceArtifact(a); err == nil {
		t.Fatal("expected error: unknown + proof_grade is semantically impossible")
	}
}

func TestValidateOutsource_UnknownCannotBeMachineTrusted(t *testing.T) {
	a := validOutsourceAcceptance()
	a.Requirements[0].Status = "unknown"
	a.Requirements[0].VerificationClass = VerificationStructuralInference
	a.Requirements[0].TrustClass = TrustClassMachineTrusted
	a.Requirements[0].UnknownReasons = []string{"incomplete"}
	a.Summary.Passed = 0
	a.Summary.Unknown = 1
	a.Summary.ProofGradeRows = 0
	a.Summary.BlockingFailures = 0
	if err := ValidateOutsourceAcceptanceArtifact(a); err == nil {
		t.Fatal("expected error: unknown + machine_trusted is semantically impossible")
	}
}

func TestValidatePM_RuntimeRequiredCannotBeProofGrade(t *testing.T) {
	a := validPMAcceptance()
	a.EngineeringRequirements[0].Status = "runtime_required"
	a.EngineeringRequirements[0].VerificationClass = VerificationProofGrade
	a.EngineeringRequirements[0].TrustClass = TrustClassMachineTrusted
	// Fix summary
	a.Summary.Implemented = 0
	a.Summary.RuntimeRequired = 1
	if err := ValidatePMAcceptanceArtifact(a); err == nil {
		t.Fatal("expected error: runtime_required + proof_grade is semantically impossible")
	}
}

func TestValidatePM_UnknownCannotBeProofGrade(t *testing.T) {
	a := validPMAcceptance()
	a.EngineeringRequirements[0].Status = "unknown"
	a.EngineeringRequirements[0].VerificationClass = VerificationProofGrade
	a.EngineeringRequirements[0].TrustClass = TrustClassMachineTrusted
	a.Summary.Implemented = 0
	a.Summary.Unknown = 1
	if err := ValidatePMAcceptanceArtifact(a); err == nil {
		t.Fatal("expected error: unknown + proof_grade is semantically impossible")
	}
}

func TestValidatePM_HumanOrRuntimeCannotBeMachineTrusted(t *testing.T) {
	a := validPMAcceptance()
	a.EngineeringRequirements[0].VerificationClass = VerificationHumanOrRuntimeRequired
	a.EngineeringRequirements[0].TrustClass = TrustClassMachineTrusted
	a.Summary.ProofGradeRows = 0
	if err := ValidatePMAcceptanceArtifact(a); err == nil {
		t.Fatal("expected error: human_or_runtime_required cannot be machine_trusted")
	}
}

// --- Bundle-level cross-reference tests ---

func bundleWithScenarioArtifacts() Bundle {
	b := testBundle()
	b.Claims = &ClaimsArtifact{
		SchemaVersion: ClaimsSchemaVersion,
		Repository:    ClaimRepositoryRef{Path: b.Report.Repo, Commit: b.Report.Commit},
		Claims: []ClaimRecord{
			{
				ClaimID:               "security.route_auth_binding",
				Title:                 "Auth binding",
				Category:              "security_maturity",
				ClaimType:             "implementation",
				Status:                "accepted",
				SupportLevel:          "verified",
				Confidence:            0.95,
				SourceOrigins:         []string{"rule"},
				SupportingEvidenceIDs: []string{"ev-1"},
				Reason:                "test",
				ProjectionEligible:    true,
			},
		},
		Summary: ClaimSummary{Verified: 1},
	}
	b.Profile = &ProfileArtifact{
		SchemaVersion: ProfileSchemaVersion,
		Repository:    ClaimRepositoryRef{Path: b.Report.Repo, Commit: b.Report.Commit},
		Highlights: []CapabilityHighlight{{
			HighlightID:           "hl-security.route_auth_binding",
			Title:                 "Auth binding",
			SupportLevel:          "verified",
			ClaimIDs:              []string{"security.route_auth_binding"},
			SupportingEvidenceIDs: []string{"ev-1"},
		}},
		CapabilityAreas: []CapabilityArea{{AreaID: "security_maturity", Title: "Security Maturity", ClaimIDs: []string{"security.route_auth_binding"}}},
		Technologies:    []string{"go"},
		ClaimIDs:        []string{"security.route_auth_binding"},
	}
	b.ResumeInput = &ResumeInputArtifact{
		SchemaVersion:           ResumeInputSchemaVersion,
		Profile:                 *b.Profile,
		VerifiedClaims:          []ResumeClaimStub{{ClaimID: "security.route_auth_binding", Title: "Auth binding", SupportLevel: "verified", Confidence: 0.95, SupportingEvidenceIDs: []string{"ev-1"}}},
		StronglySupportedClaims: []ResumeClaimStub{},
		TechnologySummary:       []string{"go"},
		EvidenceReferences:      []EvidenceReference{{EvidenceID: "ev-1", ClaimIDs: []string{"security.route_auth_binding"}}},
		SynthesisConstraints:    SynthesisConstraints{},
	}
	b.OutsourceAcceptance = &OutsourceAcceptanceArtifact{
		SchemaVersion:     OutsourceAcceptanceSchemaVersion,
		Repository:        AcceptanceRepositoryRef{Path: b.Report.Repo, Commit: b.Report.Commit},
		TraceID:           b.Trace.TraceID,
		AcceptanceProfile: "outsource-backend-api",
		Summary:           OutsourceAcceptanceSummary{Passed: 1, ProofGradeRows: 1},
		Requirements: []OutsourceRequirementRow{{
			RequirementID:         "oa-001",
			Title:                 "Auth binding",
			Category:              "security",
			Status:                "passed",
			VerificationClass:     VerificationProofGrade,
			TrustClass:            TrustClassMachineTrusted,
			Blocking:              true,
			AcceptanceIntent:      AcceptanceIntentBinding,
			ClaimIDs:              []string{"security.route_auth_binding"},
			SupportingEvidenceIDs: []string{"ev-1"},
			Reason:                "All protected routes bind auth middleware.",
			UnknownReasons:        []string{},
		}},
	}
	b.PMAcceptance = &PMAcceptanceArtifact{
		SchemaVersion:     PMAcceptanceSchemaVersion,
		Repository:        AcceptanceRepositoryRef{Path: b.Report.Repo, Commit: b.Report.Commit},
		TraceID:           b.Trace.TraceID,
		AcceptanceProfile: "pm-engineering-default",
		Summary:           PMAcceptanceSummary{Implemented: 1, ProofGradeRows: 1},
		EngineeringRequirements: []PMEngineeringRequirement{{
			RequirementID:         "pm-eng-001",
			Title:                 "Auth binding",
			Category:              "engineering_delivery",
			Status:                "implemented",
			VerificationClass:     VerificationProofGrade,
			TrustClass:            TrustClassMachineTrusted,
			DeliveryScope:         "implemented",
			ClaimIDs:              []string{"security.route_auth_binding"},
			SupportingEvidenceIDs: []string{"ev-1"},
			Reason:                "Route graph resolved through auth middleware.",
			FollowUpAction:        "",
		}},
	}
	return b
}

func TestValidateBundle_ScenarioArtifacts_Valid(t *testing.T) {
	b := bundleWithScenarioArtifacts()
	if err := ValidateBundle(b); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateBundle_OutsourceUnknownClaimID(t *testing.T) {
	b := bundleWithScenarioArtifacts()
	b.OutsourceAcceptance.Requirements[0].ClaimIDs = []string{"nonexistent.claim"}
	if err := ValidateBundle(b); err == nil {
		t.Fatal("expected error: outsource row references unknown claim_id")
	}
}

func TestValidateBundle_OutsourceUnknownEvidenceID(t *testing.T) {
	b := bundleWithScenarioArtifacts()
	b.OutsourceAcceptance.Requirements[0].SupportingEvidenceIDs = []string{"ev-nonexistent"}
	if err := ValidateBundle(b); err == nil {
		t.Fatal("expected error: outsource row references unknown evidence_id")
	}
}

func TestValidateBundle_OutsourceUnknownContradictoryEvidenceID(t *testing.T) {
	b := bundleWithScenarioArtifacts()
	b.OutsourceAcceptance.Requirements[0].ContradictoryEvidenceIDs = []string{"ev-ghost"}
	if err := ValidateBundle(b); err == nil {
		t.Fatal("expected error: outsource row references unknown contradictory evidence_id")
	}
}

func TestValidateBundle_OutsourceTraceIDMismatch(t *testing.T) {
	b := bundleWithScenarioArtifacts()
	b.OutsourceAcceptance.TraceID = "wrong-trace"
	if err := ValidateBundle(b); err == nil {
		t.Fatal("expected error: outsource trace_id mismatch")
	}
}

func TestValidateBundle_PMUnknownClaimID(t *testing.T) {
	b := bundleWithScenarioArtifacts()
	b.PMAcceptance.EngineeringRequirements[0].ClaimIDs = []string{"nonexistent.claim"}
	if err := ValidateBundle(b); err == nil {
		t.Fatal("expected error: PM row references unknown claim_id")
	}
}

func TestValidateBundle_PMUnknownEvidenceID(t *testing.T) {
	b := bundleWithScenarioArtifacts()
	b.PMAcceptance.EngineeringRequirements[0].SupportingEvidenceIDs = []string{"ev-nonexistent"}
	if err := ValidateBundle(b); err == nil {
		t.Fatal("expected error: PM row references unknown evidence_id")
	}
}

func TestValidateBundle_PMTraceIDMismatch(t *testing.T) {
	b := bundleWithScenarioArtifacts()
	b.PMAcceptance.TraceID = "wrong-trace"
	if err := ValidateBundle(b); err == nil {
		t.Fatal("expected error: PM trace_id mismatch")
	}
}

func TestValidateBundle_OutsourceRequiresClaimsJSON(t *testing.T) {
	b := bundleWithScenarioArtifacts()
	b.Claims = nil
	b.Profile = nil
	b.ResumeInput = nil
	b.PMAcceptance = nil
	if err := ValidateBundle(b); err == nil {
		t.Fatal("expected error: outsource_acceptance present without claims.json")
	}
}

func TestValidateBundle_PMRequiresClaimsJSON(t *testing.T) {
	b := bundleWithScenarioArtifacts()
	b.Claims = nil
	b.Profile = nil
	b.ResumeInput = nil
	b.OutsourceAcceptance = nil
	if err := ValidateBundle(b); err == nil {
		t.Fatal("expected error: pm_acceptance present without claims.json")
	}
}

func TestValidateBundle_OutsourceRepoCommitMismatch(t *testing.T) {
	b := bundleWithScenarioArtifacts()
	b.OutsourceAcceptance.Repository.Commit = "wrong-commit"
	if err := ValidateBundle(b); err == nil {
		t.Fatal("expected error: outsource repo/commit mismatch")
	}
}

func TestValidateBundle_OutsourceRepoPathMismatch(t *testing.T) {
	b := bundleWithScenarioArtifacts()
	b.OutsourceAcceptance.Repository.Path = "other/repo"
	if err := ValidateBundle(b); err == nil {
		t.Fatal("expected error: outsource repo path mismatch")
	}
}

func TestValidateBundle_PMRepoCommitMismatch(t *testing.T) {
	b := bundleWithScenarioArtifacts()
	b.PMAcceptance.Repository.Commit = "wrong-commit"
	if err := ValidateBundle(b); err == nil {
		t.Fatal("expected error: PM repo/commit mismatch")
	}
}

func TestClaimRecordWithoutVerificationClass_OmitsFromJSON(t *testing.T) {
	claim := ClaimRecord{
		ClaimID:               "test.claim",
		Title:                 "Test",
		Category:              "testing_maturity",
		ClaimType:             "implementation",
		Status:                "accepted",
		SupportLevel:          "supported",
		Confidence:            0.7,
		SourceOrigins:         []string{"rule"},
		SupportingEvidenceIDs: []string{"ev-1"},
		Reason:                "test",
		ProjectionEligible:    false,
	}
	data, err := json.Marshal(claim)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if _, ok := raw["verification_class"]; ok {
		t.Error("expected verification_class to be omitted when empty")
	}
	if _, ok := raw["scenario_applicability"]; ok {
		t.Error("expected scenario_applicability to be omitted when nil")
	}
}
