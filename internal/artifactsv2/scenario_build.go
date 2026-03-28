package artifactsv2

import (
	"fmt"
	"strings"
)

// ScenarioBuildOptions configures conditional internal projection of scenario
// acceptance artifacts. Empty values disable artifact emission.
type ScenarioBuildOptions struct {
	OutsourceAcceptanceProfile string
	PMAcceptanceProfile        string
}

// ScenarioAcceptanceBuildInput defines the deterministic inputs for scenario
// acceptance artifact projection.
type ScenarioAcceptanceBuildInput struct {
	RepoIdentity string
	Commit       string
	TraceID      string
	Claims       *ClaimsArtifact
	Options      ScenarioBuildOptions
}

// BuildScenarioAcceptanceArtifacts projects optional scenario acceptance
// artifacts from an existing claims artifact. For Phase 2, projection is
// intentionally conservative: enabled scenarios produce valid empty artifacts,
// and disabled scenarios produce nil outputs.
func BuildScenarioAcceptanceArtifacts(input ScenarioAcceptanceBuildInput) (*OutsourceAcceptanceArtifact, *PMAcceptanceArtifact, error) {
	if input.TraceID == "" {
		return nil, nil, fmt.Errorf("trace_id is required")
	}
	if input.RepoIdentity == "" || input.Commit == "" {
		return nil, nil, fmt.Errorf("repo identity and commit are required")
	}
	if input.Claims == nil {
		return nil, nil, nil
	}

	var outsource *OutsourceAcceptanceArtifact
	if shouldBuildOutsourceAcceptance(input.Options) {
		artifact := emptyOutsourceAcceptanceArtifact(input.RepoIdentity, input.Commit, input.TraceID, input.Options.OutsourceAcceptanceProfile)
		artifact.Requirements = buildOutsourceRequirementRows(input.Claims.Claims)
		artifact.Summary = summarizeOutsourceRequirements(artifact.Requirements)
		outsource = &artifact
	}

	var pm *PMAcceptanceArtifact
	if shouldBuildPMAcceptance(input.Options) {
		artifact := emptyPMAcceptanceArtifact(input.RepoIdentity, input.Commit, input.TraceID, input.Options.PMAcceptanceProfile)
		artifact.EngineeringRequirements = buildPMEngineeringRequirementRows(input.Claims.Claims)
		artifact.Summary = summarizePMRequirements(artifact.EngineeringRequirements)
		pm = &artifact
	}

	return outsource, pm, nil
}

func shouldBuildOutsourceAcceptance(opts ScenarioBuildOptions) bool {
	return opts.OutsourceAcceptanceProfile != ""
}

func shouldBuildPMAcceptance(opts ScenarioBuildOptions) bool {
	return opts.PMAcceptanceProfile != ""
}

func emptyOutsourceAcceptanceArtifact(repoIdentity, commit, traceID, profile string) OutsourceAcceptanceArtifact {
	return OutsourceAcceptanceArtifact{
		SchemaVersion: OutsourceAcceptanceSchemaVersion,
		Repository: AcceptanceRepositoryRef{
			Path:   repoIdentity,
			Commit: commit,
		},
		TraceID:           traceID,
		AcceptanceProfile: profile,
		Summary:           OutsourceAcceptanceSummary{},
		Requirements:      []OutsourceRequirementRow{},
	}
}

func emptyPMAcceptanceArtifact(repoIdentity, commit, traceID, profile string) PMAcceptanceArtifact {
	return PMAcceptanceArtifact{
		SchemaVersion: PMAcceptanceSchemaVersion,
		Repository: AcceptanceRepositoryRef{
			Path:   repoIdentity,
			Commit: commit,
		},
		TraceID:                 traceID,
		AcceptanceProfile:       profile,
		Summary:                 PMAcceptanceSummary{},
		EngineeringRequirements: []PMEngineeringRequirement{},
	}
}

type scenarioRequirementSpec struct {
	requirementID    string
	title            string
	category         string
	acceptanceIntent AcceptanceIntent
	blocking         bool
	deliveryScope    string
	positiveClaimID  string
	negativeClaimID  string
}

func buildOutsourceRequirementRows(claims []ClaimRecord) []OutsourceRequirementRow {
	claimIndex := indexClaimsByID(claims)
	specs := []scenarioRequirementSpec{
		{
			requirementID:    "oa-sec-secret-001",
			title:            "Hardcoded credentials must not exist in the delivered repository snapshot",
			category:         "security",
			acceptanceIntent: AcceptanceIntentNegativeExhaustive,
			blocking:         true,
			positiveClaimID:  "security.hardcoded_secret_absent",
			negativeClaimID:  "security.hardcoded_secret_present",
		},
		{
			requirementID:    "oa-auth-002",
			title:            "Protected routes must bind authentication middleware",
			category:         "security",
			acceptanceIntent: AcceptanceIntentBinding,
			blocking:         true,
			positiveClaimID:  "security.route_auth_binding",
		},
		{
			requirementID:    "oa-test-auth-001",
			title:            "Authentication module must have automated tests",
			category:         "testing",
			acceptanceIntent: AcceptanceIntentMaturity,
			blocking:         false,
			positiveClaimID:  "testing.auth_module_tests_present",
		},
		{
			requirementID:    "oa-arch-001",
			title:            "Controllers must not access the database directly",
			category:         "architecture",
			acceptanceIntent: AcceptanceIntentNegativeExhaustive,
			blocking:         true,
			positiveClaimID:  "architecture.controller_direct_db_access_absent",
			negativeClaimID:  "architecture.controller_direct_db_access_present",
		},
		{
			requirementID:    "oa-config-001",
			title:            "Secret-bearing configuration should be sourced from environment reads",
			category:         "security",
			acceptanceIntent: AcceptanceIntentExistence,
			blocking:         false,
			positiveClaimID:  "config.secret_key_sourced_from_env",
		},
		{
			requirementID:    "oa-config-002",
			title:            "Secret-bearing configuration should not remain literal-bound",
			category:         "security",
			acceptanceIntent: AcceptanceIntentBoundary,
			blocking:         true,
			positiveClaimID:  "config.secret_key_not_literal",
			negativeClaimID:  "config.secret_key_not_literal",
		},
	}

	rows := make([]OutsourceRequirementRow, 0, len(specs))
	for _, spec := range specs {
		row, ok := buildOutsourceRequirementRow(spec, claimIndex)
		if ok {
			rows = append(rows, row)
		}
	}
	return rows
}

func buildPMEngineeringRequirementRows(claims []ClaimRecord) []PMEngineeringRequirement {
	claimIndex := indexClaimsByID(claims)
	specs := []scenarioRequirementSpec{
		{
			requirementID:   "pm-auth-binding-001",
			title:           "Authentication middleware is wired to protected routes",
			category:        "security",
			deliveryScope:   "implemented",
			positiveClaimID: "security.route_auth_binding",
		},
		{
			requirementID:   "pm-auth-tests-001",
			title:           "Authentication module test coverage exists",
			category:        "testing",
			deliveryScope:   "implemented",
			positiveClaimID: "testing.auth_module_tests_present",
		},
		{
			requirementID:   "pm-secret-001",
			title:           "No hardcoded secret literals remain in the scanned boundary",
			category:        "security",
			deliveryScope:   "implemented",
			positiveClaimID: "security.hardcoded_secret_absent",
			negativeClaimID: "security.hardcoded_secret_present",
		},
		{
			requirementID:   "pm-arch-001",
			title:           "Controller/database layering is preserved",
			category:        "architecture",
			deliveryScope:   "implemented",
			positiveClaimID: "architecture.controller_direct_db_access_absent",
			negativeClaimID: "architecture.controller_direct_db_access_present",
		},
		{
			requirementID:   "pm-config-001",
			title:           "Secret configuration is wired through environment-backed reads",
			category:        "security",
			deliveryScope:   "implemented",
			positiveClaimID: "config.secret_key_sourced_from_env",
		},
		{
			requirementID:   "pm-config-002",
			title:           "Secret configuration is not literal-bound",
			category:        "security",
			deliveryScope:   "implemented",
			positiveClaimID: "config.secret_key_not_literal",
			negativeClaimID: "config.secret_key_not_literal",
		},
	}

	rows := make([]PMEngineeringRequirement, 0, len(specs))
	for _, spec := range specs {
		row, ok := buildPMEngineeringRequirementRow(spec, claimIndex)
		if ok {
			rows = append(rows, row)
		}
	}
	return rows
}

func buildOutsourceRequirementRow(spec scenarioRequirementSpec, claims map[string]ClaimRecord) (OutsourceRequirementRow, bool) {
	positive, hasPositive := claims[spec.positiveClaimID]
	negative, hasNegative := claims[spec.negativeClaimID]
	selected, status, ok := selectScenarioClaimForOutsource(positive, hasPositive, negative, hasNegative)
	if !ok {
		return OutsourceRequirementRow{}, false
	}

	claimIDs := []string{selected.ClaimID}
	supporting := append([]string(nil), selected.SupportingEvidenceIDs...)
	contradictory := append([]string(nil), selected.ContradictoryEvidenceIDs...)
	if !hasScenarioEvidence(supporting, contradictory) {
		return OutsourceRequirementRow{}, false
	}

	return OutsourceRequirementRow{
		RequirementID:            spec.requirementID,
		Title:                    spec.title,
		Category:                 spec.category,
		Status:                   status,
		VerificationClass:        selected.VerificationClass,
		TrustClass:               trustClassForVerificationClass(selected.VerificationClass),
		Blocking:                 spec.blocking,
		AcceptanceIntent:         spec.acceptanceIntent,
		ClaimIDs:                 claimIDs,
		SupportingEvidenceIDs:    supporting,
		ContradictoryEvidenceIDs: contradictory,
		Reason:                   selected.Reason,
		UnknownReasons:           outsourceUnknownReasons(status, selected),
	}, true
}

func buildPMEngineeringRequirementRow(spec scenarioRequirementSpec, claims map[string]ClaimRecord) (PMEngineeringRequirement, bool) {
	positive, hasPositive := claims[spec.positiveClaimID]
	negative, hasNegative := claims[spec.negativeClaimID]
	selected, status, ok := selectScenarioClaimForPM(positive, hasPositive, negative, hasNegative)
	if !ok {
		return PMEngineeringRequirement{}, false
	}

	supporting := append([]string(nil), selected.SupportingEvidenceIDs...)
	contradictory := append([]string(nil), selected.ContradictoryEvidenceIDs...)
	if !hasScenarioEvidence(supporting, contradictory) {
		return PMEngineeringRequirement{}, false
	}

	return PMEngineeringRequirement{
		RequirementID:            spec.requirementID,
		Title:                    spec.title,
		Category:                 spec.category,
		Status:                   status,
		VerificationClass:        selected.VerificationClass,
		TrustClass:               trustClassForVerificationClass(selected.VerificationClass),
		DeliveryScope:            spec.deliveryScope,
		ClaimIDs:                 []string{selected.ClaimID},
		SupportingEvidenceIDs:    supporting,
		ContradictoryEvidenceIDs: contradictory,
		Reason:                   selected.Reason,
		FollowUpAction:           pmFollowUpAction(status, selected.VerificationClass),
	}, true
}

func selectScenarioClaimForOutsource(positive ClaimRecord, hasPositive bool, negative ClaimRecord, hasNegative bool) (ClaimRecord, string, bool) {
	if hasNegative && negative.Status == "accepted" {
		return negative, "failed", true
	}
	if hasPositive && positive.Status == "accepted" {
		if positive.VerificationClass == VerificationProofGrade {
			return positive, "passed", true
		}
		if positive.VerificationClass == VerificationHumanOrRuntimeRequired {
			return positive, "runtime_required", true
		}
		return positive, "unknown", true
	}
	if hasPositive && positive.Status == "unknown" {
		if positive.VerificationClass == VerificationHumanOrRuntimeRequired {
			return positive, "runtime_required", true
		}
		return positive, "unknown", true
	}
	if hasPositive && positive.Status == "rejected" {
		return positive, "failed", true
	}
	return ClaimRecord{}, "", false
}

func selectScenarioClaimForPM(positive ClaimRecord, hasPositive bool, negative ClaimRecord, hasNegative bool) (ClaimRecord, string, bool) {
	if hasNegative && negative.Status == "accepted" {
		return negative, "blocked", true
	}
	if hasPositive && positive.Status == "accepted" {
		switch positive.VerificationClass {
		case VerificationProofGrade:
			return positive, "implemented", true
		case VerificationHumanOrRuntimeRequired:
			return positive, "runtime_required", true
		default:
			return positive, "partial", true
		}
	}
	if hasPositive && positive.Status == "rejected" {
		return positive, "blocked", true
	}
	if hasPositive && positive.Status == "unknown" {
		if positive.VerificationClass == VerificationHumanOrRuntimeRequired {
			return positive, "runtime_required", true
		}
		return positive, "unknown", true
	}
	return ClaimRecord{}, "", false
}

func indexClaimsByID(claims []ClaimRecord) map[string]ClaimRecord {
	out := make(map[string]ClaimRecord, len(claims))
	for _, claim := range claims {
		if id := strings.TrimSpace(claim.ClaimID); id != "" {
			out[id] = claim
		}
	}
	return out
}

func hasScenarioEvidence(supporting, contradictory []string) bool {
	return len(supporting) > 0 || len(contradictory) > 0
}

func trustClassForVerificationClass(vc VerificationClass) TrustClassValue {
	switch vc {
	case VerificationProofGrade:
		return TrustClassMachineTrusted
	case VerificationHumanOrRuntimeRequired:
		return TrustClassHumanOrRuntimeRequired
	default:
		return TrustClassAdvisory
	}
}

func outsourceUnknownReasons(status string, claim ClaimRecord) []string {
	if status != "unknown" && status != "runtime_required" {
		return []string{}
	}
	if claim.VerificationClass == VerificationHumanOrRuntimeRequired {
		return []string{"static_proof_scope_insufficient"}
	}
	return []string{"advisory_pass_not_promoted"}
}

func pmFollowUpAction(status string, vc VerificationClass) string {
	switch status {
	case "blocked":
		return "Fix the blocking implementation gap before engineering acceptance."
	case "runtime_required":
		return "Collect runtime or integration evidence before closing engineering acceptance."
	case "unknown":
		return "Inspect analyzer coverage and missing evidence before accepting the delivery."
	case "partial":
		if vc == VerificationStructuralInference {
			return "Review structural evidence and decide whether additional proof or tests are required."
		}
	}
	return ""
}

func summarizeOutsourceRequirements(rows []OutsourceRequirementRow) OutsourceAcceptanceSummary {
	var summary OutsourceAcceptanceSummary
	for _, row := range rows {
		switch row.Status {
		case "passed":
			summary.Passed++
		case "failed":
			summary.Failed++
			if row.Blocking {
				summary.BlockingFailures++
			}
		case "unknown":
			summary.Unknown++
		case "runtime_required":
			summary.RuntimeRequired++
		}
		if row.VerificationClass == VerificationProofGrade {
			summary.ProofGradeRows++
		}
	}
	return summary
}

func summarizePMRequirements(rows []PMEngineeringRequirement) PMAcceptanceSummary {
	var summary PMAcceptanceSummary
	for _, row := range rows {
		switch row.Status {
		case "implemented":
			summary.Implemented++
		case "partial":
			summary.Partial++
		case "blocked":
			summary.Blocked++
		case "unknown":
			summary.Unknown++
		case "runtime_required":
			summary.RuntimeRequired++
		}
		if row.VerificationClass == VerificationProofGrade {
			summary.ProofGradeRows++
		}
	}
	return summary
}
