package engine

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/artifactsv2"
	"github.com/verabase/code-verification-engine/internal/claims"
	"github.com/verabase/code-verification-engine/internal/facts"
	"github.com/verabase/code-verification-engine/internal/rules"
)

func TestEngineHelperFunctions(t *testing.T) {
	t.Parallel()

	if supportLevelFromFinding(rules.Finding{VerificationLevel: rules.VerificationWeakInference}) != "weak" {
		t.Fatal("expected weak support level")
	}
	if rejectionSupportLevelFromFinding(rules.Finding{VerificationLevel: rules.VerificationWeakInference}) != "unsupported" {
		t.Fatal("expected unsupported rejection support level")
	}
	if !claimEligibleForResume(artifactsv2.VerificationProofGrade, "verified") {
		t.Fatal("expected proof-grade verified claim to be resume eligible")
	}
	if claimEligibleForResume(artifactsv2.VerificationHumanOrRuntimeRequired, "verified") {
		t.Fatal("runtime-required claim must not be resume eligible")
	}
	if got := dedupeStringsSorted([]string{"b", "a", "b", ""}); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("dedupeStringsSorted() = %#v", got)
	}
	if got := evidenceIDsFromFinding(rules.Finding{Evidence: []rules.Evidence{{ID: "ev-2"}, {ID: ""}, {ID: "ev-1"}, {ID: "ev-2"}}}); len(got) != 3 || got[0] != "ev-2" || got[1] != "ev-1" || got[2] != "ev-2" {
		t.Fatalf("evidenceIDsFromFinding() = %#v", got)
	}
}

func TestEngineDerivedHelperFunctions(t *testing.T) {
	t.Parallel()

	if got := verificationClassFromFinding(
		rules.Finding{
			VerificationLevel: rules.VerificationVerified,
			TrustClass:        rules.TrustMachineTrusted,
			FactQualityFloor:  "proof",
		},
		rules.Rule{MatcherClass: rules.MatcherProof},
	); got != artifactsv2.VerificationProofGrade {
		t.Fatalf("verificationClassFromFinding(proof) = %q", got)
	}

	if got := verificationClassFromFinding(
		rules.Finding{VerificationLevel: rules.VerificationStrongInference},
		rules.Rule{},
	); got != artifactsv2.VerificationStructuralInference {
		t.Fatalf("verificationClassFromFinding(structural) = %q", got)
	}

	if got := verificationClassFromFinding(
		rules.Finding{TrustClass: rules.TrustHumanOrRuntimeRequired},
		rules.Rule{},
	); got != artifactsv2.VerificationHumanOrRuntimeRequired {
		t.Fatalf("verificationClassFromFinding(runtime) = %q", got)
	}

	if got := confidenceScoreFromFinding(rules.Finding{Confidence: rules.ConfidenceHigh}); got != 0.95 {
		t.Fatalf("confidenceScoreFromFinding(high) = %v", got)
	}
	if got := confidenceScoreFromFinding(rules.Finding{Confidence: rules.ConfidenceMedium}); got != 0.75 {
		t.Fatalf("confidenceScoreFromFinding(medium) = %v", got)
	}
	if got := confidenceScoreFromFinding(rules.Finding{}); got != 0.45 {
		t.Fatalf("confidenceScoreFromFinding(default) = %v", got)
	}

	base := []artifactsv2.EvidenceRecord{{ID: "ev-1"}, {ID: "ev-2"}}
	extra := []artifactsv2.EvidenceRecord{{ID: "ev-2"}, {ID: "ev-3"}}
	if got := appendMissingEvidenceRecords(base, nil); len(got) != 2 {
		t.Fatalf("appendMissingEvidenceRecords(nil) len = %d", len(got))
	}
	if got := appendMissingEvidenceRecords(base, extra); len(got) != 3 || got[2].ID != "ev-3" {
		t.Fatalf("appendMissingEvidenceRecords(extra) = %#v", got)
	}
}

func TestBuildConfigFactClaims_CoversNegativeAndSecretKeyBranches(t *testing.T) {
	t.Parallel()

	claims := buildConfigFactClaims(&rules.FactSet{
		ConfigReads: []facts.ConfigReadFact{
			{Language: facts.LangTypeScript, File: "config/app.ts", Span: facts.Span{Start: 1, End: 1}, Key: "JWT_SECRET", SourceKind: "env"},
			{Language: facts.LangTypeScript, File: "config/app.ts", Span: facts.Span{Start: 2, End: 2}, Key: "JWT_SECRET", SourceKind: "literal"},
			{Language: facts.LangTypeScript, File: "config/app.ts", Span: facts.Span{Start: 3, End: 3}, Key: "PORT", SourceKind: "env"},
		},
	})
	if len(claims) != 3 {
		t.Fatalf("claim count = %d, want 3", len(claims))
	}
	byID := map[string]artifactsv2.ClaimRecord{}
	for _, claim := range claims {
		byID[claim.ClaimID] = claim
	}
	if byID["config.secret_key_not_literal"].Status != "rejected" {
		t.Fatalf("secret_key_not_literal status = %q", byID["config.secret_key_not_literal"].Status)
	}
	if !configKeyLooksSecret("JWT_SECRET") || configKeyLooksSecret("PORT") {
		t.Fatal("unexpected configKeyLooksSecret() result")
	}
}

func TestInferClaimMetadataHelpers(t *testing.T) {
	t.Parallel()

	if got := inferClaimVerificationClass(claims.VerifiedClaim{SupportLevel: string(claims.ClaimSupportVerified)}); got != artifactsv2.VerificationStructuralInference {
		t.Fatalf("inferClaimVerificationClass(code_inferred) = %q", got)
	}
	if got := inferClaimVerificationClass(claims.VerifiedClaim{SupportLevel: string(claims.ClaimSupportSupported)}); got != artifactsv2.VerificationHeuristicAdvisory {
		t.Fatalf("inferClaimVerificationClass(readme_extracted) = %q", got)
	}
	if got := inferClaimVerificationClass(claims.VerifiedClaim{SupportLevel: string(claims.ClaimSupportUnsupported)}); got != artifactsv2.VerificationHumanOrRuntimeRequired {
		t.Fatalf("inferClaimVerificationClass(default) = %q", got)
	}
	if got := inferClaimVerificationClass(claims.VerifiedClaim{}); got != "" {
		t.Fatalf("inferClaimVerificationClass(default empty) = %q", got)
	}

	if got := inferClaimScenarioApplicability(claims.VerifiedClaim{ClaimType: "architecture"}); got == nil || !got.Hiring || !got.OutsourceAcceptance || !got.PMAcceptance {
		t.Fatalf("unexpected architecture applicability: %#v", got)
	}
	if got := inferClaimScenarioApplicability(claims.VerifiedClaim{ClaimType: "testing_maturity"}); got == nil || !got.Hiring || !got.OutsourceAcceptance || !got.PMAcceptance {
		t.Fatalf("unexpected testing applicability: %#v", got)
	}
	if got := inferClaimScenarioApplicability(claims.VerifiedClaim{ClaimType: "evaluation_maturity"}); got == nil || !got.Hiring || got.OutsourceAcceptance || got.PMAcceptance {
		t.Fatalf("unexpected evaluation applicability: %#v", got)
	}
	if got := inferClaimScenarioApplicability(claims.VerifiedClaim{ClaimType: "other"}); got == nil || got.OutsourceAcceptance || got.PMAcceptance {
		t.Fatalf("unexpected default applicability: %#v", got)
	}
}
