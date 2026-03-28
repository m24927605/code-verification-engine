package claims

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/rules"
)

func TestEvaluateClaim_AllPass(t *testing.T) {
	claim := Claim{
		ID:       "test.all_pass",
		Title:    "All pass",
		Category: "testing",
		RuleIDs:  []string{"RULE-1", "RULE-2"},
	}

	ruleResults := map[string]rules.Finding{
		"RULE-1": {
			RuleID:            "RULE-1",
			Status:            rules.StatusPass,
			Confidence:        rules.ConfidenceHigh,
			VerificationLevel: rules.VerificationVerified,
			TrustClass:        rules.TrustMachineTrusted,
			Message:           "passed",
		},
		"RULE-2": {
			RuleID:            "RULE-2",
			Status:            rules.StatusPass,
			Confidence:        rules.ConfidenceMedium,
			VerificationLevel: rules.VerificationStrongInference,
			TrustClass:        rules.TrustMachineTrusted,
			Message:           "passed",
		},
	}

	verdict := evaluateClaim(claim, ruleResults)

	if verdict.Status != "pass" {
		t.Errorf("expected status pass, got %s", verdict.Status)
	}
	if verdict.Confidence != "high" {
		t.Errorf("expected confidence high, got %s", verdict.Confidence)
	}
	if verdict.VerificationLevel != "verified" {
		t.Errorf("expected verification_level verified, got %s", verdict.VerificationLevel)
	}
	if len(verdict.SupportingRules) != 2 {
		t.Errorf("expected 2 supporting rules, got %d", len(verdict.SupportingRules))
	}
	if verdict.TrustBreakdown.MachineTrusted != 2 {
		t.Errorf("expected 2 machine_trusted, got %d", verdict.TrustBreakdown.MachineTrusted)
	}
	if verdict.TrustBreakdown.EffectiveTrustClass != "machine_trusted" {
		t.Errorf("expected effective trust class machine_trusted, got %s", verdict.TrustBreakdown.EffectiveTrustClass)
	}
}

func TestEvaluateClaim_MixedPassFail(t *testing.T) {
	claim := Claim{
		ID:       "test.mixed",
		Title:    "Mixed",
		Category: "testing",
		RuleIDs:  []string{"RULE-1", "RULE-2"},
	}

	ruleResults := map[string]rules.Finding{
		"RULE-1": {
			RuleID:     "RULE-1",
			Status:     rules.StatusPass,
			Confidence: rules.ConfidenceHigh,
			Message:    "passed",
		},
		"RULE-2": {
			RuleID:     "RULE-2",
			Status:     rules.StatusFail,
			Confidence: rules.ConfidenceHigh,
			Message:    "failed",
			Evidence: []rules.Evidence{
				{File: "main.go", LineStart: 10, LineEnd: 15, Symbol: "badFunc"},
			},
		},
	}

	verdict := evaluateClaim(claim, ruleResults)

	if verdict.Status != "fail" {
		t.Errorf("expected status fail, got %s", verdict.Status)
	}
	if verdict.Summary != "1 of 2 rules failed." {
		t.Errorf("unexpected summary: %s", verdict.Summary)
	}
}

func TestEvaluateClaim_PassAndUnknown(t *testing.T) {
	claim := Claim{
		ID:       "test.partial",
		Title:    "Partial",
		Category: "testing",
		RuleIDs:  []string{"RULE-1", "RULE-2"},
	}

	ruleResults := map[string]rules.Finding{
		"RULE-1": {
			RuleID:     "RULE-1",
			Status:     rules.StatusPass,
			Confidence: rules.ConfidenceMedium,
			Message:    "passed",
		},
		"RULE-2": {
			RuleID:         "RULE-2",
			Status:         rules.StatusUnknown,
			Confidence:     rules.ConfidenceLow,
			Message:        "unknown",
			UnknownReasons: []string{"no data"},
		},
	}

	verdict := evaluateClaim(claim, ruleResults)

	if verdict.Status != "partial" {
		t.Errorf("expected status partial, got %s", verdict.Status)
	}
	if len(verdict.UnknownReasons) != 1 {
		t.Errorf("expected 1 unknown reason, got %d", len(verdict.UnknownReasons))
	}
}

func TestEvaluateClaim_AllUnknown(t *testing.T) {
	claim := Claim{
		ID:       "test.unknown",
		Title:    "Unknown",
		Category: "testing",
		RuleIDs:  []string{"RULE-1"},
	}

	ruleResults := map[string]rules.Finding{
		"RULE-1": {
			RuleID:     "RULE-1",
			Status:     rules.StatusUnknown,
			Confidence: rules.ConfidenceLow,
			Message:    "unknown",
		},
	}

	verdict := evaluateClaim(claim, ruleResults)

	if verdict.Status != "unknown" {
		t.Errorf("expected status unknown, got %s", verdict.Status)
	}
}

func TestEvaluateClaim_MissingRule(t *testing.T) {
	claim := Claim{
		ID:       "test.missing",
		Title:    "Missing",
		Category: "testing",
		RuleIDs:  []string{"RULE-MISSING"},
	}

	ruleResults := map[string]rules.Finding{}

	verdict := evaluateClaim(claim, ruleResults)

	if verdict.Status != "unknown" {
		t.Errorf("expected status unknown, got %s", verdict.Status)
	}
	if len(verdict.SupportingRules) != 1 {
		t.Fatalf("expected 1 supporting rule, got %d", len(verdict.SupportingRules))
	}
	if verdict.SupportingRules[0].Status != "unknown" {
		t.Errorf("expected supporting rule status unknown, got %s", verdict.SupportingRules[0].Status)
	}
}

func TestEvaluateClaim_EvidenceChain(t *testing.T) {
	claim := Claim{
		ID:       "test.evidence",
		Title:    "Evidence",
		Category: "testing",
		RuleIDs:  []string{"RULE-1"},
	}

	ruleResults := map[string]rules.Finding{
		"RULE-1": {
			RuleID:     "RULE-1",
			Status:     rules.StatusPass,
			Confidence: rules.ConfidenceHigh,
			Message:    "found",
			Evidence: []rules.Evidence{
				{ID: "ev-1", File: "auth.go", LineStart: 5, LineEnd: 10, Symbol: "JWTMiddleware"},
				{ID: "ev-2", File: "auth.go", LineStart: 20, LineEnd: 25, Symbol: "ValidateToken"},
			},
		},
	}

	verdict := evaluateClaim(claim, ruleResults)

	if len(verdict.EvidenceChain) != 2 {
		t.Fatalf("expected 2 evidence links, got %d", len(verdict.EvidenceChain))
	}
	if verdict.EvidenceChain[0].Type != "supports" {
		t.Errorf("expected evidence type supports, got %s", verdict.EvidenceChain[0].Type)
	}
	if verdict.EvidenceChain[0].FromRule != "RULE-1" {
		t.Errorf("expected from_rule RULE-1, got %s", verdict.EvidenceChain[0].FromRule)
	}
	if verdict.EvidenceChain[0].File != "auth.go" {
		t.Errorf("expected file auth.go, got %s", verdict.EvidenceChain[0].File)
	}
}

func TestEvaluateClaim_FailEvidenceContradicts(t *testing.T) {
	claim := Claim{
		ID:       "test.contradict",
		Title:    "Contradict",
		Category: "testing",
		RuleIDs:  []string{"RULE-1"},
	}

	ruleResults := map[string]rules.Finding{
		"RULE-1": {
			RuleID:     "RULE-1",
			Status:     rules.StatusFail,
			Confidence: rules.ConfidenceHigh,
			Message:    "violation found",
			Evidence: []rules.Evidence{
				{ID: "ev-1", File: "bad.go", LineStart: 1, LineEnd: 5, Symbol: "hardcodedKey"},
			},
		},
	}

	verdict := evaluateClaim(claim, ruleResults)

	if len(verdict.EvidenceChain) != 1 {
		t.Fatalf("expected 1 evidence link, got %d", len(verdict.EvidenceChain))
	}
	if verdict.EvidenceChain[0].Type != "contradicts" {
		t.Errorf("expected evidence type contradicts, got %s", verdict.EvidenceChain[0].Type)
	}
}

func TestEvaluator_Evaluate(t *testing.T) {
	cs := &ClaimSet{
		Name: "test-set",
		Claims: []Claim{
			{ID: "c1", Title: "Claim 1", Category: "security", RuleIDs: []string{"R1"}},
			{ID: "c2", Title: "Claim 2", Category: "security", RuleIDs: []string{"R2"}},
			{ID: "c3", Title: "Claim 3", Category: "security", RuleIDs: []string{"R3"}},
		},
	}

	execResult := rules.ExecutionResult{
		Findings: []rules.Finding{
			{RuleID: "R1", Status: rules.StatusPass, Confidence: rules.ConfidenceHigh, VerificationLevel: rules.VerificationVerified, TrustClass: rules.TrustMachineTrusted},
			{RuleID: "R2", Status: rules.StatusFail, Confidence: rules.ConfidenceHigh, TrustClass: rules.TrustAdvisory},
			{RuleID: "R3", Status: rules.StatusUnknown, Confidence: rules.ConfidenceLow, TrustClass: rules.TrustAdvisory},
		},
	}

	eval := NewEvaluator()
	report := eval.Evaluate(cs, execResult)

	if report.SchemaVersion != "1.0.0" {
		t.Errorf("expected schema version 1.0.0, got %s", report.SchemaVersion)
	}
	if report.TotalClaims != 3 {
		t.Errorf("expected 3 total claims, got %d", report.TotalClaims)
	}
	if report.Verdicts.Passed != 1 {
		t.Errorf("expected 1 passed, got %d", report.Verdicts.Passed)
	}
	if report.Verdicts.Verified != 1 {
		t.Errorf("expected 1 verified, got %d", report.Verdicts.Verified)
	}
	if report.Verdicts.Failed != 1 {
		t.Errorf("expected 1 failed, got %d", report.Verdicts.Failed)
	}
	if report.Verdicts.Unknown != 1 {
		t.Errorf("expected 1 unknown, got %d", report.Verdicts.Unknown)
	}
}

func TestBuiltInClaimSets_ValidRuleIDs(t *testing.T) {
	// Collect all known rule IDs from profiles
	knownRules := make(map[string]bool)
	for _, profile := range rules.AllProfiles() {
		for _, r := range profile.Rules {
			knownRules[r.ID] = true
		}
	}

	for name, cs := range AllClaimSets() {
		for _, claim := range cs.Claims {
			for _, ruleID := range claim.RuleIDs {
				if !knownRules[ruleID] {
					t.Errorf("claim set %q, claim %q references unknown rule ID %q", name, claim.ID, ruleID)
				}
			}
		}
	}
}

func TestListClaimSetNames(t *testing.T) {
	names := ListClaimSetNames()
	if len(names) != 3 {
		t.Fatalf("expected 3 claim set names, got %d: %v", len(names), names)
	}
	expected := map[string]bool{
		"backend-security":     true,
		"backend-architecture": true,
		"fullstack-security":   true,
	}
	for _, name := range names {
		if !expected[name] {
			t.Errorf("unexpected claim set name: %s", name)
		}
	}
}

func TestConfidenceRankDefault(t *testing.T) {
	// Test the default case of confidenceRank
	if confidenceRank("unknown_value") != 0 {
		t.Error("expected 0 for unknown confidence value")
	}
	if confidenceRank("") != 0 {
		t.Error("expected 0 for empty confidence value")
	}
}

func TestVerificationRankDefault(t *testing.T) {
	// Test the default case of verificationRank
	if verificationRank("unknown_value") != 0 {
		t.Error("expected 0 for unknown verification value")
	}
	if verificationRank("") != 0 {
		t.Error("expected 0 for empty verification value")
	}
}

func TestEvaluator_EvaluatePartialVerdict(t *testing.T) {
	cs := &ClaimSet{
		Name: "test-set",
		Claims: []Claim{
			{ID: "c1", Title: "Claim 1", Category: "security", RuleIDs: []string{"R1", "R2"}},
		},
	}

	execResult := rules.ExecutionResult{
		Findings: []rules.Finding{
			{RuleID: "R1", Status: rules.StatusPass, Confidence: rules.ConfidenceMedium},
			{RuleID: "R2", Status: rules.StatusUnknown, Confidence: rules.ConfidenceLow},
		},
	}

	eval := NewEvaluator()
	report := eval.Evaluate(cs, execResult)

	if report.Verdicts.Partial != 1 {
		t.Errorf("expected 1 partial, got %d", report.Verdicts.Partial)
	}
	if report.Verdicts.Passed != 0 {
		t.Errorf("expected 0 passed (partial is not pass), got %d", report.Verdicts.Passed)
	}
}

func TestEvaluator_EvaluatePassWithLowConfidence(t *testing.T) {
	// Pass with non-high confidence should increment Passed but NOT Verified
	cs := &ClaimSet{
		Name: "test-set",
		Claims: []Claim{
			{ID: "c1", Title: "Claim 1", Category: "security", RuleIDs: []string{"R1"}},
		},
	}

	execResult := rules.ExecutionResult{
		Findings: []rules.Finding{
			{RuleID: "R1", Status: rules.StatusPass, Confidence: rules.ConfidenceMedium},
		},
	}

	eval := NewEvaluator()
	report := eval.Evaluate(cs, execResult)

	if report.Verdicts.Passed != 1 {
		t.Errorf("expected 1 passed, got %d", report.Verdicts.Passed)
	}
	if report.Verdicts.Verified != 0 {
		t.Errorf("expected 0 verified (medium confidence), got %d", report.Verdicts.Verified)
	}
}

func TestGetClaimSet(t *testing.T) {
	cs, ok := GetClaimSet("backend-security")
	if !ok {
		t.Fatal("expected to find backend-security claim set")
	}
	if cs.Name != "backend-security" {
		t.Errorf("expected name backend-security, got %s", cs.Name)
	}
	if len(cs.Claims) != 8 {
		t.Errorf("expected 8 claims in backend-security, got %d", len(cs.Claims))
	}

	_, ok = GetClaimSet("nonexistent")
	if ok {
		t.Error("expected not to find nonexistent claim set")
	}
}

// ---------------------------------------------------------------------------
// Trust boundary regression tests
// ---------------------------------------------------------------------------

func TestVerifiedRequiresVerificationLevel(t *testing.T) {
	// A claim with pass + high confidence but only strong_inference
	// must NOT be counted as verified.
	cs := &ClaimSet{
		Name: "test",
		Claims: []Claim{
			{ID: "c1", Title: "Advisory claim", Category: "security", RuleIDs: []string{"R1"}},
		},
	}
	execResult := rules.ExecutionResult{
		Findings: []rules.Finding{
			{
				RuleID:            "R1",
				Status:            rules.StatusPass,
				Confidence:        rules.ConfidenceHigh,
				VerificationLevel: rules.VerificationStrongInference, // advisory downgraded
			},
		},
	}
	eval := NewEvaluator()
	report := eval.Evaluate(cs, execResult)

	if report.Verdicts.Passed != 1 {
		t.Errorf("expected 1 passed, got %d", report.Verdicts.Passed)
	}
	if report.Verdicts.Verified != 0 {
		t.Errorf("strong_inference must NOT count as verified, got %d", report.Verdicts.Verified)
	}
}

func TestVerifiedOnlyWithVerifiedLevel(t *testing.T) {
	// Only pass + high + verified + machine_trusted should count as verified.
	cs := &ClaimSet{
		Name: "test",
		Claims: []Claim{
			{ID: "c1", Title: "Trusted claim", Category: "security", RuleIDs: []string{"R1"}},
		},
	}
	execResult := rules.ExecutionResult{
		Findings: []rules.Finding{
			{
				RuleID:            "R1",
				Status:            rules.StatusPass,
				Confidence:        rules.ConfidenceHigh,
				VerificationLevel: rules.VerificationVerified,
				TrustClass:        rules.TrustMachineTrusted,
			},
		},
	}
	eval := NewEvaluator()
	report := eval.Evaluate(cs, execResult)

	if report.Verdicts.Verified != 1 {
		t.Errorf("pass + high + verified + machine_trusted should count as verified, got %d", report.Verdicts.Verified)
	}
}

func TestEvaluateClaim_NoRules(t *testing.T) {
	claim := Claim{
		ID:       "test.empty",
		Title:    "Empty",
		Category: "testing",
		RuleIDs:  []string{},
	}

	verdict := evaluateClaim(claim, map[string]rules.Finding{})

	if verdict.Status != "unknown" {
		t.Errorf("expected status unknown for empty rule list, got %s", verdict.Status)
	}
}

// ---------------------------------------------------------------------------
// Trust boundary: advisory findings must never count as Verified
// ---------------------------------------------------------------------------

func TestAdvisoryFindingsNeverVerified(t *testing.T) {
	cs := &ClaimSet{
		Name: "test",
		Claims: []Claim{
			{ID: "c1", Title: "Advisory claim", Category: "security", RuleIDs: []string{"R1"}},
		},
	}
	execResult := rules.ExecutionResult{
		Findings: []rules.Finding{
			{
				RuleID:            "R1",
				Status:            rules.StatusPass,
				Confidence:        rules.ConfidenceHigh,
				VerificationLevel: rules.VerificationVerified, // Even if set to verified
				TrustClass:        rules.TrustAdvisory,        // Advisory must NOT count
			},
		},
	}
	eval := NewEvaluator()
	report := eval.Evaluate(cs, execResult)

	if report.Verdicts.Verified != 0 {
		t.Errorf("advisory findings must NOT count as verified, got %d", report.Verdicts.Verified)
	}
	if report.Verdicts.Passed != 1 {
		t.Errorf("advisory findings should still count as passed, got %d", report.Verdicts.Passed)
	}
}

func TestHumanRequiredFindingsNeverVerified(t *testing.T) {
	cs := &ClaimSet{
		Name: "test",
		Claims: []Claim{
			{ID: "c1", Title: "Human claim", Category: "security", RuleIDs: []string{"R1"}},
		},
	}
	execResult := rules.ExecutionResult{
		Findings: []rules.Finding{
			{
				RuleID:            "R1",
				Status:            rules.StatusPass,
				Confidence:        rules.ConfidenceHigh,
				VerificationLevel: rules.VerificationVerified,
				TrustClass:        rules.TrustHumanOrRuntimeRequired,
			},
		},
	}
	eval := NewEvaluator()
	report := eval.Evaluate(cs, execResult)

	if report.Verdicts.Verified != 0 {
		t.Errorf("human_or_runtime_required findings must NOT count as verified, got %d", report.Verdicts.Verified)
	}
}

func TestMixedTrustClassUsesLowest(t *testing.T) {
	claim := Claim{
		ID:       "test.mixed_trust",
		Title:    "Mixed trust",
		Category: "testing",
		RuleIDs:  []string{"R1", "R2"},
	}
	ruleResults := map[string]rules.Finding{
		"R1": {
			RuleID:            "R1",
			Status:            rules.StatusPass,
			Confidence:        rules.ConfidenceHigh,
			VerificationLevel: rules.VerificationVerified,
			TrustClass:        rules.TrustMachineTrusted,
		},
		"R2": {
			RuleID:            "R2",
			Status:            rules.StatusPass,
			Confidence:        rules.ConfidenceMedium,
			VerificationLevel: rules.VerificationStrongInference,
			TrustClass:        rules.TrustAdvisory,
		},
	}

	verdict := evaluateClaim(claim, ruleResults)

	if verdict.TrustBreakdown.EffectiveTrustClass != "advisory" {
		t.Errorf("mixed trust claim should use lowest trust class (advisory), got %s", verdict.TrustBreakdown.EffectiveTrustClass)
	}
	if verdict.TrustBreakdown.MachineTrusted != 1 {
		t.Errorf("expected 1 machine_trusted, got %d", verdict.TrustBreakdown.MachineTrusted)
	}
	if verdict.TrustBreakdown.Advisory != 1 {
		t.Errorf("expected 1 advisory, got %d", verdict.TrustBreakdown.Advisory)
	}
}

func TestMixedTrustClaimNotVerified(t *testing.T) {
	// A claim with mixed trust classes (machine_trusted + advisory) must NOT be verified
	cs := &ClaimSet{
		Name: "test",
		Claims: []Claim{
			{ID: "c1", Title: "Mixed claim", Category: "security", RuleIDs: []string{"R1", "R2"}},
		},
	}
	execResult := rules.ExecutionResult{
		Findings: []rules.Finding{
			{
				RuleID:            "R1",
				Status:            rules.StatusPass,
				Confidence:        rules.ConfidenceHigh,
				VerificationLevel: rules.VerificationVerified,
				TrustClass:        rules.TrustMachineTrusted,
			},
			{
				RuleID:            "R2",
				Status:            rules.StatusPass,
				Confidence:        rules.ConfidenceHigh,
				VerificationLevel: rules.VerificationVerified,
				TrustClass:        rules.TrustAdvisory,
			},
		},
	}
	eval := NewEvaluator()
	report := eval.Evaluate(cs, execResult)

	if report.Verdicts.Verified != 0 {
		t.Errorf("mixed trust class claim must NOT count as verified, got %d", report.Verdicts.Verified)
	}
}

func TestTrustClassRankDefault(t *testing.T) {
	if trustClassRank("") != 0 {
		t.Error("expected 0 for empty trust class")
	}
	if trustClassRank("invalid") != 0 {
		t.Error("expected 0 for invalid trust class")
	}
}

func TestTrustClassFromRankDefault(t *testing.T) {
	if trustClassFromRank(0) != "" {
		t.Error("expected empty string for rank 0")
	}
	if trustClassFromRank(-1) != "" {
		t.Error("expected empty string for rank -1")
	}
}

// --- Mixed trust class claims: trust-class collapsing prevention tests ---

func TestMixedTrustClass_MachineTrustedAndAdvisory_EffectiveIsAdvisory(t *testing.T) {
	// A claim with BOTH machine_trusted and advisory rules must get
	// EffectiveTrustClass = advisory (the lowest).
	claim := Claim{
		ID:       "test.mixed_mt_adv",
		Title:    "Mixed machine_trusted + advisory",
		Category: "security",
		RuleIDs:  []string{"R1", "R2", "R3"},
	}
	ruleResults := map[string]rules.Finding{
		"R1": {
			RuleID:            "R1",
			Status:            rules.StatusPass,
			Confidence:        rules.ConfidenceHigh,
			VerificationLevel: rules.VerificationVerified,
			TrustClass:        rules.TrustMachineTrusted,
		},
		"R2": {
			RuleID:            "R2",
			Status:            rules.StatusPass,
			Confidence:        rules.ConfidenceHigh,
			VerificationLevel: rules.VerificationVerified,
			TrustClass:        rules.TrustMachineTrusted,
		},
		"R3": {
			RuleID:            "R3",
			Status:            rules.StatusPass,
			Confidence:        rules.ConfidenceMedium,
			VerificationLevel: rules.VerificationStrongInference,
			TrustClass:        rules.TrustAdvisory,
		},
	}

	verdict := evaluateClaim(claim, ruleResults)

	if verdict.TrustBreakdown.EffectiveTrustClass != "advisory" {
		t.Errorf("mixed machine_trusted+advisory claim must have effective trust class advisory, got %s",
			verdict.TrustBreakdown.EffectiveTrustClass)
	}
	if verdict.TrustBreakdown.MachineTrusted != 2 {
		t.Errorf("expected 2 machine_trusted in breakdown, got %d", verdict.TrustBreakdown.MachineTrusted)
	}
	if verdict.TrustBreakdown.Advisory != 1 {
		t.Errorf("expected 1 advisory in breakdown, got %d", verdict.TrustBreakdown.Advisory)
	}
}

func TestMixedTrustClass_AllThree_EffectiveIsHumanRequired(t *testing.T) {
	// A claim with all three trust classes must get
	// EffectiveTrustClass = human_or_runtime_required (the lowest).
	claim := Claim{
		ID:       "test.mixed_all_three",
		Title:    "All three trust classes",
		Category: "security",
		RuleIDs:  []string{"R1", "R2", "R3"},
	}
	ruleResults := map[string]rules.Finding{
		"R1": {
			RuleID:     "R1",
			Status:     rules.StatusPass,
			Confidence: rules.ConfidenceHigh,
			TrustClass: rules.TrustMachineTrusted,
		},
		"R2": {
			RuleID:     "R2",
			Status:     rules.StatusPass,
			Confidence: rules.ConfidenceMedium,
			TrustClass: rules.TrustAdvisory,
		},
		"R3": {
			RuleID:     "R3",
			Status:     rules.StatusPass,
			Confidence: rules.ConfidenceLow,
			TrustClass: rules.TrustHumanOrRuntimeRequired,
		},
	}

	verdict := evaluateClaim(claim, ruleResults)

	if verdict.TrustBreakdown.EffectiveTrustClass != "human_or_runtime_required" {
		t.Errorf("expected effective trust human_or_runtime_required, got %s",
			verdict.TrustBreakdown.EffectiveTrustClass)
	}
}

func TestTrustBreakdown_AlwaysPopulated(t *testing.T) {
	// TrustBreakdown must be populated for any claim with rules,
	// even when all rules are the same trust class.
	claim := Claim{
		ID:       "test.single_class",
		Title:    "Single class",
		Category: "testing",
		RuleIDs:  []string{"R1"},
	}
	ruleResults := map[string]rules.Finding{
		"R1": {
			RuleID:     "R1",
			Status:     rules.StatusPass,
			Confidence: rules.ConfidenceHigh,
			TrustClass: rules.TrustAdvisory,
		},
	}

	verdict := evaluateClaim(claim, ruleResults)

	if verdict.TrustBreakdown.Advisory != 1 {
		t.Errorf("expected advisory=1, got %d", verdict.TrustBreakdown.Advisory)
	}
	if verdict.TrustBreakdown.EffectiveTrustClass != "advisory" {
		t.Errorf("expected effective trust advisory, got %s", verdict.TrustBreakdown.EffectiveTrustClass)
	}
}

func TestMixedTrustClaimViaEvaluator_NotVerified(t *testing.T) {
	// End-to-end via Evaluator: mixed trust claim must NOT be counted as verified
	cs := &ClaimSet{
		Name: "test",
		Claims: []Claim{
			{ID: "c1", Title: "Mixed trust", Category: "security", RuleIDs: []string{"R1", "R2"}},
		},
	}
	execResult := rules.ExecutionResult{
		Findings: []rules.Finding{
			{
				RuleID:            "R1",
				Status:            rules.StatusPass,
				Confidence:        rules.ConfidenceHigh,
				VerificationLevel: rules.VerificationVerified,
				TrustClass:        rules.TrustMachineTrusted,
			},
			{
				RuleID:            "R2",
				Status:            rules.StatusPass,
				Confidence:        rules.ConfidenceHigh,
				VerificationLevel: rules.VerificationStrongInference,
				TrustClass:        rules.TrustAdvisory,
			},
		},
	}
	eval := NewEvaluator()
	report := eval.Evaluate(cs, execResult)

	if report.Verdicts.Verified != 0 {
		t.Errorf("mixed trust class claim must NOT count as verified, got %d", report.Verdicts.Verified)
	}
	if report.Verdicts.Passed != 1 {
		t.Errorf("expected 1 passed, got %d", report.Verdicts.Passed)
	}
	if report.Claims[0].TrustBreakdown.EffectiveTrustClass != "advisory" {
		t.Errorf("expected effective trust advisory, got %s", report.Claims[0].TrustBreakdown.EffectiveTrustClass)
	}
}
