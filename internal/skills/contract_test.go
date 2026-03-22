package skills

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/rules"
)

func TestValidateReport_ValidReport(t *testing.T) {
	r := &Report{
		SchemaVersion: "1.0.0",
		Profile:       "github-engineer-core",
		Signals: []Signal{
			{
				ID: "1", SkillID: "backend_auth.jwt_middleware",
				Status: StatusObserved, TrustClass: "advisory",
				Confidence: ConfidenceMedium, EvidenceStrength: EvidenceHeuristic,
				Evidence: []rules.Evidence{{File: "auth.go", LineStart: 1, LineEnd: 5}},
			},
			{
				ID: "2", SkillID: "backend_runtime.graceful_shutdown",
				Status: StatusUnsupported, TrustClass: "human_or_runtime_required",
				Confidence: ConfidenceLow, EvidenceStrength: EvidenceHeuristic,
				UnknownReasons: []string{"no matching facts or findings"},
			},
		},
		Summary: Summary{Observed: 1, Inferred: 0, Unsupported: 1},
	}

	errs := ValidateReport(r)
	if len(errs) > 0 {
		for _, e := range errs {
			t.Errorf("unexpected validation error: %v", e)
		}
	}
}

func TestValidateReport_MissingRequiredFields(t *testing.T) {
	r := &Report{
		Signals: []Signal{
			{Status: StatusObserved, TrustClass: "advisory"},
		},
		Summary: Summary{Observed: 1},
	}
	errs := ValidateReport(r)
	if len(errs) == 0 {
		t.Fatal("expected validation errors for missing fields")
	}

	// Should catch: missing schema_version, profile, signal id, skill_id, observed without evidence
	foundSchemaErr, foundProfileErr, foundIDErr, foundSkillIDErr, foundEvidenceErr := false, false, false, false, false
	for _, e := range errs {
		msg := e.Error()
		if msg == "schema_version is required" {
			foundSchemaErr = true
		}
		if msg == "profile is required" {
			foundProfileErr = true
		}
		if msg == "signal[0]: id is required" {
			foundIDErr = true
		}
		if msg == "signal[0]: skill_id is required" {
			foundSkillIDErr = true
		}
		if msg == "signal[0]: observed signal must include evidence" {
			foundEvidenceErr = true
		}
	}
	if !foundSchemaErr {
		t.Error("missing schema_version error")
	}
	if !foundProfileErr {
		t.Error("missing profile error")
	}
	if !foundIDErr {
		t.Error("missing id error")
	}
	if !foundSkillIDErr {
		t.Error("missing skill_id error")
	}
	if !foundEvidenceErr {
		t.Error("missing evidence error for observed signal")
	}
}

func TestValidateReport_HighConfidenceHeuristicFails(t *testing.T) {
	r := &Report{
		SchemaVersion: "1.0.0",
		Profile:       "test",
		Signals: []Signal{
			{
				ID: "1", SkillID: "test.signal",
				Status: StatusInferred, TrustClass: "advisory",
				Confidence: ConfidenceHigh, EvidenceStrength: EvidenceHeuristic,
			},
		},
		Summary: Summary{Inferred: 1},
	}
	errs := ValidateReport(r)
	found := false
	for _, e := range errs {
		if e.Error() == "signal[0]: high confidence with heuristic-only evidence is not allowed" {
			found = true
		}
	}
	if !found {
		t.Error("should reject high confidence with heuristic evidence")
	}
}

func TestValidateReport_HighConfidenceHumanRequiredFails(t *testing.T) {
	r := &Report{
		SchemaVersion: "1.0.0",
		Profile:       "test",
		Signals: []Signal{
			{
				ID: "1", SkillID: "test.signal",
				Status: StatusInferred, TrustClass: "human_or_runtime_required",
				Confidence: ConfidenceHigh, EvidenceStrength: EvidenceStructural,
			},
		},
		Summary: Summary{Inferred: 1},
	}
	errs := ValidateReport(r)
	found := false
	for _, e := range errs {
		if e.Error() == "signal[0]: high confidence with human_or_runtime_required trust is not allowed" {
			found = true
		}
	}
	if !found {
		t.Error("should reject high confidence with human_or_runtime_required trust")
	}
}

func TestValidateReport_SummaryMismatch(t *testing.T) {
	r := &Report{
		SchemaVersion: "1.0.0",
		Profile:       "test",
		Signals: []Signal{
			{
				ID: "1", SkillID: "test.signal",
				Status: StatusObserved, TrustClass: "advisory",
				Confidence: ConfidenceMedium, EvidenceStrength: EvidenceStructural,
				Evidence: []rules.Evidence{{File: "a.go", LineStart: 1, LineEnd: 1}},
			},
		},
		Summary: Summary{Observed: 0, Inferred: 1}, // wrong
	}
	errs := ValidateReport(r)
	if len(errs) == 0 {
		t.Fatal("expected summary mismatch errors")
	}
}

func TestValidateReport_InvalidStatus(t *testing.T) {
	r := &Report{
		SchemaVersion: "1.0.0",
		Profile:       "test",
		Signals: []Signal{
			{
				ID: "1", SkillID: "test.signal",
				Status: "pass", TrustClass: "advisory",
				Confidence: ConfidenceMedium, EvidenceStrength: EvidenceHeuristic,
			},
		},
		Summary: Summary{},
	}
	errs := ValidateReport(r)
	found := false
	for _, e := range errs {
		if e.Error() == `signal[0]: invalid status "pass" (must be observed|inferred|unsupported)` {
			found = true
		}
	}
	if !found {
		t.Error("should reject pass/fail/unknown as skill signal status")
	}
}

func TestValidateReport_UnsupportedWithoutReasons(t *testing.T) {
	r := &Report{
		SchemaVersion: "1.0.0",
		Profile:       "test",
		Signals: []Signal{
			{
				ID: "1", SkillID: "test.signal",
				Status: StatusUnsupported, TrustClass: "human_or_runtime_required",
				Confidence: ConfidenceLow, EvidenceStrength: EvidenceHeuristic,
				// no UnknownReasons and no Evidence
			},
		},
		Summary: Summary{Unsupported: 1},
	}
	errs := ValidateReport(r)
	found := false
	for _, e := range errs {
		if e.Error() == "signal[0]: unsupported signal must include unknown_reasons when no evidence" {
			found = true
		}
	}
	if !found {
		t.Error("should require unknown_reasons for unsupported signals without evidence")
	}
}
