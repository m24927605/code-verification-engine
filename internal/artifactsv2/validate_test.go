package artifactsv2

import (
	"strings"
	"testing"
)

func TestValidateReportRejectsInconsistentConfidenceClass(t *testing.T) {
	t.Parallel()

	bundle := testBundle()
	bundle.Report.Issues[0].ConfidenceClass = "moderate"

	if err := ValidateReport(bundle.Report); err == nil {
		t.Fatal("expected ValidateReport to reject inconsistent confidence class")
	}
}

func TestValidateReportRejectsMachineTrustedWithoutStrongBreakdown(t *testing.T) {
	t.Parallel()

	bundle := testBundle()
	bundle.Report.Issues[0].ConfidenceBreakdown.RuleReliability = 0.70

	if err := ValidateReport(bundle.Report); err == nil {
		t.Fatal("expected ValidateReport to reject weak machine_trusted breakdown")
	}
}

func TestValidateBundleRejectsAgentContextReferenceMismatch(t *testing.T) {
	t.Parallel()

	bundle := testBundle()
	bundle.Trace.ContextSelections = []ContextSelectionRecord{{
		ID:                  "ctx-001",
		TriggerType:         "issue",
		TriggerID:           "iss-1",
		SelectedEvidenceIDs: []string{"ev-1"},
		EntityIDs:           []string{"fn-1"},
		SelectedSpans:       []LocationRef{{RepoRelPath: "service.ts", StartLine: 10, EndLine: 10}},
		MaxFiles:            2,
		MaxSpans:            4,
		MaxTokens:           1200,
	}}
	bundle.Trace.Agents = []AgentRun{{
		ID:                 "agent-1",
		Kind:               "bug",
		IssueType:          "bug_review",
		Question:           "Assess whether the issue should remain unknown or can be confirmed with the selected bounded context.",
		IssueID:            "iss-1",
		ContextSelectionID: "ctx-missing",
		TriggerReason:      "unknown_issue",
		InputEvidenceIDs:   []string{"ev-1"},
		MaxFiles:           2,
		MaxTokens:          1200,
		AllowSpeculation:   false,
		Status:             "planned",
	}}
	if err := ValidateBundle(bundle); err == nil {
		t.Fatal("expected ValidateBundle to reject missing context selection reference")
	}
}

func TestValidateTraceRejectsAgentWithoutQuestion(t *testing.T) {
	t.Parallel()

	trace := TraceArtifact{
		SchemaVersion: "2.0.0",
		EngineVersion: "verabase@1.0.0",
		TraceID:       "trace-1",
		Repo:          "github.com/user/repo",
		Commit:        "abc123",
		Timestamp:     "2026-03-27T12:00:00Z",
		ScanBoundary:  TraceScanBoundary{Mode: "repo", IncludedFiles: 1},
		Agents: []AgentRun{{
			ID:            "agent-1",
			Kind:          "bug",
			IssueType:     "bug_review",
			TriggerReason: "unknown_issue",
			Status:        "planned",
		}},
	}

	if err := ValidateTrace(trace); err == nil {
		t.Fatal("expected ValidateTrace to reject missing agent question")
	}
}

func TestValidateTraceRejectsInsufficientContextAgentWithoutReasons(t *testing.T) {
	t.Parallel()

	trace := TraceArtifact{
		SchemaVersion: "2.0.0",
		EngineVersion: "verabase@1.0.0",
		TraceID:       "trace-1",
		Repo:          "github.com/user/repo",
		Commit:        "abc123",
		Timestamp:     "2026-03-27T12:00:00Z",
		ScanBoundary:  TraceScanBoundary{Mode: "repo", IncludedFiles: 1},
		Agents: []AgentRun{{
			ID:            "agent-1",
			Kind:          "bug",
			IssueType:     "bug_review",
			Question:      "Assess whether the issue should remain unknown or can be confirmed with the selected bounded context.",
			TriggerReason: "unknown_issue",
			Status:        "insufficient_context",
		}},
	}

	if err := ValidateTrace(trace); err == nil {
		t.Fatal("expected ValidateTrace to reject insufficient_context agent without unresolved reasons")
	}
}

func TestValidateReportRejectsMissingRuleFamily(t *testing.T) {
	t.Parallel()

	bundle := testBundle()
	bundle.Report.Issues[0].RuleFamily = ""

	if err := ValidateReport(bundle.Report); err == nil {
		t.Fatal("expected ValidateReport to reject missing rule family")
	}
}

func TestValidateTraceRejectsMissingConfidenceCalibrationDetails(t *testing.T) {
	t.Parallel()

	trace := testBundle().Trace
	trace.ConfidenceCalibration = &ConfidenceCalibration{
		Version: "v2-release-blocking-calibration-1",
	}

	if err := ValidateTrace(trace); err == nil {
		t.Fatal("expected ValidateTrace to reject incomplete confidence calibration")
	}
}

func TestValidateTraceRejectsMissingConfidenceCalibration(t *testing.T) {
	t.Parallel()

	trace := testBundle().Trace
	trace.ConfidenceCalibration = nil

	err := ValidateTrace(trace)
	if err == nil || !strings.Contains(err.Error(), "confidence_calibration is required") {
		t.Fatalf("expected missing confidence calibration error, got %v", err)
	}
}

func TestValidateTraceRejectsMissingReleaseBlockingCalibrationFamily(t *testing.T) {
	t.Parallel()

	trace := testBundle().Trace
	delete(trace.ConfidenceCalibration.RuleFamilyBaselines, "arch_layer")

	err := ValidateTrace(trace)
	if err == nil || !strings.Contains(err.Error(), "arch_layer") {
		t.Fatalf("expected missing release-blocking family baseline error, got %v", err)
	}
}
