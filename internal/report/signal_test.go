package report

import (
	"strings"
	"testing"

	"github.com/verabase/code-verification-engine/internal/rules"
)

func TestComputeIssueSignalSummary(t *testing.T) {
	issues := []Issue{
		{RuleID: "SEC-001", Title: "Secret", Category: "security", Status: "open"},
		{RuleID: "GOF-001", Title: "Factory", Category: "architecture", Status: "open"},
		{RuleID: "AUTH-001", Title: "Unknown", Category: "security", Status: "unknown"},
	}
	ss := ComputeIssueSignalSummary(issues, map[string]rules.Rule{
		"SEC-001": {ID: "SEC-001", Category: "security"},
		"GOF-001": {ID: "GOF-001", Category: "architecture"},
		"AUTH-001": {ID: "AUTH-001", Category: "security"},
	})
	if ss.ActionableFail != 1 || ss.InformationalDetection != 1 || ss.Unknown != 1 {
		t.Fatalf("unexpected signal summary: %+v", ss)
	}
}

func TestGenerateMarkdownSeparatesPatternDetections(t *testing.T) {
	md := GenerateMarkdown(ScanReport{}, VerificationReport{
		Issues: []Issue{
			{RuleID: "SEC-001", Title: "Secret", Status: "open"},
			{RuleID: "GOF-001", Title: "Factory", Status: "open"},
		},
	})
	if !strings.Contains(md, "## Pattern Detections") {
		t.Fatalf("markdown missing pattern detections section:\n%s", md)
	}
}
