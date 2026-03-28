package engine

import (
	"context"
	"io"
	"path/filepath"
	"testing"

	"github.com/verabase/code-verification-engine/internal/artifactsv2"
)

func TestBenchmarkV2ConfidenceOrderingReleaseBlockingScenarios(t *testing.T) {
	t.Parallel()

	secretBundle := runBenchmarkScenarioBundle(t, "SEC-SECRET-001", "fail", "trusted-core")
	layerBundle := runBenchmarkScenarioBundle(t, "ARCH-LAYER-001", "fail", "backend-api")
	patternBundle := runBenchmarkScenarioBundle(t, "ARCH-PATTERN-001", "fail", "backend-api")

	secretIssue := benchmarkIssueForRule(t, secretBundle, "SEC-SECRET-001")
	layerIssue := benchmarkIssueForRule(t, layerBundle, "ARCH-LAYER-001")
	patternIssue := benchmarkIssueForRule(t, patternBundle, "ARCH-PATTERN-001")

	if secretIssue.RuleFamily != "sec_secret" {
		t.Fatalf("expected SEC-SECRET-001 issue family sec_secret, got %#v", secretIssue)
	}
	if layerIssue.RuleFamily != "arch_layer" {
		t.Fatalf("expected ARCH-LAYER-001 issue family arch_layer, got %#v", layerIssue)
	}
	if patternIssue.RuleFamily != "arch_pattern" {
		t.Fatalf("expected ARCH-PATTERN-001 issue family arch_pattern, got %#v", patternIssue)
	}

	if secretIssue.Confidence <= layerIssue.Confidence {
		t.Fatalf("expected secret confidence %f to exceed layer confidence %f", secretIssue.Confidence, layerIssue.Confidence)
	}
	if layerIssue.Confidence <= patternIssue.Confidence {
		t.Fatalf("expected layer confidence %f to exceed pattern confidence %f", layerIssue.Confidence, patternIssue.Confidence)
	}

	if secretIssue.PolicyClass != "machine_trusted" {
		t.Fatalf("expected SEC-SECRET-001 to remain machine_trusted under benchmark fail scenario, got %#v", secretIssue)
	}
	if layerIssue.PolicyClass != "advisory" {
		t.Fatalf("expected ARCH-LAYER-001 to remain advisory under benchmark fail scenario, got %#v", layerIssue)
	}
	if patternIssue.PolicyClass != "advisory" && patternIssue.PolicyClass != "unknown_retained" {
		t.Fatalf("expected ARCH-PATTERN-001 to remain non-machine-trusted, got %#v", patternIssue)
	}
}

func runBenchmarkScenarioBundle(t *testing.T, ruleID, scenario, profile string) *artifactsv2.Bundle {
	t.Helper()

	scenarioDir := filepath.Join("..", "..", "testdata", "benchmark", "trusted-core", ruleID, scenario)
	repoDir := initTempGitRepo(t, scenarioDir)
	outputDir := t.TempDir()

	result := Run(Config{
		Ctx:       context.Background(),
		RepoPath:  repoDir,
		Ref:       "HEAD",
		Profile:   profile,
		OutputDir: outputDir,
		Format:    "json",
		Progress:  io.Discard,
	})
	if result.ExitCode != 0 && result.ExitCode != 6 {
		t.Fatalf("engine.Run(%s/%s/%s) exit code %d errors=%v", profile, ruleID, scenario, result.ExitCode, result.Errors)
	}
	if result.VerifiableBundle == nil {
		t.Fatalf("engine.Run(%s/%s/%s) missing verifiable bundle", profile, ruleID, scenario)
	}
	return result.VerifiableBundle
}

func benchmarkIssueForRule(t *testing.T, bundle *artifactsv2.Bundle, ruleID string) artifactsv2.Issue {
	t.Helper()

	for _, rule := range bundle.Trace.Rules {
		if rule.ID != ruleID {
			continue
		}
		if len(rule.TriggeredIssueIDs) == 0 {
			t.Fatalf("rule %s did not trigger any issue IDs in trace", ruleID)
		}
		issueID := rule.TriggeredIssueIDs[0]
		for _, issue := range bundle.Report.Issues {
			if issue.ID == issueID {
				return issue
			}
		}
		t.Fatalf("rule %s referenced unknown issue id %s", ruleID, issueID)
	}
	t.Fatalf("rule %s not found in trace", ruleID)
	return artifactsv2.Issue{}
}
