package releasegate

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestDefaultStepsMatchesSpecOrder(t *testing.T) {
	t.Parallel()

	steps := DefaultSteps()
	if len(steps) != 8 {
		t.Fatalf("expected 8 release gate steps, got %d", len(steps))
	}

	expected := []string{
		"go test ./internal/rules",
		"go test ./internal/report",
		"go test ./internal/artifactsv2",
		"go test ./internal/acceptance",
		"go test ./internal/engine",
		"go test ./pkg/cve",
		"go test ./internal/releasegate",
		"go build ./cmd/cve",
	}

	for i, step := range steps {
		var got string
		switch len(step.Command) {
		case 2:
			got = fmt.Sprintf("%s %s", step.Command[0], step.Command[1])
		default:
			got = fmt.Sprintf("%s %s %s", step.Command[0], step.Command[1], step.Command[2])
		}
		if expected[i] == "go test ./internal/releasegate" {
			if step.Command[0] != "go" || step.Command[1] != "test" || step.Command[2] != "./internal/releasegate" {
				t.Fatalf("step %d = %#v, want release gate/cli/cmd test step", i, step.Command)
			}
			continue
		}
		if got != expected[i] {
			t.Fatalf("step %d = %q, want %q", i, got, expected[i])
		}
	}
}

func TestRequiredManualChecksMatchesSpec(t *testing.T) {
	t.Parallel()

	checks := RequiredManualChecks()
	if len(checks) != 8 {
		t.Fatalf("expected 8 manual release checks, got %d", len(checks))
	}

	expected := []string{
		"native-rule-migration",
		"deterministic-path",
		"aggregation",
		"confidence",
		"context-agent-contract",
		"claims-profile-resume",
		"bundle-validation",
		"primary-product",
	}
	for i, check := range checks {
		if check.Name != expected[i] {
			t.Fatalf("manual check %d = %q, want %q", i, check.Name, expected[i])
		}
		if check.Description == "" {
			t.Fatalf("manual check %q must have a description", check.Name)
		}
	}
}

func TestRequiredManualChecksCoverReleaseBlockingAreas(t *testing.T) {
	t.Parallel()

	checks := RequiredManualChecks()
	wantFragments := map[string]string{
		"native-rule-migration":  "issue_native, seed_native, and finding_bridged",
		"aggregation":            "family boundary",
		"confidence":             "benchmark-backed thresholds",
		"context-agent-contract": "executed agent runtime",
		"claims-profile-resume":  "claims.json, profile.json, and resume_input.json",
		"bundle-validation":      "verifiable bundle artifacts",
		"primary-product":        "deterministic primary product",
		"deterministic-path":     "deterministic path",
	}
	for _, check := range checks {
		fragment, ok := wantFragments[check.Name]
		if !ok {
			t.Fatalf("unexpected manual check %q", check.Name)
		}
		if !strings.Contains(check.Description, fragment) {
			t.Fatalf("manual check %q description %q does not contain required fragment %q", check.Name, check.Description, fragment)
		}
		delete(wantFragments, check.Name)
	}
	if len(wantFragments) != 0 {
		t.Fatalf("missing manual checks: %#v", wantFragments)
	}
}

func TestRunStopsOnFirstFailure(t *testing.T) {
	t.Parallel()

	callCount := 0
	result := Run(context.Background(), func(ctx context.Context, command []string) (string, error) {
		callCount++
		if callCount == 3 {
			return "boom", fmt.Errorf("failed")
		}
		return "ok", nil
	})

	if result.Passed {
		t.Fatal("expected release gate to fail")
	}
	if len(result.Steps) != 3 {
		t.Fatalf("expected runner to stop after third step, got %d steps", len(result.Steps))
	}
	if result.Steps[2].Passed {
		t.Fatal("expected third step to fail")
	}
}

func TestRunPassesWhenAllStepsSucceed(t *testing.T) {
	t.Parallel()

	result := Run(context.Background(), func(ctx context.Context, command []string) (string, error) {
		return "ok", nil
	})

	if !result.Passed {
		t.Fatal("expected release gate to pass")
	}
	if len(result.Steps) != len(DefaultSteps()) {
		t.Fatalf("expected all steps to run, got %d", len(result.Steps))
	}
}

func TestReleaseGateEnvAddsWritableGoCacheWhenUnset(t *testing.T) {
	t.Setenv("GOCACHE", "")

	env := releaseGateEnv()
	found := false
	for _, entry := range env {
		if strings.HasPrefix(entry, "GOCACHE=") {
			found = true
			if strings.TrimPrefix(entry, "GOCACHE=") == "" {
				t.Fatal("expected non-empty fallback GOCACHE")
			}
		}
	}
	if !found {
		t.Fatal("expected fallback GOCACHE to be injected")
	}
}

func TestReleaseGateEnvPreservesExplicitGoCache(t *testing.T) {
	t.Setenv("GOCACHE", "/tmp/custom-cache")

	env := releaseGateEnv()
	found := false
	for _, entry := range env {
		if entry == "GOCACHE=/tmp/custom-cache" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected explicit GOCACHE to be preserved, got %#v", env)
	}
	if os.Getenv("GOCACHE") != "/tmp/custom-cache" {
		t.Fatal("expected process GOCACHE env to remain unchanged")
	}
}
