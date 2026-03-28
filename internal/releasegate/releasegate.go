package releasegate

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Step is a single required command in the local release gate.
type Step struct {
	Name    string
	Command []string
}

// StepResult records the execution outcome of a single gate step.
type StepResult struct {
	Step   Step
	Passed bool
	Output string
	Err    error
}

// Result is the full outcome of a local release gate run.
type Result struct {
	Passed bool
	Steps  []StepResult
}

// ManualCheck describes a required non-automated release gate confirmation.
type ManualCheck struct {
	Name        string
	Description string
}

// Executor runs a gate step command.
type Executor func(ctx context.Context, command []string) (string, error)

// DefaultSteps returns the authoritative local release gate command list.
func DefaultSteps() []Step {
	return []Step{
		{Name: "rules", Command: []string{"go", "test", "./internal/rules"}},
		{Name: "report", Command: []string{"go", "test", "./internal/report"}},
		{Name: "artifactsv2", Command: []string{"go", "test", "./internal/artifactsv2"}},
		{Name: "acceptance", Command: []string{"go", "test", "./internal/acceptance"}},
		{Name: "engine", Command: []string{"go", "test", "./internal/engine"}},
		{Name: "pkg-cve", Command: []string{"go", "test", "./pkg/cve"}},
		{Name: "releasegate-cli", Command: []string{"go", "test", "./internal/releasegate", "./internal/cli", "./cmd/cve"}},
		{Name: "build", Command: []string{"go", "build", "./cmd/cve"}},
	}
}

// RequiredManualChecks returns the documented manual confirmations required
// before a release can be considered ready.
func RequiredManualChecks() []ManualCheck {
	return []ManualCheck{
		{Name: "native-rule-migration", Description: "native rule migration fixtures across issue_native, seed_native, and finding_bridged are green"},
		{Name: "deterministic-path", Description: "acceptance fixtures for deterministic path are green"},
		{Name: "proof-grade-scenarios", Description: "proof-grade scenario projections preserve conservative outsourcing and PM acceptance semantics across the canonical fixture corpus with stable claim/evidence references, complete first-wave benchmark matrix coverage, and traceable legacy-rule-to-claim migration metadata"},
		{Name: "aggregation", Description: "aggregation merge / non-merge / family boundary fixtures are green"},
		{Name: "confidence", Description: "confidence ordering, benchmark-backed thresholds, penalties, and caps fixtures are green"},
		{Name: "context-agent-contract", Description: "bounded context selection, planned agent contract, and executed agent runtime fixtures are green"},
		{Name: "claims-profile-resume", Description: "claims.json, profile.json, and resume_input.json projections are green with bounded claim-to-profile-to-resume references and resume-safe verification-class filtering"},
		{Name: "bundle-validation", Description: "verifiable bundle artifacts validate successfully"},
		{Name: "primary-product", Description: "issue candidate set remains the deterministic primary product"},
	}
}

// Run executes the local release gate using the provided executor.
func Run(ctx context.Context, execFn Executor) Result {
	if execFn == nil {
		execFn = DefaultExecutor
	}

	steps := DefaultSteps()
	results := make([]StepResult, 0, len(steps))
	passed := true

	for _, step := range steps {
		output, err := execFn(ctx, step.Command)
		stepResult := StepResult{
			Step:   step,
			Passed: err == nil,
			Output: strings.TrimSpace(output),
			Err:    err,
		}
		results = append(results, stepResult)
		if err != nil {
			passed = false
			break
		}
	}

	return Result{
		Passed: passed,
		Steps:  results,
	}
}

// DefaultExecutor runs a gate command through the local shell environment.
func DefaultExecutor(ctx context.Context, command []string) (string, error) {
	if len(command) == 0 {
		return "", fmt.Errorf("release gate command is empty")
	}
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.Env = releaseGateEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s: %w", strings.Join(command, " "), err)
	}
	return string(out), nil
}

func releaseGateEnv() []string {
	base := os.Environ()
	env := make([]string, 0, len(base)+1)
	for _, entry := range base {
		if strings.HasPrefix(entry, "GOCACHE=") {
			continue
		}
		env = append(env, entry)
	}
	if os.Getenv("GOCACHE") != "" {
		return append(env, "GOCACHE="+os.Getenv("GOCACHE"))
	}
	cacheDir := filepath.Join(os.TempDir(), "cve-go-build-cache")
	return append(env, "GOCACHE="+cacheDir)
}
