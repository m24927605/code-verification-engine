package cli

import (
	"os"
	"testing"
)

func TestRunVersion(t *testing.T) {
	code := Run([]string{"version"})
	if code != ExitSuccess {
		t.Errorf("version should exit 0, got %d", code)
	}
}

func TestRunNoArgs(t *testing.T) {
	code := Run([]string{})
	if code != ExitInvalidInput {
		t.Errorf("no args should exit 1, got %d", code)
	}
}

func TestRunUnknownCommand(t *testing.T) {
	code := Run([]string{"unknown"})
	if code != ExitInvalidInput {
		t.Errorf("unknown command should exit 1, got %d", code)
	}
}

func TestRunVerifyMissingArgs(t *testing.T) {
	code := Run([]string{"verify", "--output", "/tmp/out"})
	if code != ExitInvalidInput {
		t.Errorf("verify without --repo should exit 1, got %d", code)
	}
}

func TestRunVerifyMissingOutput(t *testing.T) {
	code := Run([]string{"verify", "--repo", "/tmp"})
	if code != ExitInvalidInput {
		t.Errorf("verify without --output should exit 1, got %d", code)
	}
}

func TestRunVerifyMissingBothRepoAndOutput(t *testing.T) {
	code := Run([]string{"verify"})
	if code != ExitInvalidInput {
		t.Errorf("verify without --repo and --output should exit 1, got %d", code)
	}
}

func TestRunVerifyInvalidProfile(t *testing.T) {
	code := Run([]string{"verify", "--repo", "/tmp", "--profile", "nonexistent", "--output", "/tmp/out"})
	if code != ExitInvalidInput {
		t.Errorf("verify with bad profile should exit 1, got %d", code)
	}
}

func TestRunVerifyInvalidFormat(t *testing.T) {
	code := Run([]string{"verify", "--repo", "/tmp", "--output", "/tmp/out", "--format", "xml"})
	if code != ExitInvalidInput {
		t.Errorf("verify with bad format should exit 1, got %d", code)
	}
}

func TestRunVerifyInvalidClaimSet(t *testing.T) {
	code := Run([]string{"verify", "--repo", "/tmp", "--output", "/tmp/out", "--claims", "nonexistent-claim-set"})
	if code != ExitInvalidInput {
		t.Errorf("verify with bad claim set should exit 1, got %d", code)
	}
}

func TestRunVerifyInvalidFlag(t *testing.T) {
	code := Run([]string{"verify", "--nonexistent-flag"})
	if code != ExitInvalidInput {
		t.Errorf("verify with invalid flag should exit 1, got %d", code)
	}
}

func TestRunVerifyInterpretWithoutAPIKey(t *testing.T) {
	// Ensure CVE_LLM_API_KEY is unset
	os.Unsetenv("CVE_LLM_API_KEY")
	// This will proceed past arg validation but fail at engine.Run (not a git repo).
	// The important thing is it doesn't crash and reaches the engine call.
	code := Run([]string{"verify", "--repo", "/tmp", "--output", "/tmp/cve-test-out", "--interpret"})
	// Should fail with repo error (not invalid input), proving --interpret path was reached
	if code == ExitInvalidInput {
		t.Errorf("verify with --interpret should not exit with invalid input, got %d", code)
	}
}

func TestRunVerifyInterpretWithAPIKey(t *testing.T) {
	os.Setenv("CVE_LLM_API_KEY", "test-key")
	defer os.Unsetenv("CVE_LLM_API_KEY")
	code := Run([]string{"verify", "--repo", "/tmp", "--output", "/tmp/cve-test-out", "--interpret"})
	if code == ExitInvalidInput {
		t.Errorf("verify with --interpret and API key should not exit with invalid input, got %d", code)
	}
}

func TestRunVerifyInterpretWithAPIKeyAndURL(t *testing.T) {
	os.Setenv("CVE_LLM_API_KEY", "test-key")
	os.Setenv("CVE_LLM_API_URL", "https://custom.api.example.com/v1")
	defer os.Unsetenv("CVE_LLM_API_KEY")
	defer os.Unsetenv("CVE_LLM_API_URL")
	code := Run([]string{"verify", "--repo", "/tmp", "--output", "/tmp/cve-test-out", "--interpret"})
	if code == ExitInvalidInput {
		t.Errorf("verify with --interpret, API key and URL should not exit with invalid input, got %d", code)
	}
}

func TestRunVerifyValidFormats(t *testing.T) {
	for _, fmt := range []string{"json", "md", "both"} {
		code := Run([]string{"verify", "--repo", "/tmp", "--output", "/tmp/cve-test-out", "--format", fmt})
		if code == ExitInvalidInput {
			t.Errorf("verify with format=%s should not exit with invalid input, got %d", fmt, code)
		}
	}
}

func TestRunVerifyStrictFlag(t *testing.T) {
	code := Run([]string{"verify", "--repo", "/tmp", "--output", "/tmp/cve-test-out", "--strict"})
	if code == ExitInvalidInput {
		t.Errorf("verify with --strict should not exit with invalid input, got %d", code)
	}
}

func TestRunListProfiles(t *testing.T) {
	code := Run([]string{"list-profiles"})
	if code != ExitSuccess {
		t.Errorf("list-profiles should exit 0, got %d", code)
	}
}

func TestRunListClaims(t *testing.T) {
	code := Run([]string{"list-claims"})
	if code != ExitSuccess {
		t.Errorf("list-claims should exit 0, got %d", code)
	}
}

func TestExitCodeConstants(t *testing.T) {
	if ExitSuccess != 0 {
		t.Errorf("ExitSuccess should be 0, got %d", ExitSuccess)
	}
	if ExitInvalidInput != 1 {
		t.Errorf("ExitInvalidInput should be 1, got %d", ExitInvalidInput)
	}
	if ExitRepoError != 2 {
		t.Errorf("ExitRepoError should be 2, got %d", ExitRepoError)
	}
	if ExitRuleValidation != 3 {
		t.Errorf("ExitRuleValidation should be 3, got %d", ExitRuleValidation)
	}
	if ExitAnalysisFailure != 4 {
		t.Errorf("ExitAnalysisFailure should be 4, got %d", ExitAnalysisFailure)
	}
	if ExitReportWrite != 5 {
		t.Errorf("ExitReportWrite should be 5, got %d", ExitReportWrite)
	}
	if ExitPartialSuccess != 6 {
		t.Errorf("ExitPartialSuccess should be 6, got %d", ExitPartialSuccess)
	}
	if ExitCancelled != 7 {
		t.Errorf("ExitCancelled should be 7, got %d", ExitCancelled)
	}
}

func TestVersionDefault(t *testing.T) {
	if Version != "dev" {
		t.Errorf("default Version should be 'dev', got %s", Version)
	}
}

func TestRunVerifyInvalidMode(t *testing.T) {
	code := Run([]string{"verify", "--repo", "/tmp", "--output", "/tmp/cve-test-out", "--mode", "invalid"})
	if code != ExitInvalidInput {
		t.Errorf("verify with invalid mode should exit 1, got %d", code)
	}
}

func TestRunVerifyValidModes(t *testing.T) {
	for _, mode := range []string{"verification", "skill_inference", "both"} {
		code := Run([]string{"verify", "--repo", "/tmp", "--output", "/tmp/cve-test-out", "--mode", mode})
		if code == ExitInvalidInput {
			t.Errorf("verify with mode=%s should not exit with invalid input, got %d", mode, code)
		}
	}
}

func TestRunVerifyInvalidSkillProfile(t *testing.T) {
	code := Run([]string{"verify", "--repo", "/tmp", "--output", "/tmp/cve-test-out", "--mode", "skill_inference", "--skill-profile", "nonexistent-profile"})
	if code != ExitInvalidInput {
		t.Errorf("verify with invalid skill profile should exit 1, got %d", code)
	}
}

func TestRunListSkillProfiles(t *testing.T) {
	code := Run([]string{"list-skill-profiles"})
	if code != ExitSuccess {
		t.Errorf("list-skill-profiles should exit 0, got %d", code)
	}
}

func TestRunReleaseGateList(t *testing.T) {
	code := Run([]string{"release-gate", "--list"})
	if code != ExitSuccess {
		t.Errorf("release-gate --list should exit 0, got %d", code)
	}
}

func TestRunVerifyRefFlag(t *testing.T) {
	code := Run([]string{"verify", "--repo", "/tmp", "--output", "/tmp/cve-test-out", "--ref", "v1.0.0"})
	if code == ExitInvalidInput {
		t.Errorf("verify with --ref should not exit with invalid input, got %d", code)
	}
}

func TestRunVerifyInterpretOllamaProviderWithoutAPIKey(t *testing.T) {
	os.Setenv("CVE_LLM_PROVIDER", "ollama")
	os.Setenv("CVE_LLM_API_URL", "http://localhost:11434/v1/chat/completions")
	os.Setenv("CVE_LLM_MODEL", "codellama:8b")
	defer os.Unsetenv("CVE_LLM_PROVIDER")
	defer os.Unsetenv("CVE_LLM_API_URL")
	defer os.Unsetenv("CVE_LLM_MODEL")
	code := Run([]string{"verify", "--repo", "/tmp", "--output", "/tmp/cve-test-out", "--interpret"})
	if code == ExitInvalidInput {
		t.Errorf("verify with ollama provider should not exit with invalid input, got %d", code)
	}
}

func TestRunVerifyInterpretUnsupportedProvider(t *testing.T) {
	for _, provider := range []string{"openai", "anthropic", "custom-llm"} {
		t.Run(provider, func(t *testing.T) {
			t.Setenv("CVE_LLM_PROVIDER", provider)
			t.Setenv("CVE_LLM_API_KEY", "test-key")
			code := Run([]string{"verify", "--repo", "/tmp", "--output", "/tmp/cve-test-out", "--interpret"})
			if code == ExitInvalidInput {
				t.Errorf("verify with unsupported provider %q should not exit with invalid input, got %d", provider, code)
			}
		})
	}
}

func TestRunReleaseGateInvalidFlag(t *testing.T) {
	code := Run([]string{"release-gate", "--nonexistent-flag"})
	if code != ExitInvalidInput {
		t.Errorf("release-gate with invalid flag should exit %d, got %d", ExitInvalidInput, code)
	}
}

func TestRunReleaseGateExecution(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping release gate execution in short mode")
	}
	code := Run([]string{"release-gate"})
	// May pass or fail depending on test state; just verify it runs the execution path
	if code != ExitSuccess && code != ExitAnalysisFailure {
		t.Errorf("release-gate should exit with %d or %d, got %d", ExitSuccess, ExitAnalysisFailure, code)
	}
}
