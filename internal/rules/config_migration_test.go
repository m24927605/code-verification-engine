package rules

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/facts"
)

func TestConfigEnvReadCallExistsDeterministic(t *testing.T) {
	t.Parallel()

	rule := Rule{
		ID:        "CONFIG-001",
		Type:      "exists",
		Target:    "config.env_read_call_exists",
		Languages: []string{"go"},
	}
	fs := &FactSet{
		ConfigReads: []facts.ConfigReadFact{
			{Language: facts.LangGo, File: "config.go", Span: facts.Span{Start: 1, End: 2}, Key: "DATABASE_URL", SourceKind: "env"},
			{Language: facts.LangGo, File: "config.go", Span: facts.Span{Start: 3, End: 4}, Key: "PORT", SourceKind: "file"},
		},
	}

	finding := matchExists(rule, fs, []string{"go"})
	if finding.Status != StatusPass {
		t.Fatalf("status = %q, want pass", finding.Status)
	}
	if finding.VerificationLevel != VerificationStrongInference {
		t.Fatalf("verification_level = %q, want %q", finding.VerificationLevel, VerificationStrongInference)
	}
	if len(finding.Evidence) != 1 || finding.Evidence[0].Symbol != "config_read:DATABASE_URL" {
		t.Fatalf("evidence = %#v", finding.Evidence)
	}
}

func TestConfigSecretKeySourcedFromEnvDeterministic(t *testing.T) {
	t.Parallel()

	rule := Rule{
		ID:        "CONFIG-002",
		Type:      "exists",
		Target:    "config.secret_key_sourced_from_env",
		Languages: []string{"go"},
	}
	fs := &FactSet{
		ConfigReads: []facts.ConfigReadFact{
			{Language: facts.LangGo, File: "config.go", Span: facts.Span{Start: 1, End: 2}, Key: "JWT_SECRET", SourceKind: "env"},
			{Language: facts.LangGo, File: "config.go", Span: facts.Span{Start: 3, End: 4}, Key: "DATABASE_URL", SourceKind: "env"},
		},
	}

	finding := matchExists(rule, fs, []string{"go"})
	if finding.Status != StatusPass {
		t.Fatalf("status = %q, want pass", finding.Status)
	}
	if finding.VerificationLevel != VerificationStrongInference {
		t.Fatalf("verification_level = %q, want %q", finding.VerificationLevel, VerificationStrongInference)
	}
	if len(finding.Evidence) != 1 || finding.Evidence[0].Symbol != "config_read:JWT_SECRET" {
		t.Fatalf("evidence = %#v", finding.Evidence)
	}
}

func TestConfigSecretKeyNotLiteralDeterministic(t *testing.T) {
	t.Parallel()

	rule := Rule{
		ID:        "CONFIG-003",
		Type:      "not_exists",
		Target:    "config.secret_key_not_literal",
		Languages: []string{"go"},
	}
	fs := &FactSet{
		ConfigReads: []facts.ConfigReadFact{
			{Language: facts.LangGo, File: "config.go", Span: facts.Span{Start: 1, End: 2}, Key: "JWT_SECRET", SourceKind: "env"},
			{Language: facts.LangGo, File: "config.go", Span: facts.Span{Start: 3, End: 4}, Key: "API_KEY", SourceKind: "file"},
		},
	}

	finding := matchNotExists(rule, fs, []string{"go"})
	if finding.Status != StatusPass {
		t.Fatalf("status = %q, want pass", finding.Status)
	}
	if finding.VerificationLevel != VerificationStrongInference {
		t.Fatalf("verification_level = %q, want %q", finding.VerificationLevel, VerificationStrongInference)
	}
}

func TestConfigSecretKeyNotLiteralFailsOnLiteral(t *testing.T) {
	t.Parallel()

	rule := Rule{
		ID:        "CONFIG-003",
		Type:      "not_exists",
		Target:    "config.secret_key_not_literal",
		Languages: []string{"go"},
	}
	fs := &FactSet{
		ConfigReads: []facts.ConfigReadFact{
			{Language: facts.LangGo, File: "config.go", Span: facts.Span{Start: 1, End: 2}, Key: "JWT_SECRET", SourceKind: "literal"},
		},
	}

	finding := matchNotExists(rule, fs, []string{"go"})
	if finding.Status != StatusFail {
		t.Fatalf("status = %q, want fail", finding.Status)
	}
	if len(finding.Evidence) != 1 || finding.Evidence[0].Symbol != "config_read:JWT_SECRET" {
		t.Fatalf("evidence = %#v", finding.Evidence)
	}
}

func TestConfigClaimsIgnoreTestFixturePaths(t *testing.T) {
	t.Parallel()

	rule := Rule{
		ID:        "CONFIG-001",
		Type:      "exists",
		Target:    "config.env_read_call_exists",
		Languages: []string{"go"},
	}
	fs := &FactSet{
		ConfigReads: []facts.ConfigReadFact{
			{Language: facts.LangGo, File: "config_test.go", Span: facts.Span{Start: 1, End: 2}, Key: "DATABASE_URL", SourceKind: "env"},
		},
	}

	finding := matchExists(rule, fs, []string{"go"})
	if finding.Status == StatusPass {
		t.Fatalf("status = %q, want non-pass when only test/fixture config facts exist", finding.Status)
	}
	if len(finding.Evidence) != 0 {
		t.Fatalf("expected no evidence from test/fixture config facts, got %#v", finding.Evidence)
	}
}
