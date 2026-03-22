package rules

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/facts"
)

func TestNotExistsMatcherPass(t *testing.T) {
	rule := Rule{
		ID: "ARCH-001", Type: "not_exists", Target: "db.direct_access_from_controller",
		Languages: []string{"go"}, Message: "No direct DB access from controllers.",
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("UserController", "function", "internal/controller/user.go", facts.LangGo, true, 5, 20),
		},
		Files: []facts.FileFact{
			fileFact("internal/controller/user.go", facts.LangGo),
		},
	}
	finding := matchNotExists(rule, fs, []string{"go"})
	if finding.Status != StatusPass {
		t.Errorf("status = %v, want pass", finding.Status)
	}
}

func TestNotExistsMatcherFail(t *testing.T) {
	rule := Rule{
		ID: "ARCH-001", Type: "not_exists", Target: "db.direct_access_from_controller",
		Languages: []string{"go"}, Message: "No direct DB access from controllers.",
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("getUserController", "function", "internal/controller/user.go", facts.LangGo, true, 10, 25),
		},
		DataAccess: []facts.DataAccessFact{
			dataAccess("direct_query", "internal/controller/user.go", facts.LangGo),
		},
		Files: []facts.FileFact{
			fileFact("internal/controller/user.go", facts.LangGo),
		},
	}
	finding := matchNotExists(rule, fs, []string{"go"})
	if finding.Status != StatusFail {
		t.Errorf("status = %v, want fail", finding.Status)
	}
	if len(finding.Evidence) == 0 {
		t.Error("expected evidence for fail")
	}
}

func TestNotExistsMatcherUnknown(t *testing.T) {
	rule := Rule{
		ID: "ARCH-001", Type: "not_exists", Target: "db.direct_access_from_controller",
		Languages: []string{"go"}, Message: "No direct DB access from controllers.",
	}
	fs := &FactSet{}
	finding := matchNotExists(rule, fs, []string{"go"})
	if finding.Status != StatusUnknown {
		t.Errorf("status = %v, want unknown", finding.Status)
	}
}

func TestNotExistsHardcodedCredentialFail(t *testing.T) {
	rule := Rule{
		ID: "SEC-001", Type: "not_exists", Target: "secret.hardcoded_credential",
		Languages: []string{"go"}, Message: "No hardcoded creds.",
	}
	fs := &FactSet{
		Secrets: []facts.SecretFact{
			secret("password", "config.go", facts.LangGo, 15),
		},
	}
	finding := matchNotExists(rule, fs, []string{"go"})
	if finding.Status != StatusFail {
		t.Errorf("status = %v, want fail", finding.Status)
	}
}

func TestNotExistsHardcodedCredentialPass(t *testing.T) {
	rule := Rule{
		ID: "SEC-001", Type: "not_exists", Target: "secret.hardcoded_credential",
		Languages: []string{"go"}, Message: "No hardcoded creds.",
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("main", "function", "main.go", facts.LangGo, false, 1, 5),
		},
		Files: []facts.FileFact{
			fileFact("main.go", facts.LangGo),
		},
	}
	finding := matchNotExists(rule, fs, []string{"go"})
	if finding.Status != StatusPass {
		t.Errorf("status = %v, want pass", finding.Status)
	}
}

func TestNotExistsNilFactSet(t *testing.T) {
	rule := Rule{
		ID: "ARCH-001", Type: "not_exists", Target: "db.direct_access_from_controller",
		Languages: []string{"go"}, Message: "x",
	}
	finding := matchNotExists(rule, nil, []string{"go"})
	if finding.Status != StatusUnknown {
		t.Errorf("status = %v, want unknown for nil FactSet", finding.Status)
	}
}
