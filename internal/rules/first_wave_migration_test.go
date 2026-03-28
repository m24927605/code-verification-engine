package rules

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/facts"
)

func TestMatchTestRequired_FailIncludesModuleEvidence(t *testing.T) {
	t.Parallel()

	rule := Rule{
		ID: "TEST-AUTH-001", Type: "test_required", Target: "module.auth_service",
		Languages: []string{"go"}, Message: "auth module must have tests",
		MatcherClass: MatcherStructural,
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("AuthService", "struct", "internal/auth/service.go", facts.LangGo, false, 1, 20),
		},
		Files: []facts.FileFact{
			fileFact("internal/auth/service.go", facts.LangGo),
		},
	}

	finding := matchTestRequired(rule, fs, []string{"go"})
	if finding.Status != StatusFail {
		t.Fatalf("status = %q, want %q", finding.Status, StatusFail)
	}
	if len(finding.Evidence) == 0 {
		t.Fatal("expected module evidence on fail")
	}
}

func TestMatchProtectedRoutesUseAuth_PassIncludesBindingEvidence(t *testing.T) {
	t.Parallel()

	rule := Rule{
		ID: "SEC-AUTH-002", Type: "relationship", Target: "route.protected_uses_auth_middleware",
		Languages: []string{"typescript"}, Message: "protected routes must use auth middleware",
		MatcherClass: MatcherAttestation,
	}
	fs := &FactSet{
		Imports: []facts.ImportFact{
			imp("@nestjs/passport", "", "src/users.controller.ts", facts.LangTypeScript),
		},
		Routes: []facts.RouteFact{
			route("GET", "/users", "listUsers", "src/users.controller.ts", facts.LangTypeScript, []string{"JwtAuthGuard"}),
		},
	}

	finding := matchRelationship(rule, fs, []string{"typescript"})
	if finding.Status != StatusPass {
		t.Fatalf("status = %q, want %q", finding.Status, StatusPass)
	}
	if len(finding.Evidence) == 0 {
		t.Fatal("expected route binding evidence on pass")
	}
}
