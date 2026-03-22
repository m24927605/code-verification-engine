package rules

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/facts"
)

func TestTestRequiredMatcherPass(t *testing.T) {
	rule := Rule{
		ID: "TEST-001", Type: "test_required", Target: "module.payment_service",
		Languages: []string{"go"}, Message: "Payment service needs tests.",
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("PaymentService", "struct", "internal/payment/service.go", facts.LangGo, true, 10, 50),
		},
		Tests: []facts.TestFact{
			testFact("TestPaymentService_Process", "internal/payment/service_test.go", facts.LangGo, "payment"),
		},
		Files: []facts.FileFact{
			fileFact("internal/payment/service.go", facts.LangGo),
			fileFact("internal/payment/service_test.go", facts.LangGo),
		},
	}
	finding := matchTestRequired(rule, fs, []string{"go"})
	if finding.Status != StatusPass {
		t.Errorf("status = %v, want pass", finding.Status)
	}
}

func TestTestRequiredMatcherFail(t *testing.T) {
	rule := Rule{
		ID: "TEST-001", Type: "test_required", Target: "module.payment_service",
		Languages: []string{"go"}, Message: "Payment service needs tests.",
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("PaymentService", "struct", "internal/payment/service.go", facts.LangGo, true, 10, 50),
		},
		Files: []facts.FileFact{
			fileFact("internal/payment/service.go", facts.LangGo),
		},
	}
	finding := matchTestRequired(rule, fs, []string{"go"})
	if finding.Status != StatusFail {
		t.Errorf("status = %v, want fail", finding.Status)
	}
}

func TestTestRequiredMatcherUnknown(t *testing.T) {
	rule := Rule{
		ID: "TEST-001", Type: "test_required", Target: "module.payment_service",
		Languages: []string{"go"}, Message: "Payment service needs tests.",
	}
	fs := &FactSet{}
	finding := matchTestRequired(rule, fs, []string{"go"})
	if finding.Status != StatusUnknown {
		t.Errorf("status = %v, want unknown", finding.Status)
	}
}

func TestTestRequiredAuthService(t *testing.T) {
	rule := Rule{
		ID: "TEST-002", Type: "test_required", Target: "module.auth_service",
		Languages: []string{"go"}, Message: "Auth service needs tests.",
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("AuthService", "struct", "internal/auth/service.go", facts.LangGo, true, 5, 30),
		},
		Tests: []facts.TestFact{
			testFact("TestAuthService_Authenticate", "internal/auth/service_test.go", facts.LangGo, "auth"),
		},
		Files: []facts.FileFact{
			fileFact("internal/auth/service.go", facts.LangGo),
			fileFact("internal/auth/service_test.go", facts.LangGo),
		},
	}
	finding := matchTestRequired(rule, fs, []string{"go"})
	if finding.Status != StatusPass {
		t.Errorf("status = %v, want pass", finding.Status)
	}
}

func TestTestRequiredModuleNotFound(t *testing.T) {
	rule := Rule{
		ID: "TEST-001", Type: "test_required", Target: "module.payment_service",
		Languages: []string{"go"}, Message: "Payment service needs tests.",
	}
	fs := &FactSet{
		Symbols: []facts.SymbolFact{
			sym("UserService", "struct", "internal/user/service.go", facts.LangGo, true, 5, 30),
		},
		Files: []facts.FileFact{
			fileFact("internal/user/service.go", facts.LangGo),
		},
	}
	finding := matchTestRequired(rule, fs, []string{"go"})
	if finding.Status != StatusUnknown {
		t.Errorf("status = %v, want unknown (module not found)", finding.Status)
	}
}
