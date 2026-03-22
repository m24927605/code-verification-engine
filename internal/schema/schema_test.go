package schema_test

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/facts"
	"github.com/verabase/code-verification-engine/internal/rules"
	"github.com/verabase/code-verification-engine/internal/schema"
)

func TestSchemaVersionConstants(t *testing.T) {
	if schema.ScanSchemaVersion != "1.0.0" {
		t.Errorf("expected scan schema version 1.0.0, got %s", schema.ScanSchemaVersion)
	}
	if schema.ReportSchemaVersion != "1.0.0" {
		t.Errorf("expected report schema version 1.0.0, got %s", schema.ReportSchemaVersion)
	}
	if schema.DSLVersion != "0.1" {
		t.Errorf("expected DSL version 0.1, got %s", schema.DSLVersion)
	}
}

// --- FileFact validation ---

func TestValidateFileFactValid(t *testing.T) {
	ff, _ := facts.NewFileFact(facts.LangGo, "main.go", 100)
	if err := schema.ValidateFileFact(ff); err != nil {
		t.Fatalf("expected valid, got: %v", err)
	}
}

func TestValidateFileFactMissingPath(t *testing.T) {
	ff := facts.FileFact{Language: facts.LangGo, File: "", LineCount: 100}
	if err := schema.ValidateFileFact(ff); err == nil {
		t.Fatal("expected error for missing path")
	}
}

// --- SymbolFact validation ---

func TestValidateSymbolFactValid(t *testing.T) {
	sf, _ := facts.NewSymbolFact(facts.LangGo, "main.go", facts.Span{Start: 1, End: 5}, "Foo", "function", true)
	if err := schema.ValidateSymbolFact(sf); err != nil {
		t.Fatalf("expected valid, got: %v", err)
	}
}

func TestValidateSymbolFactMissingKind(t *testing.T) {
	sf := facts.SymbolFact{
		Language: facts.LangGo,
		File:     "main.go",
		Span:     facts.Span{Start: 1, End: 5},
		Name:     "Foo",
		Kind:     "",
		Exported: true,
	}
	if err := schema.ValidateSymbolFact(sf); err == nil {
		t.Fatal("expected error for missing kind")
	}
}

// --- ImportFact validation ---

func TestValidateImportFactValid(t *testing.T) {
	imf, _ := facts.NewImportFact(facts.LangGo, "main.go", facts.Span{Start: 1, End: 1}, "fmt", "")
	if err := schema.ValidateImportFact(imf); err != nil {
		t.Fatalf("expected valid, got: %v", err)
	}
}

func TestValidateImportFactMissingImportPath(t *testing.T) {
	imf := facts.ImportFact{Language: facts.LangGo, File: "main.go", Span: facts.Span{Start: 1, End: 1}, ImportPath: ""}
	if err := schema.ValidateImportFact(imf); err == nil {
		t.Fatal("expected error for missing import path")
	}
}

// --- RouteFact validation ---

func TestValidateRouteFactValid(t *testing.T) {
	rf, _ := facts.NewRouteFact(facts.LangGo, "routes.go", facts.Span{Start: 1, End: 5}, "GET", "/users", "GetUsers", nil)
	if err := schema.ValidateRouteFact(rf); err != nil {
		t.Fatalf("expected valid, got: %v", err)
	}
}

func TestValidateRouteFactMissingMethod(t *testing.T) {
	rf := facts.RouteFact{Language: facts.LangGo, File: "routes.go", Span: facts.Span{Start: 1, End: 5}, Method: "", Path: "/users"}
	if err := schema.ValidateRouteFact(rf); err == nil {
		t.Fatal("expected error for missing method")
	}
}

// --- MiddlewareFact validation ---

func TestValidateMiddlewareFactValid(t *testing.T) {
	mf, _ := facts.NewMiddlewareFact(facts.LangGo, "mw.go", facts.Span{Start: 1, End: 10}, "Auth", "auth")
	if err := schema.ValidateMiddlewareFact(mf); err != nil {
		t.Fatalf("expected valid, got: %v", err)
	}
}

func TestValidateMiddlewareFactMissingName(t *testing.T) {
	mf := facts.MiddlewareFact{Language: facts.LangGo, File: "mw.go", Span: facts.Span{Start: 1, End: 10}, Name: ""}
	if err := schema.ValidateMiddlewareFact(mf); err == nil {
		t.Fatal("expected error for missing name")
	}
}

// --- TestFact validation ---

func TestValidateTestFactValid(t *testing.T) {
	tf, _ := facts.NewTestFact(facts.LangGo, "auth_test.go", facts.Span{Start: 1, End: 10}, "TestFoo", "auth", "")
	if err := schema.ValidateTestFact(tf); err != nil {
		t.Fatalf("expected valid, got: %v", err)
	}
}

func TestValidateTestFactMissingTestName(t *testing.T) {
	tf := facts.TestFact{Language: facts.LangGo, File: "auth_test.go", Span: facts.Span{Start: 1, End: 10}, TestName: ""}
	if err := schema.ValidateTestFact(tf); err == nil {
		t.Fatal("expected error for missing test name")
	}
}

// --- DataAccessFact validation ---

func TestValidateDataAccessFactValid(t *testing.T) {
	da, _ := facts.NewDataAccessFact(facts.LangGo, "repo.go", facts.Span{Start: 1, End: 5}, "db.Query", "sql")
	if err := schema.ValidateDataAccessFact(da); err != nil {
		t.Fatalf("expected valid, got: %v", err)
	}
}

func TestValidateDataAccessFactMissingOperation(t *testing.T) {
	da := facts.DataAccessFact{Language: facts.LangGo, File: "repo.go", Span: facts.Span{Start: 1, End: 5}, Operation: ""}
	if err := schema.ValidateDataAccessFact(da); err == nil {
		t.Fatal("expected error for missing operation")
	}
}

// --- ConfigFact validation ---

func TestValidateConfigFactValid(t *testing.T) {
	cf, _ := facts.NewConfigFact(facts.LangGo, "config.go", facts.Span{Start: 1, End: 3}, "DB_URL", "env")
	if err := schema.ValidateConfigFact(cf); err != nil {
		t.Fatalf("expected valid, got: %v", err)
	}
}

func TestValidateConfigFactMissingKey(t *testing.T) {
	cf := facts.ConfigFact{Language: facts.LangGo, File: "config.go", Span: facts.Span{Start: 1, End: 3}, Key: ""}
	if err := schema.ValidateConfigFact(cf); err == nil {
		t.Fatal("expected error for missing key")
	}
}

// --- SecretFact validation ---

func TestValidateSecretFactValid(t *testing.T) {
	sf, _ := facts.NewSecretFact(facts.LangGo, "config.go", facts.Span{Start: 1, End: 1}, "hardcoded_password", "pw")
	if err := schema.ValidateSecretFact(sf); err != nil {
		t.Fatalf("expected valid, got: %v", err)
	}
}

func TestValidateSecretFactMissingKind(t *testing.T) {
	sf := facts.SecretFact{Language: facts.LangGo, File: "config.go", Span: facts.Span{Start: 1, End: 1}, Kind: ""}
	if err := schema.ValidateSecretFact(sf); err == nil {
		t.Fatal("expected error for missing kind")
	}
}

// --- DependencyFact validation ---

func TestValidateDependencyFactValid(t *testing.T) {
	df, _ := facts.NewDependencyFact(facts.LangGo, "go.mod", facts.Span{Start: 1, End: 1}, "gin", "v1.0.0")
	if err := schema.ValidateDependencyFact(df); err != nil {
		t.Fatalf("expected valid, got: %v", err)
	}
}

func TestValidateDependencyFactMissingName(t *testing.T) {
	df := facts.DependencyFact{Language: facts.LangGo, File: "go.mod", Span: facts.Span{Start: 1, End: 1}, Name: ""}
	if err := schema.ValidateDependencyFact(df); err == nil {
		t.Fatal("expected error for missing name")
	}
}

// --- Finding validation ---

func TestValidateFindingValid(t *testing.T) {
	f, _ := facts.NewFinding("AUTH-001", "title", "pass", "high", "verified", "found", nil, nil)
	if err := schema.ValidateFinding(f); err != nil {
		t.Fatalf("expected valid, got: %v", err)
	}
}

func TestValidateFindingMissingMessage(t *testing.T) {
	f := facts.Finding{
		RuleID:            "AUTH-001",
		Title:             "title",
		Status:            "pass",
		Confidence:        "high",
		VerificationLevel: "verified",
		Message:           "",
	}
	if err := schema.ValidateFinding(f); err == nil {
		t.Fatal("expected error for missing message")
	}
}

// --- Evidence validation ---

func TestValidateEvidenceValid(t *testing.T) {
	e, _ := facts.NewEvidence("symbol", "auth.go", 1, 5, "Foo", "code")
	if err := schema.ValidateEvidence(e); err != nil {
		t.Fatalf("expected valid, got: %v", err)
	}
}

func TestValidateEvidenceInvalidSpan(t *testing.T) {
	e := facts.Evidence{Type: "symbol", File: "auth.go", LineStart: 0, LineEnd: 5}
	if err := schema.ValidateEvidence(e); err == nil {
		t.Fatal("expected error for invalid span")
	}
}

// --- Report-level Finding/Evidence validation (rules.Finding / rules.Evidence) ---

func TestValidateReportFindingValid(t *testing.T) {
	f := rules.Finding{
		RuleID:            "AUTH-001",
		Status:            rules.StatusPass,
		Confidence:        rules.ConfidenceHigh,
		VerificationLevel: rules.VerificationVerified,
		TrustClass:        rules.TrustMachineTrusted,
		Evidence: []rules.Evidence{
			{File: "auth.go", LineStart: 1, LineEnd: 10, Symbol: "Verify"},
		},
	}
	if err := schema.ValidateReportFinding(f); err != nil {
		t.Fatalf("expected valid, got: %v", err)
	}
}

func TestValidateReportFindingMissingRuleID(t *testing.T) {
	f := rules.Finding{Status: rules.StatusPass, Confidence: rules.ConfidenceHigh, VerificationLevel: rules.VerificationVerified}
	if err := schema.ValidateReportFinding(f); err == nil {
		t.Fatal("expected error for missing rule ID")
	}
}

func TestValidateReportEvidenceValid(t *testing.T) {
	e := rules.Evidence{File: "auth.go", LineStart: 1, LineEnd: 10, Symbol: "Verify"}
	if err := schema.ValidateReportEvidence(e); err != nil {
		t.Fatalf("expected valid, got: %v", err)
	}
}

func TestValidateReportEvidenceNoType(t *testing.T) {
	// rules.Evidence has no Type field — should still validate
	e := rules.Evidence{File: "auth.go", LineStart: 1, LineEnd: 10}
	if err := schema.ValidateReportEvidence(e); err != nil {
		t.Fatalf("rules.Evidence without Type should be valid, got: %v", err)
	}
}

func TestValidateReportEvidenceInvalidSpan(t *testing.T) {
	e := rules.Evidence{File: "auth.go", LineStart: 0, LineEnd: 5}
	if err := schema.ValidateReportEvidence(e); err == nil {
		t.Fatal("expected error for invalid span")
	}
}

func TestValidateReportEvidenceMissingFile(t *testing.T) {
	e := rules.Evidence{File: "", LineStart: 1, LineEnd: 5}
	if err := schema.ValidateReportEvidence(e); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestValidateReportEvidenceEndBeforeStart(t *testing.T) {
	e := rules.Evidence{File: "auth.go", LineStart: 10, LineEnd: 5}
	if err := schema.ValidateReportEvidence(e); err == nil {
		t.Fatal("expected error for end before start")
	}
}

func TestValidateReportFindingMissingStatus(t *testing.T) {
	f := rules.Finding{RuleID: "AUTH-001", Confidence: rules.ConfidenceHigh, VerificationLevel: rules.VerificationVerified}
	if err := schema.ValidateReportFinding(f); err == nil {
		t.Fatal("expected error for missing status")
	}
}

func TestValidateReportFindingMissingConfidence(t *testing.T) {
	f := rules.Finding{RuleID: "AUTH-001", Status: rules.StatusPass, VerificationLevel: rules.VerificationVerified}
	if err := schema.ValidateReportFinding(f); err == nil {
		t.Fatal("expected error for missing confidence")
	}
}

func TestValidateReportFindingMissingVerificationLevel(t *testing.T) {
	f := rules.Finding{RuleID: "AUTH-001", Status: rules.StatusPass, Confidence: rules.ConfidenceHigh}
	if err := schema.ValidateReportFinding(f); err == nil {
		t.Fatal("expected error for missing verification level")
	}
}

func TestValidateReportFindingWithInvalidEvidence(t *testing.T) {
	f := rules.Finding{
		RuleID:            "AUTH-001",
		Status:            rules.StatusPass,
		Confidence:        rules.ConfidenceHigh,
		VerificationLevel: rules.VerificationVerified,
		Evidence:          []rules.Evidence{{File: "", LineStart: 1, LineEnd: 1}},
	}
	if err := schema.ValidateReportFinding(f); err == nil {
		t.Fatal("expected error for invalid evidence")
	}
}

// --- Additional Finding/Evidence validation ---

func TestValidateFindingMissingRuleID(t *testing.T) {
	f := facts.Finding{Status: "pass", Confidence: "high", VerificationLevel: "verified", Message: "msg"}
	if err := schema.ValidateFinding(f); err == nil {
		t.Fatal("expected error for missing rule ID")
	}
}

func TestValidateFindingMissingStatus(t *testing.T) {
	f := facts.Finding{RuleID: "AUTH-001", Confidence: "high", VerificationLevel: "verified", Message: "msg"}
	if err := schema.ValidateFinding(f); err == nil {
		t.Fatal("expected error for missing status")
	}
}

func TestValidateFindingMissingConfidence(t *testing.T) {
	f := facts.Finding{RuleID: "AUTH-001", Status: "pass", VerificationLevel: "verified", Message: "msg"}
	if err := schema.ValidateFinding(f); err == nil {
		t.Fatal("expected error for missing confidence")
	}
}

func TestValidateFindingMissingVerificationLevel(t *testing.T) {
	f := facts.Finding{RuleID: "AUTH-001", Status: "pass", Confidence: "high", Message: "msg"}
	if err := schema.ValidateFinding(f); err == nil {
		t.Fatal("expected error for missing verification level")
	}
}

func TestValidateFindingWithInvalidEvidence(t *testing.T) {
	f := facts.Finding{
		RuleID: "AUTH-001", Status: "pass", Confidence: "high",
		VerificationLevel: "verified", Message: "msg",
		Evidence: []facts.Evidence{{Type: "", File: "f.go", LineStart: 1, LineEnd: 1}},
	}
	if err := schema.ValidateFinding(f); err == nil {
		t.Fatal("expected error for invalid evidence in finding")
	}
}

func TestValidateEvidenceMissingType(t *testing.T) {
	e := facts.Evidence{Type: "", File: "auth.go", LineStart: 1, LineEnd: 5}
	if err := schema.ValidateEvidence(e); err == nil {
		t.Fatal("expected error for missing type")
	}
}

func TestValidateEvidenceMissingFile(t *testing.T) {
	e := facts.Evidence{Type: "symbol", File: "", LineStart: 1, LineEnd: 5}
	if err := schema.ValidateEvidence(e); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestValidateEvidenceEndBeforeStart(t *testing.T) {
	e := facts.Evidence{Type: "symbol", File: "auth.go", LineStart: 10, LineEnd: 5}
	if err := schema.ValidateEvidence(e); err == nil {
		t.Fatal("expected error for end before start")
	}
}

// --- Validate functions: invalid language/file/span for each fact type ---

func TestValidateFileFactInvalidLanguage(t *testing.T) {
	ff := facts.FileFact{Language: "rust", File: "main.rs", LineCount: 100}
	if err := schema.ValidateFileFact(ff); err == nil {
		t.Fatal("expected error for invalid language")
	}
}

func TestValidateSymbolFactInvalidLanguage(t *testing.T) {
	sf := facts.SymbolFact{Language: "rust", File: "main.rs", Span: facts.Span{Start: 1, End: 5}, Name: "Foo", Kind: "function"}
	if err := schema.ValidateSymbolFact(sf); err == nil {
		t.Fatal("expected error for invalid language")
	}
}

func TestValidateSymbolFactMissingFile(t *testing.T) {
	sf := facts.SymbolFact{Language: facts.LangGo, File: "", Span: facts.Span{Start: 1, End: 5}, Name: "Foo", Kind: "function"}
	if err := schema.ValidateSymbolFact(sf); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestValidateSymbolFactInvalidSpan(t *testing.T) {
	sf := facts.SymbolFact{Language: facts.LangGo, File: "main.go", Span: facts.Span{Start: 0, End: 5}, Name: "Foo", Kind: "function"}
	if err := schema.ValidateSymbolFact(sf); err == nil {
		t.Fatal("expected error for invalid span")
	}
}

func TestValidateSymbolFactMissingName(t *testing.T) {
	sf := facts.SymbolFact{Language: facts.LangGo, File: "main.go", Span: facts.Span{Start: 1, End: 5}, Name: "", Kind: "function"}
	if err := schema.ValidateSymbolFact(sf); err == nil {
		t.Fatal("expected error for missing name")
	}
}

func TestValidateImportFactInvalidLanguage(t *testing.T) {
	imf := facts.ImportFact{Language: "rust", File: "main.rs", Span: facts.Span{Start: 1, End: 1}, ImportPath: "fmt"}
	if err := schema.ValidateImportFact(imf); err == nil {
		t.Fatal("expected error for invalid language")
	}
}

func TestValidateImportFactMissingFile(t *testing.T) {
	imf := facts.ImportFact{Language: facts.LangGo, File: "", Span: facts.Span{Start: 1, End: 1}, ImportPath: "fmt"}
	if err := schema.ValidateImportFact(imf); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestValidateImportFactInvalidSpan(t *testing.T) {
	imf := facts.ImportFact{Language: facts.LangGo, File: "main.go", Span: facts.Span{Start: 0, End: 1}, ImportPath: "fmt"}
	if err := schema.ValidateImportFact(imf); err == nil {
		t.Fatal("expected error for invalid span")
	}
}

func TestValidateRouteFactInvalidLanguage(t *testing.T) {
	rf := facts.RouteFact{Language: "rust", File: "routes.go", Span: facts.Span{Start: 1, End: 5}, Method: "GET", Path: "/users"}
	if err := schema.ValidateRouteFact(rf); err == nil {
		t.Fatal("expected error for invalid language")
	}
}

func TestValidateRouteFactMissingFile(t *testing.T) {
	rf := facts.RouteFact{Language: facts.LangGo, File: "", Span: facts.Span{Start: 1, End: 5}, Method: "GET", Path: "/users"}
	if err := schema.ValidateRouteFact(rf); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestValidateRouteFactInvalidSpan(t *testing.T) {
	rf := facts.RouteFact{Language: facts.LangGo, File: "routes.go", Span: facts.Span{Start: 0, End: 5}, Method: "GET", Path: "/users"}
	if err := schema.ValidateRouteFact(rf); err == nil {
		t.Fatal("expected error for invalid span")
	}
}

func TestValidateRouteFactMissingPath(t *testing.T) {
	rf := facts.RouteFact{Language: facts.LangGo, File: "routes.go", Span: facts.Span{Start: 1, End: 5}, Method: "GET", Path: ""}
	if err := schema.ValidateRouteFact(rf); err == nil {
		t.Fatal("expected error for missing path")
	}
}

func TestValidateMiddlewareFactInvalidLanguage(t *testing.T) {
	mf := facts.MiddlewareFact{Language: "rust", File: "mw.go", Span: facts.Span{Start: 1, End: 10}, Name: "Auth"}
	if err := schema.ValidateMiddlewareFact(mf); err == nil {
		t.Fatal("expected error for invalid language")
	}
}

func TestValidateMiddlewareFactMissingFile(t *testing.T) {
	mf := facts.MiddlewareFact{Language: facts.LangGo, File: "", Span: facts.Span{Start: 1, End: 10}, Name: "Auth"}
	if err := schema.ValidateMiddlewareFact(mf); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestValidateMiddlewareFactInvalidSpan(t *testing.T) {
	mf := facts.MiddlewareFact{Language: facts.LangGo, File: "mw.go", Span: facts.Span{Start: 0, End: 10}, Name: "Auth"}
	if err := schema.ValidateMiddlewareFact(mf); err == nil {
		t.Fatal("expected error for invalid span")
	}
}

func TestValidateTestFactInvalidLanguage(t *testing.T) {
	tf := facts.TestFact{Language: "rust", File: "auth_test.go", Span: facts.Span{Start: 1, End: 10}, TestName: "Test1"}
	if err := schema.ValidateTestFact(tf); err == nil {
		t.Fatal("expected error for invalid language")
	}
}

func TestValidateTestFactMissingFile(t *testing.T) {
	tf := facts.TestFact{Language: facts.LangGo, File: "", Span: facts.Span{Start: 1, End: 10}, TestName: "Test1"}
	if err := schema.ValidateTestFact(tf); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestValidateTestFactInvalidSpan(t *testing.T) {
	tf := facts.TestFact{Language: facts.LangGo, File: "auth_test.go", Span: facts.Span{Start: 0, End: 10}, TestName: "Test1"}
	if err := schema.ValidateTestFact(tf); err == nil {
		t.Fatal("expected error for invalid span")
	}
}

func TestValidateDataAccessFactInvalidLanguage(t *testing.T) {
	da := facts.DataAccessFact{Language: "rust", File: "repo.go", Span: facts.Span{Start: 1, End: 5}, Operation: "query"}
	if err := schema.ValidateDataAccessFact(da); err == nil {
		t.Fatal("expected error for invalid language")
	}
}

func TestValidateDataAccessFactMissingFile(t *testing.T) {
	da := facts.DataAccessFact{Language: facts.LangGo, File: "", Span: facts.Span{Start: 1, End: 5}, Operation: "query"}
	if err := schema.ValidateDataAccessFact(da); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestValidateDataAccessFactInvalidSpan(t *testing.T) {
	da := facts.DataAccessFact{Language: facts.LangGo, File: "repo.go", Span: facts.Span{Start: 0, End: 5}, Operation: "query"}
	if err := schema.ValidateDataAccessFact(da); err == nil {
		t.Fatal("expected error for invalid span")
	}
}

func TestValidateConfigFactInvalidLanguage(t *testing.T) {
	cf := facts.ConfigFact{Language: "rust", File: "config.go", Span: facts.Span{Start: 1, End: 3}, Key: "DB_URL"}
	if err := schema.ValidateConfigFact(cf); err == nil {
		t.Fatal("expected error for invalid language")
	}
}

func TestValidateConfigFactMissingFile(t *testing.T) {
	cf := facts.ConfigFact{Language: facts.LangGo, File: "", Span: facts.Span{Start: 1, End: 3}, Key: "DB_URL"}
	if err := schema.ValidateConfigFact(cf); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestValidateConfigFactInvalidSpan(t *testing.T) {
	cf := facts.ConfigFact{Language: facts.LangGo, File: "config.go", Span: facts.Span{Start: 0, End: 3}, Key: "DB_URL"}
	if err := schema.ValidateConfigFact(cf); err == nil {
		t.Fatal("expected error for invalid span")
	}
}

func TestValidateSecretFactInvalidLanguage(t *testing.T) {
	sf := facts.SecretFact{Language: "rust", File: "config.go", Span: facts.Span{Start: 1, End: 1}, Kind: "password"}
	if err := schema.ValidateSecretFact(sf); err == nil {
		t.Fatal("expected error for invalid language")
	}
}

func TestValidateSecretFactMissingFile(t *testing.T) {
	sf := facts.SecretFact{Language: facts.LangGo, File: "", Span: facts.Span{Start: 1, End: 1}, Kind: "password"}
	if err := schema.ValidateSecretFact(sf); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestValidateSecretFactInvalidSpan(t *testing.T) {
	sf := facts.SecretFact{Language: facts.LangGo, File: "config.go", Span: facts.Span{Start: 0, End: 1}, Kind: "password"}
	if err := schema.ValidateSecretFact(sf); err == nil {
		t.Fatal("expected error for invalid span")
	}
}

func TestValidateDependencyFactInvalidLanguage(t *testing.T) {
	df := facts.DependencyFact{Language: "rust", File: "go.mod", Span: facts.Span{Start: 1, End: 1}, Name: "gin"}
	if err := schema.ValidateDependencyFact(df); err == nil {
		t.Fatal("expected error for invalid language")
	}
}

func TestValidateDependencyFactMissingFile(t *testing.T) {
	df := facts.DependencyFact{Language: facts.LangGo, File: "", Span: facts.Span{Start: 1, End: 1}, Name: "gin"}
	if err := schema.ValidateDependencyFact(df); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestValidateDependencyFactInvalidSpan(t *testing.T) {
	df := facts.DependencyFact{Language: facts.LangGo, File: "go.mod", Span: facts.Span{Start: 0, End: 1}, Name: "gin"}
	if err := schema.ValidateDependencyFact(df); err == nil {
		t.Fatal("expected error for invalid span")
	}
}

// --- CallFact validation ---

func TestValidateCallFactValid(t *testing.T) {
	cf, _ := facts.NewCallFact(facts.LangGo, "service.go", facts.Span{Start: 1, End: 5}, "caller", "", "callee", "")
	if err := schema.ValidateCallFact(cf); err != nil {
		t.Fatalf("expected valid, got: %v", err)
	}
}

func TestValidateCallFactInvalidLanguage(t *testing.T) {
	cf := facts.CallFact{Language: "rust", File: "main.rs", Span: facts.Span{Start: 1, End: 5}, CallerName: "c", CalleeName: "d"}
	if err := schema.ValidateCallFact(cf); err == nil {
		t.Fatal("expected error for invalid language")
	}
}

func TestValidateCallFactMissingFile(t *testing.T) {
	cf := facts.CallFact{Language: facts.LangGo, File: "", Span: facts.Span{Start: 1, End: 5}, CallerName: "c", CalleeName: "d"}
	if err := schema.ValidateCallFact(cf); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestValidateCallFactInvalidSpan(t *testing.T) {
	cf := facts.CallFact{Language: facts.LangGo, File: "main.go", Span: facts.Span{Start: 0, End: 5}, CallerName: "c", CalleeName: "d"}
	if err := schema.ValidateCallFact(cf); err == nil {
		t.Fatal("expected error for invalid span")
	}
}

func TestValidateCallFactMissingCallerName(t *testing.T) {
	cf := facts.CallFact{Language: facts.LangGo, File: "main.go", Span: facts.Span{Start: 1, End: 5}, CallerName: "", CalleeName: "d"}
	if err := schema.ValidateCallFact(cf); err == nil {
		t.Fatal("expected error for missing caller name")
	}
}

func TestValidateCallFactMissingCalleeName(t *testing.T) {
	cf := facts.CallFact{Language: facts.LangGo, File: "main.go", Span: facts.Span{Start: 1, End: 5}, CallerName: "c", CalleeName: ""}
	if err := schema.ValidateCallFact(cf); err == nil {
		t.Fatal("expected error for missing callee name")
	}
}

// --- RouteBindingFact validation ---

func TestValidateRouteBindingFactValid(t *testing.T) {
	rb, _ := facts.NewRouteBindingFact(facts.LangGo, "routes.go", facts.Span{Start: 1, End: 5}, "handler", "GET", "/api", nil, nil, "route")
	if err := schema.ValidateRouteBindingFact(rb); err != nil {
		t.Fatalf("expected valid, got: %v", err)
	}
}

func TestValidateRouteBindingFactInvalidLanguage(t *testing.T) {
	rb := facts.RouteBindingFact{Language: "rust", File: "routes.go", Span: facts.Span{Start: 1, End: 5}, Handler: "h"}
	if err := schema.ValidateRouteBindingFact(rb); err == nil {
		t.Fatal("expected error for invalid language")
	}
}

func TestValidateRouteBindingFactMissingFile(t *testing.T) {
	rb := facts.RouteBindingFact{Language: facts.LangGo, File: "", Span: facts.Span{Start: 1, End: 5}, Handler: "h"}
	if err := schema.ValidateRouteBindingFact(rb); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestValidateRouteBindingFactInvalidSpan(t *testing.T) {
	rb := facts.RouteBindingFact{Language: facts.LangGo, File: "routes.go", Span: facts.Span{Start: 0, End: 5}, Handler: "h"}
	if err := schema.ValidateRouteBindingFact(rb); err == nil {
		t.Fatal("expected error for invalid span")
	}
}

func TestValidateRouteBindingFactMissingHandler(t *testing.T) {
	rb := facts.RouteBindingFact{Language: facts.LangGo, File: "routes.go", Span: facts.Span{Start: 1, End: 5}, Handler: ""}
	if err := schema.ValidateRouteBindingFact(rb); err == nil {
		t.Fatal("expected error for missing handler")
	}
}

// --- AppBindingFact validation ---

func TestValidateAppBindingFactValid(t *testing.T) {
	ab, _ := facts.NewAppBindingFact(facts.LangGo, "main.go", facts.Span{Start: 1, End: 5}, "middleware", "Auth", "global")
	if err := schema.ValidateAppBindingFact(ab); err != nil {
		t.Fatalf("expected valid, got: %v", err)
	}
}

func TestValidateAppBindingFactInvalidLanguage(t *testing.T) {
	ab := facts.AppBindingFact{Language: "rust", File: "main.rs", Span: facts.Span{Start: 1, End: 5}, Kind: "middleware", Name: "Auth"}
	if err := schema.ValidateAppBindingFact(ab); err == nil {
		t.Fatal("expected error for invalid language")
	}
}

func TestValidateAppBindingFactMissingFile(t *testing.T) {
	ab := facts.AppBindingFact{Language: facts.LangGo, File: "", Span: facts.Span{Start: 1, End: 5}, Kind: "middleware", Name: "Auth"}
	if err := schema.ValidateAppBindingFact(ab); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestValidateAppBindingFactInvalidSpan(t *testing.T) {
	ab := facts.AppBindingFact{Language: facts.LangGo, File: "main.go", Span: facts.Span{Start: 0, End: 5}, Kind: "middleware", Name: "Auth"}
	if err := schema.ValidateAppBindingFact(ab); err == nil {
		t.Fatal("expected error for invalid span")
	}
}

func TestValidateAppBindingFactMissingKind(t *testing.T) {
	ab := facts.AppBindingFact{Language: facts.LangGo, File: "main.go", Span: facts.Span{Start: 1, End: 5}, Kind: "", Name: "Auth"}
	if err := schema.ValidateAppBindingFact(ab); err == nil {
		t.Fatal("expected error for missing kind")
	}
}

func TestValidateAppBindingFactMissingName(t *testing.T) {
	ab := facts.AppBindingFact{Language: facts.LangGo, File: "main.go", Span: facts.Span{Start: 1, End: 5}, Kind: "middleware", Name: ""}
	if err := schema.ValidateAppBindingFact(ab); err == nil {
		t.Fatal("expected error for missing name")
	}
}

// --- ConfigReadFact validation ---

func TestValidateConfigReadFactValid(t *testing.T) {
	cr, _ := facts.NewConfigReadFact(facts.LangGo, "config.go", facts.Span{Start: 1, End: 3}, "DB_URL", "env")
	if err := schema.ValidateConfigReadFact(cr); err != nil {
		t.Fatalf("expected valid, got: %v", err)
	}
}

func TestValidateConfigReadFactInvalidLanguage(t *testing.T) {
	cr := facts.ConfigReadFact{Language: "rust", File: "config.go", Span: facts.Span{Start: 1, End: 3}, Key: "KEY"}
	if err := schema.ValidateConfigReadFact(cr); err == nil {
		t.Fatal("expected error for invalid language")
	}
}

func TestValidateConfigReadFactMissingFile(t *testing.T) {
	cr := facts.ConfigReadFact{Language: facts.LangGo, File: "", Span: facts.Span{Start: 1, End: 3}, Key: "KEY"}
	if err := schema.ValidateConfigReadFact(cr); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestValidateConfigReadFactInvalidSpan(t *testing.T) {
	cr := facts.ConfigReadFact{Language: facts.LangGo, File: "config.go", Span: facts.Span{Start: 0, End: 3}, Key: "KEY"}
	if err := schema.ValidateConfigReadFact(cr); err == nil {
		t.Fatal("expected error for invalid span")
	}
}

func TestValidateConfigReadFactMissingKey(t *testing.T) {
	cr := facts.ConfigReadFact{Language: facts.LangGo, File: "config.go", Span: facts.Span{Start: 1, End: 3}, Key: ""}
	if err := schema.ValidateConfigReadFact(cr); err == nil {
		t.Fatal("expected error for missing key")
	}
}

// --- FileRoleFact validation ---

func TestValidateFileRoleFactValid(t *testing.T) {
	fr, _ := facts.NewFileRoleFact(facts.LangGo, "handler.go", "controller")
	if err := schema.ValidateFileRoleFact(fr); err != nil {
		t.Fatalf("expected valid, got: %v", err)
	}
}

func TestValidateFileRoleFactInvalidLanguage(t *testing.T) {
	fr := facts.FileRoleFact{Language: "rust", File: "main.rs", Role: "controller"}
	if err := schema.ValidateFileRoleFact(fr); err == nil {
		t.Fatal("expected error for invalid language")
	}
}

func TestValidateFileRoleFactMissingFile(t *testing.T) {
	fr := facts.FileRoleFact{Language: facts.LangGo, File: "", Role: "controller"}
	if err := schema.ValidateFileRoleFact(fr); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestValidateFileRoleFactMissingRole(t *testing.T) {
	fr := facts.FileRoleFact{Language: facts.LangGo, File: "main.go", Role: ""}
	if err := schema.ValidateFileRoleFact(fr); err == nil {
		t.Fatal("expected error for missing role")
	}
}
