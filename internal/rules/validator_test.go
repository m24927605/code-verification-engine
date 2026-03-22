package rules

import (
	"strings"
	"testing"
)

func TestValidateValidRuleFile(t *testing.T) {
	rf, err := ParseFile(testdataPath("valid-backend-baseline.yaml"))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if err := Validate(rf); err != nil {
		t.Errorf("unexpected validation error: %v", err)
	}
}

func TestValidateUnsupportedVersion(t *testing.T) {
	rf, err := ParseFile(testdataPath("invalid-bad-version.yaml"))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	err = Validate(rf)
	if err == nil {
		t.Fatal("expected validation error for unsupported version")
	}
	if !strings.Contains(err.Error(), "version") {
		t.Errorf("error should mention version, got: %v", err)
	}
}

func TestValidateMissingRequiredFields(t *testing.T) {
	rf, err := ParseFile(testdataPath("invalid-missing-fields.yaml"))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	err = Validate(rf)
	if err == nil {
		t.Fatal("expected validation error for missing fields")
	}
}

func TestValidateUnsupportedTarget(t *testing.T) {
	rf, err := ParseFile(testdataPath("invalid-bad-target.yaml"))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	err = Validate(rf)
	if err == nil {
		t.Fatal("expected validation error for bad target")
	}
	if !strings.Contains(err.Error(), "target") {
		t.Errorf("error should mention target, got: %v", err)
	}
}

func TestValidateWhereConflict(t *testing.T) {
	rf, err := ParseFile(testdataPath("invalid-where-conflict.yaml"))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	err = Validate(rf)
	if err == nil {
		t.Fatal("expected validation error for where clause conflict")
	}
	if !strings.Contains(err.Error(), "name_matches") || !strings.Contains(err.Error(), "name_exact") {
		t.Errorf("error should mention both name_matches and name_exact, got: %v", err)
	}
}

func TestValidateUnsupportedRuleType(t *testing.T) {
	rf := &RuleFile{
		Version: "0.1",
		Profile: "test",
		Rules: []Rule{{
			ID: "X-001", Title: "x", Category: "x", Severity: "low",
			Languages: []string{"go"}, Type: "custom_type",
			Target: "auth.jwt_middleware", Message: "x",
		}},
	}
	err := Validate(rf)
	if err == nil {
		t.Fatal("expected validation error for unsupported type")
	}
}

func TestValidateUnsupportedLanguage(t *testing.T) {
	rf := &RuleFile{
		Version: "0.1",
		Profile: "test",
		Rules: []Rule{{
			ID: "X-001", Title: "x", Category: "x", Severity: "low",
			Languages: []string{"rust"}, Type: "exists",
			Target: "auth.jwt_middleware", Message: "x",
		}},
	}
	err := Validate(rf)
	if err == nil {
		t.Fatal("expected validation error for unsupported language")
	}
}

func TestValidateEmptyID(t *testing.T) {
	rf := &RuleFile{
		Version: "0.1",
		Profile: "test",
		Rules: []Rule{{
			Title: "x", Category: "x", Severity: "low",
			Languages: []string{"go"}, Type: "exists",
			Target: "auth.jwt_middleware", Message: "x",
		}},
	}
	err := Validate(rf)
	if err == nil {
		t.Fatal("expected validation error for empty ID")
	}
	if !strings.Contains(err.Error(), "id") {
		t.Errorf("error should mention id, got: %v", err)
	}
}
