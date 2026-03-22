package rules

import "testing"

func TestParseValidRuleFile(t *testing.T) {
	rf, err := ParseFile(testdataPath("valid-backend-baseline.yaml"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rf.Version != "0.1" {
		t.Errorf("version = %q, want %q", rf.Version, "0.1")
	}
	if rf.Profile != "backend-baseline" {
		t.Errorf("profile = %q, want %q", rf.Profile, "backend-baseline")
	}
	if len(rf.Rules) != 5 {
		t.Fatalf("len(rules) = %d, want 5", len(rf.Rules))
	}
	r := rf.Rules[0]
	if r.ID != "AUTH-001" {
		t.Errorf("rules[0].id = %q, want %q", r.ID, "AUTH-001")
	}
	if r.Type != "exists" {
		t.Errorf("rules[0].type = %q, want %q", r.Type, "exists")
	}
	if r.Target != "auth.jwt_middleware" {
		t.Errorf("rules[0].target = %q, want %q", r.Target, "auth.jwt_middleware")
	}
}

func TestParseFileNotFound(t *testing.T) {
	_, err := ParseFile("nonexistent.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestParseBytes(t *testing.T) {
	data := []byte(`
version: "0.1"
profile: "test"
rules:
  - id: "TEST-001"
    title: "Test rule"
    category: "testing"
    severity: "low"
    languages: ["go"]
    type: "exists"
    target: "auth.jwt_middleware"
    message: "Test."
`)
	rf, err := ParseBytes(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rf.Rules) != 1 {
		t.Fatalf("len(rules) = %d, want 1", len(rf.Rules))
	}
}

func TestParseRuleWithWhereClause(t *testing.T) {
	data := []byte(`
version: "0.1"
profile: "test"
rules:
  - id: "TEST-002"
    title: "Auth service must have tests"
    category: "testing"
    severity: "medium"
    languages: ["go"]
    type: "test_required"
    target: "module.auth_service"
    where:
      name_matches: ["auth", "authentication"]
      path_matches: ["internal/auth"]
    message: "Auth services must have tests."
`)
	rf, err := ParseBytes(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r := rf.Rules[0]
	if r.Where == nil {
		t.Fatal("expected where clause")
	}
	if len(r.Where.NameMatches) != 2 {
		t.Errorf("name_matches len = %d, want 2", len(r.Where.NameMatches))
	}
	if len(r.Where.PathMatches) != 1 {
		t.Errorf("path_matches len = %d, want 1", len(r.Where.PathMatches))
	}
}

func TestParseBadYAML(t *testing.T) {
	_, err := ParseBytes([]byte(`{invalid: [yaml: `))
	if err == nil {
		t.Fatal("expected error for bad YAML")
	}
}
