package autobench

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// ---------- validateManifest ----------

func TestValidateManifest_BadSchemaVersion(t *testing.T) {
	m := DatasetManifest{SchemaVersion: "0.0.0"}
	err := validateManifest("", "", &m, nil)
	if err == nil || err.Error() != `unsupported schema_version "0.0.0"` {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateManifest_MissingDatasetID(t *testing.T) {
	m := DatasetManifest{SchemaVersion: SchemaVersion}
	err := validateManifest("", "", &m, nil)
	if err == nil || err.Error() != "dataset_id is required" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateManifest_BadMode(t *testing.T) {
	m := DatasetManifest{SchemaVersion: SchemaVersion, DatasetID: "d1", Mode: "bad"}
	err := validateManifest("", "", &m, nil)
	if err == nil || err.Error() != `unsupported mode "bad"` {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateManifest_NoSuites(t *testing.T) {
	m := DatasetManifest{SchemaVersion: SchemaVersion, DatasetID: "d1", Mode: ModeFrozen}
	err := validateManifest("", "", &m, nil)
	if err == nil || err.Error() != "at least one suite is required" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateManifest_MissingProtectedPaths(t *testing.T) {
	m := DatasetManifest{
		SchemaVersion: SchemaVersion,
		DatasetID:     "d1",
		Mode:          ModeFrozen,
		Suites:        []SuiteManifest{{ID: "s1"}},
	}
	err := validateManifest("", "", &m, nil)
	if err == nil || err.Error() != "gate_policy.protected_paths is required" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateManifest_BadTrustClassInGatePolicy(t *testing.T) {
	m := DatasetManifest{
		SchemaVersion: SchemaVersion,
		DatasetID:     "d1",
		Mode:          ModeFrozen,
		Suites:        []SuiteManifest{{ID: "s1"}},
		GatePolicy: GatePolicy{
			ProtectedPaths:           []string{"src/"},
			MinPrecisionByTrustClass: map[string]float64{"bogus": 0.5},
		},
	}
	err := validateManifest("", "", &m, nil)
	if err == nil {
		t.Fatal("expected error for bad trust class")
	}
}

func TestValidateManifest_PrecisionOutOfRange(t *testing.T) {
	m := DatasetManifest{
		SchemaVersion: SchemaVersion,
		DatasetID:     "d1",
		Mode:          ModeFrozen,
		Suites:        []SuiteManifest{{ID: "s1"}},
		GatePolicy: GatePolicy{
			ProtectedPaths:           []string{"src/"},
			MinPrecisionByTrustClass: map[string]float64{string("machine_trusted"): 1.5},
		},
	}
	err := validateManifest("", "", &m, nil)
	if err == nil {
		t.Fatal("expected error for precision out of range")
	}
}

func TestValidateManifest_DuplicateSuiteID(t *testing.T) {
	m := DatasetManifest{
		SchemaVersion: SchemaVersion,
		DatasetID:     "d1",
		Mode:          ModeFrozen,
		GatePolicy:    GatePolicy{ProtectedPaths: []string{"src/"}},
		Suites: []SuiteManifest{
			{ID: "s1", Profile: "frontend", Cases: []CaseManifest{{ID: "c1"}}},
			{ID: "s1", Profile: "frontend", Cases: []CaseManifest{{ID: "c2"}}},
		},
	}
	err := validateManifest("", "", &m, make(map[string]ExpectedCase))
	if err == nil {
		t.Fatal("expected duplicate suite error")
	}
}

func TestValidateManifest_EmptySuiteID(t *testing.T) {
	m := DatasetManifest{
		SchemaVersion: SchemaVersion,
		DatasetID:     "d1",
		Mode:          ModeFrozen,
		GatePolicy:    GatePolicy{ProtectedPaths: []string{"src/"}},
		Suites:        []SuiteManifest{{ID: "", Profile: "frontend"}},
	}
	err := validateManifest("", "", &m, make(map[string]ExpectedCase))
	if err == nil || err.Error() != "suite id is required" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateManifest_UnknownProfile(t *testing.T) {
	m := DatasetManifest{
		SchemaVersion: SchemaVersion,
		DatasetID:     "d1",
		Mode:          ModeFrozen,
		GatePolicy:    GatePolicy{ProtectedPaths: []string{"src/"}},
		Suites: []SuiteManifest{
			{ID: "s1", Profile: "nonexistent-profile", Cases: []CaseManifest{{ID: "c1"}}},
		},
	}
	err := validateManifest("", "", &m, make(map[string]ExpectedCase))
	if err == nil {
		t.Fatal("expected unknown profile error")
	}
}

func TestValidateManifest_UnknownClaimSet(t *testing.T) {
	m := DatasetManifest{
		SchemaVersion: SchemaVersion,
		DatasetID:     "d1",
		Mode:          ModeFrozen,
		GatePolicy:    GatePolicy{ProtectedPaths: []string{"src/"}},
		Suites: []SuiteManifest{
			{ID: "s1", Profile: "frontend", ClaimSet: "bogus-claim-set", Cases: []CaseManifest{{ID: "c1"}}},
		},
	}
	err := validateManifest("", "", &m, make(map[string]ExpectedCase))
	if err == nil {
		t.Fatal("expected unknown claim set error")
	}
}

func TestValidateManifest_NoCasesInSuite(t *testing.T) {
	m := DatasetManifest{
		SchemaVersion: SchemaVersion,
		DatasetID:     "d1",
		Mode:          ModeFrozen,
		GatePolicy:    GatePolicy{ProtectedPaths: []string{"src/"}},
		Suites: []SuiteManifest{
			{ID: "s1", Profile: "frontend", Cases: []CaseManifest{}},
		},
	}
	err := validateManifest("", "", &m, make(map[string]ExpectedCase))
	if err == nil {
		t.Fatal("expected at least one case error")
	}
}

func TestValidateManifest_EmptyCaseID(t *testing.T) {
	m := DatasetManifest{
		SchemaVersion: SchemaVersion,
		DatasetID:     "d1",
		Mode:          ModeFrozen,
		GatePolicy:    GatePolicy{ProtectedPaths: []string{"src/"}},
		Suites: []SuiteManifest{
			{ID: "s1", Profile: "frontend", Cases: []CaseManifest{{ID: ""}}},
		},
	}
	err := validateManifest("", "", &m, make(map[string]ExpectedCase))
	if err == nil {
		t.Fatal("expected empty case id error")
	}
}

func TestValidateManifest_DuplicateCaseID(t *testing.T) {
	m := DatasetManifest{
		SchemaVersion: SchemaVersion,
		DatasetID:     "d1",
		Mode:          ModeFrozen,
		GatePolicy:    GatePolicy{ProtectedPaths: []string{"src/"}},
		Suites: []SuiteManifest{
			{ID: "s1", Profile: "frontend", Cases: []CaseManifest{
				{ID: "c1", RepoPath: "r", ExpectedPath: "e", CaseType: CasePass, TargetRules: []string{"FE-JS-001"}},
				{ID: "c1", RepoPath: "r", ExpectedPath: "e", CaseType: CasePass, TargetRules: []string{"FE-JS-001"}},
			}},
		},
	}
	err := validateManifest("", "", &m, make(map[string]ExpectedCase))
	if err == nil {
		t.Fatal("expected duplicate case id error")
	}
}

// ---------- validateCase ----------

func TestValidateCase_MissingPaths(t *testing.T) {
	suite := SuiteManifest{ID: "s1", Profile: "frontend"}
	c := CaseManifest{ID: "c1", RepoPath: "", ExpectedPath: ""}
	err := validateCase("", "", suite, c, nil, nil)
	if err == nil {
		t.Fatal("expected missing paths error")
	}
}

func TestValidateCase_BadCaseType(t *testing.T) {
	suite := SuiteManifest{ID: "s1", Profile: "frontend"}
	c := CaseManifest{ID: "c1", RepoPath: "r", ExpectedPath: "e", CaseType: "invalid"}
	err := validateCase("", "", suite, c, nil, nil)
	if err == nil {
		t.Fatal("expected bad case type error")
	}
}

func TestValidateCase_NoTargetRules(t *testing.T) {
	suite := SuiteManifest{ID: "s1", Profile: "frontend"}
	c := CaseManifest{ID: "c1", RepoPath: "r", ExpectedPath: "e", CaseType: CasePass, TargetRules: []string{}}
	err := validateCase("", "", suite, c, nil, nil)
	if err == nil {
		t.Fatal("expected no target rules error")
	}
}

func TestValidateCase_RuleNotInProfile(t *testing.T) {
	suite := SuiteManifest{ID: "s1", Profile: "frontend"}
	allowed := map[string]struct{}{"FE-JS-001": {}}
	c := CaseManifest{ID: "c1", RepoPath: "r", ExpectedPath: "e", CaseType: CasePass, TargetRules: []string{"NONEXISTENT"}}
	err := validateCase("", "", suite, c, allowed, nil)
	if err == nil {
		t.Fatal("expected rule not in profile error")
	}
}

func TestValidateCase_RepoPathNotFound(t *testing.T) {
	suite := SuiteManifest{ID: "s1", Profile: "frontend"}
	allowed := map[string]struct{}{"FE-JS-001": {}}
	c := CaseManifest{ID: "c1", RepoPath: "nonexistent/path", ExpectedPath: "e", CaseType: CasePass, TargetRules: []string{"FE-JS-001"}}
	err := validateCase("/tmp/no-such-root", "", suite, c, allowed, nil)
	if err == nil {
		t.Fatal("expected repo path stat error")
	}
}

func TestValidateCase_ExpectedPathNotFound(t *testing.T) {
	tmp := t.TempDir()
	repoDir := filepath.Join(tmp, "repo")
	os.MkdirAll(repoDir, 0o755)

	suite := SuiteManifest{ID: "s1", Profile: "frontend"}
	allowed := map[string]struct{}{"FE-JS-001": {}}
	c := CaseManifest{ID: "c1", RepoPath: "repo", ExpectedPath: "no-such-file.json", CaseType: CasePass, TargetRules: []string{"FE-JS-001"}}
	err := validateCase(tmp, "", suite, c, allowed, make(map[string]ExpectedCase))
	if err == nil {
		t.Fatal("expected expected path read error")
	}
}

func TestValidateCase_MalformedExpectedJSON(t *testing.T) {
	tmp := t.TempDir()
	repoDir := filepath.Join(tmp, "repo")
	os.MkdirAll(repoDir, 0o755)
	os.WriteFile(filepath.Join(tmp, "expected.json"), []byte("{bad json"), 0o644)

	suite := SuiteManifest{ID: "s1", Profile: "frontend"}
	allowed := map[string]struct{}{"FE-JS-001": {}}
	c := CaseManifest{ID: "c1", RepoPath: "repo", ExpectedPath: "expected.json", CaseType: CasePass, TargetRules: []string{"FE-JS-001"}}
	err := validateCase(tmp, "", suite, c, allowed, make(map[string]ExpectedCase))
	if err == nil {
		t.Fatal("expected JSON parse error")
	}
}

func TestValidateCase_ExpectedValidationFails(t *testing.T) {
	tmp := t.TempDir()
	repoDir := filepath.Join(tmp, "repo")
	os.MkdirAll(repoDir, 0o755)

	// Wrong schema version
	expected := ExpectedCase{SchemaVersion: "0.0.0", CaseID: "c1"}
	data, _ := json.Marshal(expected)
	os.WriteFile(filepath.Join(tmp, "expected.json"), data, 0o644)

	suite := SuiteManifest{ID: "s1", Profile: "frontend"}
	allowed := map[string]struct{}{"FE-JS-001": {}}
	c := CaseManifest{ID: "c1", RepoPath: "repo", ExpectedPath: "expected.json", CaseType: CasePass, TargetRules: []string{"FE-JS-001"}}
	err := validateCase(tmp, filepath.Join(tmp, "manifest.json"), suite, c, allowed, make(map[string]ExpectedCase))
	if err == nil {
		t.Fatal("expected validation error")
	}
}

// ---------- validateExpectedCase ----------

func TestValidateExpectedCase_BadSchemaVersion(t *testing.T) {
	err := validateExpectedCase(SuiteManifest{}, CaseManifest{ID: "c1"}, ExpectedCase{SchemaVersion: "0.0.0"})
	if err == nil {
		t.Fatal("expected schema version error")
	}
}

func TestValidateExpectedCase_CaseIDMismatch(t *testing.T) {
	err := validateExpectedCase(SuiteManifest{}, CaseManifest{ID: "c1"},
		ExpectedCase{SchemaVersion: SchemaVersion, CaseID: "c2"})
	if err == nil {
		t.Fatal("expected case id mismatch error")
	}
}

func TestValidateExpectedCase_ProfileMismatch(t *testing.T) {
	err := validateExpectedCase(SuiteManifest{Profile: "frontend"}, CaseManifest{ID: "c1"},
		ExpectedCase{SchemaVersion: SchemaVersion, CaseID: "c1", Profile: "backend-api"})
	if err == nil {
		t.Fatal("expected profile mismatch error")
	}
}

func TestValidateExpectedCase_ClaimSetMismatch(t *testing.T) {
	err := validateExpectedCase(
		SuiteManifest{Profile: "frontend", ClaimSet: "backend-security"},
		CaseManifest{ID: "c1"},
		ExpectedCase{SchemaVersion: SchemaVersion, CaseID: "c1", Profile: "frontend", ClaimSet: "other"},
	)
	if err == nil {
		t.Fatal("expected claim set mismatch error")
	}
}

func TestValidateExpectedCase_NoExpectations(t *testing.T) {
	err := validateExpectedCase(
		SuiteManifest{Profile: "frontend"},
		CaseManifest{ID: "c1"},
		ExpectedCase{SchemaVersion: SchemaVersion, CaseID: "c1", Profile: "frontend", Expectations: nil},
	)
	if err == nil {
		t.Fatal("expected at least one expectation error")
	}
}

func TestValidateExpectedCase_EmptyRuleID(t *testing.T) {
	err := validateExpectedCase(
		SuiteManifest{Profile: "frontend"},
		CaseManifest{ID: "c1", TargetRules: []string{"FE-JS-001"}},
		ExpectedCase{
			SchemaVersion: SchemaVersion, CaseID: "c1", Profile: "frontend",
			Expectations: []RuleExpectation{{RuleID: ""}},
		},
	)
	if err == nil {
		t.Fatal("expected empty rule_id error")
	}
}

func TestValidateExpectedCase_DuplicateRuleExpectation(t *testing.T) {
	err := validateExpectedCase(
		SuiteManifest{Profile: "frontend"},
		CaseManifest{ID: "c1", TargetRules: []string{"FE-JS-001"}},
		ExpectedCase{
			SchemaVersion: SchemaVersion, CaseID: "c1", Profile: "frontend",
			Expectations: []RuleExpectation{
				{RuleID: "FE-JS-001", ExpectedStatus: "pass", Priority: "blocking", Rationale: "r"},
				{RuleID: "FE-JS-001", ExpectedStatus: "pass", Priority: "blocking", Rationale: "r"},
			},
		},
	)
	if err == nil {
		t.Fatal("expected duplicate expectation error")
	}
}

func TestValidateExpectedCase_RuleNotInTargetRules(t *testing.T) {
	err := validateExpectedCase(
		SuiteManifest{Profile: "frontend"},
		CaseManifest{ID: "c1", TargetRules: []string{"FE-JS-001"}},
		ExpectedCase{
			SchemaVersion: SchemaVersion, CaseID: "c1", Profile: "frontend",
			Expectations: []RuleExpectation{
				{RuleID: "OTHER-RULE", ExpectedStatus: "pass", Priority: "blocking", Rationale: "r"},
			},
		},
	)
	if err == nil {
		t.Fatal("expected rule not in target_rules error")
	}
}

// ---------- validateExpectation ----------

func TestValidateExpectation_NoStatusDefined(t *testing.T) {
	err := validateExpectation(RuleExpectation{RuleID: "r1"})
	if err == nil {
		t.Fatal("expected error when no status defined")
	}
}

func TestValidateExpectation_BadExpectedStatus(t *testing.T) {
	err := validateExpectation(RuleExpectation{RuleID: "r1", ExpectedStatus: "invalid"})
	if err == nil {
		t.Fatal("expected bad status error")
	}
}

func TestValidateExpectation_BadAllowedStatus(t *testing.T) {
	err := validateExpectation(RuleExpectation{RuleID: "r1", AllowedStatuses: []string{"pass", "bogus"}})
	if err == nil {
		t.Fatal("expected bad allowed status error")
	}
}

func TestValidateExpectation_BadTrustClass(t *testing.T) {
	err := validateExpectation(RuleExpectation{
		RuleID: "r1", ExpectedStatus: "pass", ExpectedTrustClass: "bogus",
		Priority: "blocking", Rationale: "r",
	})
	if err == nil {
		t.Fatal("expected bad trust class error")
	}
}

func TestValidateExpectation_MissingPriority(t *testing.T) {
	err := validateExpectation(RuleExpectation{
		RuleID: "r1", ExpectedStatus: "pass", Priority: "",
	})
	if err == nil {
		t.Fatal("expected missing priority error")
	}
}

func TestValidateExpectation_BadPriority(t *testing.T) {
	err := validateExpectation(RuleExpectation{
		RuleID: "r1", ExpectedStatus: "pass", Priority: "critical",
	})
	if err == nil {
		t.Fatal("expected bad priority error")
	}
}

func TestValidateExpectation_NegativeEvidenceCount(t *testing.T) {
	err := validateExpectation(RuleExpectation{
		RuleID: "r1", ExpectedStatus: "pass", Priority: "blocking",
		MinimumEvidenceCount: -1,
	})
	if err == nil {
		t.Fatal("expected negative evidence count error")
	}
}

func TestValidateExpectation_MissingRationale(t *testing.T) {
	err := validateExpectation(RuleExpectation{
		RuleID: "r1", ExpectedStatus: "pass", Priority: "blocking", Rationale: "",
	})
	if err == nil {
		t.Fatal("expected missing rationale error")
	}
}

func TestValidateExpectation_ValidWithExpectedStatus(t *testing.T) {
	err := validateExpectation(RuleExpectation{
		RuleID: "r1", ExpectedStatus: "pass", Priority: "blocking", Rationale: "reason",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateExpectation_ValidWithAllowedStatuses(t *testing.T) {
	err := validateExpectation(RuleExpectation{
		RuleID: "r1", AllowedStatuses: []string{"pass", "unknown"}, Priority: "advisory", Rationale: "reason",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateExpectation_ValidWithTrustClass(t *testing.T) {
	err := validateExpectation(RuleExpectation{
		RuleID: "r1", ExpectedStatus: "pass",
		ExpectedTrustClass: "machine_trusted",
		Priority: "blocking", Rationale: "reason",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------- LoadDataset error paths ----------

func TestLoadDataset_FileNotFound(t *testing.T) {
	_, _, err := LoadDataset("", "/nonexistent/manifest.json")
	if err == nil {
		t.Fatal("expected file not found error")
	}
}

func TestLoadDataset_MalformedJSON(t *testing.T) {
	tmp := t.TempDir()
	p := filepath.Join(tmp, "manifest.json")
	os.WriteFile(p, []byte("{bad"), 0o644)
	_, _, err := LoadDataset("", p)
	if err == nil {
		t.Fatal("expected JSON parse error")
	}
}

func TestLoadDataset_ValidationError(t *testing.T) {
	tmp := t.TempDir()
	p := filepath.Join(tmp, "manifest.json")
	data, _ := json.Marshal(DatasetManifest{SchemaVersion: "0.0.0"})
	os.WriteFile(p, data, 0o644)
	_, _, err := LoadDataset("", p)
	if err == nil {
		t.Fatal("expected validation error")
	}
}
