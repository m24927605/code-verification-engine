package rules

import (
	"testing"
)

// ---------------------------------------------------------------------------
// AllProfiles
// ---------------------------------------------------------------------------

func TestAllProfiles(t *testing.T) {
	profiles := AllProfiles()

	expected := []string{
		"backend-api",
		"backend-api-strict",
		"frontend",
		"fullstack",
		"fullstack-strict",
		"design-patterns",
	}

	if len(profiles) != len(expected) {
		t.Fatalf("AllProfiles() returned %d profiles, want %d", len(profiles), len(expected))
	}

	for _, name := range expected {
		if _, ok := profiles[name]; !ok {
			t.Errorf("AllProfiles() missing key %q", name)
		}
	}
}

// ---------------------------------------------------------------------------
// GetProfile
// ---------------------------------------------------------------------------

func TestGetProfile_Exists(t *testing.T) {
	p, ok := GetProfile("backend-api")
	if !ok {
		t.Fatal("GetProfile(\"backend-api\") returned false")
	}
	if p == nil {
		t.Fatal("GetProfile(\"backend-api\") returned nil profile")
	}
	if len(p.Rules) == 0 {
		t.Error("backend-api profile has no rules")
	}
}

func TestGetProfile_NotExists(t *testing.T) {
	p, ok := GetProfile("nonexistent")
	if ok {
		t.Error("GetProfile(\"nonexistent\") returned true")
	}
	if p != nil {
		t.Error("GetProfile(\"nonexistent\") returned non-nil profile")
	}
}

// ---------------------------------------------------------------------------
// ListProfileNames
// ---------------------------------------------------------------------------

func TestListProfileNames(t *testing.T) {
	names := ListProfileNames()
	if len(names) != 6 {
		t.Errorf("ListProfileNames() returned %d names, want 6", len(names))
	}
}

// ---------------------------------------------------------------------------
// ProfileToRuleFile
// ---------------------------------------------------------------------------

func TestProfileToRuleFile(t *testing.T) {
	p, ok := GetProfile("backend-api")
	if !ok {
		t.Fatal("could not get backend-api profile")
	}

	rf := ProfileToRuleFile(p)
	if rf.Version != "0.1" {
		t.Errorf("Version = %q, want \"0.1\"", rf.Version)
	}
	if rf.Profile != "backend-api" {
		t.Errorf("Profile = %q, want \"backend-api\"", rf.Profile)
	}
	if len(rf.Rules) != len(p.Rules) {
		t.Errorf("Rules length = %d, want %d", len(rf.Rules), len(p.Rules))
	}
}

// ---------------------------------------------------------------------------
// backendAPIProfile
// ---------------------------------------------------------------------------

func TestBackendAPIProfile(t *testing.T) {
	p := backendAPIProfile()
	if p.Name != "backend-api" {
		t.Errorf("Name = %q, want \"backend-api\"", p.Name)
	}
	if len(p.Rules) == 0 {
		t.Error("backendAPIProfile has no rules")
	}
}

// ---------------------------------------------------------------------------
// frontendProfile
// ---------------------------------------------------------------------------

func TestFrontendProfile(t *testing.T) {
	p := frontendProfile()
	if p.Name != "frontend" {
		t.Errorf("Name = %q, want \"frontend\"", p.Name)
	}
	if len(p.Rules) == 0 {
		t.Error("frontendProfile has no rules")
	}
}

// ---------------------------------------------------------------------------
// fullstackProfile
// ---------------------------------------------------------------------------

func TestFullstackProfile(t *testing.T) {
	p := fullstackProfile()
	if p.Name != "fullstack" {
		t.Errorf("Name = %q, want \"fullstack\"", p.Name)
	}

	backend := backendAPIProfile()
	frontend := frontendProfile()
	patterns := designPatternsProfile()
	expectedLen := len(backend.Rules) + len(frontend.Rules) + len(patterns.Rules)

	if len(p.Rules) != expectedLen {
		t.Errorf("fullstack rules = %d, want %d (backend %d + frontend %d + patterns %d)",
			len(p.Rules), expectedLen, len(backend.Rules), len(frontend.Rules), len(patterns.Rules))
	}
}

// ---------------------------------------------------------------------------
// fullstackStrictProfile
// ---------------------------------------------------------------------------

func TestFullstackStrictProfile(t *testing.T) {
	p := fullstackStrictProfile()
	if p.Name != "fullstack-strict" {
		t.Errorf("Name = %q, want \"fullstack-strict\"", p.Name)
	}

	backendStrict := backendAPIStrictProfile()
	frontend := frontendProfile()
	patterns := designPatternsProfile()
	expectedLen := len(backendStrict.Rules) + len(frontend.Rules) + len(patterns.Rules)

	if len(p.Rules) != expectedLen {
		t.Errorf("fullstack-strict rules = %d, want %d (backend-strict %d + frontend %d + patterns %d)",
			len(p.Rules), expectedLen, len(backendStrict.Rules), len(frontend.Rules), len(patterns.Rules))
	}
}

// ---------------------------------------------------------------------------
// designPatternsProfile
// ---------------------------------------------------------------------------

func TestDesignPatternsProfile(t *testing.T) {
	p := designPatternsProfile()
	if p.Name != "design-patterns" {
		t.Errorf("Name = %q, want \"design-patterns\"", p.Name)
	}
	if len(p.Rules) == 0 {
		t.Error("designPatternsProfile has no rules")
	}

	// All rules should be GoF rules (ID starts with "GOF-")
	for _, r := range p.Rules {
		if len(r.ID) < 4 || r.ID[:4] != "GOF-" {
			t.Errorf("design-patterns rule %q does not start with GOF-", r.ID)
		}
	}
}

// ---------------------------------------------------------------------------
// backendAPIStrictProfile
// ---------------------------------------------------------------------------

func TestBackendAPIStrictProfile(t *testing.T) {
	strict := backendAPIStrictProfile()
	base := backendAPIProfile()

	if strict.Name != "backend-api-strict" {
		t.Errorf("Name = %q, want \"backend-api-strict\"", strict.Name)
	}
	if len(strict.Rules) <= len(base.Rules) {
		t.Errorf("strict rules (%d) should be more than base rules (%d)",
			len(strict.Rules), len(base.Rules))
	}
}
