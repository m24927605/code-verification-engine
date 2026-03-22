package skills

import (
	"testing"
)

func TestGetProfile_BuiltIn(t *testing.T) {
	p, ok := GetProfile("github-engineer-core")
	if !ok {
		t.Fatal("github-engineer-core profile should exist")
	}
	if p.Name != "github-engineer-core" {
		t.Errorf("name = %q, want github-engineer-core", p.Name)
	}
	if len(p.Signals) < 10 {
		t.Errorf("expected at least 10 signals, got %d", len(p.Signals))
	}
}

func TestGetProfile_Unknown(t *testing.T) {
	_, ok := GetProfile("nonexistent-profile")
	if ok {
		t.Error("unknown profile should return false")
	}
}

func TestListProfileNames(t *testing.T) {
	names := ListProfileNames()
	if len(names) == 0 {
		t.Fatal("should return at least one profile name")
	}
	found := false
	for _, n := range names {
		if n == "github-engineer-core" {
			found = true
		}
	}
	if !found {
		t.Error("github-engineer-core should be in the list")
	}
}

func TestValidateProfileName(t *testing.T) {
	if !ValidateProfileName("github-engineer-core") {
		t.Error("github-engineer-core should be valid")
	}
	if ValidateProfileName("missing-profile") {
		t.Error("missing-profile should be invalid")
	}
}

func TestAllProfiles(t *testing.T) {
	profiles := AllProfiles()
	if len(profiles) == 0 {
		t.Fatal("AllProfiles should return at least one profile")
	}
	p, ok := profiles["github-engineer-core"]
	if !ok {
		t.Fatal("github-engineer-core should be in AllProfiles")
	}
	if p.Name != "github-engineer-core" {
		t.Errorf("name = %q", p.Name)
	}
	if len(p.Signals) < 10 {
		t.Errorf("signals = %d, want >= 10", len(p.Signals))
	}
}
