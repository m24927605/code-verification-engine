package skills

import "testing"

func TestValidMode(t *testing.T) {
	tests := []struct {
		mode string
		want bool
	}{
		{"verification", true},
		{"skill_inference", true},
		{"both", true},
		{"invalid", false},
		{"", false},
		{"pass", false},
	}
	for _, tt := range tests {
		got := ValidMode(tt.mode)
		if got != tt.want {
			t.Errorf("ValidMode(%q) = %v, want %v", tt.mode, got, tt.want)
		}
	}
}

func TestModeIncludes(t *testing.T) {
	tests := []struct {
		mode    Mode
		wantVer bool
		wantSki bool
	}{
		{ModeVerification, true, false},
		{ModeSkillInference, false, true},
		{ModeBoth, true, true},
	}
	for _, tt := range tests {
		if got := tt.mode.IncludesVerification(); got != tt.wantVer {
			t.Errorf("Mode(%q).IncludesVerification() = %v, want %v", tt.mode, got, tt.wantVer)
		}
		if got := tt.mode.IncludesSkillInference(); got != tt.wantSki {
			t.Errorf("Mode(%q).IncludesSkillInference() = %v, want %v", tt.mode, got, tt.wantSki)
		}
	}
}

func TestDefaultMode(t *testing.T) {
	if DefaultMode() != ModeVerification {
		t.Errorf("DefaultMode() = %q, want verification", DefaultMode())
	}
}
