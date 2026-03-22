package skills

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteSkillsJSON(t *testing.T) {
	dir := t.TempDir()
	r := &Report{
		SchemaVersion: "1.0.0",
		Profile:       "test",
		Signals: []Signal{
			{ID: "1", SkillID: "test.signal", Status: StatusUnsupported,
				TrustClass: "human_or_runtime_required", Confidence: ConfidenceLow,
				EvidenceStrength: EvidenceHeuristic,
				UnknownReasons:   []string{"no data"}},
		},
		Summary: Summary{Unsupported: 1},
	}

	if err := WriteSkillsJSON(dir, r); err != nil {
		t.Fatalf("WriteSkillsJSON error: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "skills.json"))
	if err != nil {
		t.Fatalf("skills.json not found: %v", err)
	}

	var loaded Report
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if loaded.SchemaVersion != "1.0.0" {
		t.Errorf("schema_version = %q", loaded.SchemaVersion)
	}
	if loaded.Profile != "test" {
		t.Errorf("profile = %q", loaded.Profile)
	}
	if len(loaded.Signals) != 1 {
		t.Errorf("signals count = %d", len(loaded.Signals))
	}
}

func TestWriteSkillsJSON_InvalidDir(t *testing.T) {
	err := WriteSkillsJSON("/nonexistent/path/that/does/not/exist", &Report{})
	if err == nil {
		t.Error("expected error for invalid directory")
	}
}
