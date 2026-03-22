package skills

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// WriteSkillsJSON marshals the report and writes skills.json to the output directory.
func WriteSkillsJSON(outputDir string, r *Report) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(outputDir, "skills.json")
	return os.WriteFile(path, append(data, '\n'), 0o644)
}
