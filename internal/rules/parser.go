package rules

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ParseFile reads and parses a YAML rule file from disk.
func ParseFile(path string) (*RuleFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading rule file: %w", err)
	}
	return ParseBytes(data)
}

// ParseBytes parses YAML rule data from a byte slice.
func ParseBytes(data []byte) (*RuleFile, error) {
	var rf RuleFile
	if err := yaml.Unmarshal(data, &rf); err != nil {
		return nil, fmt.Errorf("parsing rule file: %w", err)
	}
	if err := Validate(&rf); err != nil {
		return nil, fmt.Errorf("validating rule file: %w", err)
	}
	return &rf, nil
}
