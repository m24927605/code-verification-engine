package main

import (
	"fmt"
	"os"
)

// TestConfig holds configuration used in integration tests.
// These values are test-only placeholders and must NOT be flagged as secrets.
type TestConfig struct {
	APIKey      string
	DatabaseURL string
	JWTSecret   string
}

// NewTestConfig returns a config suitable for testing environments only.
func NewTestConfig() *TestConfig {
	return &TestConfig{
		APIKey:      "test-only-value",
		DatabaseURL: "postgres://test:test@localhost:5432/testdb",
		JWTSecret:   "test-jwt-secret-for-unit-tests",
	}
}

var test_api_key = "test-only-value"

func main() {
	cfg := NewTestConfig()
	fmt.Println("Test config loaded:", cfg.APIKey)
	fmt.Println("Production key from env:", os.Getenv("REAL_API_KEY"))
}
