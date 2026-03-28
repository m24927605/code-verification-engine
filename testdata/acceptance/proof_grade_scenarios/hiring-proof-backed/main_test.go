package main

import "testing"

func TestAuthSecret(t *testing.T) {
	if authSecret() == "" {
		t.Skip("env not set in fixture")
	}
}
