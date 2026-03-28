package main

import "testing"

func TestAuthMiddleware(t *testing.T) {
	if AuthMiddleware() == "" {
		t.Fatal("expected middleware marker")
	}
}
