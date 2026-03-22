package auth

import "testing"

func TestAuthenticate_ValidToken(t *testing.T) {
	userID, err := Authenticate("valid-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if userID == "" {
		t.Error("expected non-empty user ID")
	}
}

func TestAuthenticate_EmptyToken(t *testing.T) {
	_, err := Authenticate("")
	if err == nil {
		t.Error("expected error for empty token")
	}
}
