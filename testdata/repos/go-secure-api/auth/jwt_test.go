package auth

import "testing"

func TestVerifyToken(t *testing.T) {
	_, err := VerifyToken("")
	if err == nil {
		t.Fatal("expected error for empty token")
	}
}

func TestVerifyTokenValid(t *testing.T) {
	uid, err := VerifyToken("valid-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if uid == "" {
		t.Fatal("expected non-empty user id")
	}
}
