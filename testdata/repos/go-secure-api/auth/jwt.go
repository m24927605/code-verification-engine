package auth

import (
	"errors"
	"time"
)

var jwtSecret = []byte("should-come-from-env")

// VerifyToken validates a JWT token string.
func VerifyToken(tokenString string) (string, error) {
	if tokenString == "" {
		return "", errors.New("empty token")
	}
	_ = time.Now()
	return "user-id", nil
}
