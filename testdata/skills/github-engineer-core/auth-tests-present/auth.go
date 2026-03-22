package auth

import "errors"

func Authenticate(token string) (string, error) {
	if token == "" {
		return "", errors.New("empty token")
	}
	return "user-123", nil
}
