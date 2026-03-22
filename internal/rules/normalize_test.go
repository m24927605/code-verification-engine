package rules

import "testing"

func TestTokenize(t *testing.T) {
	tests := []struct {
		input  string
		tokens []string
	}{
		{"AuthService", []string{"auth", "service"}},
		{"auth_service", []string{"auth", "service"}},
		{"authService", []string{"auth", "service"}},
		{"auth-service", []string{"auth", "service"}},
		{"AUTH_SERVICE", []string{"auth", "service"}},
		{"JWTMiddleware", []string{"jwt", "middleware"}},
		{"getUserByID", []string{"get", "user", "by", "id"}},
		{"HTMLParser", []string{"html", "parser"}},
		{"simpleword", []string{"simpleword"}},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := Tokenize(tt.input)
			if len(got) != len(tt.tokens) {
				t.Fatalf("Tokenize(%q) = %v, want %v", tt.input, got, tt.tokens)
			}
			for i := range got {
				if got[i] != tt.tokens[i] {
					t.Errorf("Tokenize(%q)[%d] = %q, want %q", tt.input, i, got[i], tt.tokens[i])
				}
			}
		})
	}
}

func TestNameMatchesToken(t *testing.T) {
	tests := []struct {
		identifier string
		pattern    string
		want       bool
	}{
		{"AuthService", "auth", true},
		{"auth_service", "auth", true},
		{"authService", "service", true},
		{"JWTMiddleware", "jwt", true},
		{"JWTMiddleware", "middleware", true},
		{"UserController", "auth", false},
		{"AuthService", "authentication", false},
	}
	for _, tt := range tests {
		t.Run(tt.identifier+"_"+tt.pattern, func(t *testing.T) {
			got := NameMatchesToken(tt.identifier, tt.pattern)
			if got != tt.want {
				t.Errorf("NameMatchesToken(%q, %q) = %v, want %v", tt.identifier, tt.pattern, got, tt.want)
			}
		})
	}
}
