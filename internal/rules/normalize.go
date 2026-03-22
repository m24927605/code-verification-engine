package rules

import (
	"strings"
	"unicode"
)

// Tokenize splits an identifier into lowercase tokens using case-and-separator-aware rules.
// Handles camelCase, PascalCase, snake_case, kebab-case, and UPPER_CASE.
func Tokenize(identifier string) []string {
	var tokens []string
	var current []rune

	flush := func() {
		if len(current) > 0 {
			tokens = append(tokens, strings.ToLower(string(current)))
			current = current[:0]
		}
	}

	runes := []rune(identifier)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if r == '_' || r == '-' || r == '.' {
			flush()
			continue
		}
		if unicode.IsUpper(r) {
			if len(current) > 0 {
				prevIsUpper := unicode.IsUpper(current[len(current)-1])
				nextIsLower := i+1 < len(runes) && unicode.IsLower(runes[i+1])
				if !prevIsUpper || nextIsLower {
					flush()
				}
			}
			current = append(current, r)
		} else {
			current = append(current, r)
		}
	}
	flush()
	return tokens
}

// NameMatchesToken returns true if the identifier contains a token matching the pattern.
func NameMatchesToken(identifier, pattern string) bool {
	tokens := Tokenize(identifier)
	p := strings.ToLower(pattern)
	for _, tok := range tokens {
		if tok == p {
			return true
		}
	}
	return false
}
