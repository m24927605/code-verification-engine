package rules

import "strings"

// AuthClassification represents the strength of authentication evidence.
type AuthClassification int

const (
	AuthNotDetected AuthClassification = iota
	AuthWeak
	AuthStrong
)

// AuthEvidence holds all signals used to classify authentication evidence.
type AuthEvidence struct {
	HasMiddlewareBinding bool   // middleware name appears in RouteFact.Middlewares
	HasAuthImport        bool   // file imports known auth/JWT package
	HasAuthName          bool   // name tokens include auth keywords
	HasContradictoryName bool   // name tokens include non-auth keywords
	MiddlewareName       string // original name for reporting
}

// authNameTokens is the set of tokens that indicate authentication purpose.
var authNameTokens = map[string]bool{
	"auth":         true,
	"jwt":          true,
	"guard":        true,
	"verify":       true,
	"authenticate": true,
	"passport":     true,
	"require":      true,
	"login":        true,
	"protect":      true,
}

// contradictoryNameTokens is the set of tokens that indicate non-auth purpose.
var contradictoryNameTokens = map[string]bool{
	"cors":        true,
	"helmet":      true,
	"log":         true,
	"logger":      true,
	"logging":     true,
	"rate":        true,
	"limit":       true,
	"throttle":    true,
	"metrics":     true,
	"error":       true,
	"compress":    true,
	"compression": true,
	"static":      true,
	"body":        true,
	"parse":       true,
	"json":        true,
	"cookie":      true,
	"csrf":        true,
	"csp":         true,
}

// ClassifyMiddlewareName determines if a middleware name has auth tokens and/or contradictory tokens.
// Auth tokens override contradictory when both present.
// Special rule: "session" is contradictory ONLY if no auth token is present.
func ClassifyMiddlewareName(name string) (hasAuth, hasContradictory bool) {
	tokens := Tokenize(name)

	var hasSession bool
	for _, tok := range tokens {
		if authNameTokens[tok] {
			hasAuth = true
		}
		if tok == "session" {
			hasSession = true
		} else if contradictoryNameTokens[tok] {
			hasContradictory = true
		}
	}

	// Apply session special rule: session is contradictory only when no auth token present.
	if hasSession && !hasAuth {
		hasContradictory = true
	}

	// Auth tokens override contradictory.
	if hasAuth && hasContradictory {
		hasContradictory = false
	}

	return hasAuth, hasContradictory
}

// ClassifyAuth determines the auth classification based on evidence signals.
//
// Scoring:
//
//	HasMiddlewareBinding → +3
//	HasAuthImport        → +2
//	HasAuthName          → +1
//	HasContradictoryName → -3 (forces AuthNotDetected when score < 1)
//
// Classification:
//
//	AuthStrong:      score >= 5
//	AuthWeak:        score >= 1 AND NOT contradictory-only
//	AuthNotDetected: score < 1 OR contradictory-only
func ClassifyAuth(ev AuthEvidence) AuthClassification {
	if ev.HasContradictoryName {
		return AuthNotDetected
	}

	score := 0
	if ev.HasMiddlewareBinding {
		score += 3
	}
	if ev.HasAuthImport {
		score += 2
	}
	if ev.HasAuthName {
		score += 1
	}

	switch {
	case score >= 5:
		return AuthStrong
	case score >= 1:
		return AuthWeak
	default:
		return AuthNotDetected
	}
}

// KnownAuthPackages maps language to known auth package import paths.
var KnownAuthPackages = map[string][]string{
	"go": {
		"github.com/golang-jwt/jwt",
		"github.com/dgrijalva/jwt-go",
		"github.com/lestrrat-go/jwx",
	},
	"javascript": {
		"jsonwebtoken",
		"passport",
		"passport-jwt",
		"express-jwt",
		"@nestjs/jwt",
		"@nestjs/passport",
		"jose",
		"@auth0/nextjs-auth0",
		"next-auth",
	},
	"typescript": {
		"jsonwebtoken",
		"passport",
		"passport-jwt",
		"express-jwt",
		"@nestjs/jwt",
		"@nestjs/passport",
		"jose",
		"@auth0/nextjs-auth0",
		"next-auth",
	},
	"python": {
		"pyjwt",
		"python-jose",
		"fastapi.security",
		"flask-jwt-extended",
		"flask-login",
		"django.contrib.auth",
	},
}

// HasKnownAuthImport checks if any import path matches a known auth package for the given language.
func HasKnownAuthImport(language string, importPaths []string) bool {
	lang := strings.ToLower(language)
	known, ok := KnownAuthPackages[lang]
	if !ok {
		return false
	}

	knownSet := make(map[string]bool, len(known))
	for _, pkg := range known {
		knownSet[pkg] = true
	}

	for _, imp := range importPaths {
		if knownSet[imp] {
			return true
		}
	}
	return false
}
