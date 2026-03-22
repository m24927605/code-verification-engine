package rules

import (
	"testing"
)

// TestClassifyAuth covers the scoring and classification logic.
func TestClassifyAuth(t *testing.T) {
	tests := []struct {
		name string
		ev   AuthEvidence
		want AuthClassification
	}{
		{
			name: "AuthStrong: binding(3) + import(2) = 5",
			ev: AuthEvidence{
				HasMiddlewareBinding: true,
				HasAuthImport:        true,
				HasAuthName:          false,
				HasContradictoryName: false,
				MiddlewareName:       "someMiddleware",
			},
			want: AuthStrong,
		},
		{
			name: "AuthStrong: binding(3) + import(2) + name(1) = 6",
			ev: AuthEvidence{
				HasMiddlewareBinding: true,
				HasAuthImport:        true,
				HasAuthName:          true,
				HasContradictoryName: false,
				MiddlewareName:       "jwtAuth",
			},
			want: AuthStrong,
		},
		{
			name: "AuthWeak: binding(3) + name(1) = 4, no import",
			ev: AuthEvidence{
				HasMiddlewareBinding: true,
				HasAuthImport:        false,
				HasAuthName:          true,
				HasContradictoryName: false,
				MiddlewareName:       "authMiddleware",
			},
			want: AuthWeak,
		},
		{
			name: "AuthWeak: name(1) only = 1",
			ev: AuthEvidence{
				HasMiddlewareBinding: false,
				HasAuthImport:        false,
				HasAuthName:          true,
				HasContradictoryName: false,
				MiddlewareName:       "jwtHandler",
			},
			want: AuthWeak,
		},
		{
			name: "AuthNotDetected: contradictory name (CORS)",
			ev: AuthEvidence{
				HasMiddlewareBinding: false,
				HasAuthImport:        false,
				HasAuthName:          false,
				HasContradictoryName: true,
				MiddlewareName:       "corsHandler",
			},
			want: AuthNotDetected,
		},
		{
			name: "AuthNotDetected: no signals at all",
			ev: AuthEvidence{
				HasMiddlewareBinding: false,
				HasAuthImport:        false,
				HasAuthName:          false,
				HasContradictoryName: false,
				MiddlewareName:       "someHandler",
			},
			want: AuthNotDetected,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyAuth(tc.ev)
			if got != tc.want {
				t.Errorf("ClassifyAuth(%+v) = %v, want %v", tc.ev, got, tc.want)
			}
		})
	}
}

// TestClassifyMiddlewareName covers name token classification including the session special rule.
func TestClassifyMiddlewareName(t *testing.T) {
	tests := []struct {
		name            string
		input           string
		wantAuth        bool
		wantContradicts bool
	}{
		{
			name:            "jwtMiddleware: auth token 'jwt'",
			input:           "jwtMiddleware",
			wantAuth:        true,
			wantContradicts: false,
		},
		{
			name:            "corsHandler: contradictory token 'cors'",
			input:           "corsHandler",
			wantAuth:        false,
			wantContradicts: true,
		},
		{
			name:            "loginRequired: auth token 'login'",
			input:           "loginRequired",
			wantAuth:        true,
			wantContradicts: false,
		},
		{
			name:            "helmetSecurity: contradictory token 'helmet'",
			input:           "helmetSecurity",
			wantAuth:        false,
			wantContradicts: true,
		},
		{
			name:            "rateLimiter: contradictory token 'rate'",
			input:           "rateLimiter",
			wantAuth:        false,
			wantContradicts: true,
		},
		{
			name:            "sessionAuth: auth overrides session → NOT contradictory",
			input:           "sessionAuth",
			wantAuth:        true,
			wantContradicts: false,
		},
		{
			name:            "sessionManager: no auth token → session IS contradictory",
			input:           "sessionManager",
			wantAuth:        false,
			wantContradicts: true,
		},
		{
			name:            "plainHandler: neither auth nor contradictory",
			input:           "plainHandler",
			wantAuth:        false,
			wantContradicts: false,
		},
		{
			name:            "authenticateUser: auth token 'authenticate'",
			input:           "authenticateUser",
			wantAuth:        true,
			wantContradicts: false,
		},
		{
			name:            "passportLocal: auth token 'passport'",
			input:           "passportLocal",
			wantAuth:        true,
			wantContradicts: false,
		},
		{
			name:            "bodyParser: contradictory token 'body'",
			input:           "bodyParser",
			wantAuth:        false,
			wantContradicts: true,
		},
		{
			name:            "errorHandler: contradictory token 'error'",
			input:           "errorHandler",
			wantAuth:        false,
			wantContradicts: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotAuth, gotContradicts := ClassifyMiddlewareName(tc.input)
			if gotAuth != tc.wantAuth || gotContradicts != tc.wantContradicts {
				t.Errorf("ClassifyMiddlewareName(%q) = (auth=%v, contradicts=%v), want (auth=%v, contradicts=%v)",
					tc.input, gotAuth, gotContradicts, tc.wantAuth, tc.wantContradicts)
			}
		})
	}
}

// TestHasKnownAuthImport covers import path matching.
func TestHasKnownAuthImport(t *testing.T) {
	tests := []struct {
		name     string
		lang     string
		imports  []string
		wantHit  bool
	}{
		{
			name:    "Go JWT match",
			lang:    "go",
			imports: []string{"fmt", "github.com/golang-jwt/jwt", "net/http"},
			wantHit: true,
		},
		{
			name:    "Go no auth import",
			lang:    "go",
			imports: []string{"fmt", "net/http", "encoding/json"},
			wantHit: false,
		},
		{
			name:    "JS jsonwebtoken match",
			lang:    "javascript",
			imports: []string{"express", "jsonwebtoken", "body-parser"},
			wantHit: true,
		},
		{
			name:    "JS passport match",
			lang:    "javascript",
			imports: []string{"passport", "express"},
			wantHit: true,
		},
		{
			name:    "JS no auth import",
			lang:    "javascript",
			imports: []string{"express", "lodash", "axios"},
			wantHit: false,
		},
		{
			name:    "Python pyjwt match",
			lang:    "python",
			imports: []string{"os", "pyjwt", "flask"},
			wantHit: true,
		},
		{
			name:    "Python fastapi.security match",
			lang:    "python",
			imports: []string{"fastapi.security", "pydantic"},
			wantHit: true,
		},
		{
			name:    "Python no auth import",
			lang:    "python",
			imports: []string{"os", "flask", "sqlalchemy"},
			wantHit: false,
		},
		{
			name:    "Unknown language: no match",
			lang:    "ruby",
			imports: []string{"jsonwebtoken"},
			wantHit: false,
		},
		{
			name:    "TypeScript treated as JS",
			lang:    "typescript",
			imports: []string{"@nestjs/jwt"},
			wantHit: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := HasKnownAuthImport(tc.lang, tc.imports)
			if got != tc.wantHit {
				t.Errorf("HasKnownAuthImport(%q, %v) = %v, want %v", tc.lang, tc.imports, got, tc.wantHit)
			}
		})
	}
}
