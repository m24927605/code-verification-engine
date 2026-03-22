package rules

import "testing"

func TestWhereFilterNameMatches(t *testing.T) {
	w := &Where{NameMatches: []string{"auth"}}
	if !WhereMatchesSymbol(w, "AuthService", "auth.go") {
		t.Error("expected AuthService to match name_matches 'auth'")
	}
	if WhereMatchesSymbol(w, "UserController", "user.go") {
		t.Error("expected UserController to not match name_matches 'auth'")
	}
}

func TestWhereFilterNameExact(t *testing.T) {
	w := &Where{NameExact: []string{"AuthService", "AuthHandler"}}
	if !WhereMatchesSymbol(w, "AuthService", "auth.go") {
		t.Error("expected AuthService to match name_exact")
	}
	if !WhereMatchesSymbol(w, "AuthHandler", "handler.go") {
		t.Error("expected AuthHandler to match name_exact")
	}
	if WhereMatchesSymbol(w, "AuthMiddleware", "middleware.go") {
		t.Error("expected AuthMiddleware to not match name_exact")
	}
}

func TestWhereFilterPathMatches(t *testing.T) {
	w := &Where{PathMatches: []string{"internal/auth"}}
	if !WhereMatchesSymbol(w, "Foo", "internal/auth/service.go") {
		t.Error("expected path match")
	}
	if WhereMatchesSymbol(w, "Foo", "internal/user/service.go") {
		t.Error("expected no path match")
	}
}

func TestWhereFilterPathExcludes(t *testing.T) {
	w := &Where{PathExcludes: []string{"vendor/", "testdata/"}}
	if !WhereMatchesSymbol(w, "Foo", "internal/auth/service.go") {
		t.Error("expected non-excluded path to match")
	}
	if WhereMatchesSymbol(w, "Foo", "vendor/lib/auth.go") {
		t.Error("expected excluded path to not match")
	}
}

func TestWhereFilterNil(t *testing.T) {
	if !WhereMatchesSymbol(nil, "Anything", "any/path.go") {
		t.Error("nil where should match everything")
	}
}

func TestWhereFilterCombined(t *testing.T) {
	w := &Where{
		NameMatches:  []string{"auth"},
		PathMatches:  []string{"internal/"},
		PathExcludes: []string{"vendor/"},
	}
	if !WhereMatchesSymbol(w, "AuthService", "internal/auth/service.go") {
		t.Error("expected combined match")
	}
	if WhereMatchesSymbol(w, "AuthService", "vendor/auth/service.go") {
		t.Error("expected excluded by path_excludes")
	}
	if WhereMatchesSymbol(w, "UserService", "internal/user/service.go") {
		t.Error("expected no name match")
	}
}
