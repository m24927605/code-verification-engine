package jsts

import (
	"reflect"
	"testing"
)

// TestResolveRouteBindings_GlobalUseBeforeRoute verifies that app.use() declared
// before a route projects its middleware into that route.
func TestResolveRouteBindings_GlobalUseBeforeRoute(t *testing.T) {
	ast := &ASTResult{
		UseCalls: []ASTUseCall{
			{Receiver: "app", Middlewares: []string{"authMiddleware"}, Line: 1},
		},
		Routes: []ASTRoute{
			{Method: "GET", Path: "/api/users", Handler: "getUsers", Line: 5},
		},
	}
	resolved := ResolveRouteBindings(ast)
	if len(resolved) != 1 {
		t.Fatalf("expected 1 route, got %d", len(resolved))
	}
	if !contains(resolved[0].Middlewares, "authMiddleware") {
		t.Errorf("expected authMiddleware in route.Middlewares, got %v", resolved[0].Middlewares)
	}
}

// TestResolveRouteBindings_GlobalUseAfterRoute verifies that app.use() declared
// after a route does NOT apply to that route (order-dependent).
func TestResolveRouteBindings_GlobalUseAfterRoute(t *testing.T) {
	ast := &ASTResult{
		Routes: []ASTRoute{
			{Method: "GET", Path: "/api/users", Handler: "getUsers", Line: 1},
		},
		UseCalls: []ASTUseCall{
			{Receiver: "app", Middlewares: []string{"authMiddleware"}, Line: 5},
		},
	}
	resolved := ResolveRouteBindings(ast)
	if len(resolved) != 1 {
		t.Fatalf("expected 1 route, got %d", len(resolved))
	}
	if contains(resolved[0].Middlewares, "authMiddleware") {
		t.Errorf("expected authMiddleware NOT in route.Middlewares (declared after route), got %v", resolved[0].Middlewares)
	}
}

// TestResolveRouteBindings_InlineMiddleware verifies that inline route middleware
// is preserved as-is.
func TestResolveRouteBindings_InlineMiddleware(t *testing.T) {
	ast := &ASTResult{
		Routes: []ASTRoute{
			{Method: "POST", Path: "/login", Handler: "login", Middlewares: []string{"validateBody"}, Line: 3},
		},
	}
	resolved := ResolveRouteBindings(ast)
	if len(resolved) != 1 {
		t.Fatalf("expected 1 route, got %d", len(resolved))
	}
	if !contains(resolved[0].Middlewares, "validateBody") {
		t.Errorf("expected validateBody in route.Middlewares, got %v", resolved[0].Middlewares)
	}
}

// TestResolveRouteBindings_NoMiddleware verifies that routes with no middleware
// produce an explicit empty slice, not nil.
func TestResolveRouteBindings_NoMiddleware(t *testing.T) {
	ast := &ASTResult{
		Routes: []ASTRoute{
			{Method: "GET", Path: "/health", Handler: "healthCheck", Line: 2},
		},
	}
	resolved := ResolveRouteBindings(ast)
	if len(resolved) != 1 {
		t.Fatalf("expected 1 route, got %d", len(resolved))
	}
	if resolved[0].Middlewares == nil {
		t.Errorf("expected Middlewares to be empty slice, not nil")
	}
	if len(resolved[0].Middlewares) != 0 {
		t.Errorf("expected 0 middlewares, got %v", resolved[0].Middlewares)
	}
}

// TestResolveRouteBindings_NestJSGuards verifies that NestJS guards are merged
// into the route Middlewares.
func TestResolveRouteBindings_NestJSGuards(t *testing.T) {
	ast := &ASTResult{
		Routes: []ASTRoute{
			{Method: "GET", Path: "/protected", Handler: "", Guards: []string{"AuthGuard", "RoleGuard"}, Line: 4},
		},
	}
	resolved := ResolveRouteBindings(ast)
	if len(resolved) != 1 {
		t.Fatalf("expected 1 route, got %d", len(resolved))
	}
	if !contains(resolved[0].Middlewares, "AuthGuard") {
		t.Errorf("expected AuthGuard in Middlewares, got %v", resolved[0].Middlewares)
	}
	if !contains(resolved[0].Middlewares, "RoleGuard") {
		t.Errorf("expected RoleGuard in Middlewares, got %v", resolved[0].Middlewares)
	}
}

// TestResolveRouteBindings_GlobalAndInlineMerged verifies that global use() middleware
// and inline middleware are combined and deduplicated.
func TestResolveRouteBindings_GlobalAndInlineMerged(t *testing.T) {
	ast := &ASTResult{
		UseCalls: []ASTUseCall{
			{Receiver: "app", Middlewares: []string{"cors", "logger"}, Line: 1},
		},
		Routes: []ASTRoute{
			{Method: "GET", Path: "/api/data", Handler: "getData", Middlewares: []string{"cors", "authCheck"}, Line: 5},
		},
	}
	resolved := ResolveRouteBindings(ast)
	if len(resolved) != 1 {
		t.Fatalf("expected 1 route, got %d", len(resolved))
	}
	mws := resolved[0].Middlewares
	// Should contain cors (deduplicated), logger, and authCheck
	for _, expected := range []string{"cors", "logger", "authCheck"} {
		if !contains(mws, expected) {
			t.Errorf("expected %q in Middlewares, got %v", expected, mws)
		}
	}
	// Verify cors is not duplicated
	count := 0
	for _, m := range mws {
		if m == "cors" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected cors to appear exactly once, got %d times in %v", count, mws)
	}
}

// TestResolveRouteBindings_RouterScoped verifies that a named router's use() does not
// apply to routes in the file when the receiver is not "app" or "router".
func TestResolveRouteBindings_RouterScoped(t *testing.T) {
	// apiRouter.use() has a specific receiver name — it should NOT apply to routes
	// because routes don't track which router they are mounted on.
	ast2 := &ASTResult{
		UseCalls: []ASTUseCall{
			{Receiver: "apiRouter", Middlewares: []string{"apiAuth"}, Line: 2},
		},
		Routes: []ASTRoute{
			{Method: "GET", Path: "/health", Handler: "health", Line: 5},
		},
	}
	resolved := ResolveRouteBindings(ast2)
	if len(resolved) != 1 {
		t.Fatalf("expected 1 route, got %d", len(resolved))
	}
	// The route is not on apiRouter, so apiAuth should NOT apply
	// (ResolveRouteBindings applies "app" and "router" receivers globally, but specific
	//  variable names only apply to routes matched to that router)
	// For this test, apiAuth should NOT be in the route's middleware since receiver
	// is a specific variable (not "app" or "router").
	if contains(resolved[0].Middlewares, "apiAuth") {
		t.Errorf("expected apiAuth NOT in Middlewares for route not on apiRouter, got %v", resolved[0].Middlewares)
	}
}

// TestParser_UseCallExtraction verifies that app.use(authMw) produces an ASTUseCall.
func TestParser_UseCallExtraction(t *testing.T) {
	src := `const app = express();
app.use(authMw);
app.get('/users', getUsers);
`
	r := Parse(src)
	if len(r.UseCalls) == 0 {
		t.Fatalf("expected at least 1 UseCall, got 0")
	}
	found := false
	for _, uc := range r.UseCalls {
		if uc.Receiver == "app" && contains(uc.Middlewares, "authMw") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected UseCall{Receiver:app, Middlewares:[authMw]}, got %v", r.UseCalls)
	}
}

// TestParser_UseCallWithPath verifies that app.use('/api', authMw) extracts both path and middleware.
func TestParser_UseCallWithPath(t *testing.T) {
	src := `app.use('/api', authMiddleware);
`
	r := Parse(src)
	if len(r.UseCalls) == 0 {
		t.Fatalf("expected at least 1 UseCall, got 0")
	}
	uc := r.UseCalls[0]
	if uc.Receiver != "app" {
		t.Errorf("expected receiver 'app', got %q", uc.Receiver)
	}
	if uc.Path != "/api" {
		t.Errorf("expected path '/api', got %q", uc.Path)
	}
	if !contains(uc.Middlewares, "authMiddleware") {
		t.Errorf("expected authMiddleware in UseCall.Middlewares, got %v", uc.Middlewares)
	}
}

// TestParser_UseCallFunctionCall verifies that router.use(cors()) extracts the function name.
func TestParser_UseCallFunctionCall(t *testing.T) {
	src := `router.use(cors());
`
	r := Parse(src)
	if len(r.UseCalls) == 0 {
		t.Fatalf("expected at least 1 UseCall, got 0")
	}
	uc := r.UseCalls[0]
	if uc.Receiver != "router" {
		t.Errorf("expected receiver 'router', got %q", uc.Receiver)
	}
	if !contains(uc.Middlewares, "cors") {
		t.Errorf("expected cors in UseCall.Middlewares, got %v", uc.Middlewares)
	}
}

// TestResolveRouteBindings_MultipleUseCalls verifies multiple use() calls before a route.
func TestResolveRouteBindings_MultipleUseCalls(t *testing.T) {
	ast := &ASTResult{
		UseCalls: []ASTUseCall{
			{Receiver: "app", Middlewares: []string{"cors"}, Line: 1},
			{Receiver: "app", Middlewares: []string{"helmet"}, Line: 2},
			{Receiver: "app", Middlewares: []string{"rateLimit"}, Line: 3},
		},
		Routes: []ASTRoute{
			{Method: "GET", Path: "/api", Handler: "handler", Line: 10},
		},
	}
	resolved := ResolveRouteBindings(ast)
	if len(resolved) != 1 {
		t.Fatalf("expected 1 route, got %d", len(resolved))
	}
	for _, expected := range []string{"cors", "helmet", "rateLimit"} {
		if !contains(resolved[0].Middlewares, expected) {
			t.Errorf("expected %q in Middlewares, got %v", expected, resolved[0].Middlewares)
		}
	}
}

// TestResolveRouteBindings_EmptyASTResult verifies handling of empty input.
func TestResolveRouteBindings_EmptyASTResult(t *testing.T) {
	ast := &ASTResult{}
	resolved := ResolveRouteBindings(ast)
	if resolved == nil {
		t.Error("expected non-nil slice for empty input")
	}
	if len(resolved) != 0 {
		t.Errorf("expected 0 routes, got %d", len(resolved))
	}
}

// TestResolveRouteBindings_PreservesRouteOrder verifies that route order is preserved.
func TestResolveRouteBindings_PreservesRouteOrder(t *testing.T) {
	ast := &ASTResult{
		UseCalls: []ASTUseCall{
			{Receiver: "app", Middlewares: []string{"mwA"}, Line: 1},
		},
		Routes: []ASTRoute{
			{Method: "GET", Path: "/first", Handler: "first", Line: 5},
			{Method: "POST", Path: "/second", Handler: "second", Line: 10},
		},
	}
	resolved := ResolveRouteBindings(ast)
	if len(resolved) != 2 {
		t.Fatalf("expected 2 routes, got %d", len(resolved))
	}
	if !reflect.DeepEqual(resolved[0].Path, "/first") {
		t.Errorf("expected first route to be /first, got %q", resolved[0].Path)
	}
	if !reflect.DeepEqual(resolved[1].Path, "/second") {
		t.Errorf("expected second route to be /second, got %q", resolved[1].Path)
	}
	// Both should have mwA
	for _, r := range resolved {
		if !contains(r.Middlewares, "mwA") {
			t.Errorf("expected mwA in route %q Middlewares, got %v", r.Path, r.Middlewares)
		}
	}
}

// TestResolveRouteBindings_PathScopedMiddleware verifies that app.use('/admin', auth)
// only applies to routes under /admin, not /public routes.
func TestResolveRouteBindings_PathScopedMiddleware(t *testing.T) {
	ast := &ASTResult{
		UseCalls: []ASTUseCall{
			{Receiver: "app", Middlewares: []string{"adminAuth"}, Path: "/admin", Line: 1},
		},
		Routes: []ASTRoute{
			{Method: "GET", Path: "/admin/users", Handler: "adminUsers", Line: 5},
			{Method: "GET", Path: "/public/health", Handler: "health", Line: 10},
			{Method: "GET", Path: "/admin", Handler: "adminDashboard", Line: 15},
		},
	}
	resolved := ResolveRouteBindings(ast)
	if len(resolved) != 3 {
		t.Fatalf("expected 3 routes, got %d", len(resolved))
	}
	for _, r := range resolved {
		switch r.Path {
		case "/admin/users":
			if !contains(r.Middlewares, "adminAuth") {
				t.Errorf("/admin/users should inherit adminAuth, got %v", r.Middlewares)
			}
		case "/admin":
			if !contains(r.Middlewares, "adminAuth") {
				t.Errorf("/admin should inherit adminAuth, got %v", r.Middlewares)
			}
		case "/public/health":
			if contains(r.Middlewares, "adminAuth") {
				t.Errorf("/public/health should NOT inherit adminAuth, got %v", r.Middlewares)
			}
		}
	}
}

// TestResolveRouteBindings_GlobalAndPathScoped verifies that global use() applies everywhere
// but path-scoped use() only to matching routes.
func TestResolveRouteBindings_GlobalAndPathScoped(t *testing.T) {
	ast := &ASTResult{
		UseCalls: []ASTUseCall{
			{Receiver: "app", Middlewares: []string{"cors"}, Line: 1},            // global
			{Receiver: "app", Middlewares: []string{"adminAuth"}, Path: "/admin", Line: 2}, // path-scoped
		},
		Routes: []ASTRoute{
			{Method: "GET", Path: "/admin/settings", Handler: "settings", Line: 10},
			{Method: "GET", Path: "/public/info", Handler: "info", Line: 15},
		},
	}
	resolved := ResolveRouteBindings(ast)
	for _, r := range resolved {
		if r.Path == "/admin/settings" {
			if !contains(r.Middlewares, "cors") {
				t.Errorf("/admin/settings should have cors (global)")
			}
			if !contains(r.Middlewares, "adminAuth") {
				t.Errorf("/admin/settings should have adminAuth (path-scoped)")
			}
		}
		if r.Path == "/public/info" {
			if !contains(r.Middlewares, "cors") {
				t.Errorf("/public/info should have cors (global)")
			}
			if contains(r.Middlewares, "adminAuth") {
				t.Errorf("/public/info should NOT have adminAuth (path-scoped to /admin)")
			}
		}
	}
}

// contains is a helper to check if a slice contains a value.
func contains(slice []string, val string) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}
