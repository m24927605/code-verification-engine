package jsts

import "strings"

// ResolveRouteBindings resolves middleware bindings for routes within a single file.
//
// Rules:
//   - app.use(mw) before a route → projected into that route's Middlewares
//   - router.use(mw) → projected into routes on that router in same file
//   - Inline route middleware (already in ASTRoute.Middlewares) → kept
//   - NestJS guards (already in ASTRoute.Guards) → merged
//   - Order-dependent: use() only applies to routes declared AFTER it (by line number)
//   - No use() and no inline → Middlewares = []string{} (explicit empty, NOT nil)
//   - Deduplication applied
//
// "Global" receivers are "app" and "router" — use() calls with these receivers apply
// to all routes. Use() calls with other receiver names (e.g. "apiRouter") are treated
// as router-scoped and do NOT apply to routes unless route tracking is implemented.
func ResolveRouteBindings(ast *ASTResult) []ASTRoute {
	if ast == nil {
		return []ASTRoute{}
	}

	// Collect global use() calls: receiver "app" or "router".
	// Non-global receivers are router-scoped and not applied to routes in this file
	// unless the route explicitly tracks its router receiver.
	type useEntry struct {
		middlewares []string
		path        string // mount path prefix; empty = global
		line        int
	}
	var globalUse []useEntry
	for _, uc := range ast.UseCalls {
		if uc.Receiver == "app" || uc.Receiver == "router" {
			globalUse = append(globalUse, useEntry{middlewares: uc.Middlewares, path: uc.Path, line: uc.Line})
		}
	}

	result := make([]ASTRoute, 0, len(ast.Routes))
	for _, rt := range ast.Routes {
		// Collect middlewares that apply to this route: global use() declared before it.
		seen := make(map[string]bool)
		var merged []string

		addUnique := func(name string) {
			if !seen[name] {
				seen[name] = true
				merged = append(merged, name)
			}
		}

		for _, ue := range globalUse {
			if ue.line < rt.Line {
				// Path-scoped use(): only apply if route path starts with mount prefix.
				// Empty path = global (applies to all routes).
				if ue.path != "" && !routeMatchesPrefix(rt.Path, ue.path) {
					continue
				}
				for _, mw := range ue.middlewares {
					addUnique(mw)
				}
			}
		}

		// Add inline middlewares from the route itself
		for _, mw := range rt.Middlewares {
			addUnique(mw)
		}

		// Merge NestJS guards
		for _, g := range rt.Guards {
			addUnique(g)
		}

		// Ensure explicit empty slice (not nil) when no middlewares found
		if merged == nil {
			merged = []string{}
		}

		resolved := rt
		resolved.Middlewares = merged
		result = append(result, resolved)
	}

	return result
}

// routeMatchesPrefix checks if a route path starts with a mount prefix.
// Normalizes by stripping trailing slashes for comparison.
func routeMatchesPrefix(routePath, prefix string) bool {
	// Normalize: strip trailing slash for comparison
	rp := strings.TrimRight(routePath, "/")
	pp := strings.TrimRight(prefix, "/")
	if pp == "" {
		return true // empty prefix matches everything
	}
	return rp == pp || strings.HasPrefix(rp, pp+"/")
}
