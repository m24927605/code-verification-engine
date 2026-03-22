package claims

// AllClaimSets returns all available built-in claim sets.
func AllClaimSets() map[string]ClaimSet {
	return map[string]ClaimSet{
		"backend-security":    backendSecurityClaimSet(),
		"backend-architecture": backendArchitectureClaimSet(),
		"fullstack-security":  fullstackSecurityClaimSet(),
	}
}

// GetClaimSet returns a claim set by name.
func GetClaimSet(name string) (*ClaimSet, bool) {
	sets := AllClaimSets()
	cs, ok := sets[name]
	if !ok {
		return nil, false
	}
	return &cs, true
}

// ListClaimSetNames returns all available claim set names.
func ListClaimSetNames() []string {
	sets := AllClaimSets()
	names := make([]string, 0, len(sets))
	for name := range sets {
		names = append(names, name)
	}
	return names
}

var allLangs = []string{"go", "javascript", "typescript", "python"}
var frontendLangs = []string{"javascript", "typescript"}

func backendSecurityClaimSet() ClaimSet {
	return ClaimSet{
		Name:        "backend-security",
		Description: "Security-focused claims for backend services",
		Claims: []Claim{
			{
				ID:          "auth.jwt_implemented",
				Title:       "JWT authentication is implemented",
				Category:    "security",
				Description: "The service implements JWT-based authentication middleware.",
				RuleIDs:     []string{"SEC-AUTH-001"},
				Scope:       Scope{Languages: allLangs},
			},
			{
				ID:          "auth.routes_protected",
				Title:       "Protected routes use auth middleware",
				Category:    "security",
				Description: "All protected routes are bound to an authentication middleware.",
				RuleIDs:     []string{"SEC-AUTH-002"},
				Scope:       Scope{Languages: allLangs},
			},
			{
				ID:          "secrets.no_hardcoded",
				Title:       "No hardcoded credentials exist",
				Category:    "security",
				Description: "The repository does not contain hardcoded passwords, API keys, or tokens.",
				RuleIDs:     []string{"SEC-SECRET-001"},
				Scope:       Scope{Languages: allLangs},
			},
			{
				ID:          "secrets.env_based_config",
				Title:       "Configuration is environment-based",
				Category:    "security",
				Description: "Secrets and configuration are loaded from environment variables.",
				RuleIDs:     []string{"SEC-SECRET-002"},
				Scope:       Scope{Languages: allLangs},
			},
			{
				ID:          "secrets.no_env_committed",
				Title:       "No .env files are committed",
				Category:    "security",
				Description: ".env files containing secrets are not committed to the repository.",
				RuleIDs:     []string{"SEC-SECRET-003"},
				Scope:       Scope{Languages: allLangs},
			},
			{
				ID:          "security.input_validated",
				Title:       "Request input is validated",
				Category:    "security",
				Description: "Request body, query, and path parameters are validated before use.",
				RuleIDs:     []string{"SEC-INPUT-001"},
				Scope:       Scope{Languages: allLangs},
			},
			{
				ID:          "security.cors_configured",
				Title:       "CORS is configured",
				Category:    "security",
				Description: "CORS is explicitly configured, not left as permissive default.",
				RuleIDs:     []string{"SEC-CORS-001"},
				Scope:       Scope{Languages: allLangs},
			},
			{
				ID:          "security.rate_limited",
				Title:       "Rate limiting is in place",
				Category:    "security",
				Description: "Rate limiting middleware is applied to prevent abuse.",
				RuleIDs:     []string{"SEC-RATE-001"},
				Scope:       Scope{Languages: allLangs},
			},
		},
	}
}

func backendArchitectureClaimSet() ClaimSet {
	return ClaimSet{
		Name:        "backend-architecture",
		Description: "Architecture claims for backend services",
		Claims: []Claim{
			{
				ID:          "arch.no_direct_db_from_controller",
				Title:       "Controllers do not access database directly",
				Category:    "architecture",
				Description: "Controllers/handlers do not directly access database clients.",
				RuleIDs:     []string{"ARCH-LAYER-001"},
				Scope:       Scope{Languages: allLangs},
			},
			{
				ID:          "arch.has_repository_layer",
				Title:       "Repository layer exists",
				Category:    "architecture",
				Description: "A repository or data access layer separates business logic from database operations.",
				RuleIDs:     []string{"ARCH-LAYER-002"},
				Scope:       Scope{Languages: allLangs},
			},
			{
				ID:          "arch.has_service_layer",
				Title:       "Service layer exists",
				Category:    "architecture",
				Description: "A service layer encapsulates business logic separately from controllers.",
				RuleIDs:     []string{"ARCH-LAYER-003"},
				Scope:       Scope{Languages: allLangs},
			},
			{
				ID:          "arch.has_error_handling",
				Title:       "Global error handling exists",
				Category:    "architecture",
				Description: "A global error handler or recovery middleware prevents unhandled crashes.",
				RuleIDs:     []string{"ARCH-ERR-001"},
				Scope:       Scope{Languages: allLangs},
			},
			{
				ID:          "arch.db_access_encapsulated",
				Title:       "Database access is encapsulated",
				Category:    "architecture",
				Description: "Database operations are encapsulated in a repository/data-access layer.",
				RuleIDs:     []string{"ARCH-PATTERN-001"},
				Scope:       Scope{Languages: allLangs},
			},
			{
				ID:          "arch.no_mutable_globals",
				Title:       "No mutable global singletons",
				Category:    "architecture",
				Description: "Mutable global state is replaced with dependency injection.",
				RuleIDs:     []string{"ARCH-PATTERN-003"},
				Scope:       Scope{Languages: allLangs},
			},
		},
	}
}

func fullstackSecurityClaimSet() ClaimSet {
	backend := backendSecurityClaimSet()
	frontendClaims := []Claim{
		{
			ID:          "frontend.no_xss_patterns",
			Title:       "No XSS-vulnerable patterns",
			Category:    "security",
			Description: "No usage of dangerouslySetInnerHTML, v-html, or direct innerHTML assignments.",
			RuleIDs:     []string{"FE-XSS-001", "FE-XSS-002"},
			Scope:       Scope{Languages: frontendLangs},
		},
		{
			ID:          "frontend.secure_token_storage",
			Title:       "Auth tokens are stored securely",
			Category:    "security",
			Description: "Auth tokens are not stored in localStorage.",
			RuleIDs:     []string{"FE-TOKEN-001"},
			Scope:       Scope{Languages: frontendLangs},
		},
		{
			ID:          "frontend.no_exposed_secrets",
			Title:       "No secrets exposed in public env vars",
			Category:    "security",
			Description: "Public environment variables do not contain secret keys or tokens.",
			RuleIDs:     []string{"FE-ENV-001"},
			Scope:       Scope{Languages: frontendLangs},
		},
		{
			ID:          "frontend.has_auth_guards",
			Title:       "Route auth guards exist",
			Category:    "security",
			Description: "Protected routes have authentication guards.",
			RuleIDs:     []string{"FE-AUTH-001"},
			Scope:       Scope{Languages: frontendLangs},
		},
	}

	allClaims := make([]Claim, 0, len(backend.Claims)+len(frontendClaims))
	allClaims = append(allClaims, backend.Claims...)
	allClaims = append(allClaims, frontendClaims...)

	return ClaimSet{
		Name:        "fullstack-security",
		Description: "Security claims for full-stack applications — backend and frontend combined",
		Claims:      allClaims,
	}
}
