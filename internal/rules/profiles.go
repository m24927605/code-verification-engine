package rules

// Profile represents a built-in verification profile.
// Users select a profile; they cannot remove or skip individual rules.
type Profile struct {
	Name        string
	Description string
	Rules       []Rule
}

// AllProfiles returns all available built-in profiles.
func AllProfiles() map[string]Profile {
	return map[string]Profile{
		"backend-api":        backendAPIProfile(),
		"backend-api-strict": backendAPIStrictProfile(),
		"frontend":           frontendProfile(),
		"fullstack":          fullstackProfile(),
		"fullstack-strict":   fullstackStrictProfile(),
		"design-patterns":    designPatternsProfile(),
	}
}

// GetProfile returns a profile by name.
func GetProfile(name string) (*Profile, bool) {
	profiles := AllProfiles()
	p, ok := profiles[name]
	if !ok {
		return nil, false
	}
	return &p, true
}

// ListProfileNames returns all available profile names.
func ListProfileNames() []string {
	profiles := AllProfiles()
	names := make([]string, 0, len(profiles))
	for name := range profiles {
		names = append(names, name)
	}
	return names
}

// ProfileToRuleFile converts a Profile into a RuleFile for engine execution.
func ProfileToRuleFile(p *Profile) *RuleFile {
	return &RuleFile{
		Version: "0.1",
		Profile: p.Name,
		Rules:   p.Rules,
	}
}

var allLanguages = []string{"go", "javascript", "typescript", "python"}

// backendAPIProfile defines the standard backend API verification rules.
// This is the default profile covering security, architecture, quality, and testing.
func backendAPIProfile() Profile {
	return Profile{
		Name:        "backend-api",
		Description: "Standard backend API verification — security, architecture, quality, and testing checks",
		Rules: []Rule{
			// ═══════════════════════════════════
			// SECURITY — Authentication
			// ═══════════════════════════════════
			{
				ID: "SEC-AUTH-001", Title: "JWT authentication must exist",
				Category: "security", Severity: "high", Languages: allLanguages,
				Type: "exists", Target: "auth.jwt_middleware",
				Message: "The project must implement JWT authentication middleware.",
			},
			{
				ID: "SEC-AUTH-002", Title: "Protected routes must use authentication middleware",
				Category: "security", Severity: "critical", Languages: allLanguages,
				Type: "relationship", Target: "route.protected_uses_auth_middleware",
				Message: "Protected routes must be bound to an authentication middleware.",
			},
			{
				ID: "SEC-AUTH-003", Title: "API key validation must exist",
				Category: "security", Severity: "medium", Languages: allLanguages,
				Type: "exists", Target: "auth.api_key_validation",
				Message: "API key validation logic should be present if the service uses API keys.",
			},

			// ═══════════════════════════════════
			// SECURITY — Secrets
			// ═══════════════════════════════════
			{
				ID: "SEC-SECRET-001", Title: "Hardcoded credentials must not exist",
				Category: "security", Severity: "critical", Languages: allLanguages,
				Type: "not_exists", Target: "secret.hardcoded_credential",
				Message: "The repository must not contain hardcoded passwords, API keys, or tokens.",
			},
			{
				ID: "SEC-SECRET-002", Title: "Environment-based configuration must exist",
				Category: "security", Severity: "high", Languages: allLanguages,
				Type: "exists", Target: "config.env_based",
				Message: "Secrets and configuration must be loaded from environment variables, not hardcoded.",
			},
			{
				ID: "SEC-SECRET-003", Title: ".env files must not be committed",
				Category: "security", Severity: "critical", Languages: allLanguages,
				Type: "not_exists", Target: "secret.env_file_committed",
				Message: ".env files containing secrets must not be committed to the repository.",
			},

			// ═══════════════════════════════════
			// SECURITY — Input & Headers
			// ═══════════════════════════════════
			{
				ID: "SEC-INPUT-001", Title: "Request input validation must exist",
				Category: "security", Severity: "high", Languages: allLanguages,
				Type: "exists", Target: "security.input_validation",
				Message: "Request body, query, and path parameters must be validated before use.",
			},
			{
				ID: "SEC-CORS-001", Title: "CORS configuration must exist",
				Category: "security", Severity: "high", Languages: allLanguages,
				Type: "exists", Target: "security.cors_configuration",
				Message: "CORS must be explicitly configured, not left as permissive default.",
			},
			{
				ID: "SEC-HELMET-001", Title: "Security headers middleware must exist",
				Category: "security", Severity: "medium", Languages: allLanguages,
				Type: "exists", Target: "security.headers_middleware",
				Message: "Security headers (e.g., helmet, secure middleware) should be applied.",
			},

			// ═══════════════════════════════════
			// SECURITY — Rate Limiting
			// ═══════════════════════════════════
			{
				ID: "SEC-RATE-001", Title: "Rate limiting middleware must exist",
				Category: "security", Severity: "high", Languages: allLanguages,
				Type: "exists", Target: "rate_limit.middleware",
				Message: "Rate limiting must be applied to prevent abuse and DoS.",
			},

			// ═══════════════════════════════════
			// ARCHITECTURE — Layering
			// ═══════════════════════════════════
			{
				ID: "ARCH-LAYER-001", Title: "Controllers must not access database directly",
				Category: "architecture", Severity: "high", Languages: allLanguages,
				Type: "not_exists", Target: "db.direct_access_from_controller",
				Message: "Controllers/handlers should not directly access database clients. Use a service or repository layer.",
			},
			{
				ID: "ARCH-LAYER-002", Title: "Repository or data access layer must exist",
				Category: "architecture", Severity: "medium", Languages: allLanguages,
				Type: "exists", Target: "layer.repository",
				Message: "A repository or data access layer should separate business logic from database operations.",
			},
			{
				ID: "ARCH-LAYER-003", Title: "Service layer must exist",
				Category: "architecture", Severity: "medium", Languages: allLanguages,
				Type: "exists", Target: "layer.service",
				Message: "A service layer should encapsulate business logic separately from controllers.",
			},

			// ═══════════════════════════════════
			// ARCHITECTURE — Design Patterns
			// ═══════════════════════════════════
			{
				ID: "ARCH-PATTERN-001", Title: "Database access must be encapsulated in repository layer",
				Category: "architecture", Severity: "high", Languages: allLanguages,
				Type: "not_exists", Target: "pattern.repository_encapsulation",
				Message: "Database operations should be encapsulated in repository/data-access layer files, not scattered across handlers or services.",
			},
			{
				ID: "ARCH-PATTERN-002", Title: "API responses should not expose raw database models",
				Category: "architecture", Severity: "medium", Languages: allLanguages,
				Type: "not_exists", Target: "pattern.dto_separation",
				Message: "Route handlers should use DTOs or response types instead of returning raw database entity objects.",
			},
			{
				ID: "ARCH-PATTERN-003", Title: "Mutable global singletons should not exist",
				Category: "architecture", Severity: "medium", Languages: allLanguages,
				Type: "not_exists", Target: "pattern.singleton_mutable_global",
				Message: "Mutable global state (singletons, global DB connections) should be replaced with dependency injection.",
			},

			// ═══════════════════════════════════
			// ARCHITECTURE — Error Handling
			// ═══════════════════════════════════
			{
				ID: "ARCH-ERR-001", Title: "Global error handler must exist",
				Category: "architecture", Severity: "high", Languages: allLanguages,
				Type: "exists", Target: "error.global_handler",
				Message: "A global error handler or recovery middleware must be present to prevent unhandled crashes.",
			},
			{
				ID: "ARCH-ERR-002", Title: "Panic recovery must exist",
				Category: "architecture", Severity: "high", Languages: []string{"go"},
				Type: "exists", Target: "error.panic_recovery",
				Message: "Go services must have panic recovery middleware to prevent process crashes.",
			},

			// ═══════════════════════════════════
			// QUALITY — Logging & Observability
			// ═══════════════════════════════════
			{
				ID: "QUAL-LOG-001", Title: "Structured logging must exist",
				Category: "quality", Severity: "medium", Languages: allLanguages,
				Type: "exists", Target: "logging.structured",
				Message: "The project should use structured logging (e.g., JSON format) instead of plain print statements.",
			},
			{
				ID: "QUAL-LOG-002", Title: "Request logging middleware must exist",
				Category: "quality", Severity: "medium", Languages: allLanguages,
				Type: "exists", Target: "logging.request_logging",
				Message: "HTTP request logging middleware should be in place for observability.",
			},

			// ═══════════════════════════════════
			// QUALITY — Health & Graceful Shutdown
			// ═══════════════════════════════════
			{
				ID: "QUAL-HEALTH-001", Title: "Health check endpoint must exist",
				Category: "quality", Severity: "medium", Languages: allLanguages,
				Type: "exists", Target: "route.health_check",
				Message: "A /health or /healthz endpoint must exist for load balancer and orchestrator probes.",
			},
			{
				ID: "QUAL-SHUTDOWN-001", Title: "Graceful shutdown must be implemented",
				Category: "quality", Severity: "medium", Languages: allLanguages,
				Type: "exists", Target: "lifecycle.graceful_shutdown",
				Message: "The server must handle SIGTERM/SIGINT for graceful shutdown.",
			},

			// ═══════════════════════════════════
			// TESTING
			// ═══════════════════════════════════
			{
				ID: "TEST-AUTH-001", Title: "Auth module must have tests",
				Category: "testing", Severity: "high", Languages: allLanguages,
				Type: "test_required", Target: "module.auth_service",
				Message: "Authentication service must have automated tests.",
			},
			{
				ID: "TEST-PAYMENT-001", Title: "Payment module must have tests",
				Category: "testing", Severity: "high", Languages: allLanguages,
				Type: "test_required", Target: "module.payment_service",
				Message: "Payment service must have automated tests.",
			},

			// ═══════════════════════════════════
			// SECURITY — Route Exposure
			// ═══════════════════════════════════
			{
				ID: "SEC-ROUTE-001", Title: "Public routes without auth must be intentional",
				Category: "security", Severity: "medium", Languages: allLanguages,
				Type: "relationship", Target: "route.public_without_auth",
				Message: "Routes exposed without authentication should be limited to health, login, and public endpoints.",
			},
		},
	}
}

var frontendLanguages = []string{"javascript", "typescript"}

// frontendProfile defines frontend security and quality verification rules.
func frontendProfile() Profile {
	return Profile{
		Name:        "frontend",
		Description: "Frontend security and quality verification — XSS prevention, auth guards, error handling, and best practices",
		Rules: []Rule{
			// ═══════════════════════════════════
			// SECURITY — XSS
			// ═══════════════════════════════════
			{
				ID: "FE-XSS-001", Title: "dangerouslySetInnerHTML / v-html must not be used",
				Category: "security", Severity: "critical", Languages: frontendLanguages,
				Type: "not_exists", Target: "frontend.xss_dangerous_html",
				Message: "Usage of dangerouslySetInnerHTML, v-html, or [innerHTML] binding bypasses XSS protection.",
			},
			{
				ID: "FE-XSS-002", Title: "Direct innerHTML assignment must not be used",
				Category: "security", Severity: "high", Languages: frontendLanguages,
				Type: "not_exists", Target: "frontend.xss_innerhtml",
				Message: "Direct innerHTML assignments bypass framework XSS protections.",
			},

			// ═══════════════════════════════════
			// SECURITY — Token Storage
			// ═══════════════════════════════════
			{
				ID: "FE-TOKEN-001", Title: "Auth tokens must not be stored in localStorage",
				Category: "security", Severity: "high", Languages: frontendLanguages,
				Type: "not_exists", Target: "frontend.token_in_localstorage",
				Message: "Storing auth tokens in localStorage is vulnerable to XSS. Use httpOnly cookies instead.",
			},

			// ═══════════════════════════════════
			// SECURITY — Environment Variables
			// ═══════════════════════════════════
			{
				ID: "FE-ENV-001", Title: "Public env vars must not expose secrets",
				Category: "security", Severity: "critical", Languages: frontendLanguages,
				Type: "not_exists", Target: "frontend.env_exposes_secret",
				Message: "NEXT_PUBLIC_, VITE_, or REACT_APP_ environment variables must not contain secret keys or tokens.",
			},

			// ═══════════════════════════════════
			// SECURITY — Auth & CSP
			// ═══════════════════════════════════
			{
				ID: "FE-AUTH-001", Title: "Route auth guard must exist",
				Category: "security", Severity: "high", Languages: frontendLanguages,
				Type: "exists", Target: "frontend.auth_guard",
				Message: "Protected routes must have authentication guards (e.g., ProtectedRoute, AuthGuard, requireAuth).",
			},
			{
				ID: "FE-CSP-001", Title: "Content Security Policy must be configured",
				Category: "security", Severity: "medium", Languages: frontendLanguages,
				Type: "exists", Target: "frontend.csp_configured",
				Message: "A Content-Security-Policy should be configured to mitigate XSS and injection attacks.",
			},

			// ═══════════════════════════════════
			// QUALITY — Error Handling
			// ═══════════════════════════════════
			{
				ID: "FE-ERR-001", Title: "API error handling must exist",
				Category: "quality", Severity: "high", Languages: frontendLanguages,
				Type: "exists", Target: "frontend.api_error_handling",
				Message: "Global API error handling (interceptors, error boundaries) must be in place.",
			},

			// ═══════════════════════════════════
			// QUALITY — Dependencies & Logging
			// ═══════════════════════════════════
			{
				ID: "FE-DEP-001", Title: "Lock file must exist",
				Category: "quality", Severity: "medium", Languages: frontendLanguages,
				Type: "exists", Target: "frontend.lockfile_exists",
				Message: "A lock file (package-lock.json, yarn.lock, or pnpm-lock.yaml) must exist for reproducible builds.",
			},
			{
				ID: "FE-LOG-001", Title: "Console.log must not be in production code",
				Category: "quality", Severity: "low", Languages: frontendLanguages,
				Type: "not_exists", Target: "frontend.console_log_in_production",
				Message: "console.log statements should be removed or stripped from production builds.",
			},

			// ═══════════════════════════════════
			// QUALITY — Forms
			// ═══════════════════════════════════
			{
				ID: "FE-FORM-001", Title: "Form validation must exist",
				Category: "quality", Severity: "medium", Languages: frontendLanguages,
				Type: "exists", Target: "frontend.form_validation",
				Message: "Form inputs should be validated using a validation library (e.g., react-hook-form, formik, zod, yup).",
			},
		},
	}
}

// fullstackProfile combines all backend-api, frontend, and design-patterns rules.
func fullstackProfile() Profile {
	backend := backendAPIProfile()
	frontend := frontendProfile()
	patterns := designPatternsProfile()
	rules := append(backend.Rules, frontend.Rules...)
	rules = append(rules, patterns.Rules...)
	return Profile{
		Name:        "fullstack",
		Description: "Full-stack verification — all backend API, frontend, and design pattern rules combined",
		Rules:       rules,
	}
}

// fullstackStrictProfile combines backend-api-strict, frontend, and design-patterns rules.
func fullstackStrictProfile() Profile {
	backend := backendAPIStrictProfile()
	frontend := frontendProfile()
	patterns := designPatternsProfile()
	rules := append(backend.Rules, frontend.Rules...)
	rules = append(rules, patterns.Rules...)
	return Profile{
		Name:        "fullstack-strict",
		Description: "Strict full-stack verification — all strict backend, frontend, and design pattern rules",
		Rules:       rules,
	}
}

// designPatternsProfile defines GoF design pattern detection rules.
func designPatternsProfile() Profile {
	return Profile{
		Name:        "design-patterns",
		Description: "GoF design pattern detection — identifies usage of all 23 Gang of Four patterns",
		Rules: []Rule{
			// ═══════════════════════════════════
			// CREATIONAL PATTERNS
			// ═══════════════════════════════════
			{
				ID: "GOF-C-001", Title: "Singleton pattern detected",
				Category: "architecture", Severity: "low", Languages: allLanguages,
				Type: "exists", Target: "gof.singleton",
				Message: "Singleton pattern usage detected. Consider dependency injection as an alternative.",
			},
			{
				ID: "GOF-C-002", Title: "Factory Method pattern detected",
				Category: "architecture", Severity: "info", Languages: allLanguages,
				Type: "exists", Target: "gof.factory_method",
				Message: "Factory Method pattern detected. Objects are created via factory methods rather than direct construction.",
			},
			{
				ID: "GOF-C-003", Title: "Abstract Factory pattern detected",
				Category: "architecture", Severity: "info", Languages: allLanguages,
				Type: "exists", Target: "gof.abstract_factory",
				Message: "Abstract Factory pattern detected. Families of related objects are created through abstract interfaces.",
			},
			{
				ID: "GOF-C-004", Title: "Builder pattern detected",
				Category: "architecture", Severity: "info", Languages: allLanguages,
				Type: "exists", Target: "gof.builder",
				Message: "Builder pattern detected. Complex objects are constructed step by step with fluent API.",
			},
			{
				ID: "GOF-C-005", Title: "Prototype pattern detected",
				Category: "architecture", Severity: "info", Languages: allLanguages,
				Type: "exists", Target: "gof.prototype",
				Message: "Prototype pattern detected. Objects are created by cloning existing instances.",
			},

			// ═══════════════════════════════════
			// STRUCTURAL PATTERNS
			// ═══════════════════════════════════
			{
				ID: "GOF-S-001", Title: "Adapter pattern detected",
				Category: "architecture", Severity: "info", Languages: allLanguages,
				Type: "exists", Target: "gof.adapter",
				Message: "Adapter pattern detected. Incompatible interfaces are made compatible via wrapper.",
			},
			{
				ID: "GOF-S-002", Title: "Bridge pattern detected",
				Category: "architecture", Severity: "info", Languages: allLanguages,
				Type: "exists", Target: "gof.bridge",
				Message: "Bridge pattern detected. Abstraction is separated from implementation.",
			},
			{
				ID: "GOF-S-003", Title: "Composite pattern detected",
				Category: "architecture", Severity: "info", Languages: allLanguages,
				Type: "exists", Target: "gof.composite",
				Message: "Composite pattern detected. Tree structures are composed of uniform component interfaces.",
			},
			{
				ID: "GOF-S-004", Title: "Decorator pattern detected",
				Category: "architecture", Severity: "info", Languages: allLanguages,
				Type: "exists", Target: "gof.decorator",
				Message: "Decorator pattern detected. Behavior is added to objects dynamically via wrapping.",
			},
			{
				ID: "GOF-S-005", Title: "Facade pattern detected",
				Category: "architecture", Severity: "info", Languages: allLanguages,
				Type: "exists", Target: "gof.facade",
				Message: "Facade pattern detected. A simplified interface aggregates multiple subsystems.",
			},
			{
				ID: "GOF-S-006", Title: "Flyweight pattern detected",
				Category: "architecture", Severity: "info", Languages: allLanguages,
				Type: "exists", Target: "gof.flyweight",
				Message: "Flyweight pattern detected. Objects are shared via cache to minimize memory usage.",
			},
			{
				ID: "GOF-S-007", Title: "Proxy pattern detected",
				Category: "architecture", Severity: "info", Languages: allLanguages,
				Type: "exists", Target: "gof.proxy",
				Message: "Proxy pattern detected. Access to an object is controlled via a surrogate.",
			},

			// ═══════════════════════════════════
			// BEHAVIORAL PATTERNS
			// ═══════════════════════════════════
			{
				ID: "GOF-B-001", Title: "Chain of Responsibility pattern detected",
				Category: "architecture", Severity: "info", Languages: allLanguages,
				Type: "exists", Target: "gof.chain_of_responsibility",
				Message: "Chain of Responsibility pattern detected. Requests are passed along a chain of handlers.",
			},
			{
				ID: "GOF-B-002", Title: "Command pattern detected",
				Category: "architecture", Severity: "info", Languages: allLanguages,
				Type: "exists", Target: "gof.command",
				Message: "Command pattern detected. Requests are encapsulated as objects.",
			},
			{
				ID: "GOF-B-003", Title: "Interpreter pattern detected",
				Category: "architecture", Severity: "info", Languages: allLanguages,
				Type: "exists", Target: "gof.interpreter",
				Message: "Interpreter pattern detected. A grammar is evaluated via an interpret interface.",
			},
			{
				ID: "GOF-B-004", Title: "Iterator pattern detected",
				Category: "architecture", Severity: "info", Languages: allLanguages,
				Type: "exists", Target: "gof.iterator",
				Message: "Iterator pattern detected. Collection elements are traversed sequentially.",
			},
			{
				ID: "GOF-B-005", Title: "Mediator pattern detected",
				Category: "architecture", Severity: "info", Languages: allLanguages,
				Type: "exists", Target: "gof.mediator",
				Message: "Mediator pattern detected. Communication between objects is centralized.",
			},
			{
				ID: "GOF-B-006", Title: "Memento pattern detected",
				Category: "architecture", Severity: "info", Languages: allLanguages,
				Type: "exists", Target: "gof.memento",
				Message: "Memento pattern detected. Object state is captured and restored externally.",
			},
			{
				ID: "GOF-B-007", Title: "Observer pattern detected",
				Category: "architecture", Severity: "info", Languages: allLanguages,
				Type: "exists", Target: "gof.observer",
				Message: "Observer pattern detected. Dependents are notified of state changes via pub/sub.",
			},
			{
				ID: "GOF-B-008", Title: "State pattern detected",
				Category: "architecture", Severity: "info", Languages: allLanguages,
				Type: "exists", Target: "gof.state",
				Message: "State pattern detected. Object behavior changes based on internal state transitions.",
			},
			{
				ID: "GOF-B-009", Title: "Strategy pattern detected",
				Category: "architecture", Severity: "info", Languages: allLanguages,
				Type: "exists", Target: "gof.strategy",
				Message: "Strategy pattern detected. Algorithms are interchangeable via a common interface.",
			},
			{
				ID: "GOF-B-010", Title: "Template Method pattern detected",
				Category: "architecture", Severity: "info", Languages: allLanguages,
				Type: "exists", Target: "gof.template_method",
				Message: "Template Method pattern detected. Algorithm skeleton is defined with steps deferred to subclasses.",
			},
			{
				ID: "GOF-B-011", Title: "Visitor pattern detected",
				Category: "architecture", Severity: "info", Languages: allLanguages,
				Type: "exists", Target: "gof.visitor",
				Message: "Visitor pattern detected. Operations are separated from object structure via double dispatch.",
			},
		},
	}
}

// backendAPIStrictProfile adds stricter rules on top of the standard profile.
func backendAPIStrictProfile() Profile {
	base := backendAPIProfile()
	base.Name = "backend-api-strict"
	base.Description = "Strict backend API verification — all standard rules plus additional hardening checks"

	// Add stricter rules
	base.Rules = append(base.Rules, []Rule{
		{
			ID: "SEC-STRICT-001", Title: "SQL injection patterns must not exist",
			Category: "security", Severity: "critical", Languages: allLanguages,
			Type: "not_exists", Target: "security.sql_injection_pattern",
			Message: "String-concatenated SQL queries must not be used. Use parameterized queries.",
		},
		{
			ID: "SEC-STRICT-002", Title: "Sensitive data must not be logged",
			Category: "security", Severity: "high", Languages: allLanguages,
			Type: "not_exists", Target: "security.sensitive_data_in_logs",
			Message: "Passwords, tokens, and PII must not appear in log statements.",
		},
		{
			ID: "ARCH-STRICT-001", Title: "Dependency injection pattern must exist",
			Category: "architecture", Severity: "medium", Languages: allLanguages,
			Type: "exists", Target: "architecture.dependency_injection",
			Message: "Dependencies should be injected, not instantiated as global singletons.",
		},
	}...)

	return base
}
