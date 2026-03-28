package rules

import (
	"fmt"
	"strings"
)

// SupportLevel indicates how well an analyzer supports a given target/fact type.
type SupportLevel string

const (
	// Supported means the analyzer fully provides this fact.
	Supported SupportLevel = "supported"
	// PartiallySup means the analyzer provides some but not complete facts.
	PartiallySup SupportLevel = "partially_supported"
	// Unsupported means the analyzer cannot provide this fact at all.
	Unsupported SupportLevel = "unsupported"
)

// CapabilityDetail provides enriched information about a capability entry,
// including optional per-framework support levels, extraction method info,
// and runtime dependencies.
type CapabilityDetail struct {
	Level      SupportLevel            // base support level
	Frameworks map[string]SupportLevel // optional: per-framework override
	Notes      string                  // human-readable note for consumers
	ASTBacked  bool                    // true if fact extraction uses AST
	RuntimeDep string                  // "python3", "node", "" = no runtime dep
}

// CapabilityMatrix maps (language, target) to a SupportLevel.
// The matrix is keyed by language first, then target.
type CapabilityMatrix struct {
	entries        map[string]map[string]SupportLevel
	details        map[string]map[string]CapabilityDetail // language → target → detail
	degradeReasons map[string]string                      // language → reason for degradation
}

// NewCapabilityMatrix creates and populates the default capability matrix.
func NewCapabilityMatrix() *CapabilityMatrix {
	m := &CapabilityMatrix{
		entries:        make(map[string]map[string]SupportLevel),
		details:        make(map[string]map[string]CapabilityDetail),
		degradeReasons: make(map[string]string),
	}
	m.populate()
	m.populateDetails()
	return m
}

// GetSupportLevel returns the support level for a given language and target.
// Unknown languages or targets return Unsupported.
func (m *CapabilityMatrix) GetSupportLevel(language, target string) SupportLevel {
	langMap, ok := m.entries[language]
	if !ok {
		return Unsupported
	}
	level, ok := langMap[target]
	if !ok {
		return Unsupported
	}
	return level
}

// GetCapabilityDetail returns enriched capability information for a language/target pair.
// If no detail is registered, it returns a CapabilityDetail with the base level from
// the entries map and empty framework/notes fields.
func (m *CapabilityMatrix) GetCapabilityDetail(language, target string) CapabilityDetail {
	level := m.GetSupportLevel(language, target)

	if langDetails, ok := m.details[language]; ok {
		if detail, ok := langDetails[target]; ok {
			// Apply degradation: if the base level was degraded, reflect it in the detail
			detail.Level = level
			return detail
		}
	}
	return CapabilityDetail{Level: level}
}

// GetDegradeReason returns the reason a language was degraded, or empty string if not degraded.
func (m *CapabilityMatrix) GetDegradeReason(language string) string {
	return m.degradeReasons[language]
}

// CheckCapability evaluates whether a rule's target is supported for the
// given languages (intersection of rule languages and repo languages).
// It returns the WORST support level across all relevant languages, because
// a polyglot repo must not mask unsupported coverage in some languages
// behind full support in others.
//   - If any relevant language is unsupported → Unsupported
//   - If any relevant language is partially_supported → PartiallySup
//   - Only if ALL relevant languages are supported → Supported
func (m *CapabilityMatrix) CheckCapability(target string, ruleLanguages, repoLanguages []string) (SupportLevel, string) {
	// Find the intersection of rule and repo languages.
	relevant := intersectLanguages(ruleLanguages, repoLanguages)
	if len(relevant) == 0 {
		return Unsupported, fmt.Sprintf("%s not supported for any repo languages", target)
	}

	worstLevel := Supported
	var unsupportedLangs []string
	var partialLangs []string

	for _, lang := range relevant {
		level := m.GetSupportLevel(lang, target)
		switch level {
		case Unsupported:
			unsupportedLangs = append(unsupportedLangs, lang)
			worstLevel = Unsupported
		case PartiallySup:
			partialLangs = append(partialLangs, lang)
			if worstLevel == Supported {
				worstLevel = PartiallySup
			}
		case Supported:
			// does not downgrade worstLevel
		}
	}

	switch worstLevel {
	case Supported:
		return Supported, ""
	case PartiallySup:
		detail := m.buildCapabilityDetail(target, partialLangs, unsupportedLangs)
		return PartiallySup, detail
	default:
		detail := m.buildCapabilityDetail(target, partialLangs, unsupportedLangs)
		return Unsupported, detail
	}
}

// buildCapabilityDetail constructs a rich detail message that includes language,
// extraction method (AST vs regex), framework context, and degradation reasons.
func (m *CapabilityMatrix) buildCapabilityDetail(target string, partialLangs, unsupportedLangs []string) string {
	var parts []string

	if len(unsupportedLangs) > 0 {
		parts = append(parts, fmt.Sprintf("%s unsupported for %s", target, strings.Join(unsupportedLangs, ", ")))
	}
	if len(partialLangs) > 0 {
		if len(unsupportedLangs) > 0 {
			parts = append(parts, fmt.Sprintf("partially supported for %s", strings.Join(partialLangs, ", ")))
		} else {
			parts = append(parts, fmt.Sprintf("%s partially supported for %s", target, strings.Join(partialLangs, ", ")))
		}
	}

	// Enrich with extraction method and framework details
	allLangs := append(append([]string{}, unsupportedLangs...), partialLangs...)
	for _, lang := range allLangs {
		d := m.GetCapabilityDetail(lang, target)
		// Add extraction method info
		if d.ASTBacked {
			parts = append(parts, fmt.Sprintf("[%s: AST-based extraction]", lang))
		} else if d.Level != Unsupported {
			parts = append(parts, fmt.Sprintf("[%s: regex-based extraction (limited)]", lang))
		}
		// Add framework detail if available
		if len(d.Frameworks) > 0 {
			var fwParts []string
			for fw, fwLevel := range d.Frameworks {
				fwParts = append(fwParts, fmt.Sprintf("%s=%s", fw, string(fwLevel)))
			}
			parts = append(parts, fmt.Sprintf("[%s frameworks: %s]", lang, strings.Join(fwParts, ", ")))
		}
		// Add notes if present
		if d.Notes != "" {
			parts = append(parts, fmt.Sprintf("[%s: %s]", lang, d.Notes))
		}
		// Add degradation reason if applicable
		if reason := m.GetDegradeReason(lang); reason != "" {
			parts = append(parts, fmt.Sprintf("[%s degraded: %s]", lang, reason))
		}
	}

	return strings.Join(parts, "; ")
}

// DegradeLanguage downgrades all entries for a language by one level.
// Supported → PartiallySup, PartiallySup → PartiallySup (unchanged).
// The reason parameter records WHY the degradation happened (e.g., "python3 unavailable").
// This should be called when the runtime environment for a language is degraded
// (e.g., python3 not available, causing fallback from AST to regex extraction).
func (m *CapabilityMatrix) DegradeLanguage(language, reason string) {
	langMap, ok := m.entries[language]
	if !ok {
		return
	}
	if reason != "" {
		m.degradeReasons[language] = reason
	}
	for target, level := range langMap {
		if level == Supported {
			langMap[target] = PartiallySup
		}
	}
}

// SupportedTargets returns all targets registered for a given language.
func (m *CapabilityMatrix) SupportedTargets(language string) []string {
	langMap, ok := m.entries[language]
	if !ok {
		return nil
	}
	targets := make([]string, 0, len(langMap))
	for t, level := range langMap {
		if level == Supported || level == PartiallySup {
			targets = append(targets, t)
		}
	}
	return targets
}

func intersectLanguages(a, b []string) []string {
	set := make(map[string]bool, len(b))
	for _, l := range b {
		set[l] = true
	}
	var result []string
	for _, l := range a {
		if set[l] {
			result = append(result, l)
		}
	}
	return result
}

// set is a helper to register a support level for a language/target pair.
func (m *CapabilityMatrix) set(language, target string, level SupportLevel) {
	if m.entries[language] == nil {
		m.entries[language] = make(map[string]SupportLevel)
	}
	m.entries[language][target] = level
}

// setDetail registers a CapabilityDetail for a language/target pair.
func (m *CapabilityMatrix) setDetail(language, target string, detail CapabilityDetail) {
	if m.details[language] == nil {
		m.details[language] = make(map[string]CapabilityDetail)
	}
	m.details[language][target] = detail
}

// populateDetails fills the detail map with framework-aware capability info
// for key targets. This is optional enrichment — not every target needs detail.
func (m *CapabilityMatrix) populateDetails() {
	// --- JavaScript / TypeScript details ---
	jsDetails := map[string]CapabilityDetail{
		"auth.jwt_middleware": {
			Level: PartiallySup,
			Frameworks: map[string]SupportLevel{
				"express": PartiallySup,
				"nestjs":  PartiallySup,
				"fastify": PartiallySup,
				"koa":     PartiallySup,
				"hapi":    Unsupported,
			},
			ASTBacked: true,
			Notes:     "AST middleware extraction + auth evidence scoring (binding+import); reduces false positives vs name-only matching",
		},
		"route.protected_uses_auth_middleware": {
			Level: PartiallySup,
			Frameworks: map[string]SupportLevel{
				"express": PartiallySup,
				"nestjs":  PartiallySup,
				"fastify": PartiallySup,
				"koa":     PartiallySup,
				"hapi":    Unsupported,
			},
			ASTBacked: true,
			Notes:     "same-file per-route binding from app.use()/router.use()/guards; auth scoring requires binding+import for strong evidence",
		},
		"secret.hardcoded_credential": {
			Level:     Supported,
			ASTBacked: true,
			Notes:     "AST extracts const assignments with secret-pattern names; mechanically sound",
		},
		"db.direct_access_from_controller": {
			Level: PartiallySup,
			Frameworks: map[string]SupportLevel{
				"express": PartiallySup,
				"nestjs":  PartiallySup,
				"fastify": PartiallySup,
			},
			ASTBacked: true,
			Notes:     "CallerName enrichment from AST function spans; file-scoped handler matching with ImportsDirect check",
		},
	}
	for target, detail := range jsDetails {
		m.setDetail("javascript", target, detail)
		m.setDetail("typescript", target, detail)
	}

	// --- Python details ---
	pyDetails := map[string]CapabilityDetail{
		"auth.jwt_middleware": {
			Level: PartiallySup,
			Frameworks: map[string]SupportLevel{
				"fastapi":   PartiallySup,
				"flask":     PartiallySup,
				"django":    PartiallySup,
				"starlette": Unsupported,
			},
			ASTBacked:  true,
			RuntimeDep: "python3",
			Notes:      "AST middleware/dependency extraction + auth evidence scoring; FastAPI Depends and Flask decorator binding",
		},
		"route.protected_uses_auth_middleware": {
			Level: PartiallySup,
			Frameworks: map[string]SupportLevel{
				"fastapi": PartiallySup,
				"flask":   PartiallySup,
				"django":  PartiallySup,
			},
			ASTBacked:  true,
			RuntimeDep: "python3",
			Notes:      "FastAPI: Depends propagation to routes; Flask: decorator binding + before_request projection; auth scoring requires binding+import",
		},
		"secret.hardcoded_credential": {
			Level:      Supported,
			ASTBacked:  true,
			RuntimeDep: "python3",
			Notes:      "AST extracts hardcoded assignments; mechanically sound",
		},
		"db.direct_access_from_controller": {
			Level: PartiallySup,
			Frameworks: map[string]SupportLevel{
				"fastapi":    PartiallySup,
				"flask":      PartiallySup,
				"django":     PartiallySup,
				"sqlalchemy": PartiallySup,
			},
			ASTBacked:  true,
			RuntimeDep: "python3",
			Notes:      "CallerName from AST/regex function spans; ImportsDirect check from file-level DB imports",
		},
	}
	for target, detail := range pyDetails {
		m.setDetail("python", target, detail)
	}

	// --- Go details (AST-backed, no runtime dep, full support) ---
	goDetails := map[string]CapabilityDetail{
		"auth.jwt_middleware": {
			Level:     Supported,
			ASTBacked: true,
			Notes:     "Go AST parser; mechanically sound middleware detection",
		},
		"route.protected_uses_auth_middleware": {
			Level:     Supported,
			ASTBacked: true,
			Notes:     "Go AST parser; mechanically sound route-middleware binding",
		},
		"secret.hardcoded_credential": {
			Level:     Supported,
			ASTBacked: true,
			Notes:     "Go AST parser; mechanically sound hardcoded string detection",
		},
		"db.direct_access_from_controller": {
			Level:     Supported,
			ASTBacked: true,
			Notes:     "Go AST parser; type-aware data-access detection",
		},
	}
	for target, detail := range goDetails {
		m.setDetail("go", target, detail)
	}
}

// populate fills the matrix with known analyzer capabilities.
func (m *CapabilityMatrix) populate() {
	// --- Go ---
	goTargets := map[string]SupportLevel{
		"auth.jwt_middleware":                  Supported,
		"auth.api_key_validation":              Supported,
		"route.protected_uses_auth_middleware": Supported,
		"route.public_without_auth":            Supported,
		"route.health_check":                   Supported,
		"db.direct_access_from_controller":     Supported,
		"secret.hardcoded_credential":          Supported,
		"secret.env_file_committed":            Supported,
		"config.env_based":                     Supported,
		"config.env_read_call_exists":          Supported,
		"config.secret_key_sourced_from_env":   Supported,
		"config.secret_key_not_literal":        Supported,
		"layer.repository":                     Supported,
		"layer.service":                        Supported,
		"pattern.repository_encapsulation":     Supported,
		"pattern.dto_separation":               PartiallySup,
		"pattern.singleton_mutable_global":     Supported,
		"security.input_validation":            PartiallySup,
		"security.cors_configuration":          Supported,
		"security.headers_middleware":          Supported,
		"security.sql_injection_pattern":       Supported,
		"security.sensitive_data_in_logs":      Supported,
		"rate_limit.middleware":                Supported,
		"error.global_handler":                 Supported,
		"error.panic_recovery":                 Supported,
		"logging.structured":                   Supported,
		"logging.request_logging":              Supported,
		"lifecycle.graceful_shutdown":          Supported,
		"module.auth_service":                  Supported,
		"module.payment_service":               Supported,
		"architecture.dependency_injection":    PartiallySup,
		"dep.lockfile_present":                 Supported,
		// Frontend targets are unsupported for Go (not registered = Unsupported).
		// GoF patterns
		"gof.singleton":               Supported,
		"gof.factory_method":          Supported,
		"gof.abstract_factory":        Supported,
		"gof.builder":                 Supported,
		"gof.prototype":               Supported,
		"gof.adapter":                 Supported,
		"gof.bridge":                  Supported,
		"gof.composite":               Supported,
		"gof.decorator":               Supported,
		"gof.facade":                  Supported,
		"gof.flyweight":               Supported,
		"gof.proxy":                   Supported,
		"gof.chain_of_responsibility": Supported,
		"gof.command":                 Supported,
		"gof.interpreter":             Supported,
		"gof.iterator":                Supported,
		"gof.mediator":                Supported,
		"gof.memento":                 Supported,
		"gof.observer":                Supported,
		"gof.state":                   Supported,
		"gof.strategy":                Supported,
		"gof.template_method":         Supported,
		"gof.visitor":                 Supported,
	}
	for target, level := range goTargets {
		m.set("go", target, level)
	}

	// --- JavaScript ---
	// JS/TS analyzers now use a Go-native recursive descent AST parser as the
	// PRIMARY extraction path, with regex fallback for patterns the AST doesn't cover.
	// AST-based extraction reliably skips comments and strings, improving precision.
	//
	// Upgrade rationale (AST-based facts, but matchers still use name heuristics):
	// - Imports, symbols, routes, middleware, secrets: AST-based (ProvenanceAST)
	//   → improved from pure regex but matchers are still heuristic name matching
	// - Data access: STILL regex-only → no improvement
	// - File-existence targets: mechanically decidable → Supported (unchanged)
	//
	// Targets upgraded from PartiallySup: NONE promoted to Supported because the
	// matchers (e.g., NameMatchesToken) remain heuristic even though the underlying
	// fact extraction is now AST-based. The AST parser reduces false positives from
	// comments/strings but does not make the matching logic mechanically sound.
	// All AST-backed targets remain PartiallySup with improved confidence.
	jsTargets := map[string]SupportLevel{
		"auth.jwt_middleware":                  PartiallySup, // AST middleware + heuristic name match
		"auth.api_key_validation":              PartiallySup, // AST middleware + heuristic name match
		"route.protected_uses_auth_middleware": PartiallySup, // AST route+middleware, heuristic correlation
		"route.public_without_auth":            PartiallySup, // AST route extraction, heuristic logic
		"route.health_check":                   PartiallySup, // AST route extraction, heuristic path match
		"db.direct_access_from_controller":     PartiallySup, // data-access still regex-only
		"secret.hardcoded_credential":          Supported,    // AST extracts const assignments with secret names; mechanically sound
		"secret.env_file_committed":            Supported,    // file existence — mechanically decidable
		"config.env_based":                     PartiallySup, // AST symbol match, heuristic
		"config.env_read_call_exists":          Supported,    // ConfigReadFact is deterministic
		"config.secret_key_sourced_from_env":   Supported,    // ConfigReadFact is deterministic
		"config.secret_key_not_literal":        Supported,    // ConfigReadFact is deterministic
		"layer.repository":                     PartiallySup, // AST symbol match, heuristic name
		"layer.service":                        PartiallySup, // AST symbol match, heuristic name
		"pattern.repository_encapsulation":     PartiallySup, // data-access still regex-only
		"pattern.dto_separation":               PartiallySup, // heuristic
		"pattern.singleton_mutable_global":     PartiallySup, // AST symbol match, heuristic
		"security.input_validation":            PartiallySup, // heuristic
		"security.cors_configuration":          PartiallySup, // AST middleware, heuristic name
		"security.headers_middleware":          PartiallySup, // AST middleware, heuristic name
		"security.sql_injection_pattern":       PartiallySup, // regex pattern match
		"security.sensitive_data_in_logs":      PartiallySup, // regex pattern match
		"rate_limit.middleware":                PartiallySup, // AST middleware, heuristic name
		"error.global_handler":                 PartiallySup, // AST symbol match, heuristic
		"logging.structured":                   PartiallySup, // AST import match, heuristic
		"logging.request_logging":              PartiallySup, // AST middleware, heuristic
		"lifecycle.graceful_shutdown":          PartiallySup, // regex signal match
		"module.auth_service":                  PartiallySup, // AST symbol match, heuristic name
		"module.payment_service":               PartiallySup, // AST symbol match, heuristic name
		"architecture.dependency_injection":    PartiallySup, // heuristic
		"dep.lockfile_present":                 Supported,    // file existence — mechanically decidable
		// Frontend targets for JS — AST-backed fact extraction, heuristic matching
		"frontend.xss_dangerous_html":        PartiallySup, // AST symbol, heuristic
		"frontend.xss_innerhtml":             PartiallySup, // AST symbol, heuristic
		"frontend.token_in_localstorage":     PartiallySup, // AST symbol, heuristic
		"frontend.env_exposes_secret":        PartiallySup, // AST symbol, heuristic
		"frontend.console_log_in_production": PartiallySup, // AST symbol, heuristic
		"frontend.auth_guard":                PartiallySup, // AST symbol, heuristic
		"frontend.csp_configured":            PartiallySup, // heuristic
		"frontend.api_error_handling":        PartiallySup, // AST symbol, heuristic
		"frontend.lockfile_exists":           Supported,    // file existence — mechanically decidable
		"frontend.form_validation":           PartiallySup, // AST symbol, heuristic
		// GoF patterns — AST symbol extraction, heuristic name matching
		"gof.singleton":               PartiallySup,
		"gof.factory_method":          PartiallySup,
		"gof.abstract_factory":        PartiallySup,
		"gof.builder":                 PartiallySup,
		"gof.prototype":               PartiallySup,
		"gof.adapter":                 PartiallySup,
		"gof.bridge":                  PartiallySup,
		"gof.composite":               PartiallySup,
		"gof.decorator":               PartiallySup,
		"gof.facade":                  PartiallySup,
		"gof.flyweight":               PartiallySup,
		"gof.proxy":                   PartiallySup,
		"gof.chain_of_responsibility": PartiallySup,
		"gof.command":                 PartiallySup,
		"gof.interpreter":             PartiallySup,
		"gof.iterator":                PartiallySup,
		"gof.mediator":                PartiallySup,
		"gof.memento":                 PartiallySup,
		"gof.observer":                PartiallySup,
		"gof.state":                   PartiallySup,
		"gof.strategy":                PartiallySup,
		"gof.template_method":         PartiallySup,
		"gof.visitor":                 PartiallySup,
	}
	for target, level := range jsTargets {
		m.set("javascript", target, level)
	}

	// --- TypeScript ---
	// TypeScript uses the same AST parser as JavaScript and has the same capabilities.
	tsTargets := make(map[string]SupportLevel, len(jsTargets))
	for k, v := range jsTargets {
		tsTargets[k] = v
	}
	for target, level := range tsTargets {
		m.set("typescript", target, level)
	}

	// --- Python ---
	// Python analyzer now uses Python's ast module via subprocess as the PRIMARY
	// extraction path (ProvenanceAST), with regex fallback if python3 is unavailable.
	//
	// AST-based extraction covers: imports, symbols, FastAPI/Flask route decorators,
	// Depends()/add_middleware, SQLAlchemy/Django ORM data access, secrets.
	// Still regex-based: Django middleware list, Django/Starlette path() routes.
	//
	// Upgrade rationale:
	// - secret.hardcoded_credential: remains Supported (was already, AST confirms)
	// - route.health_check: AST reliably extracts decorator routes → keep PartiallySup
	//   (matcher still uses heuristic path matching)
	// - db.direct_access_from_controller: AST now extracts data access for Python →
	//   keep PartiallySup (matcher logic is heuristic correlation)
	// - module.auth_service/payment_service: remain Supported (AST symbol extraction
	//   + name convention matching is mechanically sound for module detection)
	pyTargets := map[string]SupportLevel{
		"auth.jwt_middleware":                  PartiallySup, // AST middleware + heuristic name
		"auth.api_key_validation":              PartiallySup, // AST middleware + heuristic name
		"route.protected_uses_auth_middleware": PartiallySup, // AST route+middleware, heuristic correlation
		"route.public_without_auth":            PartiallySup, // AST route, heuristic logic
		"route.health_check":                   PartiallySup, // AST route, heuristic path match
		"db.direct_access_from_controller":     PartiallySup, // AST data-access, heuristic correlation
		"secret.hardcoded_credential":          Supported,    // AST extracts hardcoded assignments; mechanically sound
		"secret.env_file_committed":            Supported,    // file existence — mechanically decidable
		"config.env_based":                     PartiallySup, // AST import, heuristic
		"config.env_read_call_exists":          Supported,    // ConfigReadFact is deterministic
		"config.secret_key_sourced_from_env":   Supported,    // ConfigReadFact is deterministic
		"config.secret_key_not_literal":        Supported,    // ConfigReadFact is deterministic
		"layer.repository":                     PartiallySup, // AST symbol, heuristic name
		"layer.service":                        PartiallySup, // AST symbol, heuristic name
		"pattern.repository_encapsulation":     PartiallySup, // AST data-access, heuristic
		"pattern.dto_separation":               Unsupported,
		"pattern.singleton_mutable_global":     PartiallySup, // AST symbol, heuristic
		"security.input_validation":            PartiallySup, // heuristic
		"security.cors_configuration":          PartiallySup, // AST middleware, heuristic
		"security.headers_middleware":          Unsupported,
		"security.sql_injection_pattern":       PartiallySup, // regex pattern match
		"security.sensitive_data_in_logs":      PartiallySup, // regex pattern match
		"rate_limit.middleware":                Unsupported,
		"error.global_handler":                 PartiallySup, // AST symbol, heuristic
		"logging.structured":                   PartiallySup, // AST import, heuristic
		"logging.request_logging":              Unsupported,
		"lifecycle.graceful_shutdown":          Unsupported,
		"module.auth_service":                  Supported, // AST symbol extraction, name convention
		"module.payment_service":               Supported, // AST symbol extraction, name convention
		"architecture.dependency_injection":    Unsupported,
		"dep.lockfile_present":                 Supported, // file existence — mechanically decidable
		// Frontend targets unsupported for Python (not registered = Unsupported).
		// GoF patterns — Python has limited support (AST improves symbol detection)
		"gof.singleton":               PartiallySup,
		"gof.factory_method":          PartiallySup,
		"gof.abstract_factory":        PartiallySup,
		"gof.builder":                 PartiallySup,
		"gof.prototype":               Unsupported,
		"gof.adapter":                 PartiallySup,
		"gof.bridge":                  Unsupported,
		"gof.composite":               Unsupported,
		"gof.decorator":               Supported,
		"gof.facade":                  PartiallySup,
		"gof.flyweight":               Unsupported,
		"gof.proxy":                   Unsupported,
		"gof.chain_of_responsibility": Unsupported,
		"gof.command":                 PartiallySup,
		"gof.interpreter":             Unsupported,
		"gof.iterator":                Supported,
		"gof.mediator":                Unsupported,
		"gof.memento":                 Unsupported,
		"gof.observer":                PartiallySup,
		"gof.state":                   PartiallySup,
		"gof.strategy":                PartiallySup,
		"gof.template_method":         PartiallySup,
		"gof.visitor":                 Unsupported,
	}
	for target, level := range pyTargets {
		m.set("python", target, level)
	}
}
