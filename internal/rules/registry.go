package rules

// targetEntry defines a registered target and its required fact types.
type targetEntry struct {
	RequiredFactTypes []string
}

var targetRegistry = map[string]targetEntry{
	// ── Authentication ──
	"auth.jwt_middleware":     {RequiredFactTypes: []string{"SymbolFact", "ImportFact", "MiddlewareFact"}},
	"auth.api_key_validation": {RequiredFactTypes: []string{"SymbolFact", "ImportFact"}},

	// ── Rate Limiting ──
	"rate_limit.middleware": {RequiredFactTypes: []string{"SymbolFact", "MiddlewareFact"}},

	// ── Secrets & Config ──
	"secret.hardcoded_credential":        {RequiredFactTypes: []string{"SecretFact"}},
	"secret.env_file_committed":          {RequiredFactTypes: []string{"FileFact"}},
	"config.env_based":                   {RequiredFactTypes: []string{"SymbolFact", "ImportFact"}},
	"config.env_read_call_exists":        {RequiredFactTypes: []string{"ConfigReadFact"}},
	"config.secret_key_sourced_from_env": {RequiredFactTypes: []string{"ConfigReadFact"}},
	"config.secret_key_not_literal":      {RequiredFactTypes: []string{"ConfigReadFact"}},

	// ── Input Validation & Security Headers ──
	"security.input_validation":       {RequiredFactTypes: []string{"SymbolFact", "ImportFact"}},
	"security.cors_configuration":     {RequiredFactTypes: []string{"SymbolFact", "ImportFact", "MiddlewareFact"}},
	"security.headers_middleware":     {RequiredFactTypes: []string{"SymbolFact", "ImportFact", "MiddlewareFact"}},
	"security.sql_injection_pattern":  {RequiredFactTypes: []string{"DataAccessFact", "SymbolFact"}},
	"security.sensitive_data_in_logs": {RequiredFactTypes: []string{"SymbolFact", "ImportFact"}},

	// ── Architecture & Layering ──
	"layer.repository":                  {RequiredFactTypes: []string{"SymbolFact", "FileFact"}},
	"layer.service":                     {RequiredFactTypes: []string{"SymbolFact", "FileFact"}},
	"db.direct_access_from_controller":  {RequiredFactTypes: []string{"SymbolFact", "ImportFact", "DataAccessFact"}},
	"architecture.dependency_injection": {RequiredFactTypes: []string{"SymbolFact", "ImportFact"}},

	// ── Error Handling ──
	"error.global_handler": {RequiredFactTypes: []string{"SymbolFact", "MiddlewareFact"}},
	"error.panic_recovery": {RequiredFactTypes: []string{"SymbolFact"}},

	// ── Logging & Observability ──
	"logging.structured":      {RequiredFactTypes: []string{"SymbolFact", "ImportFact"}},
	"logging.request_logging": {RequiredFactTypes: []string{"SymbolFact", "MiddlewareFact"}},

	// ── Routes & Lifecycle ──
	"route.protected_uses_auth_middleware": {RequiredFactTypes: []string{"RouteFact"}},
	"route.public_without_auth":            {RequiredFactTypes: []string{"RouteFact"}},
	"route.health_check":                   {RequiredFactTypes: []string{"RouteFact"}},
	"lifecycle.graceful_shutdown":          {RequiredFactTypes: []string{"SymbolFact", "ImportFact"}},

	// ── Testing ──
	"module.payment_service": {RequiredFactTypes: []string{"SymbolFact", "FileFact", "TestFact"}},
	"module.auth_service":    {RequiredFactTypes: []string{"SymbolFact", "FileFact", "TestFact"}},

	// ── Design Patterns ──
	"pattern.repository_encapsulation": {RequiredFactTypes: []string{"SymbolFact", "FileFact", "DataAccessFact"}},
	"pattern.dto_separation":           {RequiredFactTypes: []string{"SymbolFact", "FileFact", "RouteFact"}},
	"pattern.singleton_mutable_global": {RequiredFactTypes: []string{"SymbolFact"}},

	// ── GoF Design Patterns — Creational ──
	"gof.singleton":        {RequiredFactTypes: []string{"SymbolFact"}},
	"gof.factory_method":   {RequiredFactTypes: []string{"SymbolFact"}},
	"gof.abstract_factory": {RequiredFactTypes: []string{"SymbolFact"}},
	"gof.builder":          {RequiredFactTypes: []string{"SymbolFact"}},
	"gof.prototype":        {RequiredFactTypes: []string{"SymbolFact"}},

	// ── GoF Design Patterns — Structural ──
	"gof.adapter":   {RequiredFactTypes: []string{"SymbolFact"}},
	"gof.bridge":    {RequiredFactTypes: []string{"SymbolFact"}},
	"gof.composite": {RequiredFactTypes: []string{"SymbolFact"}},
	"gof.decorator": {RequiredFactTypes: []string{"SymbolFact"}},
	"gof.facade":    {RequiredFactTypes: []string{"SymbolFact"}},
	"gof.flyweight": {RequiredFactTypes: []string{"SymbolFact"}},
	"gof.proxy":     {RequiredFactTypes: []string{"SymbolFact"}},

	// ── GoF Design Patterns — Behavioral ──
	"gof.chain_of_responsibility": {RequiredFactTypes: []string{"SymbolFact"}},
	"gof.command":                 {RequiredFactTypes: []string{"SymbolFact"}},
	"gof.interpreter":             {RequiredFactTypes: []string{"SymbolFact"}},
	"gof.iterator":                {RequiredFactTypes: []string{"SymbolFact"}},
	"gof.mediator":                {RequiredFactTypes: []string{"SymbolFact"}},
	"gof.memento":                 {RequiredFactTypes: []string{"SymbolFact"}},
	"gof.observer":                {RequiredFactTypes: []string{"SymbolFact"}},
	"gof.state":                   {RequiredFactTypes: []string{"SymbolFact"}},
	"gof.strategy":                {RequiredFactTypes: []string{"SymbolFact"}},
	"gof.template_method":         {RequiredFactTypes: []string{"SymbolFact"}},
	"gof.visitor":                 {RequiredFactTypes: []string{"SymbolFact"}},

	// ── Frontend Security ──
	"frontend.xss_dangerous_html":        {RequiredFactTypes: []string{"SymbolFact", "ImportFact"}},
	"frontend.xss_innerhtml":             {RequiredFactTypes: []string{"SymbolFact"}},
	"frontend.token_in_localstorage":     {RequiredFactTypes: []string{"SymbolFact"}},
	"frontend.env_exposes_secret":        {RequiredFactTypes: []string{"FileFact", "SymbolFact"}},
	"frontend.auth_guard":                {RequiredFactTypes: []string{"SymbolFact", "ImportFact", "RouteFact"}},
	"frontend.api_error_handling":        {RequiredFactTypes: []string{"SymbolFact", "ImportFact"}},
	"frontend.csp_configured":            {RequiredFactTypes: []string{"SymbolFact", "ImportFact"}},
	"frontend.lockfile_exists":           {RequiredFactTypes: []string{"FileFact"}},
	"frontend.console_log_in_production": {RequiredFactTypes: []string{"SymbolFact"}},
	"frontend.form_validation":           {RequiredFactTypes: []string{"SymbolFact", "ImportFact"}},
}

// IsValidTarget returns true if the target is in the fixed v0 registry.
func IsValidTarget(target string) bool {
	_, ok := targetRegistry[target]
	return ok
}

// RequiredFactTypes returns the fact types required to evaluate the given target.
func RequiredFactTypes(target string) []string {
	entry, ok := targetRegistry[target]
	if !ok {
		return nil
	}
	return entry.RequiredFactTypes
}

// AllTargets returns all registered target names.
func AllTargets() []string {
	targets := make([]string, 0, len(targetRegistry))
	for t := range targetRegistry {
		targets = append(targets, t)
	}
	return targets
}
