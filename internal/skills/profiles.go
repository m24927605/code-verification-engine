package skills

// Profile defines a skill inference profile with its signal definitions.
type Profile struct {
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Signals     []SignalDefinition `json:"signals"`
}

var builtinProfiles = map[string]Profile{
	"github-engineer-core": {
		Name:        "github-engineer-core",
		Description: "Core engineering skill signals derived from repository evidence",
		Signals: []SignalDefinition{
			{ID: "backend_auth.jwt_middleware", SkillID: "backend_auth.jwt_middleware", Category: CategoryImplementation, Message: "JWT middleware implementation evidence"},
			{ID: "backend_routing.middleware_binding", SkillID: "backend_routing.middleware_binding", Category: CategoryImplementation, Message: "Route-level middleware binding evidence"},
			{ID: "backend_security.secret_hygiene", SkillID: "backend_security.secret_hygiene", Category: CategoryHygiene, Message: "Secret management hygiene evidence"},
			{ID: "backend_architecture.db_layering", SkillID: "backend_architecture.db_layering", Category: CategoryImplementation, Message: "Database access layering evidence"},
			{ID: "backend_runtime.error_handling", SkillID: "backend_runtime.error_handling", Category: CategoryImplementation, Message: "Global error handling evidence"},
			{ID: "backend_runtime.graceful_shutdown", SkillID: "backend_runtime.graceful_shutdown", Category: CategoryImplementation, Message: "Graceful shutdown implementation evidence"},
			{ID: "frontend_security.xss_sensitive_api_usage", SkillID: "frontend_security.xss_sensitive_api_usage", Category: CategoryRiskExposure, Message: "Contact with XSS-sensitive APIs"},
			{ID: "frontend_auth.route_guarding", SkillID: "frontend_auth.route_guarding", Category: CategoryImplementation, Message: "Frontend route protection evidence"},
			{ID: "testing.auth_module_tests", SkillID: "testing.auth_module_tests", Category: CategoryImplementation, Message: "Auth module testing evidence"},
			{ID: "observability.request_logging", SkillID: "observability.request_logging", Category: CategoryImplementation, Message: "Request logging implementation evidence"},
		},
	},
}

// AllProfiles returns all built-in skill profiles.
func AllProfiles() map[string]Profile {
	return builtinProfiles
}

// GetProfile returns a profile by name.
func GetProfile(name string) (*Profile, bool) {
	p, ok := builtinProfiles[name]
	if !ok {
		return nil, false
	}
	return &p, true
}

// ListProfileNames returns all available profile names.
func ListProfileNames() []string {
	names := make([]string, 0, len(builtinProfiles))
	for name := range builtinProfiles {
		names = append(names, name)
	}
	return names
}

// ValidateProfileName returns true if the profile name exists.
func ValidateProfileName(name string) bool {
	_, ok := builtinProfiles[name]
	return ok
}
