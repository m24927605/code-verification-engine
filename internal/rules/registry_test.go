package rules

import "testing"

func TestTargetRegistryContainsExpectedTargets(t *testing.T) {
	expected := []string{
		"auth.jwt_middleware",
		"auth.api_key_validation",
		"rate_limit.middleware",
		"layer.repository",
		"db.direct_access_from_controller",
		"route.protected_uses_auth_middleware",
		"route.public_without_auth",
		"module.payment_service",
		"module.auth_service",
		"secret.hardcoded_credential",
	}
	for _, target := range expected {
		if !IsValidTarget(target) {
			t.Errorf("expected target %q to be valid", target)
		}
	}
}

func TestTargetRegistryRejectsUnknownTarget(t *testing.T) {
	if IsValidTarget("unknown.nonexistent") {
		t.Error("expected unknown target to be invalid")
	}
}

func TestTargetRequiredFactTypes(t *testing.T) {
	factTypes := RequiredFactTypes("auth.jwt_middleware")
	if len(factTypes) == 0 {
		t.Error("expected auth.jwt_middleware to require fact types")
	}
}

func TestRequiredFactTypesUnknownTarget(t *testing.T) {
	factTypes := RequiredFactTypes("unknown.target")
	if factTypes != nil {
		t.Error("expected nil for unknown target")
	}
}

func TestAllTargets(t *testing.T) {
	targets := AllTargets()
	if len(targets) < 61 {
		t.Errorf("expected at least 61 targets, got %d", len(targets))
	}
}
