package scope

import "testing"

func TestClassify_Production(t *testing.T) {
	cases := []string{
		"src/auth/auth.service.ts",
		"main.ts",
		"lib/utils.go",
		"billing/billing.controller.ts",
		"config/env.ts",
	}
	for _, path := range cases {
		if got := Classify(path); got != ScopeProduction {
			t.Errorf("Classify(%q) = %q, want production", path, got)
		}
	}
}

func TestClassify_Test(t *testing.T) {
	cases := []string{
		"__tests__/auth.spec.ts",
		"src/__tests__/billing.test.ts",
		"test/integration/api.test.ts",
		"tests/unit/service.spec.js",
		"auth.spec.ts",
		"billing.test.js",
		"internal/rules/types_test.go",
		"test_utils.py",
	}
	for _, path := range cases {
		if got := Classify(path); got != ScopeTest {
			t.Errorf("Classify(%q) = %q, want test", path, got)
		}
	}
}

func TestClassify_Fixture(t *testing.T) {
	cases := []string{
		"test/fixtures/data.json",
		"__fixtures__/user.ts",
		"__mocks__/service.ts",
		"mocks/api.ts",
	}
	for _, path := range cases {
		if got := Classify(path); got != ScopeFixture {
			t.Errorf("Classify(%q) = %q, want fixture", path, got)
		}
	}
}

func TestClassify_Generated(t *testing.T) {
	cases := []string{
		"generated/prisma-client.ts",
		"src/generated/types.ts",
	}
	for _, path := range cases {
		if got := Classify(path); got != ScopeGenerated {
			t.Errorf("Classify(%q) = %q, want generated", path, got)
		}
	}
}

func TestIsTestOrFixturePath(t *testing.T) {
	if !IsTestOrFixturePath("__tests__/auth.spec.ts") {
		t.Error("expected test path to be test-or-fixture")
	}
	if !IsTestOrFixturePath("__mocks__/service.ts") {
		t.Error("expected mock path to be test-or-fixture")
	}
	if IsTestOrFixturePath("src/auth.service.ts") {
		t.Error("expected production path to NOT be test-or-fixture")
	}
}

func TestIsProductionPath(t *testing.T) {
	if !IsProductionPath("src/auth.service.ts") {
		t.Error("expected production path")
	}
	if IsProductionPath("__tests__/auth.spec.ts") {
		t.Error("expected NOT production path")
	}
}
