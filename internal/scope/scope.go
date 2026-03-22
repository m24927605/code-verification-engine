package scope

import "strings"

// FileScope classifies a file path into a scope category.
type FileScope string

const (
	ScopeProduction FileScope = "production"
	ScopeTest       FileScope = "test"
	ScopeFixture    FileScope = "fixture"
	ScopeGenerated  FileScope = "generated"
)

// Classify returns the scope of a file based on its path.
func Classify(path string) FileScope {
	lower := strings.ToLower(path)

	// Fixture/mock scope (check before test — fixtures inside test dirs are fixtures)
	if isFixturePath(lower) {
		return ScopeFixture
	}

	// Generated code
	if isGeneratedPath(lower) {
		return ScopeGenerated
	}

	// Test scope
	if IsTestPath(lower) {
		return ScopeTest
	}

	return ScopeProduction
}

// IsTestPath returns true if the lowercased path indicates a test file.
func IsTestPath(path string) bool {
	lower := strings.ToLower(path)
	return strings.Contains(lower, "__tests__/") ||
		strings.Contains(lower, "/test/") ||
		strings.Contains(lower, "/tests/") ||
		strings.HasSuffix(lower, ".spec.ts") ||
		strings.HasSuffix(lower, ".spec.js") ||
		strings.HasSuffix(lower, ".spec.tsx") ||
		strings.HasSuffix(lower, ".spec.jsx") ||
		strings.HasSuffix(lower, ".test.ts") ||
		strings.HasSuffix(lower, ".test.js") ||
		strings.HasSuffix(lower, ".test.tsx") ||
		strings.HasSuffix(lower, ".test.jsx") ||
		strings.HasSuffix(lower, ".test.py") ||
		strings.HasSuffix(lower, "_test.go") ||
		strings.HasSuffix(lower, "_test.py") ||
		strings.HasPrefix(lower, "test_") ||
		containsSegment(lower, "test") ||
		containsSegment(lower, "tests") ||
		containsSegment(lower, "__tests__") ||
		strings.Contains(lower, ".spec.") ||
		strings.Contains(lower, ".test.")
}

// IsTestOrFixturePath returns true if the path is test, fixture, or mock scope.
func IsTestOrFixturePath(path string) bool {
	s := Classify(path)
	return s == ScopeTest || s == ScopeFixture
}

// IsProductionPath returns true if the path is production scope.
func IsProductionPath(path string) bool {
	return Classify(path) == ScopeProduction
}

func isFixturePath(lower string) bool {
	return strings.Contains(lower, "/fixtures/") ||
		strings.Contains(lower, "/__fixtures__/") ||
		strings.Contains(lower, "/__mocks__/") ||
		strings.Contains(lower, "/mocks/") ||
		strings.Contains(lower, "/mock/") ||
		containsSegment(lower, "fixtures") ||
		containsSegment(lower, "__fixtures__") ||
		containsSegment(lower, "__mocks__") ||
		containsSegment(lower, "mocks") ||
		strings.Contains(lower, "/fake") ||
		strings.Contains(lower, "/seed")
}

func isGeneratedPath(lower string) bool {
	return strings.Contains(lower, "/generated/") ||
		strings.Contains(lower, "/gen/") ||
		containsSegment(lower, "generated")
}

// containsSegment checks if a path contains a directory segment.
func containsSegment(path, segment string) bool {
	// Check start
	if strings.HasPrefix(path, segment+"/") {
		return true
	}
	return strings.Contains(path, "/"+segment+"/")
}
