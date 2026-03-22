package repo_test

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/repo"
)

func containsLang(langs []string, lang string) bool {
	for _, l := range langs {
		if l == lang {
			return true
		}
	}
	return false
}

func TestDetectLanguagesGoOnly(t *testing.T) {
	files := []string{"main.go", "internal/auth/jwt.go", "go.mod", "README.md"}
	langs := repo.DetectLanguages(files)

	if !containsLang(langs, "go") {
		t.Fatal("expected go to be detected")
	}
	if containsLang(langs, "python") || containsLang(langs, "javascript") || containsLang(langs, "typescript") {
		t.Fatal("unexpected languages detected")
	}
}

func TestDetectLanguagesMultiple(t *testing.T) {
	files := []string{
		"main.go",
		"go.mod",
		"web/app.ts",
		"web/component.tsx",
		"scripts/setup.py",
		"scripts/util.js",
	}
	langs := repo.DetectLanguages(files)

	for _, expected := range []string{"go", "typescript", "python", "javascript"} {
		if !containsLang(langs, expected) {
			t.Fatalf("expected %s to be detected", expected)
		}
	}
}

func TestDetectLanguagesNoSource(t *testing.T) {
	files := []string{"README.md", "LICENSE", ".gitignore", "Makefile"}
	langs := repo.DetectLanguages(files)

	if len(langs) != 0 {
		t.Fatalf("expected no languages, got %v", langs)
	}
}

func TestDetectLanguagesManifestAloneNotSufficient(t *testing.T) {
	files := []string{"package.json", "README.md"}
	langs := repo.DetectLanguages(files)

	if containsLang(langs, "javascript") || containsLang(langs, "typescript") {
		t.Fatal("manifest alone should not activate language")
	}
}

func TestDetectLanguagesTsconfigWithoutTsFiles(t *testing.T) {
	files := []string{"tsconfig.json", "src/app.js"}
	langs := repo.DetectLanguages(files)

	if containsLang(langs, "typescript") {
		t.Fatal("tsconfig.json without .ts files should not activate TypeScript")
	}
	if !containsLang(langs, "javascript") {
		t.Fatal("expected javascript to be detected from .js files")
	}
}

func TestDetectLanguagesMonorepo(t *testing.T) {
	files := []string{
		"services/api/main.go",
		"services/api/handler.go",
		"services/web/index.ts",
		"services/web/app.tsx",
		"scripts/deploy.py",
		"package.json",
	}
	langs := repo.DetectLanguages(files)

	if !containsLang(langs, "go") {
		t.Fatal("expected go")
	}
	if !containsLang(langs, "typescript") {
		t.Fatal("expected typescript")
	}
	if !containsLang(langs, "python") {
		t.Fatal("expected python")
	}
}

func TestDetectLanguagesJSXisTreatedAsJavaScript(t *testing.T) {
	files := []string{"src/App.jsx", "src/index.js"}
	langs := repo.DetectLanguages(files)

	if !containsLang(langs, "javascript") {
		t.Fatal("expected javascript for .jsx files")
	}
	if containsLang(langs, "typescript") {
		t.Fatal(".jsx should not activate typescript")
	}
}

func TestDetectLanguagesTSXisTreatedAsTypeScript(t *testing.T) {
	files := []string{"src/App.tsx", "src/index.ts"}
	langs := repo.DetectLanguages(files)

	if !containsLang(langs, "typescript") {
		t.Fatal("expected typescript for .tsx files")
	}
}

func TestDetectLanguagesEmptyFiles(t *testing.T) {
	langs := repo.DetectLanguages(nil)
	if len(langs) != 0 {
		t.Fatalf("expected no languages for nil input, got %v", langs)
	}

	langs = repo.DetectLanguages([]string{})
	if len(langs) != 0 {
		t.Fatalf("expected no languages for empty input, got %v", langs)
	}
}

func TestDetectLanguagesSorted(t *testing.T) {
	files := []string{"a.py", "b.ts", "c.go", "d.js"}
	langs := repo.DetectLanguages(files)

	for i := 1; i < len(langs); i++ {
		if langs[i] < langs[i-1] {
			t.Fatalf("languages not sorted: %v", langs)
		}
	}
}
