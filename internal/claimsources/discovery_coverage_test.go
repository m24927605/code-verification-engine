package claimsources

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/repo"
)

func TestDiscoverFromRepo_NilMeta(t *testing.T) {
	result := DiscoverFromRepo(nil)
	if result != nil {
		t.Fatalf("expected nil for nil meta, got %v", result)
	}
}

func TestDiscoverFromRepo_ValidMeta(t *testing.T) {
	root := t.TempDir()
	writeClaimsourceFixture(t, root)
	meta := &repo.RepoMetadata{
		RepoPath:  root,
		CommitSHA: "abc123",
		Files:     []string{"README.md", "internal/service.go"},
	}
	result := DiscoverFromRepo(meta)
	if len(result) != 2 {
		t.Fatalf("expected 2 descriptors, got %d", len(result))
	}
}

func TestClassifySource_AllCodeExtensions(t *testing.T) {
	tests := []struct {
		path     string
		wantType SourceType
		wantLang string
	}{
		{"src/main.go", SourceTypeCode, "go"},
		{"src/app.js", SourceTypeCode, "javascript"},
		{"src/app.jsx", SourceTypeCode, "javascript"},
		{"src/app.ts", SourceTypeCode, "typescript"},
		{"src/app.tsx", SourceTypeCode, "typescript"},
		{"src/app.py", SourceTypeCode, "python"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			desc, ok := classifySource(tt.path)
			if !ok {
				t.Fatal("expected classification")
			}
			if desc.SourceType != tt.wantType {
				t.Fatalf("got type %s, want %s", desc.SourceType, tt.wantType)
			}
			if desc.Language != tt.wantLang {
				t.Fatalf("got lang %s, want %s", desc.Language, tt.wantLang)
			}
		})
	}
}

func TestClassifySource_UnsupportedExtension(t *testing.T) {
	_, ok := classifySource("src/image.png")
	if ok {
		t.Fatal("expected false for unsupported extension")
	}
}

func TestIsEvalPath_AllBranches(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"eval/data.json", true},
		{"evals/data.json", true},
		{"benchmark/data.json", true},
		{"benchmarks/data.json", true},
		{"adversarial/data.json", true},
		{"calibration/data.json", true},
		{"src/eval/data.json", true},
		{"src/evals/data.json", true},
		{"src/benchmark/data.json", true},
		{"src/benchmarks/data.json", true},
		{"src/adversarial/data.json", true},
		{"src/calibration/data.json", true},
		{"eval.json", true},
		{"eval-suite.json", true},
		{"benchmark.json", true},
		{"benchmark-v2.json", true},
		{"adversarial.json", true},
		{"adversarial-test.json", true},
		{"calibration.json", true},
		{"calibration-set.json", true},
		{"random/data.json", false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			lower := tt.path
			base := tt.path
			if i := len(tt.path) - 1; i >= 0 {
				for j := i; j >= 0; j-- {
					if tt.path[j] == '/' {
						base = tt.path[j+1:]
						break
					}
				}
			}
			got := isEvalPath(lower, base)
			if got != tt.want {
				t.Fatalf("isEvalPath(%q, %q) = %v, want %v", lower, base, got, tt.want)
			}
		})
	}
}

func TestIsTestPath_AllBranches(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"foo_test.go", true},
		{"foo_test.py", true},
		{"foo.test.ts", true},
		{"foo.test.js", true},
		{"foo.test.tsx", true},
		{"foo.test.jsx", true},
		{"foo.spec.ts", true},
		{"foo.spec.js", true},
		{"foo.spec.tsx", true},
		{"foo.spec.jsx", true},
		{"tests/helper.go", true},
		{"test/helper.go", true},
		{"src/tests/helper.go", true},
		{"src/test/helper.go", true},
		{"test_helper.py", true},
		{"src/main.go", false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			lower := tt.path
			base := tt.path
			for j := len(tt.path) - 1; j >= 0; j-- {
				if tt.path[j] == '/' {
					base = tt.path[j+1:]
					break
				}
			}
			got := isTestPath(lower, base)
			if got != tt.want {
				t.Fatalf("isTestPath(%q, %q) = %v, want %v", lower, base, got, tt.want)
			}
		})
	}
}

func TestIsDocPath_AllBranches(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"docs/guide.md", true},
		{"adr/0001.md", true},
		{"src/docs/ref.md", true},
		{"src/adr/0001.md", true},
		{"architecture.md", true},
		{"design.md", true},
		{"spec.md", true},
		{"guide.md", true},
		{"runbook.md", true},
		{"security.md", true},
		{"ops.md", true},
		{"operational.md", true},
		{"adr-0001.md", true},
		{"architecture.txt", true},
		{"design.rst", true},
		{"spec.mdx", true},
		{"random.go", false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			lower := tt.path
			base := tt.path
			for j := len(tt.path) - 1; j >= 0; j-- {
				if tt.path[j] == '/' {
					base = tt.path[j+1:]
					break
				}
			}
			got := isDocPath(lower, base)
			if got != tt.want {
				t.Fatalf("isDocPath(%q, %q) = %v, want %v", lower, base, got, tt.want)
			}
		})
	}
}

func TestTestRoleForPath_AllBranches(t *testing.T) {
	tests := []struct {
		lower string
		want  string
	}{
		{"src/security_test.go", "security_test"},
		{"src/auth_test.go", "security_test"},
		{"src/integration_test.go", "integration_test"},
		{"src/e2e_test.go", "integration_test"},
		{"src/acceptance_test.go", "integration_test"},
		{"src/regression_test.go", "integration_test"},
		{"src/unit_test.go", "unit_test"},
	}
	for _, tt := range tests {
		t.Run(tt.lower, func(t *testing.T) {
			got := testRoleForPath(tt.lower, "")
			if got != tt.want {
				t.Fatalf("testRoleForPath(%q) = %q, want %q", tt.lower, got, tt.want)
			}
		})
	}
}

func TestDocRoleForPath_AllBranches(t *testing.T) {
	tests := []struct {
		lower string
		base  string
		want  string
	}{
		{"docs/adr/0001.md", "0001.md", "adr"},
		{"adr-0001.md", "adr-0001.md", "adr"},
		{"docs/architecture.md", "architecture.md", "architecture_doc"},
		{"docs/security.md", "security.md", "security_doc"},
		{"docs/design.md", "design.md", "design_doc"},
		{"docs/ops.md", "ops.md", "operational_doc"},
		{"docs/operational.md", "operational.md", "operational_doc"},
		{"docs/runbook.md", "runbook.md", "operational_doc"},
		{"docs/random.md", "random.md", "doc_section"},
	}
	for _, tt := range tests {
		t.Run(tt.lower, func(t *testing.T) {
			got := docRoleForPath(tt.lower, tt.base)
			if got != tt.want {
				t.Fatalf("docRoleForPath(%q, %q) = %q, want %q", tt.lower, tt.base, got, tt.want)
			}
		})
	}
}

func TestCodeRoleForPath_AllBranches(t *testing.T) {
	tests := []struct {
		lower string
		want  string
	}{
		{"src/agent/main.go", "agent_module"},
		{"src/pipeline/run.go", "pipeline"},
		{"src/service/api.go", "service"},
		{"src/route/handler.go", "route"},
		{"src/handler/api.go", "route"},
		{"src/controller/api.go", "route"},
		{"src/utils/helpers.go", "module"},
	}
	for _, tt := range tests {
		t.Run(tt.lower, func(t *testing.T) {
			got := codeRoleForPath(tt.lower, "")
			if got != tt.want {
				t.Fatalf("codeRoleForPath(%q) = %q, want %q", tt.lower, got, tt.want)
			}
		})
	}
}

func TestLanguageForPath_AllBranches(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"main.go", "go"},
		{"app.js", "javascript"},
		{"app.jsx", "javascript"},
		{"app.ts", "typescript"},
		{"app.tsx", "typescript"},
		{"app.py", "python"},
		{"doc.md", "markdown"},
		{"doc.mdx", "markdown"},
		{"data.json", "json"},
		{"config.yaml", "yaml"},
		{"config.yml", "yaml"},
		{"notes.txt", "text"},
		{"binary.dat", "text"},
		// No extension cases
		{"readme", "markdown"},
		{"src/docs/something", "markdown"},
		{"src/adr/decision", "markdown"},
		{"architecture", "markdown"},
		{"random_no_ext", "text"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := languageForPath(tt.path)
			if got != tt.want {
				t.Fatalf("languageForPath(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestSourceTypeRank_DefaultCase(t *testing.T) {
	got := sourceTypeRank(SourceType("unknown"))
	if got != 99 {
		t.Fatalf("expected 99 for unknown type, got %d", got)
	}
}

func TestDiscoverEmpty(t *testing.T) {
	result := Discover(Snapshot{Files: nil})
	if len(result) != 0 {
		t.Fatalf("expected 0 descriptors for empty files, got %d", len(result))
	}
}

func TestDiscoverSortingStability(t *testing.T) {
	// Test that descriptors with same SourceType and Path but different Role are sorted correctly
	files := []string{
		"src/agent/service.go",
		"src/pipeline/service.go",
	}
	result := Discover(Snapshot{Files: files})
	if len(result) != 2 {
		t.Fatalf("expected 2 descriptors, got %d", len(result))
	}
	// Both are code type, sorted by path
	if result[0].Path >= result[1].Path {
		t.Fatalf("expected paths sorted: %q >= %q", result[0].Path, result[1].Path)
	}
}
