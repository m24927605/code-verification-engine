package claimsources

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func writeClaimsourceFixture(t *testing.T, root string) {
	t.Helper()
	files := map[string]string{
		"README.md": `# Engine

Evidence-backed capability summary.

## Pipeline
Deterministic verification path.
`,
		"docs/architecture.md": `# Architecture

The planner and executor are separated.
`,
		"docs/adr/0001.md": `# ADR

We choose deterministic pre-checks before escalation.
`,
		"internal/service.go": `package internal

type Service struct{}

func NewService() *Service { return &Service{} }
`,
		"internal/service_test.go": `package internal

func TestService(t *testing.T) {}
`,
		"eval/adversarial.json": `{"benchmark":"adversarial evaluation","purpose":"quality gate"}`,
	}
	for path, content := range files {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDiscoverDeterministicAndTyped(t *testing.T) {
	root := t.TempDir()
	writeClaimsourceFixture(t, root)

	filesA := []string{
		"README.md",
		"docs/architecture.md",
		"docs/adr/0001.md",
		"internal/service.go",
		"internal/service_test.go",
		"eval/adversarial.json",
	}
	filesB := []string{
		"eval/adversarial.json",
		"internal/service_test.go",
		"internal/service.go",
		"docs/adr/0001.md",
		"docs/architecture.md",
		"README.md",
	}

	first := Discover(Snapshot{RepoPath: root, CommitSHA: "abc123", Files: filesA})
	second := Discover(Snapshot{RepoPath: root, CommitSHA: "abc123", Files: filesB})

	if !reflect.DeepEqual(first, second) {
		t.Fatalf("discovery not deterministic:\nfirst=%#v\nsecond=%#v", first, second)
	}

	wantTypes := map[SourceType]bool{
		SourceTypeReadme: false,
		SourceTypeDoc:    false,
		SourceTypeCode:   false,
		SourceTypeTest:   false,
		SourceTypeEval:   false,
	}

	for _, desc := range first {
		if desc.SourceID == "" {
			t.Fatalf("descriptor for %s has empty source_id", desc.Path)
		}
		if !desc.IncludedInBoundary {
			t.Fatalf("descriptor for %s should be in boundary", desc.Path)
		}
		wantTypes[desc.SourceType] = true
	}

	for typ, ok := range wantTypes {
		if !ok {
			t.Fatalf("expected source type %s to be discovered", typ)
		}
	}

	// Check the conservative roles are assigned as expected.
	roleByType := map[SourceType]string{}
	for _, desc := range first {
		roleByType[desc.SourceType] = desc.Role
	}
	if roleByType[SourceTypeReadme] != "overview_readme" {
		t.Fatalf("readme role = %q, want overview_readme", roleByType[SourceTypeReadme])
	}
	if roleByType[SourceTypeDoc] == "" {
		t.Fatal("doc role should not be empty")
	}
	if roleByType[SourceTypeCode] != "service" {
		t.Fatalf("code role = %q, want service", roleByType[SourceTypeCode])
	}
	if roleByType[SourceTypeTest] != "unit_test" {
		t.Fatalf("test role = %q, want unit_test", roleByType[SourceTypeTest])
	}
	if roleByType[SourceTypeEval] != "eval_dataset" {
		t.Fatalf("eval role = %q, want eval_dataset", roleByType[SourceTypeEval])
	}
}

func TestDiscoverGracefulWithoutOptionalSources(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"internal/service.go": `package internal

func Service() {}
`,
		"internal/service_test.go": `package internal

func TestService(t *testing.T) {}
`,
	}
	for path, content := range files {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	descriptors := Discover(Snapshot{
		RepoPath:  root,
		CommitSHA: "abc123",
		Files:     []string{"internal/service.go", "internal/service_test.go"},
	})
	if len(descriptors) != 2 {
		t.Fatalf("expected 2 descriptors, got %d: %#v", len(descriptors), descriptors)
	}
	for _, desc := range descriptors {
		if desc.SourceType != SourceTypeCode && desc.SourceType != SourceTypeTest {
			t.Fatalf("unexpected source type %s for %s", desc.SourceType, desc.Path)
		}
	}
}
