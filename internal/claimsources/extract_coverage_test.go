package claimsources

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/verabase/code-verification-engine/internal/repo"
)

func TestExtractFromRepo_NilMeta(t *testing.T) {
	result := ExtractFromRepo(nil, nil)
	if result != nil {
		t.Fatalf("expected nil for nil meta, got %v", result)
	}
}

func TestExtractFromRepo_ValidMeta(t *testing.T) {
	root := t.TempDir()
	writeClaimsourceFixture(t, root)
	meta := &repo.RepoMetadata{
		RepoPath:  root,
		CommitSHA: "abc123",
		Files:     []string{"README.md", "internal/service.go"},
	}
	descriptors := DiscoverFromRepo(meta)
	records := ExtractFromRepo(meta, descriptors)
	if len(records) == 0 {
		t.Fatal("expected non-empty records")
	}
}

func TestExtract_EmptyDescriptors(t *testing.T) {
	result := Extract(Snapshot{}, nil)
	if result != nil {
		t.Fatalf("expected nil for empty descriptors, got %v", result)
	}
}

func TestExtract_UnreadableFile(t *testing.T) {
	// Descriptors with a non-existent file path should be skipped
	snap := Snapshot{RepoPath: "/nonexistent/repo"}
	descriptors := []SourceDescriptor{
		{SourceType: SourceTypeCode, Path: "missing.go", Language: "go", Role: "module"},
	}
	result := Extract(snap, descriptors)
	if len(result) != 0 {
		t.Fatalf("expected 0 records for unreadable file, got %d", len(result))
	}
}

func TestExtract_AbsolutePath(t *testing.T) {
	root := t.TempDir()
	absPath := filepath.Join(root, "test.go")
	if err := os.WriteFile(absPath, []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	snap := Snapshot{RepoPath: root}
	descriptors := []SourceDescriptor{
		{SourceType: SourceTypeCode, Path: absPath, Language: "go", Role: "module"},
	}
	result := Extract(snap, descriptors)
	if len(result) != 1 {
		t.Fatalf("expected 1 record for absolute path, got %d", len(result))
	}
}

func TestTargetModuleFromTestPath(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"internal/service_test.go", "internal/service.go"},
		{"internal/service_test.py", "internal/service.py"},
		{"src/app.test.ts", "src/app.ts"},
		{"src/app.spec.js", "src/app.js"},
		{"src/unknown.txt", "src/unknown.txt"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := targetModuleFromTestPath(tt.input)
			if got != tt.want {
				t.Fatalf("targetModuleFromTestPath(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestEvalPurpose_AllBranches(t *testing.T) {
	tests := []struct {
		content     string
		path        string
		wantPurpose string
		wantAdv     bool
	}{
		{"adversarial test", "data.json", "adversarial", true},
		{"calibration data", "data.json", "calibration", false},
		{"benchmark suite", "data.json", "benchmark", false},
		{"some data", "data.json", "evaluation", false},
	}
	for _, tt := range tests {
		t.Run(tt.wantPurpose, func(t *testing.T) {
			purpose, adv := evalPurpose(tt.content, tt.path)
			if purpose != tt.wantPurpose {
				t.Fatalf("evalPurpose(%q) purpose = %q, want %q", tt.content, purpose, tt.wantPurpose)
			}
			if adv != tt.wantAdv {
				t.Fatalf("evalPurpose(%q) adversarial = %v, want %v", tt.content, adv, tt.wantAdv)
			}
		})
	}
}

func TestBoundedText(t *testing.T) {
	tests := []struct {
		name  string
		input string
		limit int
		want  string
	}{
		{"under limit", "hello", 10, "hello"},
		{"at limit", "hello", 5, "hello"},
		{"over limit", "hello world", 5, "hello"},
		{"zero limit", "hello", 0, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := boundedText(tt.input, tt.limit)
			if got != tt.want {
				t.Fatalf("boundedText(%q, %d) = %q, want %q", tt.input, tt.limit, got, tt.want)
			}
		})
	}
}

func TestBoundedSummary(t *testing.T) {
	tests := []struct {
		name     string
		title    string
		fragment string
		wantSub  string
	}{
		{"both present", "Title", "Fragment", "Title: Fragment"},
		{"title only", "Title", "", "Title"},
		{"fragment only", "", "Fragment", "Fragment"},
		{"both empty", "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := boundedSummary(tt.title, tt.fragment)
			if got != tt.wantSub {
				t.Fatalf("boundedSummary(%q, %q) = %q, want %q", tt.title, tt.fragment, got, tt.wantSub)
			}
		})
	}
}

func TestMaxInt(t *testing.T) {
	tests := []struct {
		a, b, want int
	}{
		{1, 2, 2},
		{3, 1, 3},
		{5, 5, 5},
	}
	for _, tt := range tests {
		got := maxInt(tt.a, tt.b)
		if got != tt.want {
			t.Fatalf("maxInt(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestLimitList(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		limit int
		want  int
	}{
		{"under limit", []string{"a", "b"}, 5, 2},
		{"at limit", []string{"a", "b"}, 2, 2},
		{"over limit", []string{"a", "b", "c"}, 2, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := limitList(tt.input, tt.limit)
			if len(got) != tt.want {
				t.Fatalf("limitList(..., %d) returned %d items, want %d", tt.limit, len(got), tt.want)
			}
		})
	}
}

func TestDedupeSorted(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  int
	}{
		{"empty", nil, 0},
		{"no dupes", []string{"a", "b", "c"}, 3},
		{"with dupes", []string{"a", "b", "a", "c"}, 3},
		{"blank entries", []string{"a", "", " ", "b"}, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dedupeSorted(tt.input)
			if len(got) != tt.want {
				t.Fatalf("dedupeSorted(%v) returned %d items, want %d", tt.input, len(got), tt.want)
			}
		})
	}
}

func TestExtractSymbols_Python(t *testing.T) {
	lines := []string{
		"def my_func(arg):",
		"    pass",
		"class MyClass:",
		"    pass",
	}
	got := extractSymbols("python", lines)
	if !containsString(got, "my_func") {
		t.Fatalf("expected my_func in symbols: %v", got)
	}
	if !containsString(got, "MyClass") {
		t.Fatalf("expected MyClass in symbols: %v", got)
	}
}

func TestExtractSymbols_JavaScript(t *testing.T) {
	lines := []string{
		"export function myFunc() {}",
		"export class MyClass {}",
		"export const MY_CONST = 42",
	}
	got := extractSymbols("javascript", lines)
	if !containsString(got, "myFunc") {
		t.Fatalf("expected myFunc in symbols: %v", got)
	}
	if !containsString(got, "MyClass") {
		t.Fatalf("expected MyClass in symbols: %v", got)
	}
	if !containsString(got, "MY_CONST") {
		t.Fatalf("expected MY_CONST in symbols: %v", got)
	}
}

func TestExtractSymbols_UnknownLanguage(t *testing.T) {
	lines := []string{"some content"}
	got := extractSymbols("rust", lines)
	if len(got) != 0 {
		t.Fatalf("expected empty symbols for unknown language, got %v", got)
	}
}

func TestExtractTestNames_Python(t *testing.T) {
	lines := []string{
		"def test_something():",
		"    pass",
		"def test_another():",
		"    pass",
	}
	got := extractTestNames("python", lines)
	if len(got) != 2 {
		t.Fatalf("expected 2 test names, got %d: %v", len(got), got)
	}
}

func TestExtractTestNames_JavaScript(t *testing.T) {
	lines := []string{
		`describe("MyModule", () => {`,
		`  it("should work", () => {`,
		`  test("another test", () => {`,
	}
	got := extractTestNames("javascript", lines)
	if len(got) != 3 {
		t.Fatalf("expected 3 test names, got %d: %v", len(got), got)
	}
}

func TestExtractTestNames_UnknownLanguage(t *testing.T) {
	lines := []string{"some content"}
	got := extractTestNames("rust", lines)
	if len(got) != 0 {
		t.Fatalf("expected empty test names for unknown language, got %v", got)
	}
}

func TestExtractCodeEvidence_NoSymbols(t *testing.T) {
	root := t.TempDir()
	codePath := filepath.Join(root, "empty.go")
	if err := os.WriteFile(codePath, []byte("package main\n// just a comment\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	desc := SourceDescriptor{
		SourceType: SourceTypeCode,
		Path:       "empty.go",
		Language:   "go",
		Role:       "module",
	}
	snap := Snapshot{RepoPath: root}
	records := Extract(snap, []SourceDescriptor{desc})
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	// When no symbols are found, the path is used as the entity ID
	if !containsString(records[0].EntityIDs, "empty.go") {
		t.Fatalf("expected path as entity ID, got %v", records[0].EntityIDs)
	}
}

func TestExtractTestEvidence_NoTestNames(t *testing.T) {
	root := t.TempDir()
	testPath := filepath.Join(root, "empty_test.go")
	if err := os.WriteFile(testPath, []byte("package main\n// no tests\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	desc := SourceDescriptor{
		SourceType: SourceTypeTest,
		Path:       "empty_test.go",
		Language:   "go",
		Role:       "unit_test",
	}
	snap := Snapshot{RepoPath: root}
	records := Extract(snap, []SourceDescriptor{desc})
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	// When no test names are found, the path is used
	if !containsString(records[0].EntityIDs, "empty_test.go") {
		t.Fatalf("expected path as entity ID, got %v", records[0].EntityIDs)
	}
}

func TestDefaultMarkdownTitle(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"README.md", "README"},
		{"docs/guide.txt", "guide"},
		{".md", "document"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := defaultMarkdownTitle(tt.path)
			if got != tt.want {
				t.Fatalf("defaultMarkdownTitle(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestSplitMarkdownSections_NoHeadings(t *testing.T) {
	lines := []string{"just some text", "and more text"}
	sections := splitMarkdownSections(lines, "doc.md")
	if len(sections) != 1 {
		t.Fatalf("expected 1 section for no headings, got %d", len(sections))
	}
	if sections[0].Title != "doc" {
		t.Fatalf("expected title 'doc', got %q", sections[0].Title)
	}
}

func TestSplitMarkdownSections_MultipleHeadings(t *testing.T) {
	lines := []string{
		"# First",
		"content1",
		"## Second",
		"content2",
	}
	sections := splitMarkdownSections(lines, "test.md")
	if len(sections) != 2 {
		t.Fatalf("expected 2 sections, got %d", len(sections))
	}
	if sections[0].Title != "First" {
		t.Fatalf("expected first section title 'First', got %q", sections[0].Title)
	}
	if sections[1].Title != "Second" {
		t.Fatalf("expected second section title 'Second', got %q", sections[1].Title)
	}
}

func TestFirstNonEmptyFragment_EdgeCases(t *testing.T) {
	tests := []struct {
		name  string
		lines []string
		start int
		end   int
	}{
		{"negative start", []string{"a", "b"}, -5, 2},
		{"end beyond len", []string{"a", "b"}, 0, 100},
		{"end before start", []string{"a", "b"}, 5, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			_ = firstNonEmptyFragment(tt.lines, tt.start, tt.end)
		})
	}
}

func TestCanonicalMetadata_Empty(t *testing.T) {
	got := canonicalMetadata(nil)
	if got != "" {
		t.Fatalf("expected empty string for nil metadata, got %q", got)
	}
}

func TestSlug(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Hello World!", "hello-world"},
		{"foo/bar.go", "foo-bar-go"},
		{"  spaces  ", "spaces"},
		{"ABC123", "abc123"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := slug(tt.input)
			if got != tt.want {
				t.Fatalf("slug(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeWhitespace(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"  hello   world  ", "hello world"},
		{"line1\r\nline2\rline3", "line1 line2 line3"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeWhitespace(tt.input)
			if got != tt.want {
				t.Fatalf("normalizeWhitespace(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeLineEndings(t *testing.T) {
	got := normalizeLineEndings("a\r\nb\rc")
	if got != "a\nb\nc" {
		t.Fatalf("normalizeLineEndings result = %q, want %q", got, "a\nb\nc")
	}
}

func TestMarkdownEvidenceKind(t *testing.T) {
	if markdownEvidenceKind(SourceTypeReadme) != "readme_section" {
		t.Fatal("expected readme_section for SourceTypeReadme")
	}
	if markdownEvidenceKind(SourceTypeDoc) != "doc_section" {
		t.Fatal("expected doc_section for SourceTypeDoc")
	}
}

func TestExtractSortingBySpans(t *testing.T) {
	root := t.TempDir()
	// Create a markdown file with multiple headings to test span-based sorting
	mdContent := "# Section A\nContent A\n# Section B\nContent B\n"
	mdPath := filepath.Join(root, "doc.md")
	if err := os.WriteFile(mdPath, []byte(mdContent), 0o644); err != nil {
		t.Fatal(err)
	}
	snap := Snapshot{RepoPath: root}
	descriptors := []SourceDescriptor{
		{SourceType: SourceTypeDoc, Path: "doc.md", Language: "markdown", Role: "doc_section"},
	}
	records := Extract(snap, descriptors)
	if len(records) < 2 {
		t.Fatalf("expected at least 2 records, got %d", len(records))
	}
	// Verify sorted by StartLine
	for i := 1; i < len(records); i++ {
		if len(records[i-1].Spans) > 0 && len(records[i].Spans) > 0 {
			if records[i-1].Spans[0].StartLine > records[i].Spans[0].StartLine {
				t.Fatalf("records not sorted by StartLine: %d > %d",
					records[i-1].Spans[0].StartLine, records[i].Spans[0].StartLine)
			}
		}
	}
}

func TestExtract_EvalEvidence(t *testing.T) {
	root := t.TempDir()
	evalDir := filepath.Join(root, "eval")
	if err := os.MkdirAll(evalDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Test calibration eval
	calibPath := filepath.Join(evalDir, "calibration-set.json")
	if err := os.WriteFile(calibPath, []byte(`{"purpose":"calibration"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// Test benchmark eval
	benchPath := filepath.Join(evalDir, "benchmark-v2.json")
	if err := os.WriteFile(benchPath, []byte(`{"purpose":"benchmark"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// Test generic eval
	genericPath := filepath.Join(evalDir, "eval-generic.json")
	if err := os.WriteFile(genericPath, []byte(`{"purpose":"testing"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	snap := Snapshot{RepoPath: root}
	descriptors := []SourceDescriptor{
		{SourceType: SourceTypeEval, Path: "eval/calibration-set.json", Language: "json", Role: "eval_dataset"},
		{SourceType: SourceTypeEval, Path: "eval/benchmark-v2.json", Language: "json", Role: "eval_dataset"},
		{SourceType: SourceTypeEval, Path: "eval/eval-generic.json", Language: "json", Role: "eval_dataset"},
	}
	records := Extract(snap, descriptors)
	if len(records) != 3 {
		t.Fatalf("expected 3 eval records, got %d", len(records))
	}

	purposeMap := map[string]bool{}
	for _, rec := range records {
		purposeMap[rec.Metadata["benchmark_purpose"]] = true
	}
	if !purposeMap["calibration"] {
		t.Fatal("expected calibration purpose")
	}
	if !purposeMap["benchmark"] {
		t.Fatal("expected benchmark purpose")
	}
	if !purposeMap["evaluation"] {
		t.Fatal("expected evaluation purpose")
	}
}

func TestExtract_TypeScriptTestEvidence(t *testing.T) {
	root := t.TempDir()
	testContent := `describe("MyModule", () => {
  it("should work", () => {});
  test("another test", () => {});
});
`
	testPath := filepath.Join(root, "app.test.ts")
	if err := os.WriteFile(testPath, []byte(testContent), 0o644); err != nil {
		t.Fatal(err)
	}
	snap := Snapshot{RepoPath: root}
	descriptors := []SourceDescriptor{
		{SourceType: SourceTypeTest, Path: "app.test.ts", Language: "typescript", Role: "unit_test"},
	}
	records := Extract(snap, descriptors)
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if len(records[0].EntityIDs) < 3 {
		t.Fatalf("expected at least 3 test names, got %d: %v", len(records[0].EntityIDs), records[0].EntityIDs)
	}
}

func TestExtract_PythonCodeEvidence(t *testing.T) {
	root := t.TempDir()
	pyContent := `def my_func(arg):
    pass

class MyClass:
    pass
`
	pyPath := filepath.Join(root, "module.py")
	if err := os.WriteFile(pyPath, []byte(pyContent), 0o644); err != nil {
		t.Fatal(err)
	}
	snap := Snapshot{RepoPath: root}
	descriptors := []SourceDescriptor{
		{SourceType: SourceTypeCode, Path: "module.py", Language: "python", Role: "module"},
	}
	records := Extract(snap, descriptors)
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if !containsString(records[0].EntityIDs, "my_func") {
		t.Fatalf("expected my_func in entity IDs: %v", records[0].EntityIDs)
	}
	if !containsString(records[0].EntityIDs, "MyClass") {
		t.Fatalf("expected MyClass in entity IDs: %v", records[0].EntityIDs)
	}
}

func TestEvalDatasetID(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"eval/adversarial.json", "adversarial"},
		{"benchmark-v2.yaml", "benchmark-v2"},
		{"data.csv", "data"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := evalDatasetID(tt.path)
			if got != tt.want {
				t.Fatalf("evalDatasetID(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestParseMarkdownHeading(t *testing.T) {
	tests := []struct {
		line      string
		wantTitle string
		wantLevel int
		wantOk    bool
	}{
		{"# Title", "Title", 1, true},
		{"## Sub Title", "Sub Title", 2, true},
		{"###### Deep", "Deep", 6, true},
		{"not a heading", "", 0, false},
		{"##no space", "", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			title, level, ok := parseMarkdownHeading(tt.line)
			if ok != tt.wantOk {
				t.Fatalf("parseMarkdownHeading(%q) ok = %v, want %v", tt.line, ok, tt.wantOk)
			}
			if ok {
				if title != tt.wantTitle {
					t.Fatalf("title = %q, want %q", title, tt.wantTitle)
				}
				if level != tt.wantLevel {
					t.Fatalf("level = %d, want %d", level, tt.wantLevel)
				}
			}
		})
	}
}
