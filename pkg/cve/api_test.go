package cve

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestNewEngine(t *testing.T) {
	e := NewEngine()
	if e == nil {
		t.Fatal("engine should not be nil")
	}
}

func TestListProfiles(t *testing.T) {
	e := NewEngine()
	profiles := e.ListProfiles()
	if len(profiles) == 0 {
		t.Error("should have at least one profile")
	}
	found := false
	for _, p := range profiles {
		if p.Name == "backend-api" {
			found = true
			if p.RuleCount == 0 {
				t.Error("backend-api should have rules")
			}
		}
	}
	if !found {
		t.Error("missing backend-api profile")
	}
}

func TestListClaimSets(t *testing.T) {
	e := NewEngine()
	sets := e.ListClaimSets()
	if len(sets) == 0 {
		t.Error("should have at least one claim set")
	}
}

func TestValidateProfile(t *testing.T) {
	e := NewEngine()
	if !e.ValidateProfile("backend-api") {
		t.Error("backend-api should be valid")
	}
	if e.ValidateProfile("nonexistent") {
		t.Error("nonexistent should be invalid")
	}
}

func TestGetAPIInfo(t *testing.T) {
	info := GetAPIInfo()
	if info.APIVersion == "" {
		t.Error("API version should not be empty")
	}
	if info.ScanSchemaVersion == "" {
		t.Error("scan schema version should not be empty")
	}
	if info.ClaimSchemaVersion == "" {
		t.Error("claim schema version should not be empty")
	}
}

func TestWithHookReceivesScanEvents(t *testing.T) {
	// Verify that hooks registered via WithHook actually fire.
	// We use an invalid repo so the pipeline fails after OnScanStart,
	// but the hook should still receive the scan_start event.
	var mu sync.Mutex
	var events []ScanEvent

	hook := func(ev ScanEvent) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, ev)
	}

	e := NewEngine(WithHook(hook))
	_, _ = e.Verify(context.Background(), VerifyInput{
		RepoPath:  "/nonexistent/repo-for-hook-test",
		Profile:   "backend-api",
		OutputDir: t.TempDir(),
		Format:    "json",
	})

	mu.Lock()
	defer mu.Unlock()
	if len(events) == 0 {
		t.Fatal("expected at least one ScanEvent from WithHook, got none")
	}
	if events[0].Type != "scan_start" {
		t.Errorf("expected first event type scan_start, got %q", events[0].Type)
	}
}

func TestWithHookFullPipeline(t *testing.T) {
	// Create a real git repo with a Go file so the full pipeline runs,
	// verifying that finding and scan_complete events are bridged.
	repoDir := t.TempDir()
	gitRun(t, repoDir, "init")
	gitRun(t, repoDir, "config", "user.email", "test@test.com")
	gitRun(t, repoDir, "config", "user.name", "Test")
	goFile := filepath.Join(repoDir, "main.go")
	if err := os.WriteFile(goFile, []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repoDir, "add", ".")
	gitRun(t, repoDir, "commit", "-m", "init")

	var mu sync.Mutex
	var eventTypes []string

	hook := func(ev ScanEvent) {
		mu.Lock()
		defer mu.Unlock()
		eventTypes = append(eventTypes, ev.Type)
	}

	e := NewEngine(WithHook(hook))
	out, err := e.Verify(context.Background(), VerifyInput{
		RepoPath:  repoDir,
		Profile:   "backend-api",
		OutputDir: t.TempDir(),
		Format:    "json",
	})
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	// Pipeline should complete successfully (exit 0) or partial (exit 6)
	if out.ExitCode != 0 && out.ExitCode != 6 {
		t.Fatalf("expected exit 0 or 6, got %d, errors: %v", out.ExitCode, out.Errors)
	}

	mu.Lock()
	defer mu.Unlock()

	// Expect all lifecycle events: scan_start, analyzer_complete, finding(s), scan_complete
	typeSet := make(map[string]bool)
	for _, et := range eventTypes {
		typeSet[et] = true
	}
	for _, required := range []string{"scan_start", "analyzer_complete", "finding", "scan_complete"} {
		if !typeSet[required] {
			t.Errorf("missing expected event type %q; got types: %v", required, eventTypes)
		}
	}
}

func gitRun(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, out)
	}
}

func TestVerifyCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel

	e := NewEngine()
	out, err := e.Verify(ctx, VerifyInput{
		RepoPath:  "/nonexistent",
		Profile:   "backend-api",
		OutputDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Verify should not return error, got %v", err)
	}
	if out.ExitCode != 7 {
		t.Errorf("expected exit code 7 for cancelled context, got %d", out.ExitCode)
	}
	if out.Success {
		t.Error("cancelled verify should not be marked as success")
	}
}

// testPlugin implements AnalyzerPlugin for testing.
type testPlugin struct {
	name       string
	languages  []string
	extensions []string
	result     []byte
	err        error
	called     bool
}

func (p *testPlugin) Name() string        { return p.name }
func (p *testPlugin) Languages() []string  { return p.languages }
func (p *testPlugin) Extensions() []string { return p.extensions }
func (p *testPlugin) Analyze(_ context.Context, _ string, files []string) ([]byte, error) {
	p.called = true
	return p.result, p.err
}

func TestWithAnalyzerPluginCalled(t *testing.T) {
	// Create a repo with a .rb file so the plugin gets invoked
	repoDir := t.TempDir()
	gitRun(t, repoDir, "init")
	gitRun(t, repoDir, "config", "user.email", "t@t.com")
	gitRun(t, repoDir, "config", "user.name", "T")
	if err := os.WriteFile(filepath.Join(repoDir, "app.rb"), []byte("class App; end\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repoDir, "add", ".")
	gitRun(t, repoDir, "commit", "-m", "init")

	plugin := &testPlugin{
		name:       "ruby-analyzer",
		languages:  []string{"ruby"},
		extensions: []string{".rb"},
		result:     []byte(`{"files":[{"file":"app.rb","language":"ruby"}]}`),
	}

	e := NewEngine(WithAnalyzerPlugin(plugin))
	out, err := e.Verify(context.Background(), VerifyInput{
		RepoPath:  repoDir,
		Profile:   "backend-api",
		OutputDir: t.TempDir(),
		Format:    "json",
	})
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if !plugin.called {
		t.Error("plugin Analyze was not called")
	}
	// Should complete without crashing (exit 0 or 6)
	if out.ExitCode != 0 && out.ExitCode != 6 {
		t.Errorf("unexpected exit code %d, errors: %v", out.ExitCode, out.Errors)
	}
}

func TestWithAnalyzerPluginNotCalledForNoFiles(t *testing.T) {
	// Create a repo with only .go files — plugin for .rb should not be called
	repoDir := t.TempDir()
	gitRun(t, repoDir, "init")
	gitRun(t, repoDir, "config", "user.email", "t@t.com")
	gitRun(t, repoDir, "config", "user.name", "T")
	if err := os.WriteFile(filepath.Join(repoDir, "main.go"), []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repoDir, "add", ".")
	gitRun(t, repoDir, "commit", "-m", "init")

	plugin := &testPlugin{
		name:       "ruby-analyzer",
		languages:  []string{"ruby"},
		extensions: []string{".rb"},
		result:     []byte(`{}`),
	}

	e := NewEngine(WithAnalyzerPlugin(plugin))
	_, err := e.Verify(context.Background(), VerifyInput{
		RepoPath:  repoDir,
		Profile:   "backend-api",
		OutputDir: t.TempDir(),
		Format:    "json",
	})
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if plugin.called {
		t.Error("plugin should not be called when no matching files exist")
	}
}

func TestWithProgress(t *testing.T) {
	var buf strings.Builder
	e := NewEngine(WithProgress(&buf))
	if e == nil {
		t.Fatal("engine should not be nil")
	}
	de := e.(*defaultEngine)
	if de.config.progress == nil {
		t.Fatal("progress writer should be set")
	}
}

func TestWithInterpretation(t *testing.T) {
	provider := &mockLLMProvider{response: "test interpretation"}
	e := NewEngine(WithInterpretation(provider))
	de := e.(*defaultEngine)
	if !de.config.interpret {
		t.Fatal("interpret flag should be true")
	}
	if de.config.llmProvider == nil {
		t.Fatal("LLM provider should be set")
	}
}

func TestWithMultipleOptions(t *testing.T) {
	var buf strings.Builder
	provider := &mockLLMProvider{response: "test"}
	plugin := &testPlugin{
		name:       "test-plugin",
		languages:  []string{"rust"},
		extensions: []string{".rs"},
		result:     []byte(`{}`),
	}

	var events []ScanEvent
	hook := func(ev ScanEvent) {
		events = append(events, ev)
	}

	e := NewEngine(
		WithProgress(&buf),
		WithInterpretation(provider),
		WithAnalyzerPlugin(plugin),
		WithHook(hook),
	)
	de := e.(*defaultEngine)
	if de.config.progress == nil {
		t.Fatal("progress should be set")
	}
	if !de.config.interpret {
		t.Fatal("interpret should be true")
	}
	if len(de.config.plugins) != 1 {
		t.Fatalf("expected 1 plugin, got %d", len(de.config.plugins))
	}
	if len(de.config.hooks) != 1 {
		t.Fatalf("expected 1 hook, got %d", len(de.config.hooks))
	}
}

func TestGetAPIInfoAllFields(t *testing.T) {
	info := GetAPIInfo()
	if info.EngineVersion == "" {
		t.Error("EngineVersion should not be empty")
	}
	if info.APIVersion != APIVersion {
		t.Errorf("expected APIVersion %q, got %q", APIVersion, info.APIVersion)
	}
	if info.ScanSchemaVersion != ScanSchemaVersion {
		t.Errorf("expected ScanSchemaVersion %q, got %q", ScanSchemaVersion, info.ScanSchemaVersion)
	}
	if info.ReportSchemaVersion != ReportSchemaVersion {
		t.Errorf("expected ReportSchemaVersion %q, got %q", ReportSchemaVersion, info.ReportSchemaVersion)
	}
	if info.ClaimSchemaVersion != ClaimSchemaVersion {
		t.Errorf("expected ClaimSchemaVersion %q, got %q", ClaimSchemaVersion, info.ClaimSchemaVersion)
	}
}

func TestSchemaVersionConstants(t *testing.T) {
	if ScanSchemaVersion == "" {
		t.Error("ScanSchemaVersion should not be empty")
	}
	if ReportSchemaVersion == "" {
		t.Error("ReportSchemaVersion should not be empty")
	}
	if ClaimSchemaVersion == "" {
		t.Error("ClaimSchemaVersion should not be empty")
	}
	if APIVersion == "" {
		t.Error("APIVersion should not be empty")
	}
}

func TestLLMProviderBridge(t *testing.T) {
	provider := &mockLLMProvider{response: "bridged response"}
	e := NewEngine(WithInterpretation(provider))
	de := e.(*defaultEngine)

	// The bridge is created during Verify, but we can verify the config
	if de.config.llmProvider == nil {
		t.Fatal("llmProvider should be set")
	}
}

func TestVerifyDefaults(t *testing.T) {
	// Test that default values are applied for empty profile/ref/format
	repoDir := t.TempDir()
	gitRun(t, repoDir, "init")
	gitRun(t, repoDir, "config", "user.email", "t@t.com")
	gitRun(t, repoDir, "config", "user.name", "T")
	if err := os.WriteFile(filepath.Join(repoDir, "main.go"), []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repoDir, "add", ".")
	gitRun(t, repoDir, "commit", "-m", "init")

	e := NewEngine()
	out, err := e.Verify(context.Background(), VerifyInput{
		RepoPath:  repoDir,
		OutputDir: t.TempDir(),
		// Profile, Ref, Format all empty — should use defaults
	})
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	// Should complete without crashing
	if out.ExitCode != 0 && out.ExitCode != 6 {
		t.Errorf("unexpected exit code %d, errors: %v", out.ExitCode, out.Errors)
	}
}

func TestVerifyWithInterpretation(t *testing.T) {
	repoDir := t.TempDir()
	gitRun(t, repoDir, "init")
	gitRun(t, repoDir, "config", "user.email", "t@t.com")
	gitRun(t, repoDir, "config", "user.name", "T")
	if err := os.WriteFile(filepath.Join(repoDir, "main.go"), []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repoDir, "add", ".")
	gitRun(t, repoDir, "commit", "-m", "init")

	provider := &mockLLMProvider{response: "test interpretation"}
	e := NewEngine(WithInterpretation(provider))
	out, err := e.Verify(context.Background(), VerifyInput{
		RepoPath:  repoDir,
		Profile:   "backend-api",
		OutputDir: t.TempDir(),
		Format:    "json",
	})
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	// Should complete without crashing
	if out.ExitCode != 0 && out.ExitCode != 6 {
		t.Errorf("unexpected exit code %d, errors: %v", out.ExitCode, out.Errors)
	}
}

// mockLLMProvider implements LLMProvider for testing.
type mockLLMProvider struct {
	response string
	err      error
}

func (m *mockLLMProvider) Complete(_ context.Context, _ string) (string, error) {
	return m.response, m.err
}

func TestWithAnalyzerPluginError(t *testing.T) {
	repoDir := t.TempDir()
	gitRun(t, repoDir, "init")
	gitRun(t, repoDir, "config", "user.email", "t@t.com")
	gitRun(t, repoDir, "config", "user.name", "T")
	if err := os.WriteFile(filepath.Join(repoDir, "app.rb"), []byte("class App; end\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repoDir, "add", ".")
	gitRun(t, repoDir, "commit", "-m", "init")

	plugin := &testPlugin{
		name:       "failing-plugin",
		languages:  []string{"ruby"},
		extensions: []string{".rb"},
		err:        fmt.Errorf("plugin crashed"),
	}

	e := NewEngine(WithAnalyzerPlugin(plugin))
	out, err := e.Verify(context.Background(), VerifyInput{
		RepoPath:  repoDir,
		Profile:   "backend-api",
		OutputDir: t.TempDir(),
		Format:    "json",
	})
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if !plugin.called {
		t.Error("plugin should have been called")
	}
	// Plugin error in non-strict mode should produce partial result
	if out.ExitCode != 0 && out.ExitCode != 6 {
		t.Errorf("expected exit 0 or 6, got %d", out.ExitCode)
	}
}
