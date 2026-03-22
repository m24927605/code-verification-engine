package cve

import (
	"context"
	"encoding/json"
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

// --- Trust boundary tests for typed public API ---

func TestVerifyOutputTypedJSONSerialization(t *testing.T) {
	out := &VerifyOutput{
		ExitCode: 0,
		Success:  true,
		Scan: ScanOutput{
			ScanSchemaVersion: ScanSchemaVersion,
			RepoPath:          "/tmp/repo",
			RepoName:          "test-repo",
			Ref:               "main",
			Languages:         []string{"go"},
			Analyzers:         map[string]string{"go": "ok"},
			Profile:           "backend-api",
		},
		Report: ReportOutput{
			ReportSchemaVersion: ReportSchemaVersion,
			Summary:             ReportSummaryOutput{Pass: 2, Fail: 1},
			TrustSummary: TrustSummary{
				MachineTrusted:         1,
				Advisory:               1,
				HumanOrRuntimeRequired: 1,
			},
			Findings: []FindingOutput{
				{RuleID: "SEC-SECRET-001", Status: "pass", TrustClass: "machine_trusted"},
				{RuleID: "SEC-AUTH-001", Status: "pass", TrustClass: "advisory"},
				{RuleID: "SEC-AUTH-002", Status: "fail", TrustClass: "human_or_runtime_required"},
			},
		},
	}

	data, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("failed to marshal VerifyOutput: %v", err)
	}

	s := string(data)
	for _, tc := range []string{"machine_trusted", "advisory", "human_or_runtime_required"} {
		if !strings.Contains(s, tc) {
			t.Errorf("serialized output missing trust_class %q", tc)
		}
	}
	if !strings.Contains(s, "trust_summary") {
		t.Error("serialized output missing trust_summary")
	}

	var roundTrip VerifyOutput
	if err := json.Unmarshal(data, &roundTrip); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if roundTrip.Report.TrustSummary.MachineTrusted != 1 {
		t.Errorf("expected machine_trusted=1, got %d", roundTrip.Report.TrustSummary.MachineTrusted)
	}
	if roundTrip.Report.TrustSummary.Advisory != 1 {
		t.Errorf("expected advisory=1, got %d", roundTrip.Report.TrustSummary.Advisory)
	}
	for _, f := range roundTrip.Report.Findings {
		if f.TrustClass == "" {
			t.Errorf("finding %s missing trust_class after round-trip", f.RuleID)
		}
	}
}

func TestFindingOutputRequiresTrustClass(t *testing.T) {
	f := FindingOutput{
		RuleID:     "TEST-001",
		Status:     "pass",
		TrustClass: "",
	}
	data, _ := json.Marshal(f)
	if !strings.Contains(string(data), `"trust_class":""`) {
		t.Error("empty trust_class should be serialized explicitly")
	}
}

func TestReportOutputJSONCompat(t *testing.T) {
	r := ReportOutput{
		ReportSchemaVersion: "1.0.0",
		Summary:             ReportSummaryOutput{Pass: 1},
		TrustSummary:        TrustSummary{MachineTrusted: 1},
		Findings: []FindingOutput{
			{RuleID: "R-001", Status: "pass", TrustClass: "machine_trusted"},
		},
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"report_schema_version", "summary", "trust_summary", "signal_summary", "findings", "trust_class"} {
		if !strings.Contains(string(data), field) {
			t.Errorf("ReportOutput JSON missing field %q", field)
		}
	}
}

func TestSignalSummaryOutput_JSONSerialization(t *testing.T) {
	out := &VerifyOutput{
		Report: ReportOutput{
			SignalSummary: SignalSummaryOutput{
				ActionableFail:         7,
				AdvisoryFail:           6,
				InformationalDetection: 19,
				Unknown:                0,
			},
		},
	}
	data, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	for _, field := range []string{"actionable_fail", "advisory_fail", "informational_detection"} {
		if !strings.Contains(s, field) {
			t.Errorf("SignalSummaryOutput JSON missing field %q", field)
		}
	}
	if !strings.Contains(s, `"actionable_fail":7`) {
		t.Error("expected actionable_fail=7 in JSON")
	}
}

func TestTrustSummaryRoundTrip(t *testing.T) {
	ts := TrustSummary{MachineTrusted: 3, Advisory: 5, HumanOrRuntimeRequired: 2}
	data, _ := json.Marshal(ts)
	var rt TrustSummary
	json.Unmarshal(data, &rt)
	if rt.MachineTrusted != 3 || rt.Advisory != 5 || rt.HumanOrRuntimeRequired != 2 {
		t.Errorf("TrustSummary round-trip failed: %+v", rt)
	}
}

// --- TrustGuidance tests ---

func TestTrustGuidance_AllMachineTrustedVerified(t *testing.T) {
	findings := []FindingOutput{
		{RuleID: "R-1", Status: "pass", TrustClass: "machine_trusted", VerificationLevel: "verified"},
		{RuleID: "R-2", Status: "pass", TrustClass: "machine_trusted", VerificationLevel: "verified"},
	}
	ts := TrustSummary{MachineTrusted: 2}
	cs := CapabilitySummaryOutput{}
	g := computeTrustGuidance(findings, ts, cs)

	if !g.CanAutomate {
		t.Error("should be automatable when all findings are machine_trusted+verified")
	}
	if g.RequiresReview {
		t.Error("should not require review when all findings are machine_trusted")
	}
	if g.DegradedAnalysis {
		t.Error("should not be degraded")
	}
}

func TestTrustGuidance_MixedTrustClasses(t *testing.T) {
	findings := []FindingOutput{
		{RuleID: "R-1", Status: "pass", TrustClass: "machine_trusted", VerificationLevel: "verified"},
		{RuleID: "R-2", Status: "pass", TrustClass: "advisory", VerificationLevel: "strong_inference"},
	}
	ts := TrustSummary{MachineTrusted: 1, Advisory: 1}
	cs := CapabilitySummaryOutput{}
	g := computeTrustGuidance(findings, ts, cs)

	if g.CanAutomate {
		t.Error("should NOT be automatable when advisory findings present")
	}
	if !g.RequiresReview {
		t.Error("should require review when advisory findings present")
	}
}

func TestTrustGuidance_DegradedAnalysis(t *testing.T) {
	findings := []FindingOutput{
		{RuleID: "R-1", Status: "pass", TrustClass: "machine_trusted", VerificationLevel: "verified"},
	}
	ts := TrustSummary{MachineTrusted: 1}
	cs := CapabilitySummaryOutput{Degraded: true}
	g := computeTrustGuidance(findings, ts, cs)

	if !g.DegradedAnalysis {
		t.Error("should be degraded when capability summary says so")
	}
	if !g.RequiresReview {
		t.Error("degraded analysis should require review")
	}
	if g.CanAutomate {
		t.Error("degraded analysis should not be automatable")
	}
}

func TestTrustGuidance_NoFindings(t *testing.T) {
	g := computeTrustGuidance(nil, TrustSummary{}, CapabilitySummaryOutput{})
	if g.CanAutomate {
		t.Error("no findings should not be automatable")
	}
	if g.Summary != "No findings to evaluate." {
		t.Errorf("unexpected summary: %s", g.Summary)
	}
}

func TestTrustGuidance_HumanRequired(t *testing.T) {
	findings := []FindingOutput{
		{RuleID: "R-1", Status: "pass", TrustClass: "human_or_runtime_required", VerificationLevel: "strong_inference"},
	}
	ts := TrustSummary{HumanOrRuntimeRequired: 1}
	cs := CapabilitySummaryOutput{}
	g := computeTrustGuidance(findings, ts, cs)

	if g.CanAutomate {
		t.Error("should not be automatable with human_required findings")
	}
	if !g.RequiresReview {
		t.Error("should require review with human_required findings")
	}
}

func TestTrustGuidance_JSONSerialization(t *testing.T) {
	out := &VerifyOutput{
		Report: ReportOutput{
			TrustGuidance: TrustGuidance{
				CanAutomate:      true,
				RequiresReview:   false,
				DegradedAnalysis: false,
				Summary:          "All findings are machine-trusted and verified. Safe for automated consumption.",
			},
		},
	}
	data, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if !strings.Contains(s, `"trust_guidance"`) {
		t.Error("JSON should contain trust_guidance")
	}
	if !strings.Contains(s, `"can_automate":true`) {
		t.Error("JSON should contain can_automate field")
	}
	if !strings.Contains(s, `"requires_review":false`) {
		t.Error("JSON should contain requires_review field")
	}

	var rt VerifyOutput
	if err := json.Unmarshal(data, &rt); err != nil {
		t.Fatal(err)
	}
	if !rt.Report.TrustGuidance.CanAutomate {
		t.Error("round-trip should preserve can_automate=true")
	}
}

func TestCapabilitySummaryOutput_JSONSerialization(t *testing.T) {
	out := &VerifyOutput{
		Report: ReportOutput{
			CapabilitySummary: CapabilitySummaryOutput{
				FullySupported: 5,
				Partial:        3,
				Unsupported:    1,
				Degraded:       true,
			},
		},
	}
	data, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if !strings.Contains(s, `"capability_summary"`) {
		t.Error("JSON should contain capability_summary")
	}
	if !strings.Contains(s, `"fully_supported":5`) {
		t.Error("JSON should contain fully_supported count")
	}
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

func TestVerify_InvalidMode_ReturnsError(t *testing.T) {
	e := NewEngine()
	_, err := e.Verify(context.Background(), VerifyInput{
		RepoPath:  "/tmp",
		OutputDir: t.TempDir(),
		Mode:      "invalid",
	})
	if err == nil {
		t.Error("expected error for invalid mode")
	}
	if !strings.Contains(err.Error(), "invalid mode") {
		t.Errorf("error should mention invalid mode, got: %v", err)
	}
}

func TestVerify_InvalidSkillProfile_ReturnsError(t *testing.T) {
	e := NewEngine()
	_, err := e.Verify(context.Background(), VerifyInput{
		RepoPath:     "/tmp",
		OutputDir:    t.TempDir(),
		Mode:         "skill_inference",
		SkillProfile: "nonexistent-profile",
	})
	if err == nil {
		t.Error("expected error for invalid skill profile")
	}
	if !strings.Contains(err.Error(), "unknown skill profile") {
		t.Errorf("error should mention unknown skill profile, got: %v", err)
	}
}

func TestListSkillProfiles(t *testing.T) {
	e := NewEngine()
	profiles := e.ListSkillProfiles()
	if len(profiles) == 0 {
		t.Error("should have at least one skill profile")
	}
	found := false
	for _, p := range profiles {
		if p.Name == "github-engineer-core" {
			found = true
			if p.SignalCount == 0 {
				t.Error("github-engineer-core should have signals")
			}
		}
	}
	if !found {
		t.Error("missing github-engineer-core profile")
	}
}

func TestValidateSkillProfile(t *testing.T) {
	e := NewEngine()
	if !e.ValidateSkillProfile("github-engineer-core") {
		t.Error("github-engineer-core should be valid")
	}
	if e.ValidateSkillProfile("nonexistent") {
		t.Error("nonexistent should be invalid")
	}
}

func TestVerify_DefaultMode_BackwardCompatible(t *testing.T) {
	e := NewEngine()
	// Mode="" should behave as verification (backward compatible)
	_, err := e.Verify(context.Background(), VerifyInput{
		RepoPath:  "/tmp",
		OutputDir: t.TempDir(),
		// Mode intentionally empty
	})
	// Should not fail with mode error — it proceeds to engine which fails on repo
	if err != nil && strings.Contains(err.Error(), "mode") {
		t.Errorf("empty mode should default to verification, not error: %v", err)
	}
}
