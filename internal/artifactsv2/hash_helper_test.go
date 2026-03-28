package artifactsv2

import (
	"bytes"
	"strings"
	"testing"
)

func TestCanonicalJSONAndHashHelpers(t *testing.T) {
	t.Parallel()

	data, err := canonicalJSON(map[string]any{
		"b": []any{true, nil, "x"},
		"a": map[string]any{
			"z": 2,
			"y": "value",
		},
	})
	if err != nil {
		t.Fatalf("canonicalJSON(): %v", err)
	}
	if string(data) != `{"a":{"y":"value","z":2},"b":[true,null,"x"]}` {
		t.Fatalf("canonicalJSON() = %s", string(data))
	}

	var buf bytes.Buffer
	if err := writeCanonicalJSON(&buf, map[string]any{"b": 2, "a": jsonLikeString("x")}); err != nil {
		t.Fatalf("writeCanonicalJSON(map): %v", err)
	}
	if buf.String() != `{"a":"x","b":2}` {
		t.Fatalf("writeCanonicalJSON(map) = %s", buf.String())
	}

	buf.Reset()
	if err := writeCanonicalJSON(&buf, []any{true, false, nil, 1.25}); err != nil {
		t.Fatalf("writeCanonicalJSON(array): %v", err)
	}
	if buf.String() != `[true,false,null,1.25]` {
		t.Fatalf("writeCanonicalJSON(array) = %s", buf.String())
	}

	if _, err := canonicalJSON(func() {}); err == nil {
		t.Fatal("expected canonicalJSON error for unsupported value")
	}
}

func TestComputeArtifactHashesAndBundleHash_WithOptionalArtifacts(t *testing.T) {
	t.Parallel()

	b := testBundleWithClaims()
	outsource, pm, err := BuildScenarioAcceptanceArtifacts(ScenarioAcceptanceBuildInput{
		RepoIdentity: b.Report.Repo,
		Commit:       b.Report.Commit,
		TraceID:      b.Trace.TraceID,
		Claims:       b.Claims,
		Options: ScenarioBuildOptions{
			OutsourceAcceptanceProfile: "outsource-default",
			PMAcceptanceProfile:        "pm-default",
		},
	})
	if err != nil {
		t.Fatalf("BuildScenarioAcceptanceArtifacts(): %v", err)
	}
	b.OutsourceAcceptance = outsource
	b.PMAcceptance = pm

	hashes, err := ComputeArtifactHashes(b)
	if err != nil {
		t.Fatalf("ComputeArtifactHashes(): %v", err)
	}
	for _, name := range []string{
		"report.json",
		"evidence.json",
		"skills.json",
		"trace.json",
		"claims.json",
		"profile.json",
		"resume_input.json",
		"outsource_acceptance.json",
		"pm_acceptance.json",
		"summary.md",
	} {
		if !strings.HasPrefix(hashes[name], "sha256:") {
			t.Fatalf("missing hash for %s: %#v", name, hashes)
		}
	}

	bundleHash := ComputeBundleHash(hashes)
	if !strings.HasPrefix(bundleHash, "sha256:") {
		t.Fatalf("ComputeBundleHash() = %q", bundleHash)
	}
	if bundleHash != ComputeBundleHash(hashes) {
		t.Fatal("expected deterministic bundle hash")
	}
}

type jsonLikeString string
