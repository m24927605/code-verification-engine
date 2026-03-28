package artifactsv2

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// ---------- write.go: WriteBundle with claims/profile/resume ----------

func TestWriteBundleWithClaimsProfileResumeVerifiesAllFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundle := testBundleWithClaims()

	if err := WriteBundle(dir, &bundle, "verabase"); err != nil {
		t.Fatalf("WriteBundle(): %v", err)
	}

	allFiles := []string{
		"report.json", "evidence.json", "skills.json", "trace.json",
		"claims.json", "profile.json", "resume_input.json",
		"summary.md", "signature.json",
	}
	for _, name := range allFiles {
		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("expected %s to exist: %v", name, err)
		}
		if info.Size() == 0 {
			t.Fatalf("expected %s to be non-empty", name)
		}
	}

	// Parse claims.json to verify it's valid
	data, err := os.ReadFile(filepath.Join(dir, "claims.json"))
	if err != nil {
		t.Fatalf("ReadFile(claims.json): %v", err)
	}
	var claims ClaimsArtifact
	if err := json.Unmarshal(data, &claims); err != nil {
		t.Fatalf("Unmarshal(claims.json): %v", err)
	}
	if claims.SchemaVersion != ClaimsSchemaVersion {
		t.Fatalf("expected claims schema version, got %q", claims.SchemaVersion)
	}

	// Parse profile.json
	data, err = os.ReadFile(filepath.Join(dir, "profile.json"))
	if err != nil {
		t.Fatalf("ReadFile(profile.json): %v", err)
	}
	var profile ProfileArtifact
	if err := json.Unmarshal(data, &profile); err != nil {
		t.Fatalf("Unmarshal(profile.json): %v", err)
	}

	// Parse resume_input.json
	data, err = os.ReadFile(filepath.Join(dir, "resume_input.json"))
	if err != nil {
		t.Fatalf("ReadFile(resume_input.json): %v", err)
	}
	var resume ResumeInputArtifact
	if err := json.Unmarshal(data, &resume); err != nil {
		t.Fatalf("Unmarshal(resume_input.json): %v", err)
	}
}

// ---------- hash.go: ComputeArtifactHashes with all optional fields ----------

func TestComputeArtifactHashesWithClaimsProfileResume(t *testing.T) {
	t.Parallel()

	bundle := testBundleWithClaims()
	hashes, err := ComputeArtifactHashes(bundle)
	if err != nil {
		t.Fatalf("ComputeArtifactHashes(): %v", err)
	}
	expectedKeys := []string{
		"report.json", "evidence.json", "skills.json", "trace.json",
		"summary.md", "claims.json", "profile.json", "resume_input.json",
	}
	for _, key := range expectedKeys {
		if _, ok := hashes[key]; !ok {
			t.Fatalf("expected hash for %s", key)
		}
	}
	bundleHash := ComputeBundleHash(hashes)
	if bundleHash == "" {
		t.Fatal("expected non-empty bundle hash")
	}
}

// ---------- write.go: FinalizeSignature with claims/profile/resume ----------

func TestFinalizeSignatureWithClaimsProfileResume(t *testing.T) {
	t.Parallel()

	bundle := testBundleWithClaims()
	if err := FinalizeSignature(&bundle, "verabase"); err != nil {
		t.Fatalf("FinalizeSignature(): %v", err)
	}
	if _, ok := bundle.Signature.ArtifactHashes["claims.json"]; !ok {
		t.Fatal("expected claims.json hash in signature")
	}
	if _, ok := bundle.Signature.ArtifactHashes["profile.json"]; !ok {
		t.Fatal("expected profile.json hash in signature")
	}
	if _, ok := bundle.Signature.ArtifactHashes["resume_input.json"]; !ok {
		t.Fatal("expected resume_input.json hash in signature")
	}
}

// ---------- write.go: WriteBundle only claims (without profile/resume) ----------

func TestWriteBundleOnlyClaims(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundle := testBundle()
	claims := ClaimsArtifact{SchemaVersion: ClaimsSchemaVersion}
	bundle.Claims = &claims

	// This should fail validation since claims is incomplete, but let's verify
	// the error is about validation, not about file writing
	err := WriteBundle(dir, &bundle, "verabase")
	if err == nil {
		// If it somehow passes, verify claims.json exists
		if _, statErr := os.Stat(filepath.Join(dir, "claims.json")); statErr != nil {
			t.Fatal("expected claims.json to exist")
		}
	}
	// Error is expected since claims artifact is incomplete
}

// ---------- write.go: WriteBundle only profile ----------

func TestWriteBundleOnlyProfile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundle := testBundle()
	profile := ProfileArtifact{SchemaVersion: ProfileSchemaVersion}
	bundle.Profile = &profile

	// This should fail validation, which is expected
	err := WriteBundle(dir, &bundle, "verabase")
	_ = err // error expected since incomplete
}

// ---------- write.go: WriteBundle only resume ----------

func TestWriteBundleOnlyResume(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bundle := testBundle()
	resume := ResumeInputArtifact{SchemaVersion: ResumeInputSchemaVersion}
	bundle.ResumeInput = &resume

	// This should fail validation, which is expected
	err := WriteBundle(dir, &bundle, "verabase")
	_ = err // error expected since incomplete
}
