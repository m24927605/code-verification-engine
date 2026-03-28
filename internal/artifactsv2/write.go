package artifactsv2

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// FinalizeSignature computes per-artifact hashes and populates the signature envelope.
func FinalizeSignature(b *Bundle, signedBy string) error {
	if b == nil {
		return fmt.Errorf("bundle is required")
	}
	if err := ValidateBundle(*b); err != nil {
		return err
	}
	hashes, err := ComputeArtifactHashes(*b)
	if err != nil {
		return err
	}
	b.Signature = SignatureArtifact{
		Version:         SignatureSchemaVersion,
		SignedBy:        signedBy,
		Timestamp:       b.Report.Timestamp,
		ArtifactHashes:  hashes,
		BundleHash:      ComputeBundleHash(hashes),
		Signature:       nil,
		SignatureScheme: nil,
	}
	return nil
}

// WriteBundle validates, finalizes, and writes the artifact bundle to disk.
func WriteBundle(dir string, bundle *Bundle, signedBy string) error {
	if dir == "" {
		return fmt.Errorf("output dir is required")
	}
	RefreshSummaryMarkdown(bundle)
	if err := FinalizeSignature(bundle, signedBy); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(dir, "report.json"), bundle.Report); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(dir, "evidence.json"), bundle.Evidence); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(dir, "skills.json"), bundle.Skills); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(dir, "trace.json"), bundle.Trace); err != nil {
		return err
	}
	if bundle.Claims != nil {
		if err := writeJSON(filepath.Join(dir, "claims.json"), bundle.Claims); err != nil {
			return err
		}
	}
	if bundle.Profile != nil {
		if err := writeJSON(filepath.Join(dir, "profile.json"), bundle.Profile); err != nil {
			return err
		}
	}
	if bundle.ResumeInput != nil {
		if err := writeJSON(filepath.Join(dir, "resume_input.json"), bundle.ResumeInput); err != nil {
			return err
		}
	}
	if bundle.OutsourceAcceptance != nil {
		if err := writeJSON(filepath.Join(dir, "outsource_acceptance.json"), bundle.OutsourceAcceptance); err != nil {
			return err
		}
	}
	if bundle.PMAcceptance != nil {
		if err := writeJSON(filepath.Join(dir, "pm_acceptance.json"), bundle.PMAcceptance); err != nil {
			return err
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "summary.md"), []byte(bundle.SummaryMD), 0o644); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(dir, "signature.json"), bundle.Signature); err != nil {
		return err
	}
	return nil
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}
