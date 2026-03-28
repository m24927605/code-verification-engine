package artifactsv2

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
)

// HashJSON computes a deterministic SHA-256 hash over canonical JSON encoding.
func HashJSON(v any) (string, error) {
	data, err := canonicalJSON(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// HashBytes computes a SHA-256 hash over raw bytes.
func HashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// ComputeArtifactHashes returns the deterministic hashes for the primary artifact set.
func ComputeArtifactHashes(b Bundle) (map[string]string, error) {
	hashes := make(map[string]string, 8)

	reportHash, err := HashJSON(b.Report)
	if err != nil {
		return nil, fmt.Errorf("hash report.json: %w", err)
	}
	evidenceHash, err := HashJSON(b.Evidence)
	if err != nil {
		return nil, fmt.Errorf("hash evidence.json: %w", err)
	}
	skillsHash, err := HashJSON(b.Skills)
	if err != nil {
		return nil, fmt.Errorf("hash skills.json: %w", err)
	}
	traceHash, err := HashJSON(b.Trace)
	if err != nil {
		return nil, fmt.Errorf("hash trace.json: %w", err)
	}

	hashes["report.json"] = reportHash
	hashes["evidence.json"] = evidenceHash
	hashes["skills.json"] = skillsHash
	hashes["trace.json"] = traceHash
	if b.Claims != nil {
		claimsHash, err := HashJSON(*b.Claims)
		if err != nil {
			return nil, fmt.Errorf("hash claims.json: %w", err)
		}
		hashes["claims.json"] = claimsHash
	}
	if b.Profile != nil {
		profileHash, err := HashJSON(*b.Profile)
		if err != nil {
			return nil, fmt.Errorf("hash profile.json: %w", err)
		}
		hashes["profile.json"] = profileHash
	}
	if b.ResumeInput != nil {
		resumeInputHash, err := HashJSON(*b.ResumeInput)
		if err != nil {
			return nil, fmt.Errorf("hash resume_input.json: %w", err)
		}
		hashes["resume_input.json"] = resumeInputHash
	}
	hashes["summary.md"] = HashBytes([]byte(b.SummaryMD))
	return hashes, nil
}

// ComputeBundleHash computes a deterministic bundle hash from the artifact hash set.
func ComputeBundleHash(artifactHashes map[string]string) string {
	keys := make([]string, 0, len(artifactHashes))
	for key := range artifactHashes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var buf bytes.Buffer
	for _, key := range keys {
		buf.WriteString(key)
		buf.WriteByte('=')
		buf.WriteString(artifactHashes[key])
		buf.WriteByte('\n')
	}
	return HashBytes(buf.Bytes())
}

func canonicalJSON(v any) ([]byte, error) {
	var normalized any
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&normalized); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := writeCanonicalJSON(&buf, normalized); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonicalJSON(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		enc, err := json.Marshal(x)
		if err != nil {
			return err
		}
		buf.Write(enc)
	case json.Number:
		buf.WriteString(x.String())
	case float64:
		buf.WriteString(strconv.FormatFloat(x, 'f', -1, 64))
	case []any:
		buf.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonicalJSON(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for key := range x {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			encKey, err := json.Marshal(key)
			if err != nil {
				return err
			}
			buf.Write(encKey)
			buf.WriteByte(':')
			if err := writeCanonicalJSON(buf, x[key]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		raw, err := json.Marshal(x)
		if err != nil {
			return err
		}
		var nested any
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&nested); err != nil {
			return err
		}
		return writeCanonicalJSON(buf, nested)
	}
	return nil
}
