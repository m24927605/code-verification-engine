package rules

import (
	"crypto/sha256"
	"fmt"
)

// EvidenceID generates a deterministic, content-derived identifier for an evidence item.
// This ID is stable across runs for the same evidence and can be used by downstream
// systems for deduplication and cross-reference.
func EvidenceID(ev Evidence) string {
	content := fmt.Sprintf("%s:%d:%d:%s", ev.File, ev.LineStart, ev.LineEnd, ev.Symbol)
	hash := sha256.Sum256([]byte(content))
	return fmt.Sprintf("ev-%x", hash[:8])
}
