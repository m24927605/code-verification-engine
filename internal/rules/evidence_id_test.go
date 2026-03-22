package rules

import (
	"strings"
	"testing"
)

func TestEvidenceID_Deterministic(t *testing.T) {
	ev := Evidence{File: "main.go", LineStart: 10, LineEnd: 20, Symbol: "Foo"}
	id1 := EvidenceID(ev)
	id2 := EvidenceID(ev)
	if id1 != id2 {
		t.Errorf("EvidenceID not deterministic: %s != %s", id1, id2)
	}
	if !strings.HasPrefix(id1, "ev-") {
		t.Errorf("expected prefix 'ev-', got %s", id1)
	}
}

func TestEvidenceID_Different(t *testing.T) {
	ev1 := Evidence{File: "main.go", LineStart: 10, LineEnd: 20, Symbol: "Foo"}
	ev2 := Evidence{File: "main.go", LineStart: 10, LineEnd: 20, Symbol: "Bar"}
	if EvidenceID(ev1) == EvidenceID(ev2) {
		t.Error("different evidence should produce different IDs")
	}
}

func TestEvidenceID_ConsistentLength(t *testing.T) {
	evA := Evidence{File: "a.go", LineStart: 1, LineEnd: 2, Symbol: "X"}
	evB := Evidence{File: "some/deep/path/file.go", LineStart: 999, LineEnd: 1050, Symbol: "LongSymbolName"}
	idA := EvidenceID(evA)
	idB := EvidenceID(evB)
	if len(idA) != len(idB) {
		t.Errorf("expected consistent length, got %d and %d", len(idA), len(idB))
	}
}
