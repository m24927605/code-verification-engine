package artifactsv2

import (
	"sort"
)

// EvidenceStore is a deterministic in-memory index for normalized evidence.
// It is intentionally small and conservative for the current compatibility path.
type EvidenceStore struct {
	ordered    []EvidenceRecord
	byID       map[string]EvidenceRecord
	byClaim    map[string][]string
	byProducer map[string][]string
	byFile     map[string][]string
}

// NewEvidenceStore constructs an empty store.
func NewEvidenceStore() *EvidenceStore {
	return &EvidenceStore{
		byID:       make(map[string]EvidenceRecord),
		byClaim:    make(map[string][]string),
		byProducer: make(map[string][]string),
		byFile:     make(map[string][]string),
	}
}

// NewEvidenceStoreFromRecords constructs and indexes a store from evidence records.
func NewEvidenceStoreFromRecords(records []EvidenceRecord) *EvidenceStore {
	store := NewEvidenceStore()
	for _, record := range records {
		store.Upsert(record)
	}
	store.Finalize()
	return store
}

// Upsert adds or replaces an evidence record by ID.
func (s *EvidenceStore) Upsert(record EvidenceRecord) {
	if s == nil || record.ID == "" {
		return
	}
	if _, exists := s.byID[record.ID]; !exists {
		s.ordered = append(s.ordered, record)
	} else {
		for i := range s.ordered {
			if s.ordered[i].ID == record.ID {
				s.ordered[i] = record
				break
			}
		}
	}
	s.byID[record.ID] = record
}

// Finalize rebuilds secondary indexes and stabilizes ordering.
func (s *EvidenceStore) Finalize() {
	if s == nil {
		return
	}
	sort.Slice(s.ordered, func(i, j int) bool { return s.ordered[i].ID < s.ordered[j].ID })
	s.byClaim = make(map[string][]string)
	s.byProducer = make(map[string][]string)
	s.byFile = make(map[string][]string)
	for _, record := range s.ordered {
		for _, claim := range compactStrings(record.Claims) {
			s.byClaim[claim] = append(s.byClaim[claim], record.ID)
		}
		if record.ProducerID != "" {
			s.byProducer[record.ProducerID] = append(s.byProducer[record.ProducerID], record.ID)
		}
		for _, loc := range record.Locations {
			if loc.RepoRelPath != "" {
				s.byFile[loc.RepoRelPath] = append(s.byFile[loc.RepoRelPath], record.ID)
			}
		}
	}
	for key := range s.byClaim {
		s.byClaim[key] = dedupeStringsSorted(s.byClaim[key])
	}
	for key := range s.byProducer {
		s.byProducer[key] = dedupeStringsSorted(s.byProducer[key])
	}
	for key := range s.byFile {
		s.byFile[key] = dedupeStringsSorted(s.byFile[key])
	}
}

// All returns all evidence records in deterministic order.
func (s *EvidenceStore) All() []EvidenceRecord {
	if s == nil {
		return nil
	}
	out := make([]EvidenceRecord, len(s.ordered))
	copy(out, s.ordered)
	return out
}

// Get returns an evidence record by ID.
func (s *EvidenceStore) Get(id string) (EvidenceRecord, bool) {
	if s == nil {
		return EvidenceRecord{}, false
	}
	record, ok := s.byID[id]
	return record, ok
}

// IDsByClaim returns evidence IDs indexed by claim.
func (s *EvidenceStore) IDsByClaim(claim string) []string {
	if s == nil {
		return nil
	}
	return append([]string(nil), s.byClaim[claim]...)
}

// IDsByProducer returns evidence IDs indexed by producer.
func (s *EvidenceStore) IDsByProducer(producer string) []string {
	if s == nil {
		return nil
	}
	return append([]string(nil), s.byProducer[producer]...)
}

// IDsByFile returns evidence IDs indexed by repo-relative file path.
func (s *EvidenceStore) IDsByFile(path string) []string {
	if s == nil {
		return nil
	}
	return append([]string(nil), s.byFile[path]...)
}
