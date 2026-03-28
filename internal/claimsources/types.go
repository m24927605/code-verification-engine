package claimsources

// SourceType identifies the class of repository source being discovered.
type SourceType string

const (
	SourceTypeCode   SourceType = "code"
	SourceTypeTest   SourceType = "test"
	SourceTypeEval   SourceType = "eval"
	SourceTypeDoc    SourceType = "doc"
	SourceTypeReadme SourceType = "readme"
)

// SourceDescriptor is a deterministic description of a discovered source file.
type SourceDescriptor struct {
	SourceID           string     `json:"source_id"`
	SourceType         SourceType `json:"source_type"`
	Path               string     `json:"path"`
	Language           string     `json:"language"`
	Role               string     `json:"role"`
	IncludedInBoundary bool       `json:"included_in_boundary"`
}

// SourceSpan captures a stable line-span within a source file.
type SourceSpan struct {
	StartLine int `json:"start_line"`
	EndLine   int `json:"end_line"`
}

// SourceEvidenceRecord is a normalized, deterministic evidence-like record
// extracted from a discovered source.
type SourceEvidenceRecord struct {
	EvidenceID string            `json:"evidence_id"`
	SourceType SourceType        `json:"source_type"`
	Producer   string            `json:"producer"`
	Path       string            `json:"path"`
	Kind       string            `json:"kind"`
	Summary    string            `json:"summary"`
	Spans      []SourceSpan      `json:"spans"`
	EntityIDs  []string          `json:"entity_ids"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// Snapshot provides the minimal repository snapshot needed by discovery and extraction.
type Snapshot struct {
	RepoPath  string
	CommitSHA string
	Files     []string
}
