package claims

// Claim represents a verifiable assertion about a codebase.
type Claim struct {
	ID          string   `json:"id"`          // e.g., "auth.jwt_implemented"
	Title       string   `json:"title"`       // Human-readable title
	Category    string   `json:"category"`    // security, architecture, quality, testing
	Description string   `json:"description"` // What this claim means
	RuleIDs     []string `json:"rule_ids"`    // Rules that support/refute this claim
	Scope       Scope    `json:"scope"`       // What scope this claim covers
}

// Scope defines the boundaries of a claim.
type Scope struct {
	Languages  []string `json:"languages,omitempty"`  // Required languages
	Frameworks []string `json:"frameworks,omitempty"` // Required frameworks (optional)
	Paths      []string `json:"paths,omitempty"`      // Path patterns in scope
}

// ClaimSet is a named collection of claims to verify.
type ClaimSet struct {
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Claims      []Claim `json:"claims"`
}

// ClaimOrigin identifies how a claim candidate entered the verification graph.
type ClaimOrigin string

const (
	ClaimOriginReadmeExtracted ClaimOrigin = "readme_extracted"
	ClaimOriginDocExtracted    ClaimOrigin = "doc_extracted"
	ClaimOriginCodeInferred    ClaimOrigin = "code_inferred"
	ClaimOriginTestInferred    ClaimOrigin = "test_inferred"
	ClaimOriginEvalInferred    ClaimOrigin = "eval_inferred"
	ClaimOriginRuleInferred    ClaimOrigin = "rule_inferred"
)

// ClaimSupportLevel captures how strongly a claim is supported by evidence.
type ClaimSupportLevel string

const (
	ClaimSupportVerified          ClaimSupportLevel = "verified"
	ClaimSupportStronglySupported ClaimSupportLevel = "strongly_supported"
	ClaimSupportSupported         ClaimSupportLevel = "supported"
	ClaimSupportWeak              ClaimSupportLevel = "weak"
	ClaimSupportUnsupported       ClaimSupportLevel = "unsupported"
	ClaimSupportContradicted      ClaimSupportLevel = "contradicted"
)

// ClaimGraphEdgeType captures the allowed claim graph relation types.
type ClaimGraphEdgeType string

const (
	ClaimEdgeSupportedBy    ClaimGraphEdgeType = "supported_by"
	ClaimEdgeContradictedBy ClaimGraphEdgeType = "contradicted_by"
	ClaimEdgeDerivedFrom    ClaimGraphEdgeType = "derived_from"
	ClaimEdgeValidatedBy    ClaimGraphEdgeType = "validated_by"
	ClaimEdgeDocumentedBy   ClaimGraphEdgeType = "documented_by"
	ClaimEdgeProjectedTo    ClaimGraphEdgeType = "projected_to"
)

// SourceSpan is a typed span boundary for source evidence in the claim graph.
type SourceSpan struct {
	File      string `json:"file"`
	LineStart int    `json:"line_start"`
	LineEnd   int    `json:"line_end"`
	Symbol    string `json:"symbol,omitempty"`
	Excerpt   string `json:"excerpt,omitempty"`
}

// SourceEvidenceRecord is the multi-source evidence input used for claim extraction.
type SourceEvidenceRecord struct {
	EvidenceID  string            `json:"evidence_id"`
	SourceType  string            `json:"source_type"`
	Origin      string            `json:"origin,omitempty"`
	Producer    string            `json:"producer"`
	Path        string            `json:"path"`
	Kind        string            `json:"kind"`
	Summary     string            `json:"summary"`
	Spans       []SourceSpan      `json:"spans,omitempty"`
	EntityIDs   []string          `json:"entity_ids,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	ClaimIDs    []string          `json:"claim_ids,omitempty"`
	Supports    []string          `json:"supports,omitempty"`
	Contradicts []string          `json:"contradicts,omitempty"`
}

// ClaimCandidate represents a multi-source extracted claim awaiting verification.
type ClaimCandidate struct {
	ClaimID              string   `json:"claim_id"`
	Title                string   `json:"title"`
	Category             string   `json:"category"`
	ClaimType            string   `json:"claim_type"`
	Origin               string   `json:"origin"`
	CandidateEvidenceIDs []string `json:"candidate_evidence_ids,omitempty"`
	Scope                Scope    `json:"scope"`
	SourceTypes          []string `json:"source_types,omitempty"`
	Description          string   `json:"description,omitempty"`
	Reason               string   `json:"reason,omitempty"`
}

// VerifiedClaim captures the multi-source verified form of a claim candidate.
type VerifiedClaim struct {
	ClaimID                  string   `json:"claim_id"`
	Title                    string   `json:"title"`
	Category                 string   `json:"category"`
	ClaimType                string   `json:"claim_type"`
	Status                   string   `json:"status"`
	SupportLevel             string   `json:"support_level"`
	Confidence               float64  `json:"confidence"`
	SupportingEvidenceIDs    []string `json:"supporting_evidence_ids,omitempty"`
	ContradictoryEvidenceIDs []string `json:"contradictory_evidence_ids,omitempty"`
	SourceOrigins            []string `json:"source_origins,omitempty"`
	Reason                   string   `json:"reason"`
}

// ClaimGraphEdge links claims and evidence through support, contradiction, or derivation.
type ClaimGraphEdge struct {
	FromID     string `json:"from_id"`
	ToID       string `json:"to_id"`
	Type       string `json:"type"`
	EvidenceID string `json:"evidence_id,omitempty"`
}

// ClaimGraph is the canonical multi-source claim verification graph.
type ClaimGraph struct {
	SchemaVersion string                 `json:"schema_version"`
	Claims        []VerifiedClaim        `json:"claims"`
	Evidence      []SourceEvidenceRecord `json:"evidence,omitempty"`
	Edges         []ClaimGraphEdge       `json:"edges"`
}

// ClaimVerdict represents the verification result for a single claim.
type ClaimVerdict struct {
	ClaimID           string         `json:"claim_id"`
	Title             string         `json:"title"`
	Category          string         `json:"category"`
	Status            string         `json:"status"`             // pass, fail, unknown, partial
	Confidence        string         `json:"confidence"`         // high, medium, low
	VerificationLevel string         `json:"verification_level"` // verified, strong_inference, weak_inference
	TrustBreakdown    TrustBreakdown `json:"trust_breakdown"`    // Trust class distribution across supporting rules
	Summary           string         `json:"summary"`            // Human-readable verdict summary
	SupportingRules   []RuleResult   `json:"supporting_rules"`   // Individual rule results
	EvidenceChain     []EvidenceLink `json:"evidence_chain"`     // Connected evidence
	UnknownReasons    []string       `json:"unknown_reasons,omitempty"`
}

// TrustBreakdown counts the trust classes of rules contributing to a claim.
type TrustBreakdown struct {
	MachineTrusted         int    `json:"machine_trusted"`
	Advisory               int    `json:"advisory"`
	HumanOrRuntimeRequired int    `json:"human_or_runtime_required"`
	EffectiveTrustClass    string `json:"effective_trust_class"` // Lowest trust class among contributing rules
}

// RuleResult links a rule evaluation to a claim.
type RuleResult struct {
	RuleID     string `json:"rule_id"`
	Status     string `json:"status"`
	Confidence string `json:"confidence"`
	Message    string `json:"message"`
}

// EvidenceLink represents a piece of evidence in the claim's evidence chain.
type EvidenceLink struct {
	ID        string `json:"evidence_id"`
	Type      string `json:"type"` // "supports", "contradicts", "partial"
	File      string `json:"file"`
	LineStart int    `json:"line_start"`
	LineEnd   int    `json:"line_end"`
	Symbol    string `json:"symbol,omitempty"`
	Excerpt   string `json:"excerpt,omitempty"`
	FromRule  string `json:"from_rule"` // Which rule produced this evidence
	Relation  string `json:"relation"`  // How this evidence relates to the claim
}

// ClaimReport is the claim-centric verification output.
type ClaimReport struct {
	SchemaVersion   string           `json:"claim_report_schema_version"`
	ClaimSetName    string           `json:"claim_set"`
	TotalClaims     int              `json:"total_claims"`
	Verdicts        VerdictSummary   `json:"verdict_summary"`
	Claims          []ClaimVerdict   `json:"claims"`
	ClaimCandidates []ClaimCandidate `json:"claim_candidates,omitempty"`
	VerifiedClaims  []VerifiedClaim  `json:"verified_claims,omitempty"`
	ClaimGraph      *ClaimGraph      `json:"claim_graph,omitempty"`
}

// VerdictSummary counts claim verdicts.
type VerdictSummary struct {
	Verified int `json:"verified"` // pass with high confidence
	Passed   int `json:"passed"`   // pass with any confidence
	Failed   int `json:"failed"`
	Unknown  int `json:"unknown"`
	Partial  int `json:"partial"` // some rules pass, some fail/unknown
}
