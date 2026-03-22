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

// ClaimVerdict represents the verification result for a single claim.
type ClaimVerdict struct {
	ClaimID           string         `json:"claim_id"`
	Title             string         `json:"title"`
	Category          string         `json:"category"`
	Status            string         `json:"status"`             // pass, fail, unknown, partial
	Confidence        string         `json:"confidence"`         // high, medium, low
	VerificationLevel string         `json:"verification_level"` // verified, strong_inference, weak_inference
	Summary           string         `json:"summary"`            // Human-readable verdict summary
	SupportingRules   []RuleResult   `json:"supporting_rules"`   // Individual rule results
	EvidenceChain     []EvidenceLink `json:"evidence_chain"`     // Connected evidence
	UnknownReasons    []string       `json:"unknown_reasons,omitempty"`
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
	ID       string `json:"evidence_id"`
	Type     string `json:"type"`      // "supports", "contradicts", "partial"
	File     string `json:"file"`
	LineStart int   `json:"line_start"`
	LineEnd   int   `json:"line_end"`
	Symbol   string `json:"symbol,omitempty"`
	Excerpt  string `json:"excerpt,omitempty"`
	FromRule string `json:"from_rule"` // Which rule produced this evidence
	Relation string `json:"relation"`  // How this evidence relates to the claim
}

// ClaimReport is the claim-centric verification output.
type ClaimReport struct {
	SchemaVersion string         `json:"claim_report_schema_version"`
	ClaimSetName  string         `json:"claim_set"`
	TotalClaims   int            `json:"total_claims"`
	Verdicts      VerdictSummary `json:"verdict_summary"`
	Claims        []ClaimVerdict `json:"claims"`
}

// VerdictSummary counts claim verdicts.
type VerdictSummary struct {
	Verified int `json:"verified"` // pass with high confidence
	Passed   int `json:"passed"`   // pass with any confidence
	Failed   int `json:"failed"`
	Unknown  int `json:"unknown"`
	Partial  int `json:"partial"` // some rules pass, some fail/unknown
}
