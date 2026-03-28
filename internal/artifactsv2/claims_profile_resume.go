package artifactsv2

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	ClaimsSchemaVersion      = "1.0.0"
	ProfileSchemaVersion     = "1.0.0"
	ResumeInputSchemaVersion = "1.0.0"
)

// ClaimsProjectionInput is the deterministic input used to derive claims,
// profile, and resume-input artifacts without invoking LLM synthesis.
type ClaimsProjectionInput struct {
	Repository   ClaimRepositoryRef
	Claims       []ClaimRecord
	Technologies []string
}

// ClaimsProjectionArtifacts bundles the three projection artifacts that are
// derived from a canonical claim set.
type ClaimsProjectionArtifacts struct {
	Claims      ClaimsArtifact
	Profile     ProfileArtifact
	ResumeInput ResumeInputArtifact
}

// ClaimRepositoryRef identifies the repository snapshot that the claims were
// derived from.
type ClaimRepositoryRef struct {
	Path   string `json:"path"`
	Commit string `json:"commit"`
}

// ClaimRecord is the normalized machine-readable claim record used by the
// multi-source claims subsystem.
type ClaimRecord struct {
	ClaimID                  string                 `json:"claim_id"`
	Title                    string                 `json:"title"`
	Category                 string                 `json:"category"`
	ClaimType                string                 `json:"claim_type"`
	Status                   string                 `json:"status"`
	SupportLevel             string                 `json:"support_level"`
	Confidence               float64                `json:"confidence"`
	VerificationClass        VerificationClass      `json:"verification_class,omitempty"`
	ScenarioApplicability    *ScenarioApplicability `json:"scenario_applicability,omitempty"`
	SourceOrigins            []string               `json:"source_origins"`
	SupportingEvidenceIDs    []string               `json:"supporting_evidence_ids"`
	ContradictoryEvidenceIDs []string               `json:"contradictory_evidence_ids"`
	Reason                   string                 `json:"reason"`
	ProjectionEligible       bool                   `json:"projection_eligible"`
}

// ClaimSummary counts support levels across a claim set.
type ClaimSummary struct {
	Verified          int `json:"verified"`
	StronglySupported int `json:"strongly_supported"`
	Supported         int `json:"supported"`
	Weak              int `json:"weak"`
	Unsupported       int `json:"unsupported"`
	Contradicted      int `json:"contradicted"`
}

// ClaimsArtifact is the primary machine-readable multi-source claims artifact.
type ClaimsArtifact struct {
	SchemaVersion string             `json:"claim_schema_version"`
	Repository    ClaimRepositoryRef `json:"repository"`
	Claims        []ClaimRecord      `json:"claims"`
	Summary       ClaimSummary       `json:"summary"`
}

// CapabilityHighlight is a safe default profile highlight derived from strong claims.
type CapabilityHighlight struct {
	HighlightID           string   `json:"highlight_id"`
	Title                 string   `json:"title"`
	SupportLevel          string   `json:"support_level"`
	ClaimIDs              []string `json:"claim_ids"`
	SupportingEvidenceIDs []string `json:"supporting_evidence_ids"`
}

// CapabilityArea groups claims by capability category.
type CapabilityArea struct {
	AreaID   string   `json:"area_id"`
	Title    string   `json:"title"`
	ClaimIDs []string `json:"claim_ids"`
}

// ProfileArtifact is the structured capability profile projection.
type ProfileArtifact struct {
	SchemaVersion   string                `json:"profile_schema_version"`
	Repository      ClaimRepositoryRef    `json:"repository"`
	Highlights      []CapabilityHighlight `json:"highlights"`
	CapabilityAreas []CapabilityArea      `json:"capability_areas"`
	Technologies    []string              `json:"technologies"`
	ClaimIDs        []string              `json:"claim_ids"`
}

// ResumeClaimStub is the bounded claim stub used in resume synthesis input.
type ResumeClaimStub struct {
	ClaimID               string   `json:"claim_id"`
	Title                 string   `json:"title"`
	SupportLevel          string   `json:"support_level"`
	Confidence            float64  `json:"confidence"`
	SupportingEvidenceIDs []string `json:"supporting_evidence_ids"`
}

// EvidenceReference is a bounded evidence reference for resume synthesis.
type EvidenceReference struct {
	EvidenceID            string   `json:"evidence_id"`
	ClaimIDs              []string `json:"claim_ids"`
	ContradictoryClaimIDs []string `json:"contradictory_claim_ids,omitempty"`
}

// SynthesisConstraints constrains how downstream synthesis may use claims.
type SynthesisConstraints struct {
	AllowUnsupportedClaims        bool `json:"allow_unsupported_claims"`
	AllowClaimInvention           bool `json:"allow_claim_invention"`
	AllowContradictionSuppression bool `json:"allow_contradiction_suppression"`
}

// ResumeInputArtifact is the bounded synthesis input artifact.
type ResumeInputArtifact struct {
	SchemaVersion           string               `json:"resume_input_schema_version"`
	Profile                 ProfileArtifact      `json:"profile"`
	VerifiedClaims          []ResumeClaimStub    `json:"verified_claims"`
	StronglySupportedClaims []ResumeClaimStub    `json:"strongly_supported_claims"`
	TechnologySummary       []string             `json:"technology_summary"`
	EvidenceReferences      []EvidenceReference  `json:"evidence_references"`
	SynthesisConstraints    SynthesisConstraints `json:"synthesis_constraints"`
}

// BuildClaimsProfileResumeArtifacts derives the claims/profile/resume-input
// projection set from deterministic claim records.
func BuildClaimsProfileResumeArtifacts(input ClaimsProjectionInput) (ClaimsProjectionArtifacts, error) {
	if err := validateClaimsProjectionInput(input); err != nil {
		return ClaimsProjectionArtifacts{}, err
	}

	claims := normalizeClaimRecords(input.Claims)
	claimsArtifact := ClaimsArtifact{
		SchemaVersion: ClaimsSchemaVersion,
		Repository:    input.Repository,
		Claims:        claims,
		Summary:       summarizeClaims(claims),
	}
	profile := projectCapabilityProfile(input.Repository, claims, input.Technologies)
	resume := projectResumeInput(profile, claims)

	artifacts := ClaimsProjectionArtifacts{
		Claims:      claimsArtifact,
		Profile:     profile,
		ResumeInput: resume,
	}
	if err := ValidateClaimsProfileResumeArtifacts(artifacts); err != nil {
		return ClaimsProjectionArtifacts{}, err
	}
	return artifacts, nil
}

// ValidateClaimsProfileResumeArtifacts validates the three projection artifacts.
func ValidateClaimsProfileResumeArtifacts(a ClaimsProjectionArtifacts) error {
	if err := ValidateClaimsArtifact(a.Claims); err != nil {
		return fmt.Errorf("claims.json: %w", err)
	}
	if err := ValidateProfileArtifact(a.Profile); err != nil {
		return fmt.Errorf("profile.json: %w", err)
	}
	if err := ValidateResumeInputArtifact(a.ResumeInput); err != nil {
		return fmt.Errorf("resume_input.json: %w", err)
	}
	if err := validateClaimReferenceIntegrity(a.Claims, a.Profile, a.ResumeInput); err != nil {
		return err
	}
	return nil
}

// WriteClaimsProfileResumeArtifacts writes the three projection artifacts to disk.
func WriteClaimsProfileResumeArtifacts(dir string, artifacts ClaimsProjectionArtifacts) error {
	if dir == "" {
		return fmt.Errorf("output dir is required")
	}
	if err := ValidateClaimsProfileResumeArtifacts(artifacts); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := writeClaimsJSON(filepath.Join(dir, "claims.json"), artifacts.Claims); err != nil {
		return err
	}
	if err := writeClaimsJSON(filepath.Join(dir, "profile.json"), artifacts.Profile); err != nil {
		return err
	}
	if err := writeClaimsJSON(filepath.Join(dir, "resume_input.json"), artifacts.ResumeInput); err != nil {
		return err
	}
	return nil
}

func validateClaimsProjectionInput(input ClaimsProjectionInput) error {
	if input.Repository.Path == "" || input.Repository.Commit == "" {
		return fmt.Errorf("repository path and commit are required")
	}
	if len(input.Claims) == 0 {
		return fmt.Errorf("at least one claim is required")
	}
	return nil
}

func normalizeClaimRecords(in []ClaimRecord) []ClaimRecord {
	out := make([]ClaimRecord, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, claim := range in {
		claim.ClaimID = strings.TrimSpace(claim.ClaimID)
		if claim.ClaimID == "" {
			continue
		}
		if _, ok := seen[claim.ClaimID]; ok {
			continue
		}
		seen[claim.ClaimID] = struct{}{}
		claim.Title = strings.TrimSpace(claim.Title)
		claim.Category = strings.TrimSpace(claim.Category)
		claim.ClaimType = strings.TrimSpace(claim.ClaimType)
		claim.Status = strings.TrimSpace(claim.Status)
		claim.SupportLevel = strings.TrimSpace(claim.SupportLevel)
		claim.SourceOrigins = dedupeStringsSorted(claim.SourceOrigins)
		claim.SupportingEvidenceIDs = dedupeStringsSorted(claim.SupportingEvidenceIDs)
		claim.ContradictoryEvidenceIDs = dedupeStringsSorted(claim.ContradictoryEvidenceIDs)
		claim.Reason = strings.TrimSpace(claim.Reason)
		out = append(out, claim)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ClaimID < out[j].ClaimID })
	return out
}

func summarizeClaims(claims []ClaimRecord) ClaimSummary {
	var summary ClaimSummary
	for _, claim := range claims {
		switch claim.SupportLevel {
		case "verified":
			summary.Verified++
		case "strongly_supported":
			summary.StronglySupported++
		case "supported":
			summary.Supported++
		case "weak":
			summary.Weak++
		case "unsupported":
			summary.Unsupported++
		case "contradicted":
			summary.Contradicted++
		}
	}
	return summary
}

func projectCapabilityProfile(repo ClaimRepositoryRef, claims []ClaimRecord, technologies []string) ProfileArtifact {
	eligibleClaims := make([]ClaimRecord, 0, len(claims))
	for _, claim := range claims {
		if claim.ProjectionEligible &&
			(claim.VerificationClass == "" || claim.VerificationClass == VerificationProofGrade || claim.VerificationClass == VerificationStructuralInference) &&
			(claim.SupportLevel == "verified" || claim.SupportLevel == "strongly_supported" || claim.SupportLevel == "supported") {
			eligibleClaims = append(eligibleClaims, claim)
		}
	}
	highlights := make([]CapabilityHighlight, 0, len(eligibleClaims))
	for _, claim := range eligibleClaims {
		if claim.SupportLevel != "verified" && claim.SupportLevel != "strongly_supported" {
			continue
		}
		highlights = append(highlights, CapabilityHighlight{
			HighlightID:           "hl-" + claim.ClaimID,
			Title:                 claim.Title,
			SupportLevel:          claim.SupportLevel,
			ClaimIDs:              []string{claim.ClaimID},
			SupportingEvidenceIDs: append([]string(nil), claim.SupportingEvidenceIDs...),
		})
	}
	sort.Slice(highlights, func(i, j int) bool {
		if highlightRank(highlights[i].SupportLevel) != highlightRank(highlights[j].SupportLevel) {
			return highlightRank(highlights[i].SupportLevel) < highlightRank(highlights[j].SupportLevel)
		}
		return highlights[i].HighlightID < highlights[j].HighlightID
	})

	areas := make(map[string][]string)
	for _, claim := range claims {
		if claim.VerificationClass != "" && claim.VerificationClass != VerificationProofGrade && claim.VerificationClass != VerificationStructuralInference {
			continue
		}
		if claim.SupportLevel != "verified" && claim.SupportLevel != "strongly_supported" && claim.SupportLevel != "supported" {
			continue
		}
		areaID := normalizeCategoryID(claim.Category)
		if areaID == "" {
			continue
		}
		areas[areaID] = append(areas[areaID], claim.ClaimID)
	}
	areaIDs := make([]string, 0, len(areas))
	for areaID := range areas {
		areaIDs = append(areaIDs, areaID)
	}
	sort.Strings(areaIDs)
	capabilityAreas := make([]CapabilityArea, 0, len(areaIDs))
	for _, areaID := range areaIDs {
		capabilityAreas = append(capabilityAreas, CapabilityArea{
			AreaID:   areaID,
			Title:    capabilityAreaTitle(areaID),
			ClaimIDs: dedupeStringsSorted(areas[areaID]),
		})
	}

	return ProfileArtifact{
		SchemaVersion:   "1.0.0",
		Repository:      repo,
		Highlights:      highlights,
		CapabilityAreas: capabilityAreas,
		Technologies:    dedupeStringsSorted(technologies),
		ClaimIDs:        claimIDsFromRecords(claims),
	}
}

func projectResumeInput(profile ProfileArtifact, claims []ClaimRecord) ResumeInputArtifact {
	verified := make([]ResumeClaimStub, 0)
	strong := make([]ResumeClaimStub, 0)
	evidenceRefs := make(map[string]*EvidenceReference)
	for _, claim := range claims {
		stub := ResumeClaimStub{
			ClaimID:               claim.ClaimID,
			Title:                 claim.Title,
			SupportLevel:          claim.SupportLevel,
			Confidence:            claim.Confidence,
			SupportingEvidenceIDs: append([]string(nil), claim.SupportingEvidenceIDs...),
		}
		switch claim.SupportLevel {
		case "verified":
			if claim.ProjectionEligible && (claim.VerificationClass == "" || claim.VerificationClass == VerificationProofGrade || claim.VerificationClass == VerificationStructuralInference) {
				verified = append(verified, stub)
			}
		case "strongly_supported":
			if claim.ProjectionEligible && (claim.VerificationClass == "" || claim.VerificationClass == VerificationProofGrade || claim.VerificationClass == VerificationStructuralInference) {
				strong = append(strong, stub)
			}
		}
		for _, evidenceID := range append(append([]string(nil), claim.SupportingEvidenceIDs...), claim.ContradictoryEvidenceIDs...) {
			if evidenceID == "" {
				continue
			}
			ref, ok := evidenceRefs[evidenceID]
			if !ok {
				ref = &EvidenceReference{EvidenceID: evidenceID}
				evidenceRefs[evidenceID] = ref
			}
			if slicesContains(ref.ClaimIDs, claim.ClaimID) {
				// already tracked
			} else {
				ref.ClaimIDs = append(ref.ClaimIDs, claim.ClaimID)
			}
			if len(claim.ContradictoryEvidenceIDs) > 0 && slicesContains(claim.ContradictoryEvidenceIDs, evidenceID) && !slicesContains(ref.ContradictoryClaimIDs, claim.ClaimID) {
				ref.ContradictoryClaimIDs = append(ref.ContradictoryClaimIDs, claim.ClaimID)
			}
		}
	}
	sort.Slice(verified, func(i, j int) bool { return verified[i].ClaimID < verified[j].ClaimID })
	sort.Slice(strong, func(i, j int) bool { return strong[i].ClaimID < strong[j].ClaimID })
	refs := make([]EvidenceReference, 0, len(evidenceRefs))
	for _, ref := range evidenceRefs {
		ref.ClaimIDs = dedupeStringsSorted(ref.ClaimIDs)
		ref.ContradictoryClaimIDs = dedupeStringsSorted(ref.ContradictoryClaimIDs)
		refs = append(refs, *ref)
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].EvidenceID < refs[j].EvidenceID })
	return ResumeInputArtifact{
		SchemaVersion:           ResumeInputSchemaVersion,
		Profile:                 profile,
		VerifiedClaims:          verified,
		StronglySupportedClaims: strong,
		TechnologySummary:       append([]string(nil), profile.Technologies...),
		EvidenceReferences:      refs,
		SynthesisConstraints: SynthesisConstraints{
			AllowUnsupportedClaims:        false,
			AllowClaimInvention:           false,
			AllowContradictionSuppression: false,
		},
	}
}

func validateClaimReferenceIntegrity(claims ClaimsArtifact, profile ProfileArtifact, resume ResumeInputArtifact) error {
	claimIndex := make(map[string]struct{}, len(claims.Claims))
	for _, claim := range claims.Claims {
		claimIndex[claim.ClaimID] = struct{}{}
	}
	for _, highlight := range profile.Highlights {
		for _, claimID := range highlight.ClaimIDs {
			if _, ok := claimIndex[claimID]; !ok {
				return fmt.Errorf("profile highlight references unknown claim %q", claimID)
			}
		}
	}
	for _, area := range profile.CapabilityAreas {
		for _, claimID := range area.ClaimIDs {
			if _, ok := claimIndex[claimID]; !ok {
				return fmt.Errorf("profile capability area references unknown claim %q", claimID)
			}
		}
	}
	for _, stub := range append(append([]ResumeClaimStub(nil), resume.VerifiedClaims...), resume.StronglySupportedClaims...) {
		if _, ok := claimIndex[stub.ClaimID]; !ok {
			return fmt.Errorf("resume input references unknown claim %q", stub.ClaimID)
		}
	}
	return nil
}

func ValidateClaimsArtifact(a ClaimsArtifact) error {
	if a.SchemaVersion != ClaimsSchemaVersion {
		return fmt.Errorf("claim_schema_version is required")
	}
	if a.Repository.Path == "" || a.Repository.Commit == "" {
		return fmt.Errorf("repository.path and repository.commit are required")
	}
	if len(a.Claims) == 0 {
		return fmt.Errorf("claims is required")
	}
	ids := make(map[string]struct{}, len(a.Claims))
	for i, claim := range a.Claims {
		if claim.ClaimID == "" {
			return fmt.Errorf("claims[%d]: claim_id is required", i)
		}
		if _, ok := ids[claim.ClaimID]; ok {
			return fmt.Errorf("claims[%d]: duplicate claim_id %q", i, claim.ClaimID)
		}
		ids[claim.ClaimID] = struct{}{}
		if claim.Title == "" || claim.Category == "" || claim.ClaimType == "" {
			return fmt.Errorf("claims[%d]: title, category, and claim_type are required", i)
		}
		if !validClaimType(claim.ClaimType) {
			return fmt.Errorf("claims[%d]: invalid claim_type %q", i, claim.ClaimType)
		}
		if !validClaimStatus(claim.Status) {
			return fmt.Errorf("claims[%d]: invalid status %q", i, claim.Status)
		}
		if !validClaimSupportLevel(claim.SupportLevel) {
			return fmt.Errorf("claims[%d]: invalid support_level %q", i, claim.SupportLevel)
		}
		if claim.Confidence < 0 || claim.Confidence > 1 {
			return fmt.Errorf("claims[%d]: confidence must be normalized", i)
		}
		// Validate verification_class when present.
		if claim.VerificationClass != "" && !claim.VerificationClass.IsValid() {
			return fmt.Errorf("claims[%d]: invalid verification_class %q", i, claim.VerificationClass)
		}
		// Validate scenario_applicability when present: at least one scenario must be true.
		if claim.ScenarioApplicability != nil {
			sa := claim.ScenarioApplicability
			if !sa.Hiring && !sa.OutsourceAcceptance && !sa.PMAcceptance {
				return fmt.Errorf("claims[%d]: scenario_applicability must declare at least one applicable scenario", i)
			}
		}
		// Cross-check: proof_grade verification requires strong support evidence.
		if claim.VerificationClass == VerificationProofGrade {
			if claim.SupportLevel != "verified" && claim.SupportLevel != "strongly_supported" {
				return fmt.Errorf("claims[%d]: proof_grade verification_class requires verified or strongly_supported support_level, got %q", i, claim.SupportLevel)
			}
		}
		if len(claim.SourceOrigins) == 0 {
			return fmt.Errorf("claims[%d]: source_origins is required", i)
		}
		if len(claim.SupportingEvidenceIDs) == 0 && len(claim.ContradictoryEvidenceIDs) == 0 {
			return fmt.Errorf("claims[%d]: at least one supporting or contradictory evidence id is required", i)
		}
		if claim.ProjectionEligible && claim.SupportLevel != "verified" && claim.SupportLevel != "strongly_supported" {
			return fmt.Errorf("claims[%d]: projection_eligible is only allowed for verified or strongly_supported claims", i)
		}
		if !claim.ProjectionEligible && (claim.SupportLevel == "verified" || claim.SupportLevel == "strongly_supported") {
			// Conservative by default: verified or strongly_supported claims should normally
			// be projection eligible, but we do not fail this path to preserve compatibility
			// with gradual migration fixtures.
		}
	}
	return nil
}

func ValidateProfileArtifact(a ProfileArtifact) error {
	if a.SchemaVersion != ProfileSchemaVersion {
		return fmt.Errorf("profile_schema_version is required")
	}
	if a.Repository.Path == "" || a.Repository.Commit == "" {
		return fmt.Errorf("repository.path and repository.commit are required")
	}
	for i, highlight := range a.Highlights {
		if highlight.HighlightID == "" || highlight.Title == "" {
			return fmt.Errorf("highlights[%d]: highlight_id and title are required", i)
		}
		if !validClaimSupportLevel(highlight.SupportLevel) {
			return fmt.Errorf("highlights[%d]: invalid support_level %q", i, highlight.SupportLevel)
		}
		if highlight.SupportLevel != "verified" && highlight.SupportLevel != "strongly_supported" {
			return fmt.Errorf("highlights[%d]: default highlights must be verified or strongly_supported", i)
		}
		if len(highlight.ClaimIDs) == 0 || len(highlight.SupportingEvidenceIDs) == 0 {
			return fmt.Errorf("highlights[%d]: claim_ids and supporting_evidence_ids are required", i)
		}
	}
	for i, area := range a.CapabilityAreas {
		if area.AreaID == "" || area.Title == "" {
			return fmt.Errorf("capability_areas[%d]: area_id and title are required", i)
		}
		if len(area.ClaimIDs) == 0 {
			return fmt.Errorf("capability_areas[%d]: claim_ids are required", i)
		}
	}
	if len(a.ClaimIDs) == 0 {
		return fmt.Errorf("claim_ids are required")
	}
	return nil
}

func ValidateResumeInputArtifact(a ResumeInputArtifact) error {
	if a.SchemaVersion != ResumeInputSchemaVersion {
		return fmt.Errorf("resume_input_schema_version is required")
	}
	if err := ValidateProfileArtifact(a.Profile); err != nil {
		return err
	}
	for i, stub := range a.VerifiedClaims {
		if err := validateResumeClaimStub(stub, i, "verified_claims"); err != nil {
			return err
		}
		if stub.SupportLevel != "verified" {
			return fmt.Errorf("verified_claims[%d]: support_level must be verified", i)
		}
	}
	for i, stub := range a.StronglySupportedClaims {
		if err := validateResumeClaimStub(stub, i, "strongly_supported_claims"); err != nil {
			return err
		}
		if stub.SupportLevel != "strongly_supported" {
			return fmt.Errorf("strongly_supported_claims[%d]: support_level must be strongly_supported", i)
		}
	}
	for i, ref := range a.EvidenceReferences {
		if ref.EvidenceID == "" {
			return fmt.Errorf("evidence_references[%d]: evidence_id is required", i)
		}
		if len(ref.ClaimIDs) == 0 {
			return fmt.Errorf("evidence_references[%d]: claim_ids are required", i)
		}
	}
	return validateSynthesisConstraints(a.SynthesisConstraints)
}

func validateResumeClaimStub(stub ResumeClaimStub, index int, label string) error {
	if stub.ClaimID == "" || stub.Title == "" {
		return fmt.Errorf("%s[%d]: claim_id and title are required", label, index)
	}
	if !validClaimSupportLevel(stub.SupportLevel) {
		return fmt.Errorf("%s[%d]: invalid support_level %q", label, index, stub.SupportLevel)
	}
	if stub.Confidence < 0 || stub.Confidence > 1 {
		return fmt.Errorf("%s[%d]: confidence must be normalized", label, index)
	}
	if len(stub.SupportingEvidenceIDs) == 0 {
		return fmt.Errorf("%s[%d]: supporting_evidence_ids are required", label, index)
	}
	return nil
}

func validateSynthesisConstraints(c SynthesisConstraints) error {
	if c.AllowUnsupportedClaims {
		return fmt.Errorf("allow_unsupported_claims must be false")
	}
	if c.AllowClaimInvention {
		return fmt.Errorf("allow_claim_invention must be false")
	}
	if c.AllowContradictionSuppression {
		return fmt.Errorf("allow_contradiction_suppression must be false")
	}
	return nil
}

func writeClaimsJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

func claimIDsFromRecords(claims []ClaimRecord) []string {
	ids := make([]string, 0, len(claims))
	for _, claim := range claims {
		ids = append(ids, claim.ClaimID)
	}
	return dedupeStringsSorted(ids)
}

func validClaimSupportLevel(level string) bool {
	switch level {
	case "verified", "strongly_supported", "supported", "weak", "unsupported", "contradicted":
		return true
	default:
		return false
	}
}

func validClaimStatus(status string) bool {
	switch status {
	case "accepted", "downgraded", "rejected", "unknown":
		return true
	default:
		return false
	}
}

func validClaimType(claimType string) bool {
	switch claimType {
	case "implementation", "architecture", "security_maturity", "testing_maturity", "evaluation_maturity", "operational_maturity":
		return true
	default:
		return false
	}
}

func highlightRank(level string) int {
	switch level {
	case "verified":
		return 0
	case "strongly_supported":
		return 1
	case "supported":
		return 2
	case "weak":
		return 3
	case "unsupported":
		return 4
	case "contradicted":
		return 5
	default:
		return 99
	}
}

func normalizeCategoryID(category string) string {
	cleaned := strings.ToLower(strings.TrimSpace(category))
	cleaned = strings.ReplaceAll(cleaned, " ", "_")
	cleaned = strings.ReplaceAll(cleaned, "-", "_")
	return cleaned
}

func capabilityAreaTitle(areaID string) string {
	switch areaID {
	case "architecture":
		return "Architecture and System Design"
	case "security_maturity":
		return "Security Maturity"
	case "testing_maturity":
		return "Testing Maturity"
	case "evaluation_maturity":
		return "Evaluation Maturity"
	case "operational_maturity":
		return "Operational Maturity"
	default:
		return strings.Title(strings.ReplaceAll(areaID, "_", " "))
	}
}

func slicesContains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
