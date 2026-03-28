package claims

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/rules"
)

func TestNormalizeSourceType(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in, want string
	}{
		{"readme", "readme"},
		{"doc", "doc"},
		{"docs", "doc"},
		{"documentation", "doc"},
		{"code", "code"},
		{"test", "test"},
		{"tests", "test"},
		{"eval", "eval"},
		{"evaluation", "eval"},
		{"EVAL", "eval"},
		{"unknown", "code"},
		{"", "code"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := normalizeSourceType(tt.in); got != tt.want {
				t.Fatalf("normalizeSourceType(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestNormalizeClaimCategory(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in, want string
	}{
		{"security", "security"},
		{"security_maturity", "security"},
		{"architecture", "architecture"},
		{"architectural", "architecture"},
		{"testing", "testing"},
		{"testing_maturity", "testing"},
		{"evaluation", "evaluation"},
		{"evaluation_maturity", "evaluation"},
		{"operational", "operational"},
		{"operational_maturity", "operational"},
		{"implementation", "implementation"},
		{"general", "general"},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := normalizeClaimCategory(tt.in); got != tt.want {
				t.Fatalf("normalizeClaimCategory(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestInferClaimOrigin(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in, want string
	}{
		{"readme", string(ClaimOriginReadmeExtracted)},
		{"doc", string(ClaimOriginDocExtracted)},
		{"test", string(ClaimOriginTestInferred)},
		{"eval", string(ClaimOriginEvalInferred)},
		{"code", string(ClaimOriginCodeInferred)},
		{"unknown", string(ClaimOriginCodeInferred)},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := inferClaimOrigin(tt.in); got != tt.want {
				t.Fatalf("inferClaimOrigin(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestInferClaimTypeFromDefinition(t *testing.T) {
	t.Parallel()
	tests := []struct {
		category, want string
	}{
		{"architecture", "architecture"},
		{"security", "security_maturity"},
		{"testing", "testing_maturity"},
		{"evaluation", "evaluation_maturity"},
		{"operational", "operational_maturity"},
		{"implementation", "implementation"},
		{"general", "implementation"},
		{"", "implementation"},
	}
	for _, tt := range tests {
		t.Run(tt.category, func(t *testing.T) {
			claim := Claim{Category: tt.category}
			if got := inferClaimTypeFromDefinition(claim); got != tt.want {
				t.Fatalf("inferClaimTypeFromDefinition(cat=%q) = %q, want %q", tt.category, got, tt.want)
			}
		})
	}
}

func TestInferClaimTypeFromSource(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, sourceType, text, want string
	}{
		{"test source", "test", "anything", "testing_maturity"},
		{"eval source", "eval", "anything", "evaluation_maturity"},
		{"doc with security text", "doc", "auth middleware", "security_maturity"},
		{"readme with arch text", "readme", "pipeline architecture", "architecture"},
		{"code with test text", "code", "test coverage", "testing_maturity"},
		{"unknown source", "unknown", "anything", "implementation"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := inferClaimTypeFromSource(tt.sourceType, tt.text); got != tt.want {
				t.Fatalf("inferClaimTypeFromSource(%q, %q) = %q, want %q", tt.sourceType, tt.text, got, tt.want)
			}
		})
	}
}

func TestInferClaimTypeFromText(t *testing.T) {
	t.Parallel()
	tests := []struct {
		text, want string
	}{
		{"security hardening", "security_maturity"},
		{"auth middleware", "security_maturity"},
		{"secret management", "security_maturity"},
		{"architecture overview", "architecture"},
		{"pipeline design", "architecture"},
		{"service layer", "architecture"},
		{"repository pattern", "architecture"},
		{"test coverage", "testing_maturity"},
		{"eval metrics", "evaluation_maturity"},
		{"benchmark results", "evaluation_maturity"},
		{"operational runbook", "operational_maturity"},
		{"deploy workflow", "operational_maturity"},
		{"runtime config", "operational_maturity"},
		{"simple module", "implementation"},
	}
	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			if got := inferClaimTypeFromText(tt.text); got != tt.want {
				t.Fatalf("inferClaimTypeFromText(%q) = %q, want %q", tt.text, got, tt.want)
			}
		})
	}
}

func TestInferClaimCategory(t *testing.T) {
	t.Parallel()
	tests := []struct {
		text, sourceType, want string
	}{
		{"security review", "code", "security"},
		{"auth middleware", "code", "security"},
		{"secret rotation", "code", "security"},
		{"architecture design", "code", "architecture"},
		{"pipeline orchestration", "code", "architecture"},
		{"service mesh", "code", "architecture"},
		{"repository layer", "code", "architecture"},
		{"test suite", "code", "testing"},
		{"eval harness", "code", "evaluation"},
		{"benchmark run", "code", "evaluation"},
		{"operational config", "code", "operational"},
		{"deploy script", "code", "operational"},
		{"runtime monitor", "code", "operational"},
		{"helper function", "code", "implementation"},
		{"random notes", "doc", "general"},
	}
	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			if got := inferClaimCategory(tt.text, tt.sourceType); got != tt.want {
				t.Fatalf("inferClaimCategory(%q, %q) = %q, want %q", tt.text, tt.sourceType, got, tt.want)
			}
		})
	}
}

func TestEdgeTypeForSource(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		sourceType   string
		status       string
		supportLevel string
		ev           SourceEvidenceRecord
		claimID      string
		want         string
	}{
		{
			name: "contradiction", sourceType: "code", status: ClaimStatusRejected,
			supportLevel: string(ClaimSupportContradicted),
			ev:           SourceEvidenceRecord{Contradicts: []string{"claim.x"}},
			claimID:      "claim.x", want: "contradicted_by",
		},
		{
			name: "doc source", sourceType: "doc", status: ClaimStatusAccepted,
			supportLevel: string(ClaimSupportSupported),
			ev:           SourceEvidenceRecord{ClaimIDs: []string{"claim.x"}},
			claimID:      "claim.x", want: "documented_by",
		},
		{
			name: "readme source", sourceType: "readme", status: ClaimStatusAccepted,
			supportLevel: string(ClaimSupportSupported),
			ev:           SourceEvidenceRecord{ClaimIDs: []string{"claim.x"}},
			claimID:      "claim.x", want: "documented_by",
		},
		{
			name: "code source", sourceType: "code", status: ClaimStatusAccepted,
			supportLevel: string(ClaimSupportVerified),
			ev:           SourceEvidenceRecord{ClaimIDs: []string{"claim.x"}},
			claimID:      "claim.x", want: "validated_by",
		},
		{
			name: "test source", sourceType: "test", status: ClaimStatusAccepted,
			supportLevel: string(ClaimSupportVerified),
			ev:           SourceEvidenceRecord{ClaimIDs: []string{"claim.x"}},
			claimID:      "claim.x", want: "validated_by",
		},
		{
			name: "eval source", sourceType: "eval", status: ClaimStatusAccepted,
			supportLevel: string(ClaimSupportVerified),
			ev:           SourceEvidenceRecord{ClaimIDs: []string{"claim.x"}},
			claimID:      "claim.x", want: "validated_by",
		},
		{
			// "unknown_type" normalizes to "code", so hits validated_by
			name: "unknown_type is code", sourceType: "unknown_type", status: ClaimStatusAccepted,
			supportLevel: string(ClaimSupportSupported),
			ev:           SourceEvidenceRecord{ClaimIDs: []string{"claim.x"}},
			claimID:      "claim.x", want: "validated_by",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := edgeTypeForSource(tt.sourceType, tt.status, tt.supportLevel, tt.ev, tt.claimID)
			if got != tt.want {
				t.Fatalf("edgeTypeForSource(%q, %q, %q, ..., %q) = %q, want %q", tt.sourceType, tt.status, tt.supportLevel, tt.claimID, got, tt.want)
			}
		})
	}
}

func TestAssessClaimSupport(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name                string
		candidate           ClaimCandidate
		supportSourceTypes  []string
		contradictSrcTypes  []string
		supportIDs          []string
		contradictIDs       []string
		wantLevel           string
		wantStatus          string
	}{
		{
			name:       "no evidence at all",
			candidate:  ClaimCandidate{},
			wantLevel:  string(ClaimSupportUnsupported),
			wantStatus: ClaimStatusUnknown,
		},
		{
			name:               "contradiction stronger than support",
			candidate:          ClaimCandidate{},
			supportSourceTypes: []string{"doc"},
			contradictSrcTypes: []string{"code"},
			supportIDs:         []string{"ev-1"},
			contradictIDs:      []string{"ev-2"},
			wantLevel:          string(ClaimSupportContradicted),
			wantStatus:         ClaimStatusRejected,
		},
		{
			name:               "doc-only support is weak",
			candidate:          ClaimCandidate{},
			supportSourceTypes: []string{"doc"},
			supportIDs:         []string{"ev-1"},
			wantLevel:          string(ClaimSupportWeak),
			wantStatus:         ClaimStatusDowngraded,
		},
		{
			name:               "verified: 2 strong + 2 distinct + no contradictions",
			candidate:          ClaimCandidate{},
			supportSourceTypes: []string{"code", "test"},
			supportIDs:         []string{"ev-1", "ev-2"},
			wantLevel:          string(ClaimSupportVerified),
			wantStatus:         ClaimStatusAccepted,
		},
		{
			name:               "strongly supported: 1 strong + 2 distinct + no contradictions",
			candidate:          ClaimCandidate{},
			supportSourceTypes: []string{"code", "doc"},
			supportIDs:         []string{"ev-1", "ev-2"},
			wantLevel:          string(ClaimSupportStronglySupported),
			wantStatus:         ClaimStatusAccepted,
		},
		{
			name:               "default with contradiction",
			candidate:          ClaimCandidate{},
			supportSourceTypes: []string{"code"},
			contradictSrcTypes: []string{"doc"},
			supportIDs:         []string{"ev-1"},
			contradictIDs:      []string{"ev-2"},
			wantLevel:          string(ClaimSupportContradicted),
			wantStatus:         ClaimStatusRejected,
		},
		{
			name:               "default doc origin",
			candidate:          ClaimCandidate{Origin: string(ClaimOriginDocExtracted)},
			supportSourceTypes: []string{"code"},
			supportIDs:         []string{"ev-1"},
			wantLevel:          string(ClaimSupportSupported),
			wantStatus:         ClaimStatusDowngraded,
		},
		{
			name:               "default readme origin",
			candidate:          ClaimCandidate{Origin: string(ClaimOriginReadmeExtracted)},
			supportSourceTypes: []string{"code"},
			supportIDs:         []string{"ev-1"},
			wantLevel:          string(ClaimSupportSupported),
			wantStatus:         ClaimStatusDowngraded,
		},
		{
			name:               "default code origin single source",
			candidate:          ClaimCandidate{Origin: string(ClaimOriginCodeInferred)},
			supportSourceTypes: []string{"code"},
			supportIDs:         []string{"ev-1"},
			wantLevel:          string(ClaimSupportSupported),
			wantStatus:         ClaimStatusDowngraded,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			level, status, _, _ := assessClaimSupport(tt.candidate, tt.supportSourceTypes, tt.contradictSrcTypes, tt.supportIDs, tt.contradictIDs)
			if level != tt.wantLevel {
				t.Fatalf("level = %q, want %q", level, tt.wantLevel)
			}
			if status != tt.wantStatus {
				t.Fatalf("status = %q, want %q", status, tt.wantStatus)
			}
		})
	}
}

func TestSourceEvidencePath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in, want string
	}{
		{"", "unknown"},
		{"internal/foo.go", "internal/foo.go"},
		{"internal\\foo.go", "internal/foo.go"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := sourceEvidencePath(tt.in); got != tt.want {
				t.Fatalf("sourceEvidencePath(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestHumanizeClaimID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in, want string
	}{
		{"architecture.multi_agent_pipeline", "Architecture Multi Agent Pipeline"},
		{"security_maturity.auth-middleware", "Security Maturity Auth Middleware"},
		{"", ""},
		{"   ", "   "}, // whitespace-only returns raw
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := humanizeClaimID(tt.in); got != tt.want {
				t.Fatalf("humanizeClaimID(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestCandidateReason(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		cand   *ClaimCandidate
		want   string
	}{
		{
			"no evidence", &ClaimCandidate{}, "seeded claim without supporting evidence",
		},
		{
			"readme origin", &ClaimCandidate{
				CandidateEvidenceIDs: []string{"ev-1"},
				Origin:               string(ClaimOriginReadmeExtracted),
			}, "documentation-derived claim candidate awaiting verification",
		},
		{
			"doc origin", &ClaimCandidate{
				CandidateEvidenceIDs: []string{"ev-1"},
				Origin:               string(ClaimOriginDocExtracted),
			}, "documentation-derived claim candidate awaiting verification",
		},
		{
			"code origin", &ClaimCandidate{
				CandidateEvidenceIDs: []string{"ev-1"},
				Origin:               string(ClaimOriginCodeInferred),
			}, "evidence-backed claim candidate",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := candidateReason(tt.cand, nil); got != tt.want {
				t.Fatalf("candidateReason() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSourceTypeStrength(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want int
	}{
		{"code", 4},
		{"test", 3},
		{"eval", 3},
		{"doc", 2},
		{"readme", 1},
		{"unknown", 4}, // normalizeSourceType("unknown") -> "code" -> 4
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := sourceTypeStrength(tt.in); got != tt.want {
				t.Fatalf("sourceTypeStrength(%q) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

func TestOriginRank(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want int
	}{
		{string(ClaimOriginCodeInferred), 5},
		{string(ClaimOriginTestInferred), 4},
		{string(ClaimOriginEvalInferred), 4},
		{string(ClaimOriginDocExtracted), 3},
		{string(ClaimOriginReadmeExtracted), 2},
		{string(ClaimOriginRuleInferred), 1},
		{"unknown", 0},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := originRank(tt.in); got != tt.want {
				t.Fatalf("originRank(%q) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

func TestCanonicalizeClaimID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in, want string
	}{
		{"architecture.3_agent_pipeline", "architecture.multi_agent_pipeline"},
		{"architecture.agent_architecture", "architecture.multi_agent_pipeline"},
		{"architecture.multi_agent_architecture", "architecture.multi_agent_pipeline"},
		{"architecture.secure_answer", "architecture.secure_answer_pipeline"},
		{"operational_maturity.langfuse_tracing", "operational_maturity.structured_tracing"},
		{"operational_maturity.tracing", "operational_maturity.structured_tracing"},
		{"evaluation_maturity.red_team_evaluation", "evaluation_maturity.adversarial_evaluation"},
		{"evaluation_maturity.redteam_evaluation", "evaluation_maturity.adversarial_evaluation"},
		{"architecture.some_other", "architecture.some_other"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := canonicalizeClaimID(tt.in); got != tt.want {
				t.Fatalf("canonicalizeClaimID(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestShouldPruneClaimID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		claimID    string
		sourceType string
		want       bool
	}{
		{"empty", "", "code", true},
		{"general prefix", "general.something", "code", true},
		{"file extension .py", "architecture.module.py", "code", true},
		{"file extension .ts", "architecture.module.ts", "code", true},
		{"file extension .md", "architecture.module.md", "code", true},
		{"chunk prefix", "architecture.chunk_123", "code", true},
		{"task prefix", "architecture.task_3", "code", true},
		{"path separator /", "architecture/foo", "code", true},
		{"path separator \\", "architecture\\foo", "code", true},
		{"doc non-curated", "architecture.random_claim", "doc", true},
		{"readme non-curated", "architecture.random_claim", "readme", true},
		{"doc curated", "architecture.multi_agent_pipeline", "doc", false},
		{"code normal", "architecture.good_claim", "code", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldPruneClaimID(tt.claimID, tt.sourceType); got != tt.want {
				t.Fatalf("shouldPruneClaimID(%q, %q) = %v, want %v", tt.claimID, tt.sourceType, got, tt.want)
			}
		})
	}
}

func TestIsCuratedDocumentationClaim(t *testing.T) {
	t.Parallel()
	curated := []string{
		"architecture.multi_agent_pipeline",
		"architecture.secure_answer_pipeline",
		"operational_maturity.structured_tracing",
		"evaluation_maturity.adversarial_evaluation",
		"evaluation_maturity.quality_gating",
		"security_maturity.auth_middleware",
		"security_maturity.defense_in_depth",
	}
	for _, id := range curated {
		if !isCuratedDocumentationClaim(id) {
			t.Fatalf("expected %q to be curated", id)
		}
	}
	if isCuratedDocumentationClaim("architecture.random") {
		t.Fatal("expected random claim to not be curated")
	}
}

func TestInferClaimIDsFromSourceEvidence_AllKeywordBranches(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		ev      SourceEvidenceRecord
		wantLen int
		wantID  string
	}{
		{
			name:    "multi-agent",
			ev:      SourceEvidenceRecord{SourceType: "code", Summary: "multi-agent orchestrator"},
			wantLen: 1, wantID: "architecture.multi_agent_pipeline",
		},
		{
			name:    "secure_answer",
			ev:      SourceEvidenceRecord{SourceType: "code", Summary: "secure_answer pipeline"},
			wantLen: 1, wantID: "architecture.secure_answer_pipeline",
		},
		{
			name:    "langfuse tracing",
			ev:      SourceEvidenceRecord{SourceType: "code", Summary: "langfuse integration"},
			wantLen: 1, wantID: "operational_maturity.structured_tracing",
		},
		{
			name:    "observability",
			ev:      SourceEvidenceRecord{SourceType: "code", Summary: "observability stack"},
			wantLen: 1, wantID: "operational_maturity.structured_tracing",
		},
		{
			name:    "adversarial eval",
			ev:      SourceEvidenceRecord{SourceType: "code", Summary: "adversarial testing"},
			wantLen: 1, wantID: "evaluation_maturity.adversarial_evaluation",
		},
		{
			name:    "red-team",
			ev:      SourceEvidenceRecord{SourceType: "code", Summary: "red-team evaluation"},
			wantLen: 1, wantID: "evaluation_maturity.adversarial_evaluation",
		},
		{
			name:    "benchmark eval",
			ev:      SourceEvidenceRecord{SourceType: "code", Summary: "benchmark suite"},
			wantLen: 1, wantID: "evaluation_maturity.quality_gating",
		},
		{
			name:    "auth middleware",
			ev:      SourceEvidenceRecord{SourceType: "code", Summary: "auth jwt handler"},
			wantLen: 1, wantID: "security_maturity.auth_middleware",
		},
		{
			name:    "security hardening",
			ev:      SourceEvidenceRecord{SourceType: "code", Summary: "security hardening"},
			wantLen: 1, wantID: "security_maturity.defense_in_depth",
		},
		{
			name:    "defense-in-depth",
			ev:      SourceEvidenceRecord{SourceType: "code", Summary: "defense-in-depth layers"},
			wantLen: 1, wantID: "security_maturity.defense_in_depth",
		},
		{
			name: "code fallback with module_kind",
			ev: SourceEvidenceRecord{
				SourceType: "code", Summary: "helper module",
				Metadata: map[string]string{"module_kind": "scheduler"},
			},
			wantLen: 1, wantID: "architecture.scheduler",
		},
		{
			name: "test fallback with test_kind",
			ev: SourceEvidenceRecord{
				SourceType: "test", Summary: "unit tests",
				Metadata: map[string]string{"test_kind": "integration"},
			},
			wantLen: 1, wantID: "testing_maturity.integration",
		},
		{
			// security_test in test_kind triggers "security" keyword -> defense_in_depth
			name: "test fallback security_test",
			ev: SourceEvidenceRecord{
				SourceType: "test", Summary: "runs checks",
				Metadata: map[string]string{"test_kind": "security_test"},
			},
			wantLen: 1, wantID: "security_maturity.defense_in_depth",
		},
		{
			name: "eval fallback with dataset_id",
			ev: SourceEvidenceRecord{
				SourceType: "eval", Summary: "runs dataset",
				Metadata: map[string]string{"dataset_id": "accuracy_v2"},
			},
			wantLen: 1, wantID: "evaluation_maturity.accuracy_v2",
		},
		{
			name: "eval fallback empty dataset_id",
			ev: SourceEvidenceRecord{
				SourceType: "eval", Summary: "runs checks",
				Metadata: map[string]string{},
			},
			wantLen: 1, wantID: "evaluation_maturity.evaluation_asset",
		},
		{
			name:    "doc unmatched returns nil",
			ev:      SourceEvidenceRecord{SourceType: "doc", Summary: "random notes"},
			wantLen: 0,
		},
		{
			name:    "readme unmatched returns nil",
			ev:      SourceEvidenceRecord{SourceType: "readme", Summary: "project readme"},
			wantLen: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inferClaimIDsFromSourceEvidence(tt.ev)
			if len(got) != tt.wantLen {
				t.Fatalf("got %d claim IDs %v, want %d", len(got), got, tt.wantLen)
			}
			if tt.wantLen > 0 && got[0] != tt.wantID {
				t.Fatalf("got %q, want %q", got[0], tt.wantID)
			}
		})
	}
}

func TestCloneSourceEvidenceRecords(t *testing.T) {
	t.Parallel()
	orig := []SourceEvidenceRecord{
		{
			EvidenceID: "ev-1",
			Spans:      []SourceSpan{{File: "a.go", LineStart: 1, LineEnd: 2}},
			EntityIDs:  []string{"ent-1"},
			Metadata:   map[string]string{"key": "val"},
			ClaimIDs:   []string{"c1"},
			Supports:   []string{"s1"},
			Contradicts: []string{"ct1"},
		},
	}
	cloned := cloneSourceEvidenceRecords(orig)
	if len(cloned) != 1 {
		t.Fatalf("expected 1 record, got %d", len(cloned))
	}
	// Mutate original to ensure deep copy
	orig[0].Metadata["key"] = "changed"
	orig[0].Spans[0].File = "changed.go"
	orig[0].EntityIDs[0] = "changed"
	if cloned[0].Metadata["key"] != "val" {
		t.Fatal("metadata was not deep copied")
	}
	if cloned[0].Spans[0].File != "a.go" {
		t.Fatal("spans was not deep copied")
	}
	if cloned[0].EntityIDs[0] != "ent-1" {
		t.Fatal("entity IDs was not deep copied")
	}
}

func TestSourceEvidenceMatchesClaim(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		ev      SourceEvidenceRecord
		claimID string
		want    bool
	}{
		{
			name:    "match via ClaimIDs",
			ev:      SourceEvidenceRecord{SourceType: "code", ClaimIDs: []string{"architecture.foo"}},
			claimID: "architecture.foo",
			want:    true,
		},
		{
			name:    "match via Supports",
			ev:      SourceEvidenceRecord{SourceType: "code", Supports: []string{"architecture.foo"}},
			claimID: "architecture.foo",
			want:    true,
		},
		{
			name:    "match via Contradicts",
			ev:      SourceEvidenceRecord{SourceType: "code", Contradicts: []string{"architecture.foo"}},
			claimID: "architecture.foo",
			want:    true,
		},
		{
			name:    "no match",
			ev:      SourceEvidenceRecord{SourceType: "code", ClaimIDs: []string{"architecture.bar"}},
			claimID: "architecture.foo",
			want:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sourceEvidenceMatchesClaim(tt.ev, tt.claimID); got != tt.want {
				t.Fatalf("sourceEvidenceMatchesClaim() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsClaimContradiction(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		ev      SourceEvidenceRecord
		claimID string
		want    bool
	}{
		{
			name:    "explicit contradicts",
			ev:      SourceEvidenceRecord{Contradicts: []string{"claim.x"}},
			claimID: "claim.x",
			want:    true,
		},
		{
			name:    "contradiction origin",
			ev:      SourceEvidenceRecord{Origin: "contradiction"},
			claimID: "claim.x",
			want:    true,
		},
		{
			name:    "no contradiction",
			ev:      SourceEvidenceRecord{Origin: "code_inferred"},
			claimID: "claim.x",
			want:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isClaimContradiction(tt.ev, tt.claimID); got != tt.want {
				t.Fatalf("isClaimContradiction() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBuildSourceEvidenceFromExecution_NoEvidence(t *testing.T) {
	t.Parallel()

	claimSet := &ClaimSet{
		Claims: []Claim{{ID: "auth.jwt", RuleIDs: []string{"SEC-001"}}},
	}
	exec := rules.ExecutionResult{
		Findings: []rules.Finding{
			{
				RuleID:     "SEC-001",
				Status:     rules.StatusFail,
				Confidence: rules.ConfidenceHigh,
				Message:    "JWT not found",
			},
		},
	}
	records := buildSourceEvidenceFromExecution(claimSet, exec)
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if len(records[0].Contradicts) == 0 {
		t.Fatal("expected contradicts to be populated for failed finding")
	}
}

func TestBuildSourceEvidenceFromExecution_UnknownStatus(t *testing.T) {
	t.Parallel()

	exec := rules.ExecutionResult{
		Findings: []rules.Finding{
			{
				RuleID:  "RULE-X",
				Status:  rules.StatusUnknown,
				Message: "Could not determine",
			},
		},
	}
	records := buildSourceEvidenceFromExecution(nil, exec)
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if len(records[0].Supports) != 0 || len(records[0].Contradicts) != 0 {
		t.Fatal("unknown status should not have supports or contradicts")
	}
}

func TestBuildSourceEvidenceFromExecution_WithEvidenceUnknownStatus(t *testing.T) {
	t.Parallel()

	exec := rules.ExecutionResult{
		Findings: []rules.Finding{
			{
				RuleID:  "RULE-Y",
				Status:  rules.StatusUnknown,
				Message: "Uncertain",
				Evidence: []rules.Evidence{
					{File: "a.go", LineStart: 1, LineEnd: 5},
				},
			},
		},
	}
	records := buildSourceEvidenceFromExecution(nil, exec)
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if len(records[0].Supports) != 0 || len(records[0].Contradicts) != 0 {
		t.Fatal("unknown status should not populate supports or contradicts")
	}
}

func TestVerifyClaimCandidates_SortOrder(t *testing.T) {
	t.Parallel()

	candidates := []ClaimCandidate{
		{ClaimID: "z.claim", CandidateEvidenceIDs: []string{"ev-1"}},
		{ClaimID: "a.claim", CandidateEvidenceIDs: []string{"ev-2"}},
	}
	evidence := []SourceEvidenceRecord{
		{EvidenceID: "ev-1", SourceType: "code", ClaimIDs: []string{"z.claim"}},
		{EvidenceID: "ev-2", SourceType: "code", ClaimIDs: []string{"a.claim"}},
	}
	verified := VerifyClaimCandidates(candidates, evidence)
	if len(verified) != 2 {
		t.Fatalf("expected 2 verified, got %d", len(verified))
	}
	if verified[0].ClaimID != "a.claim" {
		t.Fatalf("expected sorted by claim ID, got %q first", verified[0].ClaimID)
	}
}

func TestExtractClaimCandidates_InferredFromCode(t *testing.T) {
	t.Parallel()

	candidates := ExtractClaimCandidates(nil, []SourceEvidenceRecord{
		{
			EvidenceID: "ev-code",
			SourceType: "code",
			Origin:     string(ClaimOriginCodeInferred),
			Path:       "internal/scheduler/scheduler.go",
			Summary:    "scheduler module",
			Metadata:   map[string]string{"module_kind": "scheduler"},
		},
	})
	if len(candidates) == 0 {
		t.Fatal("expected at least 1 candidate")
	}
	if candidates[0].ClaimID != "architecture.scheduler" {
		t.Fatalf("expected architecture.scheduler, got %q", candidates[0].ClaimID)
	}
	if candidates[0].Origin != string(ClaimOriginCodeInferred) {
		t.Fatalf("expected code_inferred origin, got %q", candidates[0].Origin)
	}
}

func TestInferClaimIDsFromSourceEvidence_TestFallbackEmptyKind(t *testing.T) {
	t.Parallel()
	got := inferClaimIDsFromSourceEvidence(SourceEvidenceRecord{
		SourceType: "test",
		Summary:    "runs validation",
		Metadata:   map[string]string{"test_kind": ""},
	})
	if len(got) != 1 || got[0] != "testing_maturity.test" {
		t.Fatalf("expected testing_maturity.test, got %v", got)
	}
}

func TestInferClaimIDsFromSourceEvidence_CodeFallbackEmptyModuleKind(t *testing.T) {
	t.Parallel()
	got := inferClaimIDsFromSourceEvidence(SourceEvidenceRecord{
		SourceType: "code",
		Summary:    "generic module",
		Metadata:   map[string]string{"module_kind": ""},
	})
	if len(got) != 1 || got[0] != "architecture.module" {
		t.Fatalf("expected architecture.module, got %v", got)
	}
}

func TestNormalizeAndFilterClaimIDs_Deduplication(t *testing.T) {
	t.Parallel()
	got := normalizeAndFilterClaimIDs([]string{"architecture.foo", "architecture.foo"}, "code")
	if len(got) != 1 {
		t.Fatalf("expected 1 after dedup, got %d: %v", len(got), got)
	}
}

func TestChooseStrongerOrigin(t *testing.T) {
	t.Parallel()
	got := chooseStrongerOrigin(string(ClaimOriginDocExtracted), string(ClaimOriginCodeInferred))
	if got != string(ClaimOriginCodeInferred) {
		t.Fatalf("expected code_inferred, got %q", got)
	}
	got = chooseStrongerOrigin(string(ClaimOriginCodeInferred), string(ClaimOriginDocExtracted))
	if got != string(ClaimOriginCodeInferred) {
		t.Fatalf("expected code_inferred to remain, got %q", got)
	}
}
