package claims

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/rules"
)

func TestBuildMultiSourceClaimGraph_DowngradesReadmeOnlyClaim(t *testing.T) {
	t.Parallel()

	claimSet := &ClaimSet{
		Name: "resume-safe",
		Claims: []Claim{
			{
				ID:       "architecture.multi_agent_pipeline",
				Title:    "Multi-agent pipeline exists",
				Category: "architecture",
				RuleIDs:  []string{"ARCH-001"},
			},
		},
	}

	graph := BuildMultiSourceClaimGraph(claimSet, []SourceEvidenceRecord{
		{
			EvidenceID: "ev-readme",
			SourceType: "readme",
			Origin:     string(ClaimOriginReadmeExtracted),
			Producer:   "README.md",
			Path:       "README.md",
			Kind:       "claim_fragment",
			Summary:    "We ship a multi-agent pipeline.",
			Spans: []SourceSpan{{
				File:      "README.md",
				LineStart: 10,
				LineEnd:   12,
			}},
			ClaimIDs: []string{"architecture.multi_agent_pipeline"},
		},
	})

	if graph == nil {
		t.Fatal("expected claim graph")
	}
	if len(graph.Claims) != 1 {
		t.Fatalf("expected 1 verified claim, got %d", len(graph.Claims))
	}
	claim := graph.Claims[0]
	if claim.SupportLevel != string(ClaimSupportWeak) {
		t.Fatalf("expected README-only claim to downgrade to weak, got %q", claim.SupportLevel)
	}
	if claim.Status != ClaimStatusDowngraded {
		t.Fatalf("expected README-only claim to be downgraded, got %q", claim.Status)
	}
	if len(claim.SupportingEvidenceIDs) != 1 || claim.SupportingEvidenceIDs[0] != "ev-readme" {
		t.Fatalf("expected README evidence to remain traceable, got %#v", claim.SupportingEvidenceIDs)
	}
	if len(graph.Edges) != 1 || graph.Edges[0].Type != string(ClaimEdgeDocumentedBy) {
		t.Fatalf("expected documented_by claim edge, got %#v", graph.Edges)
	}
}

func TestBuildMultiSourceClaimGraph_ContradictsDocsWithCodeEvidence(t *testing.T) {
	t.Parallel()

	claimSet := &ClaimSet{
		Name: "resume-safe",
		Claims: []Claim{
			{
				ID:       "architecture.multi_agent_pipeline",
				Title:    "Multi-agent pipeline exists",
				Category: "architecture",
				RuleIDs:  []string{"ARCH-001"},
			},
		},
	}

	graph := BuildMultiSourceClaimGraph(claimSet, []SourceEvidenceRecord{
		{
			EvidenceID: "ev-doc",
			SourceType: "doc",
			Origin:     string(ClaimOriginDocExtracted),
			Producer:   "docs/design.md",
			Path:       "docs/design.md",
			Kind:       "claim_fragment",
			Summary:    "The system uses a multi-agent pipeline.",
			ClaimIDs:   []string{"architecture.multi_agent_pipeline"},
			Supports:   []string{"architecture.multi_agent_pipeline"},
		},
		{
			EvidenceID:  "ev-code",
			SourceType:  "code",
			Origin:      string(ClaimOriginCodeInferred),
			Producer:    "rule:ARCH-001",
			Path:        "internal/engine/engine.go",
			Kind:        "rule_result",
			Summary:     "The engine is single-path and does not use a multi-agent pipeline.",
			ClaimIDs:    []string{"architecture.multi_agent_pipeline"},
			Contradicts: []string{"architecture.multi_agent_pipeline"},
		},
	})

	if graph == nil {
		t.Fatal("expected claim graph")
	}
	if len(graph.Claims) != 1 {
		t.Fatalf("expected 1 verified claim, got %d", len(graph.Claims))
	}
	claim := graph.Claims[0]
	if claim.SupportLevel != string(ClaimSupportContradicted) {
		t.Fatalf("expected contradicted support level, got %q", claim.SupportLevel)
	}
	if claim.Status != ClaimStatusRejected {
		t.Fatalf("expected rejected status, got %q", claim.Status)
	}
	if len(claim.ContradictoryEvidenceIDs) != 1 || claim.ContradictoryEvidenceIDs[0] != "ev-code" {
		t.Fatalf("expected code contradiction to be preserved, got %#v", claim.ContradictoryEvidenceIDs)
	}
	foundContradictedEdge := false
	for _, edge := range graph.Edges {
		if edge.Type == string(ClaimEdgeContradictedBy) && edge.ToID == "ev-code" {
			foundContradictedEdge = true
			break
		}
	}
	if !foundContradictedEdge {
		t.Fatalf("expected contradicted_by edge to code evidence, got %#v", graph.Edges)
	}
}

func TestEvaluator_PopulatesMultiSourceClaimGraphFromRuleFindings(t *testing.T) {
	t.Parallel()

	claimSet := &ClaimSet{
		Name: "rule-backed",
		Claims: []Claim{
			{
				ID:       "auth.jwt_implemented",
				Title:    "JWT authentication is implemented",
				Category: "security",
				RuleIDs:  []string{"SEC-AUTH-001"},
			},
		},
	}

	execResult := rules.ExecutionResult{
		Findings: []rules.Finding{
			{
				RuleID:            "SEC-AUTH-001",
				Status:            rules.StatusPass,
				Confidence:        rules.ConfidenceHigh,
				VerificationLevel: rules.VerificationVerified,
				TrustClass:        rules.TrustMachineTrusted,
				Message:           "JWT authentication middleware is present.",
				Evidence: []rules.Evidence{{
					ID:        "ev-code",
					File:      "internal/auth/middleware.go",
					LineStart: 10,
					LineEnd:   18,
					Symbol:    "JWTMiddleware",
				}},
			},
		},
	}

	report := NewEvaluator().Evaluate(claimSet, execResult)
	if report.ClaimGraph == nil {
		t.Fatal("expected claim graph to be populated")
	}
	if len(report.ClaimCandidates) != 1 {
		t.Fatalf("expected 1 claim candidate, got %d", len(report.ClaimCandidates))
	}
	if len(report.VerifiedClaims) != 1 {
		t.Fatalf("expected 1 verified claim, got %d", len(report.VerifiedClaims))
	}
	if report.ClaimGraph.Claims[0].Status != ClaimStatusDowngraded && report.ClaimGraph.Claims[0].Status != ClaimStatusAccepted {
		t.Fatalf("unexpected status in claim graph: %#v", report.ClaimGraph.Claims[0])
	}
	if report.ClaimGraph.Claims[0].ClaimID != "auth.jwt_implemented" {
		t.Fatalf("unexpected claim id in graph: %#v", report.ClaimGraph.Claims[0])
	}
}

func TestBuildMultiSourceClaimGraph_InferredClaimIDsStillMatchEvidence(t *testing.T) {
	t.Parallel()

	graph := BuildMultiSourceClaimGraph(nil, []SourceEvidenceRecord{
		{
			EvidenceID: "ev-code",
			SourceType: "code",
			Origin:     string(ClaimOriginCodeInferred),
			Producer:   "claimsources@v1",
			Path:       "internal/agents/planner.go",
			Kind:       "code_module",
			Summary:    "planner module with symbols: Plan",
			Metadata: map[string]string{
				"module_kind": "planner",
			},
		},
		{
			EvidenceID: "ev-readme",
			SourceType: "readme",
			Origin:     string(ClaimOriginReadmeExtracted),
			Producer:   "claimsources@v1",
			Path:       "README.md",
			Kind:       "readme_section",
			Summary:    "Planner, executor, and verifier coordinate the pipeline.",
			Metadata: map[string]string{
				"section_title": "Architecture",
			},
		},
	})

	if graph == nil {
		t.Fatal("expected claim graph")
	}
	if len(graph.Claims) == 0 {
		t.Fatal("expected inferred claim to be produced")
	}

	var found bool
	for _, claim := range graph.Claims {
		if claim.ClaimID != "architecture.multi_agent_pipeline" {
			continue
		}
		found = true
		if len(claim.SourceOrigins) == 0 {
			t.Fatalf("expected source origins for inferred claim, got %#v", claim)
		}
		if len(claim.SupportingEvidenceIDs) == 0 {
			t.Fatalf("expected supporting evidence ids for inferred claim, got %#v", claim)
		}
		break
	}
	if !found {
		t.Fatalf("expected architecture.multi_agent_pipeline claim in %#v", graph.Claims)
	}
}

func TestInferClaimIDsFromSourceEvidence_DocUnmatchedSuppressed(t *testing.T) {
	t.Parallel()

	got := inferClaimIDsFromSourceEvidence(SourceEvidenceRecord{
		SourceType: "doc",
		Path:       "docs/architecture.md",
		Summary:    "Architecture overview",
		Metadata: map[string]string{
			"section_title": "Architecture Overview",
		},
	})
	if len(got) != 0 {
		t.Fatalf("expected unmatched doc claim to be suppressed, got %#v", got)
	}
}

func TestInferClaimIDsFromSourceEvidence_CanonicalizesDocAlias(t *testing.T) {
	t.Parallel()

	got := inferClaimIDsFromSourceEvidence(SourceEvidenceRecord{
		SourceType: "readme",
		Path:       "README.md",
		Summary:    "3-agent pipeline with planner, executor, and verifier",
		Metadata: map[string]string{
			"section_title": "3-Agent Architecture",
		},
	})
	if len(got) != 1 || got[0] != "architecture.multi_agent_pipeline" {
		t.Fatalf("expected canonical multi-agent claim, got %#v", got)
	}
}

func TestExtractClaimCandidates_PrunesGeneralAndTaskNoise(t *testing.T) {
	t.Parallel()

	candidates := ExtractClaimCandidates(nil, []SourceEvidenceRecord{
		{
			EvidenceID: "ev-general",
			SourceType: "doc",
			Origin:     string(ClaimOriginDocExtracted),
			Path:       "docs/notes.md",
			Summary:    "Acceptance criteria",
			ClaimIDs:   []string{"general.acceptance_criteria"},
		},
		{
			EvidenceID: "ev-task",
			SourceType: "doc",
			Origin:     string(ClaimOriginDocExtracted),
			Path:       "docs/plan.md",
			Summary:    "Task 3 create FugleService",
			ClaimIDs:   []string{"architecture.task_3._create_fugleservice"},
		},
		{
			EvidenceID: "ev-keep",
			SourceType: "doc",
			Origin:     string(ClaimOriginDocExtracted),
			Path:       "README.md",
			Summary:    "shared secure answer pipeline",
			ClaimIDs:   []string{"architecture.secure_answer_pipeline"},
		},
	})

	if len(candidates) != 1 {
		t.Fatalf("expected only curated claim to survive pruning, got %#v", candidates)
	}
	if candidates[0].ClaimID != "architecture.secure_answer_pipeline" {
		t.Fatalf("unexpected surviving claim %#v", candidates[0])
	}
}

func TestExtractClaimCandidates_CanonicalizesExplicitAliases(t *testing.T) {
	t.Parallel()

	candidates := ExtractClaimCandidates(nil, []SourceEvidenceRecord{
		{
			EvidenceID: "ev-1",
			SourceType: "readme",
			Origin:     string(ClaimOriginReadmeExtracted),
			Path:       "README.md",
			Summary:    "3-agent pipeline",
			ClaimIDs:   []string{"architecture.3_agent_pipeline"},
		},
		{
			EvidenceID: "ev-2",
			SourceType: "readme",
			Origin:     string(ClaimOriginReadmeExtracted),
			Path:       "README.md",
			Summary:    "multi-agent pipeline",
			ClaimIDs:   []string{"architecture.multi_agent_pipeline"},
		},
	})

	if len(candidates) != 1 {
		t.Fatalf("expected alias and canonical form to merge, got %#v", candidates)
	}
	if candidates[0].ClaimID != "architecture.multi_agent_pipeline" {
		t.Fatalf("unexpected canonical claim %#v", candidates[0])
	}
}
