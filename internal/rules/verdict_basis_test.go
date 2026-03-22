package rules

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/facts"
)

func TestSetVerdictBasis(t *testing.T) {
	tests := []struct {
		name              string
		matcherClass      MatcherClass
		verificationLevel VerificationLevel
		wantBasis         string
	}{
		{
			name:              "proof_matcher with verified -> proof",
			matcherClass:      MatcherProof,
			verificationLevel: VerificationVerified,
			wantBasis:         "proof",
		},
		{
			name:              "proof_matcher with strong_inference -> heuristic (no proof facts)",
			matcherClass:      MatcherProof,
			verificationLevel: VerificationStrongInference,
			wantBasis:         "heuristic_inference",
		},
		{
			name:              "proof_matcher with weak_inference -> heuristic (no proof facts)",
			matcherClass:      MatcherProof,
			verificationLevel: VerificationWeakInference,
			wantBasis:         "heuristic_inference",
		},
		{
			name:              "structural_matcher -> structural_binding",
			matcherClass:      MatcherStructural,
			verificationLevel: VerificationStrongInference,
			wantBasis:         "structural_binding",
		},
		{
			name:              "heuristic_matcher -> heuristic_inference",
			matcherClass:      MatcherHeuristic,
			verificationLevel: VerificationStrongInference,
			wantBasis:         "heuristic_inference",
		},
		{
			name:              "attestation_matcher -> runtime_required",
			matcherClass:      MatcherAttestation,
			verificationLevel: VerificationWeakInference,
			wantBasis:         "runtime_required",
		},
		{
			name:              "empty matcher_class -> heuristic_inference",
			matcherClass:      "",
			verificationLevel: VerificationStrongInference,
			wantBasis:         "heuristic_inference",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &Finding{
				MatcherClass:      tt.matcherClass,
				VerificationLevel: tt.verificationLevel,
			}
			// Pass nil FactSet — fact quality defaults to heuristic,
			// so proof_matcher with verified + nil fs → heuristic floor
			// → verdict downgrades to heuristic_inference.
			// For these unit tests, use a FactSet with proof-quality facts
			// so the verdict basis reflects the matcher class cleanly.
			fs := &FactSet{}
			if tt.matcherClass == MatcherProof && tt.verificationLevel == VerificationVerified {
				// Provide proof-quality evidence so the proof verdict holds
				fs = &FactSet{
					Secrets: []facts.SecretFact{
						{File: "test.go", Quality: facts.QualityProof, Language: facts.LangGo, Span: facts.Span{Start: 1, End: 1}, Kind: "test"},
					},
				}
				f.Evidence = []Evidence{{File: "test.go", LineStart: 1, LineEnd: 1}}
			}
			setVerdictBasis(f, fs)
			if f.VerdictBasis != tt.wantBasis {
				t.Errorf("VerdictBasis = %q, want %q", f.VerdictBasis, tt.wantBasis)
			}
		})
	}
}

func TestEngineSetVerdictBasisIntegration(t *testing.T) {
	// Verify that Execute sets VerdictBasis on findings.
	rf := &RuleFile{
		Version: "0.1",
		Profile: "test",
		Rules: []Rule{
			{
				ID: "SEC-001", Title: "No secrets", Category: "security", Severity: "critical",
				Languages: []string{"go"}, Type: "not_exists", Target: "secret.hardcoded_credential",
				Message:      "No hardcoded creds.",
				MatcherClass: MatcherProof,
			},
		},
	}
	fs := &FactSet{}
	engine := NewEngine()
	result := engine.Execute(rf, fs, []string{"go"})

	if len(result.Findings) != 1 {
		t.Fatalf("findings count = %d, want 1", len(result.Findings))
	}
	if result.Findings[0].VerdictBasis == "" {
		t.Error("VerdictBasis should be set after Execute")
	}
}
