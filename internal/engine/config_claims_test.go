package engine

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/facts"
	"github.com/verabase/code-verification-engine/internal/rules"
)

func TestBuildConfigFactClaims(t *testing.T) {
	t.Parallel()

	claims := buildConfigFactClaims(&rules.FactSet{
		ConfigReads: []facts.ConfigReadFact{
			{
				Language:   facts.LangTypeScript,
				File:       "src/config/app.ts",
				Span:       facts.Span{Start: 1, End: 1},
				Key:        "JWT_SECRET",
				SourceKind: "env",
			},
			{
				Language:   facts.LangTypeScript,
				File:       "src/config/app.ts",
				Span:       facts.Span{Start: 2, End: 2},
				Key:        "JWT_SECRET",
				SourceKind: "literal",
			},
		},
	})
	if len(claims) != 3 {
		t.Fatalf("claim count = %d, want 3", len(claims))
	}

	byID := make(map[string]string, len(claims))
	for _, claim := range claims {
		byID[claim.ClaimID] = claim.Status
	}
	if byID["config.env_read_call_exists"] != "accepted" {
		t.Fatalf("env_read_call_exists status = %q", byID["config.env_read_call_exists"])
	}
	if byID["config.secret_key_sourced_from_env"] != "accepted" {
		t.Fatalf("secret_key_sourced_from_env status = %q", byID["config.secret_key_sourced_from_env"])
	}
	if byID["config.secret_key_not_literal"] != "rejected" {
		t.Fatalf("secret_key_not_literal status = %q", byID["config.secret_key_not_literal"])
	}
}
