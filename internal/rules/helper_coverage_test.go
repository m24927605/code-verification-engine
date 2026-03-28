package rules

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/facts"
)

func TestMetadataHelperCoverage(t *testing.T) {
	t.Parallel()

	if FactQualityStructural.Rank() != 1 {
		t.Fatal("expected structural rank to be 1")
	}
	if !(&ScenarioApplicability{Hiring: true}).Any() {
		t.Fatal("expected Any() to report true")
	}
	sa := &ScenarioApplicability{Hiring: true, OutsourceAcceptance: true, PMAcceptance: true}
	if !sa.Allows("hiring") || !sa.Allows("outsource_acceptance") || !sa.Allows("pm_acceptance") || sa.Allows("other") {
		t.Fatal("unexpected Allows() result")
	}
}

func TestConfigMatcherHelperCoverage(t *testing.T) {
	t.Parallel()

	reads := []facts.ConfigReadFact{
		{Language: facts.LangTypeScript, File: "config/app.ts", Span: facts.Span{Start: 1, End: 1}, Key: "JWT_SECRET", SourceKind: "env", Quality: facts.QualityProof},
		{Language: facts.LangTypeScript, File: "config/app.ts", Span: facts.Span{Start: 2, End: 2}, Key: "JWT_SECRET", SourceKind: "literal", Quality: facts.QualityStructural},
	}
	fs := &FactSet{ConfigReads: reads}
	if !hasSecretKeyConfigReads(fs, []string{"typescript"}) {
		t.Fatal("expected secret key config reads")
	}
	kinds := configReadSourceKinds(fs, []string{"typescript"})
	if len(kinds) != 2 {
		t.Fatalf("configReadSourceKinds() = %#v", kinds)
	}
	if !isConfigReadKindPresent(fs, []string{"typescript"}, "env") || !isConfigReadKindPresent(fs, []string{"typescript"}, "literal") || isConfigReadKindPresent(fs, []string{"typescript"}, "file") {
		t.Fatal("unexpected source kind presence")
	}
	if got := configReadFactQuality(fs, []string{"typescript"}); got != facts.QualityProof {
		t.Fatalf("configReadFactQuality() = %q, want %q", got, facts.QualityProof)
	}
	if appendIfMissing([]string{"a"}, "a")[0] != "a" {
		t.Fatal("appendIfMissing should preserve existing value")
	}
	if got := appendIfMissing([]string{"a"}, "b"); len(got) != 2 {
		t.Fatalf("appendIfMissing() = %#v", got)
	}
}
