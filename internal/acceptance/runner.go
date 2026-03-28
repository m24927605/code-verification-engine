package acceptance

import (
	"fmt"

	"github.com/verabase/code-verification-engine/internal/artifactsv2"
)

// RunFixture executes a deterministic artifact fixture and validates both
// artifact expectations and optional determinism guarantees.
func RunFixture(fixture Fixture) (*artifactsv2.BuildResult, error) {
	first, err := artifactsv2.BuildArtifacts(fixture.Input)
	if err != nil {
		return nil, fmt.Errorf("build artifacts: %w", err)
	}
	if err := AssertBundleAgainstFixture(first.Bundle, fixture.Manifest); err != nil {
		return nil, err
	}
	if fixture.Manifest.ExpectedBundleHashStable {
		second, err := artifactsv2.BuildArtifacts(fixture.Input)
		if err != nil {
			return nil, fmt.Errorf("rebuild artifacts: %w", err)
		}
		if err := AssertBundleDeterministic(first.Bundle, second.Bundle); err != nil {
			return nil, err
		}
	}
	return first, nil
}
