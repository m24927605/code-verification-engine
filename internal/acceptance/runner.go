package acceptance

import (
	"fmt"

	"github.com/verabase/code-verification-engine/internal/artifactsv2"
)

// RunCompatFixture executes a deterministic v2 compatibility fixture and
// validates both artifact expectations and optional determinism guarantees.
func RunCompatFixture(fixture CompatFixture) (*artifactsv2.CompatBuildResult, error) {
	first, err := artifactsv2.BuildCompatArtifacts(fixture.Input)
	if err != nil {
		return nil, fmt.Errorf("build compat artifacts: %w", err)
	}
	if err := AssertBundleAgainstFixture(first.Bundle, fixture.Manifest); err != nil {
		return nil, err
	}
	if fixture.Manifest.ExpectedBundleHashStable {
		second, err := artifactsv2.BuildCompatArtifacts(fixture.Input)
		if err != nil {
			return nil, fmt.Errorf("rebuild compat artifacts: %w", err)
		}
		if err := AssertBundleDeterministic(first.Bundle, second.Bundle); err != nil {
			return nil, err
		}
	}
	return first, nil
}

