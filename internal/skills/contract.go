package skills

import "fmt"

// ValidateReport performs fail-closed validation on a skill report.
// Returns a list of violations. An empty list means the report is valid.
func ValidateReport(r *Report) []error {
	var errs []error

	if r.SchemaVersion == "" {
		errs = append(errs, fmt.Errorf("schema_version is required"))
	}
	if r.Profile == "" {
		errs = append(errs, fmt.Errorf("profile is required"))
	}

	observed, inferred, unsupported := 0, 0, 0

	for i, s := range r.Signals {
		prefix := fmt.Sprintf("signal[%d]", i)

		if s.ID == "" {
			errs = append(errs, fmt.Errorf("%s: id is required", prefix))
		}
		if s.SkillID == "" {
			errs = append(errs, fmt.Errorf("%s: skill_id is required", prefix))
		}

		switch s.Status {
		case StatusObserved:
			observed++
		case StatusInferred:
			inferred++
		case StatusUnsupported:
			unsupported++
		default:
			errs = append(errs, fmt.Errorf("%s: invalid status %q (must be observed|inferred|unsupported)", prefix, s.Status))
		}

		switch s.TrustClass {
		case "machine_trusted", "advisory", "human_or_runtime_required":
			// ok
		default:
			errs = append(errs, fmt.Errorf("%s: invalid trust_class %q", prefix, s.TrustClass))
		}

		// observed signals must include evidence
		if s.Status == StatusObserved && len(s.Evidence) == 0 {
			errs = append(errs, fmt.Errorf("%s: observed signal must include evidence", prefix))
		}

		// unsupported signals should include unknown_reasons when no evidence
		if s.Status == StatusUnsupported && len(s.Evidence) == 0 && len(s.UnknownReasons) == 0 {
			errs = append(errs, fmt.Errorf("%s: unsupported signal must include unknown_reasons when no evidence", prefix))
		}

		// high confidence cannot be emitted with heuristic-only evidence
		if s.Confidence == ConfidenceHigh && s.EvidenceStrength == EvidenceHeuristic {
			errs = append(errs, fmt.Errorf("%s: high confidence with heuristic-only evidence is not allowed", prefix))
		}

		// high confidence cannot be emitted when trust class is human_or_runtime_required
		if s.Confidence == ConfidenceHigh && s.TrustClass == "human_or_runtime_required" {
			errs = append(errs, fmt.Errorf("%s: high confidence with human_or_runtime_required trust is not allowed", prefix))
		}
	}

	// Summary counts must match actual signal counts
	if r.Summary.Observed != observed {
		errs = append(errs, fmt.Errorf("summary.observed=%d but actual count=%d", r.Summary.Observed, observed))
	}
	if r.Summary.Inferred != inferred {
		errs = append(errs, fmt.Errorf("summary.inferred=%d but actual count=%d", r.Summary.Inferred, inferred))
	}
	if r.Summary.Unsupported != unsupported {
		errs = append(errs, fmt.Errorf("summary.unsupported=%d but actual count=%d", r.Summary.Unsupported, unsupported))
	}

	return errs
}
