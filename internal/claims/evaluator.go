package claims

import (
	"fmt"

	"github.com/verabase/code-verification-engine/internal/rules"
)

// Evaluator converts rule-level findings into claim-level verdicts.
type Evaluator struct{}

// NewEvaluator creates a new claim evaluator.
func NewEvaluator() *Evaluator { return &Evaluator{} }

// Evaluate takes rule execution results and produces claim verdicts.
func (e *Evaluator) Evaluate(claimSet *ClaimSet, execResult rules.ExecutionResult) *ClaimReport {
	report := &ClaimReport{
		SchemaVersion: "1.0.0",
		ClaimSetName:  claimSet.Name,
		TotalClaims:   len(claimSet.Claims),
	}

	// Build rule result lookup
	ruleResults := make(map[string]rules.Finding)
	for _, f := range execResult.Findings {
		ruleResults[f.RuleID] = f
	}

	for _, claim := range claimSet.Claims {
		verdict := evaluateClaim(claim, ruleResults)
		report.Claims = append(report.Claims, verdict)

		switch verdict.Status {
		case "pass":
			if verdict.Confidence == "high" {
				report.Verdicts.Verified++
			}
			report.Verdicts.Passed++
		case "fail":
			report.Verdicts.Failed++
		case "unknown":
			report.Verdicts.Unknown++
		case "partial":
			report.Verdicts.Partial++
		}
	}

	return report
}

func evaluateClaim(claim Claim, ruleResults map[string]rules.Finding) ClaimVerdict {
	verdict := ClaimVerdict{
		ClaimID:  claim.ID,
		Title:    claim.Title,
		Category: claim.Category,
	}

	var supporting []RuleResult
	var evidenceChain []EvidenceLink

	passCount, failCount, unknownCount := 0, 0, 0
	highestConfidence := "low"
	bestVerification := "weak_inference"

	for _, ruleID := range claim.RuleIDs {
		finding, ok := ruleResults[ruleID]
		if !ok {
			unknownCount++
			supporting = append(supporting, RuleResult{
				RuleID: ruleID, Status: "unknown", Message: "rule not evaluated",
			})
			continue
		}

		supporting = append(supporting, RuleResult{
			RuleID:     ruleID,
			Status:     string(finding.Status),
			Confidence: string(finding.Confidence),
			Message:    finding.Message,
		})

		switch finding.Status {
		case rules.StatusPass:
			passCount++
		case rules.StatusFail:
			failCount++
		case rules.StatusUnknown:
			unknownCount++
			verdict.UnknownReasons = append(verdict.UnknownReasons, finding.UnknownReasons...)
		}

		if confidenceRank(string(finding.Confidence)) > confidenceRank(highestConfidence) {
			highestConfidence = string(finding.Confidence)
		}
		if verificationRank(string(finding.VerificationLevel)) > verificationRank(bestVerification) {
			bestVerification = string(finding.VerificationLevel)
		}

		// Build evidence chain
		for _, ev := range finding.Evidence {
			linkType := "supports"
			if finding.Status == rules.StatusFail {
				linkType = "contradicts"
			}
			evidenceChain = append(evidenceChain, EvidenceLink{
				ID:       ev.ID,
				Type:     linkType,
				File:     ev.File,
				LineStart: ev.LineStart,
				LineEnd:   ev.LineEnd,
				Symbol:   ev.Symbol,
				FromRule: ruleID,
				Relation: string(finding.Status) + " via " + ruleID,
			})
		}
	}

	verdict.SupportingRules = supporting
	verdict.EvidenceChain = evidenceChain
	verdict.Confidence = highestConfidence
	verdict.VerificationLevel = bestVerification

	// Determine claim status
	total := passCount + failCount + unknownCount
	if total == 0 {
		verdict.Status = "unknown"
		verdict.Summary = "No rules evaluated for this claim."
	} else if failCount > 0 {
		verdict.Status = "fail"
		verdict.Summary = fmt.Sprintf("%d of %d rules failed.", failCount, total)
	} else if unknownCount > 0 && passCount > 0 {
		verdict.Status = "partial"
		verdict.Summary = fmt.Sprintf("%d passed, %d unknown out of %d rules.", passCount, unknownCount, total)
	} else if unknownCount == total {
		verdict.Status = "unknown"
		verdict.Summary = fmt.Sprintf("All %d rules returned unknown.", total)
	} else {
		verdict.Status = "pass"
		verdict.Summary = fmt.Sprintf("All %d rules passed.", total)
	}

	return verdict
}

func confidenceRank(c string) int {
	switch c {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func verificationRank(v string) int {
	switch v {
	case "verified":
		return 3
	case "strong_inference":
		return 2
	case "weak_inference":
		return 1
	default:
		return 0
	}
}
