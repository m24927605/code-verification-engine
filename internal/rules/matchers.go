package rules

import "github.com/verabase/code-verification-engine/internal/scope"

// matchRule dispatches to the appropriate matcher based on rule type.
func matchRule(rule Rule, fs *FactSet, repoLanguages []string) Finding {
	switch rule.Type {
	case "exists":
		return matchExists(rule, fs, repoLanguages)
	case "not_exists":
		return matchNotExists(rule, fs, repoLanguages)
	case "relationship":
		return matchRelationship(rule, fs, repoLanguages)
	case "test_required":
		return matchTestRequired(rule, fs, repoLanguages)
	default:
		return Finding{
			RuleID:            rule.ID,
			Status:            StatusUnknown,
			Confidence:        ConfidenceLow,
			VerificationLevel: VerificationWeakInference,
			Message:           rule.Message,
			UnknownReasons:    []string{UnknownUnsupportedPattern, "rule type: " + rule.Type},
		}
	}
}

// languageMatch returns true if lang is in the allowed languages list.
func languageMatch(lang string, allowed []string) bool {
	for _, l := range allowed {
		if l == lang {
			return true
		}
	}
	return false
}

// hasMinimalFacts checks if the fact set has at least some facts of the required types.
func hasMinimalFacts(fs *FactSet, requiredTypes []string) bool {
	if fs == nil {
		return false
	}
	for _, ft := range requiredTypes {
		switch ft {
		case "SymbolFact":
			if len(fs.Symbols) == 0 {
				return false
			}
		case "RouteFact":
			if len(fs.Routes) == 0 {
				return false
			}
		case "FileFact":
			if len(fs.Files) == 0 {
				return false
			}
		case "ConfigReadFact":
			hasConfigRead := false
			for _, cr := range fs.ConfigReads {
				if !scope.IsTestOrFixturePath(cr.File) {
					hasConfigRead = true
					break
				}
			}
			if !hasConfigRead {
				return false
			}
		}
	}
	return true
}
