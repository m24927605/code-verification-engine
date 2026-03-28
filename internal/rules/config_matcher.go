package rules

import (
	"strings"

	"github.com/verabase/code-verification-engine/internal/facts"
	"github.com/verabase/code-verification-engine/internal/scope"
)

func findConfigEnvReadCall(rule Rule, fs *FactSet) []Evidence {
	var evidence []Evidence
	for _, cr := range fs.ConfigReads {
		if !languageMatch(string(cr.Language), rule.Languages) {
			continue
		}
		if scope.IsTestOrFixturePath(cr.File) {
			continue
		}
		if cr.SourceKind != "env" {
			continue
		}
		evidence = append(evidence, Evidence{
			File:      cr.File,
			LineStart: cr.Span.Start,
			LineEnd:   cr.Span.End,
			Symbol:    "config_read:" + cr.Key,
		})
	}
	return evidence
}

func findSecretKeySourcedFromEnv(rule Rule, fs *FactSet) []Evidence {
	var evidence []Evidence
	for _, cr := range fs.ConfigReads {
		if !languageMatch(string(cr.Language), rule.Languages) {
			continue
		}
		if scope.IsTestOrFixturePath(cr.File) {
			continue
		}
		if cr.SourceKind != "env" || !isSecretKeyConfigName(cr.Key) {
			continue
		}
		evidence = append(evidence, Evidence{
			File:      cr.File,
			LineStart: cr.Span.Start,
			LineEnd:   cr.Span.End,
			Symbol:    "config_read:" + cr.Key,
		})
	}
	return evidence
}

func findSecretKeyNotLiteralEvidence(rule Rule, fs *FactSet) []Evidence {
	var evidence []Evidence
	for _, cr := range fs.ConfigReads {
		if !languageMatch(string(cr.Language), rule.Languages) {
			continue
		}
		if scope.IsTestOrFixturePath(cr.File) {
			continue
		}
		if cr.SourceKind != "literal" || !isSecretKeyConfigName(cr.Key) {
			continue
		}
		evidence = append(evidence, Evidence{
			File:      cr.File,
			LineStart: cr.Span.Start,
			LineEnd:   cr.Span.End,
			Symbol:    "config_read:" + cr.Key,
		})
	}
	return evidence
}

func hasSecretKeyConfigReads(fs *FactSet, ruleLanguages []string) bool {
	for _, cr := range fs.ConfigReads {
		if !languageMatch(string(cr.Language), ruleLanguages) {
			continue
		}
		if scope.IsTestOrFixturePath(cr.File) {
			continue
		}
		if isSecretKeyConfigName(cr.Key) {
			return true
		}
	}
	return false
}

func isSecretKeyConfigName(key string) bool {
	lower := strings.ToLower(strings.TrimSpace(key))
	if lower == "" {
		return false
	}
	patterns := []string{
		"secret",
		"password",
		"passwd",
		"token",
		"api_key",
		"apikey",
		"client_secret",
		"private_key",
		"jwt_secret",
		"refresh_token",
	}
	for _, pattern := range patterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

func configReadSourceKinds(fs *FactSet, ruleLanguages []string) map[string]bool {
	kinds := make(map[string]bool)
	for _, cr := range fs.ConfigReads {
		if !languageMatch(string(cr.Language), ruleLanguages) {
			continue
		}
		if scope.IsTestOrFixturePath(cr.File) {
			continue
		}
		kinds[strings.ToLower(strings.TrimSpace(cr.SourceKind))] = true
	}
	return kinds
}

func isConfigReadKindPresent(fs *FactSet, ruleLanguages []string, kind string) bool {
	for _, cr := range fs.ConfigReads {
		if !languageMatch(string(cr.Language), ruleLanguages) {
			continue
		}
		if scope.IsTestOrFixturePath(cr.File) {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(cr.SourceKind), kind) {
			return true
		}
	}
	return false
}

func configReadFactQuality(fs *FactSet, ruleLanguages []string) facts.FactQuality {
	for _, cr := range fs.ConfigReads {
		if !languageMatch(string(cr.Language), ruleLanguages) {
			continue
		}
		if cr.Quality != "" {
			return cr.Quality
		}
	}
	return facts.QualityHeuristic
}
