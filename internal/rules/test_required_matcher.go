package rules

import (
	"path/filepath"
	"strings"
)

// matchTestRequired checks whether a critical module has automated tests.
func matchTestRequired(rule Rule, fs *FactSet, repoLanguages []string) Finding {
	finding := Finding{
		RuleID:  rule.ID,
		Message: rule.Message,
	}

	required := RequiredFactTypes(rule.Target)
	if !hasMinimalFacts(fs, required) {
		finding.Status = StatusUnknown
		finding.Confidence = ConfidenceLow
		finding.VerificationLevel = VerificationWeakInference
		finding.UnknownReasons = []string{UnknownInsufficientEvidence, "target: " + rule.Target}
		return finding
	}

	moduleFiles := identifyModuleFiles(rule, fs)
	if len(moduleFiles) == 0 {
		finding.Status = StatusUnknown
		finding.Confidence = ConfidenceLow
		finding.VerificationLevel = VerificationWeakInference
		finding.UnknownReasons = []string{UnknownInsufficientEvidence, "could not identify module for target: " + rule.Target}
		return finding
	}

	testEvidence := findModuleTests(rule, fs, moduleFiles)
	if len(testEvidence) > 0 {
		finding.Status = StatusPass
		finding.Confidence = ConfidenceHigh
		finding.VerificationLevel = VerificationVerified
		finding.Evidence = testEvidence
	} else {
		finding.Status = StatusFail
		finding.Confidence = ConfidenceHigh
		finding.VerificationLevel = VerificationVerified
		finding.Evidence = evidenceForModuleFiles(moduleFiles)
	}
	return finding
}

func identifyModuleFiles(rule Rule, fs *FactSet) map[string]bool {
	moduleKeywords := targetModuleKeywords(rule.Target)
	files := make(map[string]bool)

	for _, sym := range fs.Symbols {
		if !languageMatch(string(sym.Language), rule.Languages) {
			continue
		}
		if !WhereMatchesSymbol(rule.Where, sym.Name, sym.File) {
			continue
		}
		for _, kw := range moduleKeywords {
			if NameMatchesToken(sym.Name, kw) || strings.Contains(strings.ToLower(sym.File), kw) {
				files[sym.File] = true
			}
		}
	}

	for _, f := range fs.Files {
		if !languageMatch(string(f.Language), rule.Languages) {
			continue
		}
		for _, kw := range moduleKeywords {
			if strings.Contains(strings.ToLower(f.File), kw) {
				files[f.File] = true
			}
		}
	}

	return files
}

func targetModuleKeywords(target string) []string {
	switch target {
	case "module.payment_service":
		return []string{"payment", "billing", "invoice", "subscription", "entitlement"}
	case "module.auth_service":
		return []string{"auth"}
	default:
		return nil
	}
}

func findModuleTests(rule Rule, fs *FactSet, moduleFiles map[string]bool) []Evidence {
	var evidence []Evidence
	moduleKeywords := targetModuleKeywords(rule.Target)
	seen := make(map[string]bool)

	for _, test := range fs.Tests {
		if !languageMatch(string(test.Language), rule.Languages) {
			continue
		}
		if seen[test.File+":"+test.TestName] {
			continue
		}
		lineStart := test.Span.Start
		if lineStart < 1 {
			lineStart = 1
		}
		lineEnd := test.Span.End
		if lineEnd < lineStart {
			lineEnd = lineStart
		}
		// Check if test is in the same directory as a module file
		testDir := filepath.Dir(test.File)
		for mf := range moduleFiles {
			if filepath.Dir(mf) == testDir {
				evidence = append(evidence, Evidence{
					File:      test.File,
					LineStart: lineStart,
					LineEnd:   lineEnd,
					Symbol:    test.TestName,
				})
				seen[test.File+":"+test.TestName] = true
				break
			}
		}
		if seen[test.File+":"+test.TestName] {
			continue
		}
		// Check by module keyword in test name or target module field
		for _, kw := range moduleKeywords {
			if NameMatchesToken(test.TestName, kw) || strings.Contains(strings.ToLower(test.TargetModule), kw) {
				evidence = append(evidence, Evidence{
					File:      test.File,
					LineStart: lineStart,
					LineEnd:   lineEnd,
					Symbol:    test.TestName,
				})
				seen[test.File+":"+test.TestName] = true
				break
			}
		}
	}
	return evidence
}

func evidenceForModuleFiles(moduleFiles map[string]bool) []Evidence {
	if len(moduleFiles) == 0 {
		return nil
	}
	evidence := make([]Evidence, 0, len(moduleFiles))
	for file := range moduleFiles {
		evidence = append(evidence, Evidence{
			File:      file,
			LineStart: 1,
			LineEnd:   1,
			Symbol:    filepath.Base(file),
		})
	}
	return evidence
}
