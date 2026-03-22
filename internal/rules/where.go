package rules

import "strings"

// WhereMatchesSymbol returns true if the given symbol name and file path
// satisfy all constraints in the Where clause.
// A nil Where clause matches everything.
func WhereMatchesSymbol(w *Where, name, filePath string) bool {
	if w == nil {
		return true
	}

	if len(w.NameMatches) > 0 {
		matched := false
		for _, pattern := range w.NameMatches {
			if NameMatchesToken(name, pattern) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	if len(w.NameExact) > 0 {
		matched := false
		for _, exact := range w.NameExact {
			if name == exact {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	if len(w.PathMatches) > 0 {
		matched := false
		for _, pm := range w.PathMatches {
			if strings.Contains(filePath, pm) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	for _, pe := range w.PathExcludes {
		if strings.Contains(filePath, pe) {
			return false
		}
	}

	return true
}
