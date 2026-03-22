package repo

import (
	"path/filepath"
	"sort"
	"strings"
)

// sourceExtensions maps file extensions to their language.
var sourceExtensions = map[string]string{
	".go":  "go",
	".js":  "javascript",
	".jsx": "javascript",
	".ts":  "typescript",
	".tsx": "typescript",
	".py":  "python",
}

// DetectLanguages determines which supported languages are present
// based on file extensions. A language is only activated if source files
// with matching extensions exist. Manifest files alone are not sufficient.
func DetectLanguages(files []string) []string {
	seen := make(map[string]bool)

	for _, f := range files {
		ext := strings.ToLower(filepath.Ext(f))
		if lang, ok := sourceExtensions[ext]; ok {
			seen[lang] = true
		}
	}

	langs := make([]string, 0, len(seen))
	for lang := range seen {
		langs = append(langs, lang)
	}
	sort.Strings(langs)
	return langs
}
