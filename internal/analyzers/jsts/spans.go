package jsts

// jsDBPackages is the set of known JS/TS database library import paths.
var jsDBPackages = map[string]bool{
	"sequelize":      true,
	"typeorm":        true,
	"prisma":         true,
	"@prisma/client": true,
	"mongoose":       true,
	"mongodb":        true,
	"knex":           true,
	"pg":             true,
	"mysql":          true,
	"mysql2":         true,
	"better-sqlite3": true,
	"drizzle-orm":    true,
	"mikro-orm":      true,
}

// HasDBImport returns true if the ASTResult contains an import from a known DB package.
func HasDBImport(result *ASTResult) bool {
	for _, imp := range result.Imports {
		if jsDBPackages[imp.Source] {
			return true
		}
	}
	return false
}

// FunctionSpan represents a named function/method scope for caller enrichment.
type FunctionSpan struct {
	Name      string
	Kind      string // "function" or "method"
	StartLine int
	EndLine   int
}

// BuildFunctionSpans extracts function/method spans from ASTResult symbols.
// Class spans are excluded (too broad). Anonymous functions (empty name) are skipped.
// Symbols with EndLine <= Line (invalid spans) are also skipped.
func BuildFunctionSpans(result *ASTResult) []FunctionSpan {
	var spans []FunctionSpan
	for _, sym := range result.Symbols {
		if sym.Kind == "class" {
			continue
		}
		if sym.Kind != "function" && sym.Kind != "method" {
			continue
		}
		if sym.Name == "" {
			continue
		}
		if sym.EndLine <= sym.Line {
			continue
		}
		spans = append(spans, FunctionSpan{
			Name:      sym.Name,
			Kind:      sym.Kind,
			StartLine: sym.Line,
			EndLine:   sym.EndLine,
		})
	}
	return spans
}

// FindEnclosingSpan returns the narrowest function span containing the given line.
// A span contains a line if StartLine <= line <= EndLine.
// Returns ("", "") if no span contains the line.
func FindEnclosingSpan(spans []FunctionSpan, line int) (name, kind string) {
	best := -1
	bestWidth := -1
	for i, s := range spans {
		if line < s.StartLine || line > s.EndLine {
			continue
		}
		width := s.EndLine - s.StartLine
		if best == -1 || width < bestWidth {
			best = i
			bestWidth = width
		}
	}
	if best == -1 {
		return "", ""
	}
	return spans[best].Name, spans[best].Kind
}
