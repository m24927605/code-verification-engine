package facts

// FactProvenance indicates how a fact was derived.
type FactProvenance string

const (
	// ProvenanceAST indicates the fact was derived from a full AST parse.
	ProvenanceAST FactProvenance = "ast_derived"
	// ProvenanceHeuristic indicates the fact was derived from regex heuristics
	// applied to raw source lines (may include strings/comments).
	ProvenanceHeuristic FactProvenance = "heuristic"
	// ProvenanceStructural indicates the fact was derived from regex applied
	// to structurally-filtered code tokens (strings/comments excluded).
	ProvenanceStructural FactProvenance = "structural"
)

// Language represents a supported programming language.
type Language string

const (
	LangGo         Language = "go"
	LangJavaScript Language = "javascript"
	LangTypeScript Language = "typescript"
	LangPython     Language = "python"
)

var supportedLanguages = map[Language]bool{
	LangGo:         true,
	LangJavaScript: true,
	LangTypeScript: true,
	LangPython:     true,
}

// IsValid returns true if the language is supported.
func (l Language) IsValid() bool {
	return supportedLanguages[l]
}
