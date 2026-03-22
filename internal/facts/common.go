package facts

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
