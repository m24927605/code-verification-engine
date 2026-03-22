package common

import "strings"

// structural_parser.go — A Go-based tokenizer that splits source into meaningful
// chunks (code, string, comment, whitespace) so that regex extraction can run
// only on actual code tokens, avoiding false positives from strings/comments.

// TokenType classifies a source token.
type TokenType int

const (
	TokenCode       TokenType = iota
	TokenString               // string literal (including template literals, triple-quoted)
	TokenComment              // single-line or multi-line comment
	TokenWhitespace           // runs of whitespace
)

// Token represents a classified chunk of source text.
type Token struct {
	Type    TokenType
	Content string
	Line    int // 1-based line number where the token starts
}

// Tokenize splits source into classified tokens based on the language.
// Supported langs: "javascript", "typescript", "python".
func Tokenize(source string, lang string) []Token {
	switch lang {
	case "javascript", "typescript":
		return tokenizeJSTS(source)
	case "python":
		return tokenizePython(source)
	default:
		// Fallback: treat entire source as code
		if source == "" {
			return nil
		}
		return []Token{{Type: TokenCode, Content: source, Line: 1}}
	}
}

// CodeOnly returns the concatenation of all TokenCode tokens, preserving line
// structure by replacing non-code tokens with equivalent blank lines/spaces.
// This lets line-based regex extraction work correctly with original line numbers.
func CodeOnly(tokens []Token) string {
	if len(tokens) == 0 {
		return ""
	}

	// Calculate total source length for pre-allocation hint
	totalLen := 0
	for _, t := range tokens {
		totalLen += len(t.Content)
	}

	buf := make([]byte, 0, totalLen)
	for _, t := range tokens {
		if t.Type == TokenCode {
			buf = append(buf, t.Content...)
		} else {
			// Replace with spaces, preserving newlines for line numbering
			for _, ch := range []byte(t.Content) {
				if ch == '\n' {
					buf = append(buf, '\n')
				} else {
					buf = append(buf, ' ')
				}
			}
		}
	}
	return string(buf)
}

// StripCommentsOnly returns source with only comments replaced by spaces,
// preserving all string literals. This is useful when extraction regexes
// need to see string content (import paths, route paths, secret values)
// but should not match patterns inside comments.
func StripCommentsOnly(tokens []Token) string {
	if len(tokens) == 0 {
		return ""
	}

	totalLen := 0
	for _, t := range tokens {
		totalLen += len(t.Content)
	}

	buf := make([]byte, 0, totalLen)
	for _, t := range tokens {
		if t.Type == TokenComment {
			for _, ch := range []byte(t.Content) {
				if ch == '\n' {
					buf = append(buf, '\n')
				} else {
					buf = append(buf, ' ')
				}
			}
		} else {
			buf = append(buf, t.Content...)
		}
	}
	return string(buf)
}

// StripCommentsAndMultilineStrings returns source with comments and multi-line
// string literals (triple-quoted in Python, template literals in JS/TS)
// replaced by spaces, preserving single-line string literals.
// This is useful for Python where docstrings (triple-quoted) are a common
// source of false positives.
func StripCommentsAndMultilineStrings(tokens []Token) string {
	if len(tokens) == 0 {
		return ""
	}

	totalLen := 0
	for _, t := range tokens {
		totalLen += len(t.Content)
	}

	buf := make([]byte, 0, totalLen)
	for _, t := range tokens {
		if t.Type == TokenComment {
			for _, ch := range []byte(t.Content) {
				if ch == '\n' {
					buf = append(buf, '\n')
				} else {
					buf = append(buf, ' ')
				}
			}
		} else if t.Type == TokenString && strings.Count(t.Content, "\n") > 0 {
			// Multi-line string: replace with spaces preserving newlines
			for _, ch := range []byte(t.Content) {
				if ch == '\n' {
					buf = append(buf, '\n')
				} else {
					buf = append(buf, ' ')
				}
			}
		} else {
			buf = append(buf, t.Content...)
		}
	}
	return string(buf)
}

// IsLineCode checks whether the given 1-based line number has any code content
// (is not entirely inside a multiline string or comment).
func IsLineCode(tokens []Token, lineNum int) bool {
	for _, t := range tokens {
		if t.Type != TokenCode {
			continue
		}
		// Check if this code token covers the given line
		content := t.Content
		startLine := t.Line
		for _, ch := range content {
			if startLine == lineNum {
				if ch != ' ' && ch != '\t' && ch != '\n' && ch != '\r' {
					return true
				}
			}
			if ch == '\n' {
				startLine++
			}
			if startLine > lineNum {
				break
			}
		}
	}
	return false
}

// --- JS/TS tokenizer ---

func tokenizeJSTS(source string) []Token {
	var tokens []Token
	runes := []byte(source)
	n := len(runes)
	i := 0
	line := 1
	codeStart := 0
	codeStartLine := 1

	flushCode := func(end int) {
		if end > codeStart {
			tokens = append(tokens, Token{Type: TokenCode, Content: string(runes[codeStart:end]), Line: codeStartLine})
		}
	}

	for i < n {
		ch := runes[i]

		// Single-line comment
		if ch == '/' && i+1 < n && runes[i+1] == '/' {
			flushCode(i)
			start := i
			startLine := line
			for i < n && runes[i] != '\n' {
				i++
			}
			tokens = append(tokens, Token{Type: TokenComment, Content: string(runes[start:i]), Line: startLine})
			codeStart = i
			codeStartLine = line
			continue
		}

		// Multi-line comment
		if ch == '/' && i+1 < n && runes[i+1] == '*' {
			flushCode(i)
			start := i
			startLine := line
			i += 2
			for i < n {
				if runes[i] == '\n' {
					line++
				}
				if runes[i] == '*' && i+1 < n && runes[i+1] == '/' {
					i += 2
					break
				}
				i++
			}
			tokens = append(tokens, Token{Type: TokenComment, Content: string(runes[start:i]), Line: startLine})
			codeStart = i
			codeStartLine = line
			continue
		}

		// Template literal
		if ch == '`' {
			flushCode(i)
			start := i
			startLine := line
			i++
			for i < n {
				if runes[i] == '\n' {
					line++
				}
				if runes[i] == '\\' && i+1 < n {
					i += 2
					continue
				}
				if runes[i] == '`' {
					i++
					break
				}
				i++
			}
			tokens = append(tokens, Token{Type: TokenString, Content: string(runes[start:i]), Line: startLine})
			codeStart = i
			codeStartLine = line
			continue
		}

		// String literals
		if ch == '\'' || ch == '"' {
			flushCode(i)
			start := i
			startLine := line
			quote := ch
			i++
			for i < n {
				if runes[i] == '\\' && i+1 < n {
					i += 2
					continue
				}
				if runes[i] == quote {
					i++
					break
				}
				if runes[i] == '\n' {
					// Unterminated string — stop at newline
					break
				}
				i++
			}
			tokens = append(tokens, Token{Type: TokenString, Content: string(runes[start:i]), Line: startLine})
			codeStart = i
			codeStartLine = line
			continue
		}

		// Regex literal: only after certain tokens that indicate a division is unlikely
		if ch == '/' && i > 0 {
			// Simple heuristic: if preceded by certain characters, it's likely a regex
			prev := findPrevNonSpace(runes, i)
			if prev >= 0 && isRegexPreceder(runes[prev]) {
				flushCode(i)
				start := i
				startLine := line
				i++ // skip opening /
				for i < n {
					if runes[i] == '\\' && i+1 < n {
						i += 2
						continue
					}
					if runes[i] == '[' {
						// Character class — skip to ]
						i++
						for i < n && runes[i] != ']' {
							if runes[i] == '\\' && i+1 < n {
								i += 2
								continue
							}
							i++
						}
						if i < n {
							i++ // skip ]
						}
						continue
					}
					if runes[i] == '/' {
						i++
						// Skip flags
						for i < n && (runes[i] >= 'a' && runes[i] <= 'z') {
							i++
						}
						break
					}
					if runes[i] == '\n' {
						// Not a valid regex
						break
					}
					i++
				}
				tokens = append(tokens, Token{Type: TokenString, Content: string(runes[start:i]), Line: startLine})
				codeStart = i
				codeStartLine = line
				continue
			}
		}

		if ch == '\n' {
			line++
		}
		i++
	}

	flushCode(n)
	return tokens
}

func findPrevNonSpace(buf []byte, pos int) int {
	for j := pos - 1; j >= 0; j-- {
		if buf[j] != ' ' && buf[j] != '\t' {
			return j
		}
	}
	return -1
}

func isRegexPreceder(ch byte) bool {
	// Characters after which '/' starts a regex rather than division
	switch ch {
	case '=', '(', '[', '!', '&', '|', '?', ':', ';', ',', '{', '}', '\n', '^', '~', '+', '-', '*', '%':
		return true
	}
	return false
}

// --- Python tokenizer ---

func tokenizePython(source string) []Token {
	var tokens []Token
	runes := []byte(source)
	n := len(runes)
	i := 0
	line := 1
	codeStart := 0
	codeStartLine := 1

	flushCode := func(end int) {
		if end > codeStart {
			tokens = append(tokens, Token{Type: TokenCode, Content: string(runes[codeStart:end]), Line: codeStartLine})
		}
	}

	for i < n {
		ch := runes[i]

		// Single-line comment
		if ch == '#' {
			flushCode(i)
			start := i
			startLine := line
			for i < n && runes[i] != '\n' {
				i++
			}
			tokens = append(tokens, Token{Type: TokenComment, Content: string(runes[start:i]), Line: startLine})
			codeStart = i
			codeStartLine = line
			continue
		}

		// Triple-quoted strings (must check before single quotes)
		if (ch == '\'' || ch == '"') && i+2 < n && runes[i+1] == ch && runes[i+2] == ch {
			flushCode(i)
			start := i
			startLine := line
			quote := ch
			i += 3
			for i < n {
				if runes[i] == '\n' {
					line++
				}
				if runes[i] == '\\' && i+1 < n {
					i += 2
					continue
				}
				if runes[i] == quote && i+2 < n && runes[i+1] == quote && runes[i+2] == quote {
					i += 3
					break
				}
				i++
			}
			tokens = append(tokens, Token{Type: TokenString, Content: string(runes[start:i]), Line: startLine})
			codeStart = i
			codeStartLine = line
			continue
		}

		// Regular string literals
		if ch == '\'' || ch == '"' {
			flushCode(i)
			start := i
			startLine := line
			quote := ch
			i++
			for i < n {
				if runes[i] == '\\' && i+1 < n {
					i += 2
					continue
				}
				if runes[i] == quote {
					i++
					break
				}
				if runes[i] == '\n' {
					// Unterminated string — stop at newline
					break
				}
				i++
			}
			tokens = append(tokens, Token{Type: TokenString, Content: string(runes[start:i]), Line: startLine})
			codeStart = i
			codeStartLine = line
			continue
		}

		if ch == '\n' {
			line++
		}
		i++
	}

	flushCode(n)
	return tokens
}
