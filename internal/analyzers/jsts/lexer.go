package jsts

// lexer.go — A focused lexer for JavaScript/TypeScript that produces a stream
// of tokens suitable for a recursive descent parser. It properly handles
// strings, comments, template literals, and regex literals so that the parser
// can extract facts from syntax structure rather than regex line matching.

// TokKind classifies a lexer token.
type TokKind int

const (
	TokEOF TokKind = iota
	TokIdent
	TokNumber
	TokString     // single/double quoted string (content without quotes)
	TokTemplate   // template literal (content without backticks)
	TokPunct      // single or multi-char punctuation: ( ) { } [ ] ; , . => ...
	TokKeyword    // reserved keywords
	TokDecorator  // @Identifier
	TokLineComment
	TokBlockComment
	TokRegex
	TokNewline // significant for ASI
)

// Tok represents a single lexer token.
type Tok struct {
	Kind  TokKind
	Value string
	Line  int // 1-based
	Col   int // 0-based
}

var keywords = map[string]bool{
	"import": true, "export": true, "from": true, "default": true, "as": true,
	"function": true, "class": true, "const": true, "let": true, "var": true,
	"return": true, "if": true, "else": true, "for": true, "while": true,
	"do": true, "switch": true, "case": true, "break": true, "continue": true,
	"new": true, "this": true, "super": true, "typeof": true, "instanceof": true,
	"async": true, "await": true, "yield": true, "throw": true, "try": true,
	"catch": true, "finally": true, "extends": true, "implements": true,
	"interface": true, "type": true, "enum": true, "abstract": true,
	"static": true, "private": true, "protected": true, "public": true,
	"readonly": true, "declare": true, "module": true, "require": true,
	"get": true, "set": true, "of": true, "in": true, "delete": true,
	"void": true, "null": true, "undefined": true, "true": true, "false": true,
}

// Lexer tokenizes JS/TS source code.
type Lexer struct {
	src   []byte
	pos   int
	line  int
	col   int
	toks  []Tok
	// For regex detection: track last significant token kind
	lastSig TokKind
}

// Tokenize produces a token stream from source code.
func Tokenize(source string) []Tok {
	l := &Lexer{
		src:  []byte(source),
		line: 1,
	}
	l.tokenize()
	return l.toks
}

func (l *Lexer) tokenize() {
	for l.pos < len(l.src) {
		l.skipWhitespaceExceptNewline()
		if l.pos >= len(l.src) {
			break
		}
		ch := l.src[l.pos]

		// Newline
		if ch == '\n' {
			l.emit(TokNewline, "\n")
			l.pos++
			l.line++
			l.col = 0
			continue
		}

		// Carriage return
		if ch == '\r' {
			l.pos++
			l.col++
			continue
		}

		// Single-line comment
		if ch == '/' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '/' {
			l.readLineComment()
			continue
		}

		// Multi-line comment
		if ch == '/' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '*' {
			l.readBlockComment()
			continue
		}

		// Template literal
		if ch == '`' {
			l.readTemplateLiteral()
			continue
		}

		// String literals
		if ch == '\'' || ch == '"' {
			l.readString(ch)
			continue
		}

		// Decorator (@Identifier)
		if ch == '@' && l.pos+1 < len(l.src) && isIdentStart(l.src[l.pos+1]) {
			l.readDecorator()
			continue
		}

		// Regex literal (heuristic: after certain tokens)
		if ch == '/' && l.canStartRegex() {
			l.readRegex()
			continue
		}

		// Numbers
		if isDigit(ch) || (ch == '.' && l.pos+1 < len(l.src) && isDigit(l.src[l.pos+1])) {
			l.readNumber()
			continue
		}

		// Identifiers and keywords
		if isIdentStart(ch) {
			l.readIdent()
			continue
		}

		// Multi-char punctuation
		if p := l.matchPunct(); p != "" {
			l.emit(TokPunct, p)
			l.pos += len(p)
			l.col += len(p)
			continue
		}

		// Single-char punctuation
		l.emit(TokPunct, string(ch))
		l.pos++
		l.col++
	}

	l.emit(TokEOF, "")
}

func (l *Lexer) emit(kind TokKind, value string) {
	t := Tok{Kind: kind, Value: value, Line: l.line, Col: l.col}
	l.toks = append(l.toks, t)
	if kind != TokNewline && kind != TokLineComment && kind != TokBlockComment {
		l.lastSig = kind
	}
}

func (l *Lexer) skipWhitespaceExceptNewline() {
	for l.pos < len(l.src) {
		ch := l.src[l.pos]
		if ch == ' ' || ch == '\t' {
			l.pos++
			l.col++
		} else {
			break
		}
	}
}

func (l *Lexer) readLineComment() {
	start := l.pos
	startLine := l.line
	l.pos += 2 // skip //
	l.col += 2
	for l.pos < len(l.src) && l.src[l.pos] != '\n' {
		l.pos++
		l.col++
	}
	l.emit(TokLineComment, string(l.src[start:l.pos]))
	_ = startLine
}

func (l *Lexer) readBlockComment() {
	start := l.pos
	l.pos += 2 // skip /*
	l.col += 2
	for l.pos < len(l.src) {
		if l.src[l.pos] == '\n' {
			l.line++
			l.col = 0
			l.pos++
			continue
		}
		if l.src[l.pos] == '*' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '/' {
			l.pos += 2
			l.col += 2
			break
		}
		l.pos++
		l.col++
	}
	l.emit(TokBlockComment, string(l.src[start:l.pos]))
}

func (l *Lexer) readTemplateLiteral() {
	start := l.pos
	startLine := l.line
	l.pos++ // skip opening `
	l.col++
	for l.pos < len(l.src) {
		ch := l.src[l.pos]
		if ch == '\n' {
			l.line++
			l.col = 0
			l.pos++
			continue
		}
		if ch == '\\' && l.pos+1 < len(l.src) {
			l.pos += 2
			l.col += 2
			continue
		}
		if ch == '`' {
			l.pos++
			l.col++
			break
		}
		l.pos++
		l.col++
	}
	content := string(l.src[start:l.pos])
	t := Tok{Kind: TokTemplate, Value: content, Line: startLine, Col: 0}
	l.toks = append(l.toks, t)
	l.lastSig = TokTemplate
}

func (l *Lexer) readString(quote byte) {
	start := l.pos
	l.pos++ // skip opening quote
	l.col++
	for l.pos < len(l.src) {
		ch := l.src[l.pos]
		if ch == '\\' && l.pos+1 < len(l.src) {
			l.pos += 2
			l.col += 2
			continue
		}
		if ch == quote {
			l.pos++
			l.col++
			break
		}
		if ch == '\n' {
			// Unterminated string
			break
		}
		l.pos++
		l.col++
	}
	raw := string(l.src[start:l.pos])
	// Extract content without quotes
	content := raw
	if len(raw) >= 2 && raw[len(raw)-1] == quote {
		content = raw[1 : len(raw)-1]
	} else if len(raw) >= 1 {
		content = raw[1:]
	}
	t := Tok{Kind: TokString, Value: content, Line: l.line, Col: l.col}
	l.toks = append(l.toks, t)
	l.lastSig = TokString
}

func (l *Lexer) readDecorator() {
	start := l.pos
	l.pos++ // skip @
	l.col++
	for l.pos < len(l.src) && isIdentPart(l.src[l.pos]) {
		l.pos++
		l.col++
	}
	l.emit(TokDecorator, string(l.src[start:l.pos]))
}

func (l *Lexer) canStartRegex() bool {
	// After these token kinds, / is likely division, not regex
	switch l.lastSig {
	case TokIdent, TokNumber, TokString, TokTemplate:
		return false
	case TokPunct:
		// After ) or ], / is division
		if len(l.toks) > 0 {
			last := l.toks[len(l.toks)-1]
			if last.Value == ")" || last.Value == "]" {
				return false
			}
		}
		return true
	default:
		return true
	}
}

func (l *Lexer) readRegex() {
	start := l.pos
	l.pos++ // skip opening /
	l.col++
	for l.pos < len(l.src) {
		ch := l.src[l.pos]
		if ch == '\\' && l.pos+1 < len(l.src) {
			l.pos += 2
			l.col += 2
			continue
		}
		if ch == '[' {
			// Character class — skip to ]
			l.pos++
			l.col++
			for l.pos < len(l.src) && l.src[l.pos] != ']' {
				if l.src[l.pos] == '\\' && l.pos+1 < len(l.src) {
					l.pos += 2
					l.col += 2
					continue
				}
				l.pos++
				l.col++
			}
			if l.pos < len(l.src) {
				l.pos++ // skip ]
				l.col++
			}
			continue
		}
		if ch == '/' {
			l.pos++
			l.col++
			// Skip flags
			for l.pos < len(l.src) && l.src[l.pos] >= 'a' && l.src[l.pos] <= 'z' {
				l.pos++
				l.col++
			}
			break
		}
		if ch == '\n' {
			break
		}
		l.pos++
		l.col++
	}
	l.emit(TokRegex, string(l.src[start:l.pos]))
}

func (l *Lexer) readNumber() {
	start := l.pos
	// Handle 0x, 0o, 0b prefixes
	if l.src[l.pos] == '0' && l.pos+1 < len(l.src) {
		next := l.src[l.pos+1]
		if next == 'x' || next == 'X' || next == 'o' || next == 'O' || next == 'b' || next == 'B' {
			l.pos += 2
			l.col += 2
		}
	}
	for l.pos < len(l.src) && (isDigit(l.src[l.pos]) || l.src[l.pos] == '.' || l.src[l.pos] == '_' ||
		l.src[l.pos] == 'e' || l.src[l.pos] == 'E' || l.src[l.pos] == 'n' ||
		isHexDigit(l.src[l.pos])) {
		l.pos++
		l.col++
	}
	l.emit(TokNumber, string(l.src[start:l.pos]))
}

func (l *Lexer) readIdent() {
	start := l.pos
	for l.pos < len(l.src) && isIdentPart(l.src[l.pos]) {
		l.pos++
		l.col++
	}
	word := string(l.src[start:l.pos])
	if keywords[word] {
		l.emit(TokKeyword, word)
	} else {
		l.emit(TokIdent, word)
	}
}

func (l *Lexer) matchPunct() string {
	if l.pos+2 < len(l.src) {
		three := string(l.src[l.pos : l.pos+3])
		switch three {
		case "===", "!==", "...", "**=", "<<=", ">>=", "&&=", "||=", "??=":
			return three
		}
	}
	if l.pos+1 < len(l.src) {
		two := string(l.src[l.pos : l.pos+2])
		switch two {
		case "=>", "==", "!=", "<=", ">=", "&&", "||", "++", "--",
			"+=", "-=", "*=", "/=", "%=", "**", "<<", ">>", "??",
			"?.":
			return two
		}
	}
	return ""
}

func isIdentStart(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_' || ch == '$'
}

func isIdentPart(ch byte) bool {
	return isIdentStart(ch) || isDigit(ch)
}

func isDigit(ch byte) bool {
	return ch >= '0' && ch <= '9'
}

func isHexDigit(ch byte) bool {
	return isDigit(ch) || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')
}
