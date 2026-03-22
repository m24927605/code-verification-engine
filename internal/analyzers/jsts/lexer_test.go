package jsts

import (
	"testing"
)

// findTokens returns all tokens of a given kind from the token stream.
func findTokens(toks []Tok, kind TokKind) []Tok {
	var result []Tok
	for _, t := range toks {
		if t.Kind == kind {
			result = append(result, t)
		}
	}
	return result
}

func TestLexer_TemplateLiteral_Simple(t *testing.T) {
	src := "`hello world`"
	toks := Tokenize(src)
	tmpl := findTokens(toks, TokTemplate)
	if len(tmpl) != 1 {
		t.Fatalf("expected 1 template literal, got %d", len(tmpl))
	}
	if tmpl[0].Value != "`hello world`" {
		t.Errorf("expected full template content, got %q", tmpl[0].Value)
	}
}

func TestLexer_TemplateLiteral_WithInterpolation(t *testing.T) {
	src := "`hello ${world}`"
	toks := Tokenize(src)
	tmpl := findTokens(toks, TokTemplate)
	if len(tmpl) != 1 {
		t.Fatalf("expected 1 template literal, got %d", len(tmpl))
	}
}

func TestLexer_TemplateLiteral_WithEscape(t *testing.T) {
	src := "`hello \\`escaped\\``"
	toks := Tokenize(src)
	tmpl := findTokens(toks, TokTemplate)
	if len(tmpl) != 1 {
		t.Fatalf("expected 1 template literal, got %d", len(tmpl))
	}
}

func TestLexer_TemplateLiteral_Multiline(t *testing.T) {
	src := "`line1\nline2\nline3`"
	toks := Tokenize(src)
	tmpl := findTokens(toks, TokTemplate)
	if len(tmpl) != 1 {
		t.Fatalf("expected 1 template literal, got %d", len(tmpl))
	}
	// The template should span multiple lines
	if tmpl[0].Line != 1 {
		t.Errorf("expected template to start on line 1, got %d", tmpl[0].Line)
	}
}

func TestLexer_TemplateLiteral_Empty(t *testing.T) {
	src := "``"
	toks := Tokenize(src)
	tmpl := findTokens(toks, TokTemplate)
	if len(tmpl) != 1 {
		t.Fatalf("expected 1 template literal, got %d", len(tmpl))
	}
}

func TestLexer_TemplateLiteral_Unterminated(t *testing.T) {
	// Should not panic; unterminated template literal
	src := "`unterminated"
	toks := Tokenize(src)
	if toks == nil {
		t.Error("expected non-nil token slice")
	}
}

func TestLexer_RegexLiteral_Simple(t *testing.T) {
	src := "const x = /pattern/g;"
	toks := Tokenize(src)
	regexToks := findTokens(toks, TokRegex)
	if len(regexToks) != 1 {
		t.Fatalf("expected 1 regex token, got %d", len(regexToks))
	}
}

func TestLexer_RegexLiteral_WithFlags(t *testing.T) {
	src := "const re = /[a-z]+/gi;"
	toks := Tokenize(src)
	regexToks := findTokens(toks, TokRegex)
	if len(regexToks) != 1 {
		t.Fatalf("expected 1 regex token, got %d", len(regexToks))
	}
}

func TestLexer_RegexLiteral_WithEscape(t *testing.T) {
	src := "const re = /\\//;"
	toks := Tokenize(src)
	regexToks := findTokens(toks, TokRegex)
	if len(regexToks) != 1 {
		t.Fatalf("expected 1 regex token, got %d: tokens=%v", len(regexToks), toks)
	}
}

func TestLexer_RegexLiteral_WithCharClass(t *testing.T) {
	src := "const re = /[abc]/;"
	toks := Tokenize(src)
	regexToks := findTokens(toks, TokRegex)
	if len(regexToks) != 1 {
		t.Fatalf("expected 1 regex token, got %d", len(regexToks))
	}
}

func TestLexer_RegexLiteral_CharClassWithEscape(t *testing.T) {
	src := "const re = /[a\\]b]/;"
	toks := Tokenize(src)
	// Should not panic
	if toks == nil {
		t.Error("expected non-nil tokens")
	}
}

func TestLexer_RegexLiteral_Unterminated(t *testing.T) {
	src := "const re = /unterminated\n"
	toks := Tokenize(src)
	// Should not panic
	if toks == nil {
		t.Error("expected non-nil tokens")
	}
}

func TestLexer_DivisionNotRegex_AfterIdent(t *testing.T) {
	// After an identifier, / is division, not regex
	src := "a / b"
	toks := Tokenize(src)
	regexToks := findTokens(toks, TokRegex)
	if len(regexToks) != 0 {
		t.Errorf("expected no regex tokens after ident (division), got %d", len(regexToks))
	}
}

func TestLexer_DivisionNotRegex_AfterNumber(t *testing.T) {
	src := "10 / 2"
	toks := Tokenize(src)
	regexToks := findTokens(toks, TokRegex)
	if len(regexToks) != 0 {
		t.Errorf("expected no regex tokens after number (division), got %d", len(regexToks))
	}
}

func TestLexer_DivisionNotRegex_AfterCloseParen(t *testing.T) {
	src := "(x) / 2"
	toks := Tokenize(src)
	regexToks := findTokens(toks, TokRegex)
	if len(regexToks) != 0 {
		t.Errorf("expected no regex tokens after ) (division), got %d", len(regexToks))
	}
}

func TestLexer_DivisionNotRegex_AfterCloseBracket(t *testing.T) {
	src := "a[0] / 2"
	toks := Tokenize(src)
	regexToks := findTokens(toks, TokRegex)
	if len(regexToks) != 0 {
		t.Errorf("expected no regex tokens after ] (division), got %d", len(regexToks))
	}
}

func TestLexer_RegexAfterOpenParen(t *testing.T) {
	src := "if (/pattern/.test(x)) {}"
	toks := Tokenize(src)
	regexToks := findTokens(toks, TokRegex)
	if len(regexToks) != 1 {
		t.Fatalf("expected 1 regex token inside if(), got %d", len(regexToks))
	}
}

func TestLexer_BlockComment_Simple(t *testing.T) {
	src := "/* hello */"
	toks := Tokenize(src)
	comments := findTokens(toks, TokBlockComment)
	if len(comments) != 1 {
		t.Fatalf("expected 1 block comment, got %d", len(comments))
	}
}

func TestLexer_BlockComment_Multiline(t *testing.T) {
	src := "/* line1\nline2\nline3 */"
	toks := Tokenize(src)
	comments := findTokens(toks, TokBlockComment)
	if len(comments) != 1 {
		t.Fatalf("expected 1 multiline block comment, got %d", len(comments))
	}
}

func TestLexer_BlockComment_Unterminated(t *testing.T) {
	// Unterminated block comment — should not panic
	src := "/* unterminated"
	toks := Tokenize(src)
	if toks == nil {
		t.Error("expected non-nil tokens")
	}
}

func TestLexer_BlockComment_Empty(t *testing.T) {
	src := "/**/"
	toks := Tokenize(src)
	comments := findTokens(toks, TokBlockComment)
	if len(comments) != 1 {
		t.Fatalf("expected 1 empty block comment, got %d", len(comments))
	}
}

func TestLexer_String_EscapedQuote_Single(t *testing.T) {
	src := `'it\'s a test'`
	toks := Tokenize(src)
	strings_ := findTokens(toks, TokString)
	if len(strings_) != 1 {
		t.Fatalf("expected 1 string token, got %d", len(strings_))
	}
}

func TestLexer_String_EscapedQuote_Double(t *testing.T) {
	src := `"she said \"hello\""`
	toks := Tokenize(src)
	strings_ := findTokens(toks, TokString)
	if len(strings_) != 1 {
		t.Fatalf("expected 1 string token, got %d", len(strings_))
	}
}

func TestLexer_String_Unterminated(t *testing.T) {
	// Unterminated string - hits newline
	src := "\"unterminated\nconst x = 1;"
	toks := Tokenize(src)
	// Should not panic; the string token should be present
	strings_ := findTokens(toks, TokString)
	if len(strings_) < 1 {
		t.Error("expected at least 1 string token for unterminated string")
	}
}

func TestLexer_String_SingleCharContent(t *testing.T) {
	src := `'a'`
	toks := Tokenize(src)
	strings_ := findTokens(toks, TokString)
	if len(strings_) != 1 {
		t.Fatalf("expected 1 string token, got %d", len(strings_))
	}
	if strings_[0].Value != "a" {
		t.Errorf("expected value 'a', got %q", strings_[0].Value)
	}
}

func TestLexer_String_UnterminatedSingleChar(t *testing.T) {
	// Single quote that hits newline before end
	src := "'\n"
	toks := Tokenize(src)
	if toks == nil {
		t.Error("expected non-nil tokens")
	}
	// Should have a string token with empty-ish content
	strings_ := findTokens(toks, TokString)
	if len(strings_) < 1 {
		t.Error("expected at least 1 string token for unterminated single char string")
	}
}

func TestLexer_Number_Integer(t *testing.T) {
	src := "42"
	toks := Tokenize(src)
	nums := findTokens(toks, TokNumber)
	if len(nums) != 1 {
		t.Fatalf("expected 1 number, got %d", len(nums))
	}
	if nums[0].Value != "42" {
		t.Errorf("expected '42', got %q", nums[0].Value)
	}
}

func TestLexer_Number_Float(t *testing.T) {
	src := "3.14"
	toks := Tokenize(src)
	nums := findTokens(toks, TokNumber)
	if len(nums) != 1 {
		t.Fatalf("expected 1 number, got %d", len(nums))
	}
}

func TestLexer_Number_LeadingDot(t *testing.T) {
	src := ".5"
	toks := Tokenize(src)
	nums := findTokens(toks, TokNumber)
	if len(nums) != 1 {
		t.Fatalf("expected 1 number for .5, got %d", len(nums))
	}
}

func TestLexer_Number_Hex(t *testing.T) {
	src := "0xFF"
	toks := Tokenize(src)
	nums := findTokens(toks, TokNumber)
	if len(nums) != 1 {
		t.Fatalf("expected 1 hex number, got %d", len(nums))
	}
	if nums[0].Value != "0xFF" {
		t.Errorf("expected '0xFF', got %q", nums[0].Value)
	}
}

func TestLexer_Number_Octal(t *testing.T) {
	src := "0o777"
	toks := Tokenize(src)
	nums := findTokens(toks, TokNumber)
	if len(nums) != 1 {
		t.Fatalf("expected 1 octal number, got %d", len(nums))
	}
}

func TestLexer_Number_Binary(t *testing.T) {
	src := "0b1010"
	toks := Tokenize(src)
	nums := findTokens(toks, TokNumber)
	if len(nums) != 1 {
		t.Fatalf("expected 1 binary number, got %d", len(nums))
	}
}

func TestLexer_Number_BigInt(t *testing.T) {
	src := "100n"
	toks := Tokenize(src)
	nums := findTokens(toks, TokNumber)
	if len(nums) != 1 {
		t.Fatalf("expected 1 bigint number, got %d", len(nums))
	}
}

func TestLexer_Number_Exponential(t *testing.T) {
	src := "1e10"
	toks := Tokenize(src)
	nums := findTokens(toks, TokNumber)
	if len(nums) != 1 {
		t.Fatalf("expected 1 exponential number, got %d", len(nums))
	}
}

func TestLexer_Number_NumericSeparator(t *testing.T) {
	src := "1_000_000"
	toks := Tokenize(src)
	nums := findTokens(toks, TokNumber)
	if len(nums) != 1 {
		t.Fatalf("expected 1 number with underscore separator, got %d", len(nums))
	}
}

func TestLexer_Punct_ThreeChar(t *testing.T) {
	for _, punct := range []string{"===", "!==", "..."} {
		toks := Tokenize(punct)
		puncts := findTokens(toks, TokPunct)
		if len(puncts) != 1 {
			t.Errorf("expected 1 punct token for %q, got %d", punct, len(puncts))
			continue
		}
		if puncts[0].Value != punct {
			t.Errorf("expected %q, got %q", punct, puncts[0].Value)
		}
	}
}

func TestLexer_Punct_TwoChar(t *testing.T) {
	// Note: "/=" starts with "/" which is handled as a potential regex at start;
	// test it in context (after a number so it's division assignment)
	tests := []struct {
		src      string
		expected string
	}{
		{"=>x", "=>"},
		{"==x", "=="},
		{"!=x", "!="},
		{"<=x", "<="},
		{">=x", ">="},
		{"&&x", "&&"},
		{"||x", "||"},
		{"++x", "++"},
		{"--x", "--"},
		{"+=x", "+="},
		{"-=x", "-="},
		{"*=x", "*="},
		{"1/=2", "/="},
		{"%=x", "%="},
		{"**x", "**"},
		{"<<x", "<<"},
		{">>x", ">>"},
		{"??x", "??"},
		{"?.x", "?."},
	}
	for _, tc := range tests {
		toks := Tokenize(tc.src)
		puncts := findTokens(toks, TokPunct)
		found := false
		for _, p := range puncts {
			if p.Value == tc.expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected punct token %q in %q, got puncts: %v", tc.expected, tc.src, puncts)
		}
	}
}

func TestLexer_Tokenize_CarriageReturn(t *testing.T) {
	src := "const x = 1;\r\nconst y = 2;"
	toks := Tokenize(src)
	// Should not panic and produce tokens
	if toks == nil {
		t.Error("expected non-nil tokens")
	}
	idents := findTokens(toks, TokIdent)
	if len(idents) < 2 {
		t.Errorf("expected at least 2 idents (x, y), got %d", len(idents))
	}
}

func TestLexer_Tokenize_EmptyInput(t *testing.T) {
	toks := Tokenize("")
	if len(toks) < 1 {
		t.Error("expected at least EOF token")
	}
	if toks[len(toks)-1].Kind != TokEOF {
		t.Error("expected last token to be EOF")
	}
}

func TestLexer_CanStartRegex_AfterString(t *testing.T) {
	// After a string, / should be division not regex
	src := `"hello" / 2`
	toks := Tokenize(src)
	regexToks := findTokens(toks, TokRegex)
	if len(regexToks) != 0 {
		t.Errorf("expected no regex tokens after string literal, got %d", len(regexToks))
	}
}

func TestLexer_CanStartRegex_AfterTemplate(t *testing.T) {
	// After a template literal, / should be division
	src := "`hello` / 2"
	toks := Tokenize(src)
	regexToks := findTokens(toks, TokRegex)
	if len(regexToks) != 0 {
		t.Errorf("expected no regex tokens after template literal, got %d", len(regexToks))
	}
}

func TestLexer_CanStartRegex_AfterPunct(t *testing.T) {
	// After open paren, / can start regex
	src := "(/pattern/)"
	toks := Tokenize(src)
	regexToks := findTokens(toks, TokRegex)
	if len(regexToks) != 1 {
		t.Errorf("expected 1 regex token after '(', got %d", len(regexToks))
	}
}
