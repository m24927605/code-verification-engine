package common_test

import (
	"strings"
	"testing"

	"github.com/verabase/code-verification-engine/internal/analyzers/common"
)

// --- JS/TS tokenization ---

func TestTokenizeJS_SingleLineComment(t *testing.T) {
	source := "const x = 1; // this is a comment\nconst y = 2;"
	tokens := common.Tokenize(source, "javascript")

	hasComment := false
	for _, tok := range tokens {
		if tok.Type == common.TokenComment {
			hasComment = true
			if !strings.Contains(tok.Content, "// this is a comment") {
				t.Errorf("expected comment content, got %q", tok.Content)
			}
		}
	}
	if !hasComment {
		t.Error("expected to find a comment token")
	}
}

func TestTokenizeJS_MultiLineComment(t *testing.T) {
	source := "const x = 1;\n/* multi\nline\ncomment */\nconst y = 2;"
	tokens := common.Tokenize(source, "javascript")

	hasComment := false
	for _, tok := range tokens {
		if tok.Type == common.TokenComment {
			hasComment = true
			if !strings.Contains(tok.Content, "multi") {
				t.Errorf("expected multi-line comment content, got %q", tok.Content)
			}
		}
	}
	if !hasComment {
		t.Error("expected to find a comment token")
	}
}

func TestTokenizeJS_StringLiterals(t *testing.T) {
	source := `const a = 'single'; const b = "double";`
	tokens := common.Tokenize(source, "javascript")

	stringCount := 0
	for _, tok := range tokens {
		if tok.Type == common.TokenString {
			stringCount++
		}
	}
	if stringCount != 2 {
		t.Errorf("expected 2 string tokens, got %d", stringCount)
	}
}

func TestTokenizeJS_TemplateLiteral(t *testing.T) {
	source := "const msg = `hello ${name}`;"
	tokens := common.Tokenize(source, "javascript")

	hasTemplate := false
	for _, tok := range tokens {
		if tok.Type == common.TokenString && strings.Contains(tok.Content, "`") {
			hasTemplate = true
		}
	}
	if !hasTemplate {
		t.Error("expected template literal token")
	}
}

func TestTokenizeJS_TemplateLiteralMultiLine(t *testing.T) {
	source := "const sql = `SELECT *\nFROM users\nWHERE id = 1`;"
	tokens := common.Tokenize(source, "javascript")

	hasTemplate := false
	for _, tok := range tokens {
		if tok.Type == common.TokenString && strings.Contains(tok.Content, "SELECT") {
			hasTemplate = true
		}
	}
	if !hasTemplate {
		t.Error("expected multi-line template literal token")
	}
}

func TestTokenizeJS_EscapedQuotes(t *testing.T) {
	source := `const s = "he said \"hello\"";`
	tokens := common.Tokenize(source, "javascript")

	hasString := false
	for _, tok := range tokens {
		if tok.Type == common.TokenString {
			hasString = true
			if !strings.Contains(tok.Content, "hello") {
				t.Errorf("expected string with escaped quotes, got %q", tok.Content)
			}
		}
	}
	if !hasString {
		t.Error("expected string token")
	}
}

func TestTokenizeJS_CodeInsideStringNotTreatedAsCode(t *testing.T) {
	source := `console.log("app.get('/api/secret')");`
	tokens := common.Tokenize(source, "javascript")

	// The route pattern is inside a string — CodeOnly should blank it out
	codeOnly := common.CodeOnly(tokens)
	// The code-only version should NOT contain app.get('/api/secret')
	if strings.Contains(codeOnly, "app.get") {
		t.Error("code inside string should not appear in CodeOnly output")
	}
}

func TestTokenizeJS_CommentedImportNotCode(t *testing.T) {
	source := "// import express from 'express';\nconst x = 1;"
	tokens := common.Tokenize(source, "javascript")

	stripped := common.StripCommentsOnly(tokens)
	lines := strings.Split(stripped, "\n")
	firstLine := strings.TrimSpace(lines[0])
	if strings.Contains(firstLine, "import") {
		t.Error("commented import should be stripped by StripCommentsOnly")
	}
}

// --- Python tokenization ---

func TestTokenizePython_SingleLineComment(t *testing.T) {
	source := "x = 1  # comment\ny = 2"
	tokens := common.Tokenize(source, "python")

	hasComment := false
	for _, tok := range tokens {
		if tok.Type == common.TokenComment {
			hasComment = true
		}
	}
	if !hasComment {
		t.Error("expected to find a comment token")
	}
}

func TestTokenizePython_TripleQuotedString(t *testing.T) {
	source := `x = """
this is a
multi-line string
"""
y = 1`
	tokens := common.Tokenize(source, "python")

	hasTriple := false
	for _, tok := range tokens {
		if tok.Type == common.TokenString && strings.Contains(tok.Content, "multi-line") {
			hasTriple = true
		}
	}
	if !hasTriple {
		t.Error("expected triple-quoted string token")
	}
}

func TestTokenizePython_TripleQuotedSingleQuotes(t *testing.T) {
	source := "x = '''\ntriple single\n'''\ny = 1"
	tokens := common.Tokenize(source, "python")

	hasTriple := false
	for _, tok := range tokens {
		if tok.Type == common.TokenString && strings.Contains(tok.Content, "triple single") {
			hasTriple = true
		}
	}
	if !hasTriple {
		t.Error("expected triple-single-quoted string token")
	}
}

func TestTokenizePython_CodeInsideTripleStringNotCode(t *testing.T) {
	source := `x = """
import os
from flask import Flask
SECRET_KEY = "abc123"
"""
y = 1`
	tokens := common.Tokenize(source, "python")

	codeOnly := common.CodeOnly(tokens)
	lines := strings.Split(codeOnly, "\n")
	// Lines 2-4 should be blank (inside triple-quoted string)
	for i := 1; i <= 3; i++ {
		if strings.TrimSpace(lines[i]) != "" {
			t.Errorf("line %d inside triple-quoted string should be blank in CodeOnly, got %q", i+1, lines[i])
		}
	}
}

func TestTokenizePython_RegularStrings(t *testing.T) {
	source := `x = 'single'
y = "double"`
	tokens := common.Tokenize(source, "python")

	stringCount := 0
	for _, tok := range tokens {
		if tok.Type == common.TokenString {
			stringCount++
		}
	}
	if stringCount != 2 {
		t.Errorf("expected 2 string tokens, got %d", stringCount)
	}
}

// --- StripCommentsOnly ---

func TestStripCommentsOnly_PreservesStrings(t *testing.T) {
	source := `const x = "hello"; // comment
const y = 'world';`
	tokens := common.Tokenize(source, "javascript")
	stripped := common.StripCommentsOnly(tokens)

	if !strings.Contains(stripped, `"hello"`) {
		t.Error("StripCommentsOnly should preserve string literals")
	}
	if strings.Contains(stripped, "comment") {
		t.Error("StripCommentsOnly should strip comments")
	}
}

// --- CodeOnly ---

func TestCodeOnly_StripsStringsAndComments(t *testing.T) {
	source := `const x = "hello"; // comment`
	tokens := common.Tokenize(source, "javascript")
	codeOnly := common.CodeOnly(tokens)

	if strings.Contains(codeOnly, "hello") {
		t.Error("CodeOnly should strip string content")
	}
	if strings.Contains(codeOnly, "comment") {
		t.Error("CodeOnly should strip comment content")
	}
	// Should preserve code structure
	if !strings.Contains(codeOnly, "const x =") {
		t.Error("CodeOnly should preserve code tokens")
	}
}

// --- Edge cases ---

func TestTokenize_EmptySource(t *testing.T) {
	tokens := common.Tokenize("", "javascript")
	if len(tokens) != 0 {
		t.Errorf("expected 0 tokens for empty source, got %d", len(tokens))
	}
}

func TestTokenize_UnknownLanguage(t *testing.T) {
	tokens := common.Tokenize("some code", "ruby")
	if len(tokens) != 1 || tokens[0].Type != common.TokenCode {
		t.Error("expected entire source as single code token for unknown language")
	}
}

func TestTokenize_LineNumbers(t *testing.T) {
	source := "line1\nline2\nline3"
	tokens := common.Tokenize(source, "javascript")
	if len(tokens) < 1 {
		t.Fatal("expected at least 1 token")
	}
	if tokens[0].Line != 1 {
		t.Errorf("expected first token on line 1, got %d", tokens[0].Line)
	}
}

func TestTokenizeJS_RegexLiteral(t *testing.T) {
	source := "const re = /pattern/gi;\n"
	tokens := common.Tokenize(source, "javascript")

	hasStringToken := false
	for _, tok := range tokens {
		if tok.Type == common.TokenString && strings.Contains(tok.Content, "/pattern/") {
			hasStringToken = true
		}
	}
	if !hasStringToken {
		t.Error("expected regex literal to be tokenized as string token")
	}
}

// --- StripCommentsAndMultilineStrings ---

func TestStripCommentsAndMultilineStrings_Basic(t *testing.T) {
	source := "x = 1  # comment\ny = '''\nmultiline\nstring\n'''\nz = 2"
	tokens := common.Tokenize(source, "python")
	stripped := common.StripCommentsAndMultilineStrings(tokens)

	if strings.Contains(stripped, "comment") {
		t.Error("should strip comments")
	}
	if strings.Contains(stripped, "multiline") {
		t.Error("should strip multi-line strings")
	}
	if !strings.Contains(stripped, "x = 1") {
		t.Error("should preserve code")
	}
	if !strings.Contains(stripped, "z = 2") {
		t.Error("should preserve code after stripped content")
	}
}

func TestStripCommentsAndMultilineStrings_Empty(t *testing.T) {
	result := common.StripCommentsAndMultilineStrings(nil)
	if result != "" {
		t.Error("expected empty string for nil tokens")
	}
}

func TestStripCommentsAndMultilineStrings_SingleLineStringsPreserved(t *testing.T) {
	source := `x = "hello"
y = 'world'`
	tokens := common.Tokenize(source, "python")
	stripped := common.StripCommentsAndMultilineStrings(tokens)

	if !strings.Contains(stripped, `"hello"`) {
		t.Error("single-line strings should be preserved")
	}
	if !strings.Contains(stripped, `'world'`) {
		t.Error("single-line strings should be preserved")
	}
}

// --- IsLineCode ---

func TestIsLineCode_CodeLine(t *testing.T) {
	source := "const x = 1;\nconst y = 2;"
	tokens := common.Tokenize(source, "javascript")

	if !common.IsLineCode(tokens, 1) {
		t.Error("line 1 should be code")
	}
	if !common.IsLineCode(tokens, 2) {
		t.Error("line 2 should be code")
	}
}

func TestIsLineCode_CommentLine(t *testing.T) {
	source := "// this is a comment\nconst x = 1;"
	tokens := common.Tokenize(source, "javascript")

	if common.IsLineCode(tokens, 1) {
		t.Error("line 1 is a comment, should not be code")
	}
	if !common.IsLineCode(tokens, 2) {
		t.Error("line 2 should be code")
	}
}

func TestIsLineCode_StringLine(t *testing.T) {
	source := "const x = `\nmultiline\nstring\n`;\nconst y = 1;"
	tokens := common.Tokenize(source, "javascript")

	// Line 2 is inside a template literal
	if common.IsLineCode(tokens, 2) {
		t.Error("line 2 inside template literal should not be code")
	}
	if !common.IsLineCode(tokens, 5) {
		t.Error("line 5 should be code")
	}
}

func TestIsLineCode_NonexistentLine(t *testing.T) {
	source := "const x = 1;"
	tokens := common.Tokenize(source, "javascript")

	if common.IsLineCode(tokens, 100) {
		t.Error("non-existent line should not be code")
	}
}

// --- Additional tokenizer edge cases ---

func TestTokenize_EmptyPython(t *testing.T) {
	tokens := common.Tokenize("", "python")
	if len(tokens) != 0 {
		t.Errorf("expected 0 tokens for empty Python source, got %d", len(tokens))
	}
}

func TestTokenizeJS_DivisionNotRegex(t *testing.T) {
	// After a number, / is division, not regex
	source := "const x = 10 / 2;"
	tokens := common.Tokenize(source, "javascript")

	// Should be all code tokens (no string token for /2/)
	for _, tok := range tokens {
		if tok.Type == common.TokenString {
			t.Errorf("division should not create string token, got %q", tok.Content)
		}
	}
}

func TestTokenizeJS_RegexAfterEquals(t *testing.T) {
	// After '=', / starts a regex
	source := "const re = /pattern/g;"
	tokens := common.Tokenize(source, "javascript")

	hasRegex := false
	for _, tok := range tokens {
		if tok.Type == common.TokenString && strings.Contains(tok.Content, "/pattern/") {
			hasRegex = true
		}
	}
	if !hasRegex {
		t.Error("expected regex after equals")
	}
}

func TestTokenizePython_EscapedQuoteInString(t *testing.T) {
	source := `x = "he said \"hello\""`
	tokens := common.Tokenize(source, "python")

	hasString := false
	for _, tok := range tokens {
		if tok.Type == common.TokenString {
			hasString = true
		}
	}
	if !hasString {
		t.Error("expected string token with escaped quotes")
	}
}

func TestCodeOnly_Empty(t *testing.T) {
	result := common.CodeOnly(nil)
	if result != "" {
		t.Error("expected empty string for nil tokens")
	}
}

func TestStripCommentsOnly_Empty(t *testing.T) {
	result := common.StripCommentsOnly(nil)
	if result != "" {
		t.Error("expected empty string for nil tokens")
	}
}

func TestTokenize_TypeScript(t *testing.T) {
	source := "const x: string = 'hello'; // comment"
	tokens := common.Tokenize(source, "typescript")

	hasComment := false
	hasString := false
	for _, tok := range tokens {
		if tok.Type == common.TokenComment {
			hasComment = true
		}
		if tok.Type == common.TokenString {
			hasString = true
		}
	}
	if !hasComment {
		t.Error("expected comment token in TypeScript")
	}
	if !hasString {
		t.Error("expected string token in TypeScript")
	}
}

func TestStripCommentsOnly_WhitespaceToken(t *testing.T) {
	// Whitespace tokens should be preserved
	tokens := []common.Token{
		{Type: common.TokenCode, Content: "code", Line: 1},
		{Type: common.TokenWhitespace, Content: "  ", Line: 1},
		{Type: common.TokenCode, Content: "more", Line: 1},
	}
	result := common.StripCommentsOnly(tokens)
	if !strings.Contains(result, "code") || !strings.Contains(result, "more") {
		t.Error("code should be preserved")
	}
}

func TestStripCommentsAndMultilineStrings_JSTemplateLiteral(t *testing.T) {
	source := "const sql = `SELECT *\nFROM users`;\nconst x = 1;"
	tokens := common.Tokenize(source, "javascript")
	stripped := common.StripCommentsAndMultilineStrings(tokens)

	if strings.Contains(stripped, "SELECT") {
		t.Error("multi-line template literal should be stripped")
	}
	if !strings.Contains(stripped, "const x = 1") {
		t.Error("code after stripped template should be preserved")
	}
}

func TestTokenizeJS_MultilineComment(t *testing.T) {
	source := "const x = 1;\n/* multi\nline\ncomment */\nconst y = 2;"
	tokens := common.Tokenize(source, "javascript")

	codeOnly := common.CodeOnly(tokens)
	if strings.Contains(codeOnly, "multi") || strings.Contains(codeOnly, "comment") {
		t.Error("multi-line comment should not be in code")
	}
	if !strings.Contains(codeOnly, "const x = 1") {
		t.Error("code before comment should be preserved")
	}
	if !strings.Contains(codeOnly, "const y = 2") {
		t.Error("code after comment should be preserved")
	}
}
