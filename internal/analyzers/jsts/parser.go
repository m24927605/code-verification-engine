package jsts

import (
	"strings"
)

// ASTResult holds all extracted constructs from a JS/TS source file.
type ASTResult struct {
	Imports     []ASTImport
	Symbols     []ASTSymbol
	Routes      []ASTRoute
	Middlewares []ASTMiddleware
	Secrets     []ASTSecret
	UseCalls    []ASTUseCall
}

// ASTUseCall represents an app.use() or router.use() call.
type ASTUseCall struct {
	Receiver    string   // "app", "router", or variable name
	Middlewares []string // middleware names passed as arguments
	Path        string   // mount path if present
	Line        int
}

// ASTImport represents an import or require statement.
type ASTImport struct {
	Source string   // module path
	Names  []string // imported names (empty for default/namespace)
	Line   int
}

// ASTSymbol represents a declared symbol (function, class, method, variable).
type ASTSymbol struct {
	Name     string
	Kind     string // "function", "class", "method", "variable"
	Exported bool
	Line     int
	EndLine  int
}

// ASTRoute represents an HTTP route definition.
type ASTRoute struct {
	Method      string
	Path        string
	Handler     string   // handler function name (last arg)
	Middlewares []string // middleware function names (args between path and handler)
	Guards      []string // from @UseGuards decorator (TS only)
	Line        int
}

// ASTMiddleware represents a middleware registration.
type ASTMiddleware struct {
	Name      string
	Framework string
	Line      int
}

// ASTSecret represents a detected hardcoded secret.
type ASTSecret struct {
	Name  string
	Value string
	Line  int
}

// parser holds state for a recursive-descent parse of the token stream.
type parser struct {
	toks          []Tok
	pos           int
	res           *ASTResult
	pendingGuards []string // guards from @UseGuards to attach to next route
}

// Parse tokenizes source and extracts AST-level facts from JS/TS code.
func Parse(source string) *ASTResult {
	tokens := Tokenize(source)
	p := &parser{
		toks: tokens,
		res:  &ASTResult{},
	}
	p.parse()
	return p.res
}

func (p *parser) parse() {
	for !p.atEnd() {
		p.skipNewlines()
		if p.atEnd() {
			break
		}
		if !p.parseTopLevel() {
			p.advance() // skip unknown token
		}
	}
}

func (p *parser) parseTopLevel() bool {
	tok := p.peek()

	// Decorators
	if tok.Kind == TokDecorator {
		return p.parseDecorator()
	}

	// Keywords
	if tok.Kind == TokKeyword {
		switch tok.Value {
		case "import":
			return p.parseImport()
		case "export":
			return p.parseExport()
		case "function", "async":
			return p.parseFunctionDecl(false)
		case "class":
			return p.parseClassDecl(false)
		case "const", "let", "var":
			return p.parseVarDecl(false)
		}
	}

	// Identifier-based patterns: app.get(...), router.post(...), etc.
	if tok.Kind == TokIdent {
		return p.parseExprStatement()
	}

	return false
}

// --- Import parsing ---

func (p *parser) parseImport() bool {
	startLine := p.peek().Line
	p.advance() // skip 'import'

	// import type { ... } from '...' — skip type-only imports' "type" keyword
	if p.peekIs(TokKeyword, "type") {
		p.advance()
	}

	var names []string

	// import { A, B } from 'mod'
	if p.peekIs(TokPunct, "{") {
		names = p.parseNamedImports()
		p.expectKeyword("from")
		if src := p.expectString(); src != "" {
			p.res.Imports = append(p.res.Imports, ASTImport{Source: src, Names: names, Line: startLine})
			return true
		}
		return true
	}

	// import * as X from 'mod'
	if p.peekIs(TokPunct, "*") {
		p.advance() // skip *
		if p.peekIs(TokKeyword, "as") {
			p.advance()
		}
		if p.peek().Kind == TokIdent || p.peek().Kind == TokKeyword {
			p.advance() // skip alias name
		}
		p.expectKeyword("from")
		if src := p.expectString(); src != "" {
			p.res.Imports = append(p.res.Imports, ASTImport{Source: src, Line: startLine})
			return true
		}
		return true
	}

	// import 'mod' (side-effect import)
	if p.peek().Kind == TokString {
		src := p.peek().Value
		p.advance()
		p.res.Imports = append(p.res.Imports, ASTImport{Source: src, Line: startLine})
		return true
	}

	// import X from 'mod' or import X, { A, B } from 'mod'
	if p.peek().Kind == TokIdent || p.peek().Kind == TokKeyword {
		p.advance() // skip default import name

		// import X, { A, B } from 'mod'
		if p.peekIs(TokPunct, ",") {
			p.advance() // skip comma
			if p.peekIs(TokPunct, "{") {
				names = p.parseNamedImports()
			} else if p.peekIs(TokPunct, "*") {
				p.advance()
				if p.peekIs(TokKeyword, "as") {
					p.advance()
				}
				if p.peek().Kind == TokIdent || p.peek().Kind == TokKeyword {
					p.advance()
				}
			}
		}

		p.expectKeyword("from")
		if src := p.expectString(); src != "" {
			p.res.Imports = append(p.res.Imports, ASTImport{Source: src, Names: names, Line: startLine})
			return true
		}
		return true
	}

	return true
}

func (p *parser) parseNamedImports() []string {
	var names []string
	if !p.peekIs(TokPunct, "{") {
		return names
	}
	p.advance() // skip {

	for !p.atEnd() && !p.peekIs(TokPunct, "}") {
		p.skipNewlines()
		if p.atEnd() || p.peekIs(TokPunct, "}") {
			break
		}
		tok := p.peek()
		if tok.Kind == TokIdent || tok.Kind == TokKeyword {
			name := tok.Value
			p.advance()
			// handle 'as' alias
			if p.peekIs(TokKeyword, "as") {
				p.advance()
				if p.peek().Kind == TokIdent || p.peek().Kind == TokKeyword {
					p.advance()
				}
			}
			names = append(names, name)
		} else {
			p.advance()
		}
		if p.peekIs(TokPunct, ",") {
			p.advance()
		}
	}
	if p.peekIs(TokPunct, "}") {
		p.advance()
	}
	return names
}

// --- Export parsing ---

func (p *parser) parseExport() bool {
	p.advance() // skip 'export'

	// export default ...
	if p.peekIs(TokKeyword, "default") {
		p.advance()
		if p.peekIs(TokKeyword, "function") || p.peekIs(TokKeyword, "async") {
			return p.parseFunctionDecl(true)
		}
		if p.peekIs(TokKeyword, "class") {
			return p.parseClassDecl(true)
		}
		// export default expression — skip
		return true
	}

	// export function, export async function, export class, export const/let/var
	if p.peekIs(TokKeyword, "function") || p.peekIs(TokKeyword, "async") {
		return p.parseFunctionDecl(true)
	}
	if p.peekIs(TokKeyword, "class") || p.peekIs(TokKeyword, "abstract") {
		return p.parseClassDecl(true)
	}
	if p.peekIs(TokKeyword, "const") || p.peekIs(TokKeyword, "let") || p.peekIs(TokKeyword, "var") {
		return p.parseVarDecl(true)
	}
	if p.peekIs(TokKeyword, "interface") {
		return p.parseInterfaceDecl(true)
	}
	if p.peekIs(TokKeyword, "type") {
		// export type X = ... — just emit as a symbol
		p.advance() // skip 'type'
		if p.peek().Kind == TokIdent {
			name := p.peek().Value
			line := p.peek().Line
			p.advance()
			p.res.Symbols = append(p.res.Symbols, ASTSymbol{
				Name: name, Kind: "type", Exported: true, Line: line, EndLine: line,
			})
		}
		return true
	}
	if p.peekIs(TokKeyword, "enum") {
		p.advance() // skip 'enum'
		if p.peek().Kind == TokIdent {
			name := p.peek().Value
			line := p.peek().Line
			p.advance()
			p.res.Symbols = append(p.res.Symbols, ASTSymbol{
				Name: name, Kind: "enum", Exported: true, Line: line, EndLine: line,
			})
		}
		p.skipBraces()
		return true
	}

	return true
}

// --- Function declaration ---

func (p *parser) parseFunctionDecl(exported bool) bool {
	line := p.peek().Line

	// async function ...
	if p.peekIs(TokKeyword, "async") {
		p.advance()
	}

	if !p.peekIs(TokKeyword, "function") {
		return false
	}
	p.advance() // skip 'function'

	// function* (generator)
	if p.peekIs(TokPunct, "*") {
		p.advance()
	}

	name := ""
	if p.peek().Kind == TokIdent || p.peek().Kind == TokKeyword {
		name = p.peek().Value
		p.advance()
	}

	// Skip params
	p.skipParens()

	// Skip optional return type annotation
	if p.peekIs(TokPunct, ":") {
		p.advance()
		p.skipTypeAnnotation()
	}

	endLine := p.peek().Line
	// Skip function body
	if p.peekIs(TokPunct, "{") {
		endLine = p.skipBraces()
	}

	if name != "" {
		p.res.Symbols = append(p.res.Symbols, ASTSymbol{
			Name: name, Kind: "function", Exported: exported, Line: line, EndLine: endLine,
		})
	}
	return true
}

// --- Class declaration ---

func (p *parser) parseClassDecl(exported bool) bool {
	line := p.peek().Line

	if p.peekIs(TokKeyword, "abstract") {
		p.advance()
	}

	if !p.peekIs(TokKeyword, "class") {
		return false
	}
	p.advance() // skip 'class'

	name := ""
	if p.peek().Kind == TokIdent || p.peek().Kind == TokKeyword {
		name = p.peek().Value
		p.advance()
	}

	// Skip extends/implements/generic params
	for !p.atEnd() && !p.peekIs(TokPunct, "{") {
		if p.peek().Kind == TokNewline {
			p.advance()
			continue
		}
		p.advance()
	}

	endLine := line
	if p.peekIs(TokPunct, "{") {
		endLine = p.parseClassBody()
	}

	if name != "" {
		p.res.Symbols = append(p.res.Symbols, ASTSymbol{
			Name: name, Kind: "class", Exported: exported, Line: line, EndLine: endLine,
		})
	}
	return true
}

// parseClassBody scans the class body for decorators and method-level constructs.
func (p *parser) parseClassBody() int {
	if !p.peekIs(TokPunct, "{") {
		return p.peek().Line
	}
	p.advance() // skip opening {
	depth := 1
	endLine := p.peek().Line

	for !p.atEnd() && depth > 0 {
		tok := p.peek()

		if tok.Kind == TokNewline || tok.Kind == TokLineComment || tok.Kind == TokBlockComment {
			p.advance()
			continue
		}

		// Handle nested braces
		if tok.Kind == TokPunct && tok.Value == "{" {
			depth++
			p.advance()
			continue
		}
		if tok.Kind == TokPunct && tok.Value == "}" {
			depth--
			endLine = tok.Line
			if depth == 0 {
				p.advance()
				return endLine
			}
			p.advance()
			continue
		}

		// Only scan for decorators at the class body level (depth == 1)
		if depth == 1 && tok.Kind == TokDecorator {
			p.parseDecorator()
			continue
		}

		p.advance()
	}
	return endLine
}

// --- Interface declaration ---

func (p *parser) parseInterfaceDecl(exported bool) bool {
	if !p.peekIs(TokKeyword, "interface") {
		return false
	}
	line := p.peek().Line
	p.advance() // skip 'interface'

	name := ""
	if p.peek().Kind == TokIdent || p.peek().Kind == TokKeyword {
		name = p.peek().Value
		p.advance()
	}

	// Skip extends/generic params
	for !p.atEnd() && !p.peekIs(TokPunct, "{") {
		if p.peek().Kind == TokNewline {
			p.advance()
			continue
		}
		p.advance()
	}

	endLine := line
	if p.peekIs(TokPunct, "{") {
		endLine = p.skipBraces()
	}

	if name != "" {
		p.res.Symbols = append(p.res.Symbols, ASTSymbol{
			Name: name, Kind: "interface", Exported: exported, Line: line, EndLine: endLine,
		})
	}
	return true
}

// --- Variable declaration (const/let/var) ---

func (p *parser) parseVarDecl(exported bool) bool {
	line := p.peek().Line
	p.advance() // skip const/let/var

	if p.atEnd() {
		return true
	}

	tok := p.peek()
	if tok.Kind != TokIdent && tok.Kind != TokKeyword {
		// destructuring or other pattern — skip
		return true
	}

	name := tok.Value
	nameLine := tok.Line
	p.advance()

	// Skip optional type annotation: name: Type = ...
	if p.peekIs(TokPunct, ":") {
		p.advance()
		p.skipTypeAnnotation()
	}

	// Check for = assignment
	if !p.peekIs(TokPunct, "=") {
		// Declaration without assignment
		p.res.Symbols = append(p.res.Symbols, ASTSymbol{
			Name: name, Kind: "variable", Exported: exported, Line: nameLine, EndLine: nameLine,
		})
		return true
	}
	p.advance() // skip '='

	p.skipNewlines()

	// Check for require('...')
	if p.peekIs(TokKeyword, "require") {
		return p.parseRequire(name, line)
	}

	// Check for arrow function: (...) => or async (...) =>
	if p.isArrowFunction() {
		endLine := p.skipArrowFunction()
		p.res.Symbols = append(p.res.Symbols, ASTSymbol{
			Name: name, Kind: "function", Exported: exported, Line: nameLine, EndLine: endLine,
		})
		return true
	}

	// Check for function expression: function(...) { }
	if p.peekIs(TokKeyword, "function") {
		endLine := nameLine
		p.advance() // skip 'function'
		// skip optional name
		if p.peek().Kind == TokIdent {
			p.advance()
		}
		p.skipParens()
		if p.peekIs(TokPunct, "{") {
			endLine = p.skipBraces()
		}
		p.res.Symbols = append(p.res.Symbols, ASTSymbol{
			Name: name, Kind: "function", Exported: exported, Line: nameLine, EndLine: endLine,
		})
		return true
	}

	// Check for secret pattern in variable assignment
	if p.peek().Kind == TokString {
		val := p.peek().Value
		if isSecretName(name) && len(val) >= 4 {
			kind := classifySecret(name)
			p.res.Secrets = append(p.res.Secrets, ASTSecret{
				Name: name, Value: val, Line: nameLine,
			})
			_ = kind
		}
		p.advance()
		p.res.Symbols = append(p.res.Symbols, ASTSymbol{
			Name: name, Kind: "variable", Exported: exported, Line: nameLine, EndLine: nameLine,
		})
		return true
	}

	// Generic variable assignment
	p.res.Symbols = append(p.res.Symbols, ASTSymbol{
		Name: name, Kind: "variable", Exported: exported, Line: nameLine, EndLine: nameLine,
	})
	return true
}

func (p *parser) parseRequire(name string, line int) bool {
	p.advance() // skip 'require'
	if p.peekIs(TokPunct, "(") {
		p.advance() // skip (
		if p.peek().Kind == TokString {
			src := p.peek().Value
			p.advance()
			if p.peekIs(TokPunct, ")") {
				p.advance()
			}
			p.res.Imports = append(p.res.Imports, ASTImport{Source: src, Line: line})
			return true
		}
		// Skip to closing )
		for !p.atEnd() && !p.peekIs(TokPunct, ")") {
			p.advance()
		}
		if p.peekIs(TokPunct, ")") {
			p.advance()
		}
	}
	return true
}

// --- Expression statements (routes, middleware) ---

func (p *parser) parseExprStatement() bool {
	tok := p.peek()

	// Look for: ident.method(args) pattern
	if tok.Kind != TokIdent {
		return false
	}

	receiver := tok.Value
	p.advance()

	if !p.peekIs(TokPunct, ".") {
		return true
	}
	p.advance() // skip '.'

	if p.peek().Kind != TokIdent && p.peek().Kind != TokKeyword {
		return true
	}

	method := p.peek().Value
	methodLine := p.peek().Line
	p.advance()

	if !p.peekIs(TokPunct, "(") {
		return true
	}

	// Now we have receiver.method( — check patterns
	return p.parseCallExpr(receiver, method, methodLine)
}

func (p *parser) parseCallExpr(receiver, method string, line int) bool {
	// receiver.method( — peek at args
	p.advance() // skip '('

	// Route patterns: app.get('/path', ...), router.post('/path', ...), fastify.get('/path', ...)
	httpMethods := map[string]string{
		"get": "GET", "post": "POST", "put": "PUT", "delete": "DELETE",
		"patch": "PATCH", "options": "OPTIONS", "head": "HEAD", "all": "ALL",
	}

	if upper, ok := httpMethods[strings.ToLower(method)]; ok {
		if p.peek().Kind == TokString {
			path := p.peek().Value
			if strings.HasPrefix(path, "/") || strings.HasPrefix(path, ":") {
				p.advance() // skip path string
				// Collect remaining args: middleware identifiers and final handler
				var args []string
				for !p.atEnd() {
					// skip commas and newlines
					if p.peekIs(TokPunct, ",") {
						p.advance()
						p.skipNewlines()
						continue
					}
					if p.peek().Kind == TokNewline {
						p.advance()
						continue
					}
					if p.peekIs(TokPunct, ")") {
						break
					}
					if p.peek().Kind == TokIdent {
						args = append(args, p.peek().Value)
						p.advance()
						// Skip function call parens if present: mw()
						if p.peekIs(TokPunct, "(") {
							p.skipParens()
						}
					} else {
						// Skip arrow functions, function expressions, etc.
						break
					}
				}
				var handler string
				var middlewares []string
				if len(args) > 0 {
					handler = args[len(args)-1]
					middlewares = args[:len(args)-1]
				}
				p.res.Routes = append(p.res.Routes, ASTRoute{
					Method: upper, Path: path, Handler: handler,
					Middlewares: middlewares, Line: line,
				})
			}
		}
		p.skipToCloseParen()
		return true
	}

	// Middleware: app.use(X) or app.use('/path', X) or app.use(X, Y)
	if method == "use" {
		uc := p.extractUseCall(receiver, line)
		p.res.UseCalls = append(p.res.UseCalls, uc)
		// Also record each middleware name in the legacy Middlewares list for backward
		// compatibility with existing bridge/middleware consumers.
		for _, mw := range uc.Middlewares {
			p.res.Middlewares = append(p.res.Middlewares, ASTMiddleware{
				Name: mw, Framework: "express", Line: line,
			})
		}
		p.skipToCloseParen()
		return true
	}

	// fastify.register(X)
	if method == "register" {
		if p.peek().Kind == TokIdent {
			pluginName := p.peek().Value
			framework := "fastify-plugin"
			if isHapiReceiver(receiver) {
				framework = "hapi-plugin"
			}
			p.res.Middlewares = append(p.res.Middlewares, ASTMiddleware{
				Name: pluginName, Framework: framework, Line: line,
			})
		}
		p.skipToCloseParen()
		return true
	}

	// fastify.addHook('name', handler)
	if method == "addHook" {
		if p.peek().Kind == TokString {
			hookName := p.peek().Value
			p.res.Middlewares = append(p.res.Middlewares, ASTMiddleware{
				Name: hookName, Framework: "fastify-hook", Line: line,
			})
		}
		p.skipToCloseParen()
		return true
	}

	// server.route({ method: 'GET', path: '/...' }) or fastify.route({ url: '/...' })
	if method == "route" {
		p.parseRouteObject(line)
		p.skipToCloseParen()
		return true
	}

	// server.ext('onPreHandler', handler)
	if method == "ext" {
		if p.peek().Kind == TokString {
			extName := p.peek().Value
			p.res.Middlewares = append(p.res.Middlewares, ASTMiddleware{
				Name: extName, Framework: "hapi-ext", Line: line,
			})
		}
		p.skipToCloseParen()
		return true
	}

	p.skipToCloseParen()
	return true
}

func (p *parser) parseRouteObject(line int) {
	// We're inside route({ ... }) — look for method/path/url keys
	routeMethod := ""
	routePath := ""

	depth := 1 // we've consumed the opening (
	for !p.atEnd() && depth > 0 {
		tok := p.peek()
		if tok.Kind == TokPunct && tok.Value == "(" {
			depth++
			p.advance()
			continue
		}
		if tok.Kind == TokPunct && tok.Value == ")" {
			depth--
			if depth == 0 {
				break
			}
			p.advance()
			continue
		}

		// Look for method: 'GET' or path: '/...' or url: '/...'
		if (tok.Kind == TokIdent || tok.Kind == TokKeyword) && p.pos+1 < len(p.toks) {
			key := tok.Value
			next := p.toks[p.pos+1]
			if next.Kind == TokPunct && next.Value == ":" {
				p.advance() // skip key
				p.advance() // skip :
				p.skipNewlines()
				if p.peek().Kind == TokString {
					val := p.peek().Value
					switch key {
					case "method":
						routeMethod = strings.ToUpper(val)
					case "path", "url":
						routePath = val
					}
					p.advance()
					continue
				}
			}
		}
		p.advance()
	}

	if routePath != "" {
		if routeMethod == "" {
			routeMethod = "ANY"
		}
		p.res.Routes = append(p.res.Routes, ASTRoute{
			Method: routeMethod, Path: routePath, Line: line,
		})
	}
}

func (p *parser) extractMiddlewareName() string {
	tok := p.peek()

	// app.use(cors) or app.use(cors()) or app.use(express.json())
	if tok.Kind == TokIdent {
		name := tok.Value
		// Check if it's receiver.method() like express.json()
		if p.pos+2 < len(p.toks) && p.toks[p.pos+1].Kind == TokPunct && p.toks[p.pos+1].Value == "." {
			return name
		}
		return name
	}
	return ""
}

// extractUseCall parses the arguments of an app.use(...) or router.use(...) call.
// The opening '(' has already been consumed by parseCallExpr.
// It returns an ASTUseCall with any path and middleware names found.
func (p *parser) extractUseCall(receiver string, line int) ASTUseCall {
	uc := ASTUseCall{Receiver: receiver, Line: line}

	for !p.atEnd() && !p.peekIs(TokPunct, ")") {
		p.skipNewlines()
		if p.atEnd() || p.peekIs(TokPunct, ")") {
			break
		}

		tok := p.peek()

		// Skip commas
		if tok.Kind == TokPunct && tok.Value == "," {
			p.advance()
			continue
		}

		// String argument — mount path
		if tok.Kind == TokString {
			if uc.Path == "" {
				uc.Path = tok.Value
			}
			p.advance()
			continue
		}

		// Identifier argument — middleware name (possibly followed by call parens)
		if tok.Kind == TokIdent {
			name := tok.Value
			p.advance()
			// Skip call parens: cors() or express.json()
			if p.peekIs(TokPunct, ".") {
				// receiver.method() form — just use outer name
				p.advance()
				if p.peek().Kind == TokIdent || p.peek().Kind == TokKeyword {
					p.advance()
				}
			}
			if p.peekIs(TokPunct, "(") {
				p.skipParens()
			}
			uc.Middlewares = append(uc.Middlewares, name)
			continue
		}

		// Anything else (arrow functions, etc.) — stop
		break
	}

	return uc
}

// --- Decorator parsing ---

func (p *parser) parseDecorator() bool {
	tok := p.peek()
	line := tok.Line
	decoratorName := tok.Value // e.g., "@Controller"

	p.advance() // skip decorator token

	// Parse decorator arguments if present
	var arg string
	var identArgs []string
	if p.peekIs(TokPunct, "(") {
		p.advance() // skip (
		if p.peek().Kind == TokString {
			arg = p.peek().Value
		}
		// Collect identifier arguments (e.g., @UseGuards(AuthGuard, RoleGuard))
		for !p.atEnd() && !p.peekIs(TokPunct, ")") {
			if p.peek().Kind == TokIdent {
				identArgs = append(identArgs, p.peek().Value)
			}
			p.advance()
			if p.peekIs(TokPunct, ",") {
				p.advance()
			}
		}
		if p.peekIs(TokPunct, ")") {
			p.advance()
		}
	}

	// Map NestJS decorators to routes/middleware
	switch decoratorName {
	case "@Controller":
		prefix := "/" + strings.TrimPrefix(arg, "/")
		if arg == "" {
			prefix = "/"
		}
		p.res.Routes = append(p.res.Routes, ASTRoute{
			Method: "PREFIX", Path: prefix, Line: line,
		})
	case "@Get", "@Post", "@Put", "@Delete", "@Patch", "@Options", "@Head", "@All":
		httpMethod := strings.ToUpper(strings.TrimPrefix(decoratorName, "@"))
		path := arg
		if path == "" {
			path = "/"
		}
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		// Attach any pending guards from preceding @UseGuards decorator
		var guards []string
		if len(p.pendingGuards) > 0 {
			guards = append(guards, p.pendingGuards...)
			p.pendingGuards = nil
		}
		p.res.Routes = append(p.res.Routes, ASTRoute{
			Method: httpMethod, Path: path, Guards: guards, Line: line,
		})
	case "@UseGuards":
		// Collect guard names from both string and identifier arguments
		var guardNames []string
		if arg != "" {
			guardNames = append(guardNames, arg)
		}
		guardNames = append(guardNames, identArgs...)
		for _, name := range guardNames {
			p.res.Middlewares = append(p.res.Middlewares, ASTMiddleware{
				Name: name, Framework: "nestjs-guard", Line: line,
			})
		}
		// Store as pending guards to attach to the next route decorator
		p.pendingGuards = append(p.pendingGuards, guardNames...)
	case "@UseInterceptors":
		if arg != "" {
			p.res.Middlewares = append(p.res.Middlewares, ASTMiddleware{
				Name: arg, Framework: "nestjs-interceptor", Line: line,
			})
		}
		for _, name := range identArgs {
			p.res.Middlewares = append(p.res.Middlewares, ASTMiddleware{
				Name: name, Framework: "nestjs-interceptor", Line: line,
			})
		}
	}

	return true
}

// --- Arrow function detection ---

func (p *parser) isArrowFunction() bool {
	// Look for patterns: () =>, async () =>, (a, b) =>, async (a) =>
	saved := p.pos

	if p.peekIs(TokKeyword, "async") {
		p.pos++
	}

	if p.peekIs(TokPunct, "(") {
		// Skip parens and check for =>
		depth := 0
		for p.pos < len(p.toks) {
			t := p.toks[p.pos]
			if t.Kind == TokPunct && t.Value == "(" {
				depth++
			} else if t.Kind == TokPunct && t.Value == ")" {
				depth--
				if depth == 0 {
					p.pos++
					// Skip optional return type annotation
					if p.pos < len(p.toks) && p.toks[p.pos].Kind == TokPunct && p.toks[p.pos].Value == ":" {
						p.pos++
						tmpPos := p.pos
						p.skipTypeAnnotation()
						_ = tmpPos
					}
					// Skip newlines
					for p.pos < len(p.toks) && p.toks[p.pos].Kind == TokNewline {
						p.pos++
					}
					if p.pos < len(p.toks) && p.toks[p.pos].Kind == TokPunct && p.toks[p.pos].Value == "=>" {
						p.pos = saved
						return true
					}
					p.pos = saved
					return false
				}
			}
			p.pos++
		}
		p.pos = saved
		return false
	}

	// Single param without parens: x =>
	if p.pos < len(p.toks) && (p.toks[p.pos].Kind == TokIdent || p.toks[p.pos].Kind == TokKeyword) {
		p.pos++
		for p.pos < len(p.toks) && p.toks[p.pos].Kind == TokNewline {
			p.pos++
		}
		if p.pos < len(p.toks) && p.toks[p.pos].Kind == TokPunct && p.toks[p.pos].Value == "=>" {
			p.pos = saved
			return true
		}
	}

	p.pos = saved
	return false
}

func (p *parser) skipArrowFunction() int {
	// Skip async
	if p.peekIs(TokKeyword, "async") {
		p.advance()
	}

	// Skip params
	if p.peekIs(TokPunct, "(") {
		p.skipParens()
	} else if p.peek().Kind == TokIdent || p.peek().Kind == TokKeyword {
		p.advance()
	}

	// Skip optional return type
	if p.peekIs(TokPunct, ":") {
		p.advance()
		p.skipTypeAnnotation()
	}

	// Skip =>
	p.skipNewlines()
	if p.peekIs(TokPunct, "=>") {
		p.advance()
	}

	p.skipNewlines()

	// Arrow body
	if p.peekIs(TokPunct, "{") {
		return p.skipBraces()
	}

	// Expression body — advance past the expression (simplified)
	endLine := p.peek().Line
	return endLine
}

// --- Helper methods ---

func (p *parser) peek() Tok {
	if p.pos >= len(p.toks) {
		return Tok{Kind: TokEOF}
	}
	return p.toks[p.pos]
}

func (p *parser) advance() {
	if p.pos < len(p.toks) {
		p.pos++
	}
}

func (p *parser) atEnd() bool {
	return p.pos >= len(p.toks) || p.toks[p.pos].Kind == TokEOF
}

func (p *parser) peekIs(kind TokKind, value string) bool {
	if p.pos >= len(p.toks) {
		return false
	}
	t := p.toks[p.pos]
	return t.Kind == kind && t.Value == value
}

func (p *parser) skipNewlines() {
	for p.pos < len(p.toks) {
		t := p.toks[p.pos]
		if t.Kind == TokNewline || t.Kind == TokLineComment || t.Kind == TokBlockComment {
			p.pos++
		} else {
			break
		}
	}
}

func (p *parser) expectKeyword(kw string) bool {
	p.skipNewlines()
	if p.peekIs(TokKeyword, kw) {
		p.advance()
		return true
	}
	return false
}

func (p *parser) expectString() string {
	p.skipNewlines()
	if p.peek().Kind == TokString {
		v := p.peek().Value
		p.advance()
		return v
	}
	return ""
}

func (p *parser) skipParens() {
	if !p.peekIs(TokPunct, "(") {
		return
	}
	depth := 0
	for !p.atEnd() {
		t := p.peek()
		if t.Kind == TokPunct && t.Value == "(" {
			depth++
		} else if t.Kind == TokPunct && t.Value == ")" {
			depth--
			if depth == 0 {
				p.advance()
				return
			}
		}
		p.advance()
	}
}

func (p *parser) skipBraces() int {
	if !p.peekIs(TokPunct, "{") {
		return p.peek().Line
	}
	depth := 0
	endLine := p.peek().Line
	for !p.atEnd() {
		t := p.peek()
		if t.Kind == TokPunct && t.Value == "{" {
			depth++
		} else if t.Kind == TokPunct && t.Value == "}" {
			depth--
			endLine = t.Line
			if depth == 0 {
				p.advance()
				return endLine
			}
		}
		p.advance()
	}
	return endLine
}

func (p *parser) skipToCloseParen() {
	depth := 1 // already consumed opening paren
	for !p.atEnd() {
		t := p.peek()
		if t.Kind == TokPunct && t.Value == "(" {
			depth++
		} else if t.Kind == TokPunct && t.Value == ")" {
			depth--
			if depth == 0 {
				p.advance()
				return
			}
		}
		p.advance()
	}
}

func (p *parser) skipTypeAnnotation() {
	// Simple heuristic: skip tokens until we hit =, {, =>, ;, ), newline at depth 0
	depth := 0
	for !p.atEnd() {
		t := p.peek()
		if t.Kind == TokPunct {
			switch t.Value {
			case "<":
				depth++
			case ">":
				if depth > 0 {
					depth--
				}
			case "=", "=>", "{", ";":
				if depth == 0 {
					return
				}
			case ")":
				if depth == 0 {
					return
				}
			case ",":
				if depth == 0 {
					return
				}
			}
		}
		if t.Kind == TokNewline && depth == 0 {
			return
		}
		if t.Kind == TokKeyword && depth == 0 {
			// Some keywords signal end of type annotation
			switch t.Value {
			case "function", "class", "const", "let", "var", "import", "export":
				return
			}
		}
		p.advance()
	}
}

// --- Secret detection ---

var secretPatterns = []string{
	"secret", "token", "password", "passwd", "pwd",
	"api_key", "apikey", "api_secret",
	"jwt_secret", "auth_secret",
}

func isSecretName(name string) bool {
	lower := strings.ToLower(name)
	for _, p := range secretPatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

func classifySecret(name string) string {
	lower := strings.ToLower(name)
	if strings.Contains(lower, "api_key") || strings.Contains(lower, "apikey") || strings.Contains(lower, "api_secret") {
		return "hardcoded_api_key"
	}
	if strings.Contains(lower, "password") || strings.Contains(lower, "passwd") || strings.Contains(lower, "pwd") {
		return "hardcoded_password"
	}
	return "hardcoded_secret"
}

func isHapiReceiver(name string) bool {
	lower := strings.ToLower(name)
	return lower == "server" || strings.Contains(lower, "hapi")
}
