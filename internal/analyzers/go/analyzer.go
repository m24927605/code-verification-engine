package goanalyzer

import (
	"bufio"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"

	"github.com/verabase/code-verification-engine/internal/analyzers"
	"github.com/verabase/code-verification-engine/internal/facts"
	"github.com/verabase/code-verification-engine/internal/typegraph"
)

// GoAnalyzer extracts facts from Go source files using go/parser and go/ast.
type GoAnalyzer struct{}

// New creates a new GoAnalyzer.
func New() *GoAnalyzer {
	return &GoAnalyzer{}
}

// Language returns the language this analyzer handles.
func (a *GoAnalyzer) Language() facts.Language {
	return facts.LangGo
}

// Extensions returns file extensions handled by this analyzer.
func (a *GoAnalyzer) Extensions() []string {
	return []string{".go"}
}

// Analyze parses Go files and extracts normalized facts.
func (a *GoAnalyzer) Analyze(dir string, files []string) (*analyzers.AnalysisResult, error) {
	result := &analyzers.AnalysisResult{}
	result.TypeGraph = typegraph.New()
	fset := token.NewFileSet()

	for _, relPath := range files {
		absPath := filepath.Join(dir, relPath)

		// FileFact
		lineCount, err := countLines(absPath)
		if err != nil {
			result.SkippedFiles = append(result.SkippedFiles, analyzers.SkippedFile{File: relPath, Reason: "read error"})
			continue
		}
		ff, err := facts.NewFileFact(facts.LangGo, relPath, lineCount)
		if err != nil {
			continue
		}
		ff.Quality = facts.QualityProof
		result.Files = append(result.Files, ff)

		// Parse file
		node, err := parser.ParseFile(fset, absPath, nil, parser.ParseComments)
		if err != nil {
			result.SkippedFiles = append(result.SkippedFiles, analyzers.SkippedFile{File: relPath, Reason: "parse error"})
			continue
		}

		isTestFile := strings.HasSuffix(relPath, "_test.go")

		// Imports
		for _, imp := range node.Imports {
			importPath := strings.Trim(imp.Path.Value, `"`)
			alias := ""
			if imp.Name != nil {
				alias = imp.Name.Name
			}
			span := spanFromPos(fset, imp.Pos(), imp.End())
			impFact, err := facts.NewImportFact(facts.LangGo, relPath, span, importPath, alias)
			if err == nil {
				impFact.Quality = facts.QualityProof
				result.Imports = append(result.Imports, impFact)
			}
		}

		// Track imports for this file for data access detection
		fileImports := collectFileImports(node)

		// Functions and methods
		for _, decl := range node.Decls {
			funcDecl, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}

			name := funcDecl.Name.Name
			exported := ast.IsExported(name)
			kind := "function"
			if funcDecl.Recv != nil {
				kind = "method"
			}
			span := spanFromPos(fset, funcDecl.Pos(), funcDecl.End())

			sf, err := facts.NewSymbolFact(facts.LangGo, relPath, span, name, kind, exported)
			if err == nil {
				sf.Quality = facts.QualityProof
				result.Symbols = append(result.Symbols, sf)
			}

			// TestFact
			if isTestFile && strings.HasPrefix(name, "Test") {
				targetPath := strings.TrimSuffix(relPath, "_test.go") + ".go"
				targetModule := filepath.Dir(relPath)
				tf, err := facts.NewTestFact(facts.LangGo, relPath, span, name, targetModule, targetPath)
				if err == nil {
					tf.Quality = facts.QualityProof
					result.Tests = append(result.Tests, tf)
				}
			}

			// Middleware detection
			if isMiddlewareSignature(funcDecl) || isFiberHandlerSignature(funcDecl) || strings.Contains(strings.ToLower(name), "middleware") {
				mSpan := spanFromPos(fset, funcDecl.Pos(), funcDecl.End())
				mf, err := facts.NewMiddlewareFact(facts.LangGo, relPath, mSpan, name, "http")
				if err == nil {
					mf.Quality = facts.QualityProof
					result.Middlewares = append(result.Middlewares, mf)
				}
			}
		}

		// Type declarations
		for _, decl := range node.Decls {
			genDecl, ok := decl.(*ast.GenDecl)
			if !ok {
				continue
			}
			if genDecl.Tok == token.TYPE {
				for _, spec := range genDecl.Specs {
					typeSpec, ok := spec.(*ast.TypeSpec)
					if !ok {
						continue
					}
					name := typeSpec.Name.Name
					exported := ast.IsExported(name)
					kind := "type"
					switch typeSpec.Type.(type) {
					case *ast.StructType:
						kind = "struct"
					case *ast.InterfaceType:
						kind = "interface"
					}
					span := spanFromPos(fset, typeSpec.Pos(), typeSpec.End())
					sf, err := facts.NewSymbolFact(facts.LangGo, relPath, span, name, kind, exported)
					if err == nil {
						sf.Quality = facts.QualityProof
						result.Symbols = append(result.Symbols, sf)
					}
				}
			}
		}

		// Route extraction
		routes := extractRoutes(fset, node, relPath)
		result.Routes = append(result.Routes, routes...)

		// Middleware detection from Use() calls (Fiber, Gorilla Mux)
		useMiddlewares := extractUseMiddlewares(fset, node, relPath)
		result.Middlewares = append(result.Middlewares, useMiddlewares...)

		// Data access extraction
		dataAccess := extractDataAccess(fset, node, relPath, fileImports)
		result.DataAccess = append(result.DataAccess, dataAccess...)

		// Secret extraction
		secrets := extractSecrets(fset, node, relPath)
		result.Secrets = append(result.Secrets, secrets...)

		// TypeGraph extraction
		extractTypeGraph(fset, node, relPath, result.TypeGraph)
	}

	return result, nil
}

func spanFromPos(fset *token.FileSet, start, end token.Pos) facts.Span {
	s := fset.Position(start)
	e := fset.Position(end)
	return facts.Span{Start: s.Line, End: e.Line}
}

func countLines(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		count++
	}
	return count, scanner.Err()
}

func collectFileImports(node *ast.File) map[string]bool {
	imports := make(map[string]bool)
	for _, imp := range node.Imports {
		importPath := strings.Trim(imp.Path.Value, `"`)
		imports[importPath] = true
	}
	return imports
}

// isMiddlewareSignature checks for func(http.Handler) http.Handler pattern.
func isMiddlewareSignature(f *ast.FuncDecl) bool {
	if f.Type.Params == nil || f.Type.Results == nil {
		return false
	}
	if len(f.Type.Params.List) != 1 || len(f.Type.Results.List) != 1 {
		return false
	}
	paramType := typeString(f.Type.Params.List[0].Type)
	resultType := typeString(f.Type.Results.List[0].Type)
	return paramType == "http.Handler" && resultType == "http.Handler"
}

// isFiberHandlerSignature checks for functions returning fiber.Handler.
func isFiberHandlerSignature(f *ast.FuncDecl) bool {
	if f.Type.Results == nil {
		return false
	}
	for _, res := range f.Type.Results.List {
		if typeString(res.Type) == "fiber.Handler" {
			return true
		}
	}
	return false
}

// extractUseMiddlewares detects app.Use()/router.Use() calls for Fiber and Gorilla Mux.
func extractUseMiddlewares(fset *token.FileSet, node *ast.File, relPath string) []facts.MiddlewareFact {
	var middlewares []facts.MiddlewareFact
	ast.Inspect(node, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if sel.Sel.Name == "Use" && len(call.Args) >= 1 {
			name := extractIdent(call.Args[0])
			if name == "" {
				name = "anonymous"
			}
			span := spanFromPos(fset, call.Pos(), call.End())
			mf, err := facts.NewMiddlewareFact(facts.LangGo, relPath, span, name, "http")
			if err == nil {
				mf.Quality = facts.QualityProof
				middlewares = append(middlewares, mf)
			}
		}
		return true
	})
	return middlewares
}

func typeString(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		if ident, ok := e.X.(*ast.Ident); ok {
			return ident.Name + "." + e.Sel.Name
		}
		return e.Sel.Name
	case *ast.StarExpr:
		return "*" + typeString(e.X)
	case *ast.ArrayType:
		return "[]" + typeString(e.Elt)
	case *ast.MapType:
		return "map[" + typeString(e.Key) + "]" + typeString(e.Value)
	case *ast.InterfaceType:
		return "interface{}"
	case *ast.FuncType:
		return "func(...)"
	case *ast.Ellipsis:
		return "..." + typeString(e.Elt)
	case *ast.ChanType:
		return "chan " + typeString(e.Value)
	}
	return ""
}

// extractTypeGraph extracts struct, interface, and method information into the TypeGraph.
func extractTypeGraph(fset *token.FileSet, node *ast.File, relPath string, tg *typegraph.TypeGraph) {
	// Collect all type declarations first
	typeNodes := make(map[string]*typegraph.TypeNode)

	for _, decl := range node.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.TYPE {
			continue
		}
		for _, spec := range genDecl.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok {
				continue
			}
			name := typeSpec.Name.Name
			span := spanFromPos(fset, typeSpec.Pos(), typeSpec.End())
			tgSpan := typegraph.Span{Start: span.Start, End: span.End}

			switch st := typeSpec.Type.(type) {
			case *ast.StructType:
				tn := &typegraph.TypeNode{
					Name:     name,
					Kind:     "struct",
					File:     relPath,
					Language: "go",
					Exported: ast.IsExported(name),
					Span:     tgSpan,
				}
				// Extract fields
				if st.Fields != nil {
					for _, field := range st.Fields.List {
						typeName := typeString(field.Type)
						if len(field.Names) == 0 {
							// Embedded type — treat as implements
							tn.Implements = append(tn.Implements, typeName)
							continue
						}
						for _, fieldName := range field.Names {
							fi := typegraph.FieldInfo{
								Name:     fieldName.Name,
								TypeName: typeName,
								IsPublic: ast.IsExported(fieldName.Name),
							}
							tn.Fields = append(tn.Fields, fi)
						}
					}
				}
				typeNodes[name] = tn
				tg.AddNode(tn)

			case *ast.InterfaceType:
				tn := &typegraph.TypeNode{
					Name:     name,
					Kind:     "interface",
					File:     relPath,
					Language: "go",
					Exported: ast.IsExported(name),
					Span:     tgSpan,
				}
				// Extract interface methods
				if st.Methods != nil {
					for _, method := range st.Methods.List {
						if len(method.Names) == 0 {
							// Embedded interface
							continue
						}
						funcType, ok := method.Type.(*ast.FuncType)
						if !ok {
							continue
						}
						mi := typegraph.MethodInfo{
							Name:       method.Names[0].Name,
							IsAbstract: true,
							IsPublic:   ast.IsExported(method.Names[0].Name),
						}
						mi.Params = extractParams(funcType)
						mi.ReturnType = extractReturnType(funcType)
						tn.Methods = append(tn.Methods, mi)
					}
				}
				tg.AddNode(tn)
			}
		}
	}

	// Collect methods (func with receiver) and attach to structs
	for _, decl := range node.Decls {
		funcDecl, ok := decl.(*ast.FuncDecl)
		if !ok || funcDecl.Recv == nil {
			continue
		}
		recvName := extractReceiverName(funcDecl.Recv)
		if recvName == "" {
			continue
		}
		tn, exists := typeNodes[recvName]
		if !exists {
			continue
		}
		mi := typegraph.MethodInfo{
			Name:     funcDecl.Name.Name,
			IsPublic: ast.IsExported(funcDecl.Name.Name),
		}
		mi.Params = extractParams(funcDecl.Type)
		mi.ReturnType = extractReturnType(funcDecl.Type)
		tn.Methods = append(tn.Methods, mi)
	}
}

func extractReceiverName(recv *ast.FieldList) string {
	if recv == nil || len(recv.List) == 0 {
		return ""
	}
	expr := recv.List[0].Type
	// Handle pointer receiver *T
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	if ident, ok := expr.(*ast.Ident); ok {
		return ident.Name
	}
	return ""
}

func extractParams(funcType *ast.FuncType) []typegraph.ParamInfo {
	if funcType.Params == nil {
		return nil
	}
	var params []typegraph.ParamInfo
	for _, field := range funcType.Params.List {
		typeName := typeString(field.Type)
		if len(field.Names) == 0 {
			params = append(params, typegraph.ParamInfo{TypeName: typeName})
		} else {
			for _, name := range field.Names {
				params = append(params, typegraph.ParamInfo{
					Name:     name.Name,
					TypeName: typeName,
				})
			}
		}
	}
	return params
}

func extractReturnType(funcType *ast.FuncType) string {
	if funcType.Results == nil || len(funcType.Results.List) == 0 {
		return ""
	}
	// Return the first result type (simplification)
	return typeString(funcType.Results.List[0].Type)
}

// extractRoutes detects HTTP route registrations.
func extractRoutes(fset *token.FileSet, node *ast.File, relPath string) []facts.RouteFact {
	var routes []facts.RouteFact
	ast.Inspect(node, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		method, path, handler, middlewares := matchRouteCall(call)
		if path != "" {
			span := spanFromPos(fset, call.Pos(), call.End())
			rf, err := facts.NewRouteFact(facts.LangGo, relPath, span, method, path, handler, middlewares)
			if err == nil {
				rf.Quality = facts.QualityProof
				routes = append(routes, rf)
			}
		}
		return true
	})
	return routes
}

func matchRouteCall(call *ast.CallExpr) (method, path, handler string, middlewares []string) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", "", "", nil
	}
	funcName := sel.Sel.Name

	switch funcName {
	case "HandleFunc", "Handle":
		if len(call.Args) >= 2 {
			path = extractStringLit(call.Args[0])
			last := len(call.Args) - 1
			handler = extractIdent(call.Args[last])
			for i := 1; i < last; i++ {
				if mw := extractIdent(call.Args[i]); mw != "" {
					middlewares = append(middlewares, mw)
				}
			}
			return "ANY", path, handler, middlewares
		}
	case "GET", "POST", "PUT", "DELETE", "PATCH", "Get", "Post", "Put", "Delete", "Patch":
		if len(call.Args) >= 2 {
			path = extractStringLit(call.Args[0])
			last := len(call.Args) - 1
			handler = extractIdent(call.Args[last])
			for i := 1; i < last; i++ {
				if mw := extractIdent(call.Args[i]); mw != "" {
					middlewares = append(middlewares, mw)
				}
			}
			return strings.ToUpper(funcName), path, handler, middlewares
		}
	}
	return "", "", "", nil
}

func extractStringLit(expr ast.Expr) string {
	lit, ok := expr.(*ast.BasicLit)
	if ok && lit.Kind == token.STRING {
		return strings.Trim(lit.Value, `"`)
	}
	return ""
}

func extractIdent(expr ast.Expr) string {
	if ident, ok := expr.(*ast.Ident); ok {
		return ident.Name
	}
	if sel, ok := expr.(*ast.SelectorExpr); ok {
		return sel.Sel.Name
	}
	return ""
}

// funcSpan represents the span of a function declaration in a file.
type funcSpan struct {
	name      string
	kind      string // "function" or "method"
	startLine int
	endLine   int
}

// buildFuncSpans collects all function/method declarations and their line spans.
func buildFuncSpans(fset *token.FileSet, node *ast.File) []funcSpan {
	var spans []funcSpan
	for _, decl := range node.Decls {
		funcDecl, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		kind := "function"
		if funcDecl.Recv != nil {
			kind = "method"
		}
		start := fset.Position(funcDecl.Pos()).Line
		end := fset.Position(funcDecl.End()).Line
		spans = append(spans, funcSpan{
			name:      funcDecl.Name.Name,
			kind:      kind,
			startLine: start,
			endLine:   end,
		})
	}
	return spans
}

// findEnclosingFunc returns the funcSpan containing the given line, or nil.
func findEnclosingFunc(spans []funcSpan, line int) *funcSpan {
	for i := range spans {
		if line >= spans[i].startLine && line <= spans[i].endLine {
			return &spans[i]
		}
	}
	return nil
}

// extractDataAccess detects database access calls.
func extractDataAccess(fset *token.FileSet, node *ast.File, relPath string, imports map[string]bool) []facts.DataAccessFact {
	var accesses []facts.DataAccessFact

	var backend string
	switch {
	case imports["database/sql"]:
		backend = "database/sql"
	case hasImportContaining(imports, "gorm"):
		backend = "gorm"
	case hasImportContaining(imports, "sqlx"):
		backend = "sqlx"
	case hasImportContaining(imports, "entgo.io/ent"):
		backend = "ent"
	default:
		return nil
	}

	dbMethods := map[string]bool{
		"Query": true, "QueryRow": true, "Exec": true,
		"QueryContext": true, "QueryRowContext": true, "ExecContext": true,
		"Prepare": true, "PrepareContext": true,
		"Find": true, "First": true, "Create": true, "Save": true, "Delete": true, "Where": true,
	}

	// Ent ORM methods
	entMethods := map[string]bool{
		"Query": true, "Create": true, "Update": true, "Delete": true,
		"Get": true, "GetX": true, "All": true, "Only": true, "OnlyX": true,
	}
	if backend == "ent" {
		for k, v := range entMethods {
			dbMethods[k] = v
		}
	}

	funcSpans := buildFuncSpans(fset, node)

	ast.Inspect(node, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if dbMethods[sel.Sel.Name] {
			span := spanFromPos(fset, call.Pos(), call.End())
			da, err := facts.NewDataAccessFact(facts.LangGo, relPath, span, sel.Sel.Name, backend)
			if err == nil {
				da.Quality = facts.QualityProof
				da.ImportsDirect = true // backend was detected from imports
				if fs := findEnclosingFunc(funcSpans, span.Start); fs != nil {
					da.CallerName = fs.name
					da.CallerKind = fs.kind
				}
				accesses = append(accesses, da)
			}
		}
		return true
	})

	return accesses
}

func hasImportContaining(imports map[string]bool, substr string) bool {
	for path := range imports {
		if strings.Contains(path, substr) {
			return true
		}
	}
	return false
}

// extractSecrets detects hardcoded secret variable declarations.
func extractSecrets(fset *token.FileSet, node *ast.File, relPath string) []facts.SecretFact {
	var secrets []facts.SecretFact

	secretPatterns := []string{"secret", "password", "passwd", "token", "apikey", "api_key", "credential"}

	for _, decl := range node.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		if genDecl.Tok != token.VAR && genDecl.Tok != token.CONST {
			continue
		}
		for _, spec := range genDecl.Specs {
			valueSpec, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range valueSpec.Names {
				nameLower := strings.ToLower(name.Name)
				isSecretName := false
				for _, pattern := range secretPatterns {
					if strings.Contains(nameLower, pattern) {
						isSecretName = true
						break
					}
				}
				if !isSecretName {
					continue
				}
				if i < len(valueSpec.Values) && hasHardcodedValue(valueSpec.Values[i]) {
					span := spanFromPos(fset, valueSpec.Pos(), valueSpec.End())
					sf, err := facts.NewSecretFact(facts.LangGo, relPath, span, "hardcoded_secret", name.Name)
					if err == nil {
						sf.Quality = facts.QualityProof
						secrets = append(secrets, sf)
					}
				}
			}
		}
	}
	return secrets
}

func hasHardcodedValue(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.BasicLit:
		return e.Kind == token.STRING
	case *ast.CallExpr:
		// []byte("...") pattern
		if len(e.Args) == 1 {
			return hasHardcodedValue(e.Args[0])
		}
	case *ast.CompositeLit:
		// []byte{...} pattern - not a string secret
		return false
	}
	return false
}
