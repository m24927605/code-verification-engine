package ts

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"regexp"

	"github.com/verabase/code-verification-engine/internal/analyzers"
	"github.com/verabase/code-verification-engine/internal/analyzers/common"
	"github.com/verabase/code-verification-engine/internal/facts"
	"github.com/verabase/code-verification-engine/internal/typegraph"
)

var (
	tsClassRe         = regexp.MustCompile(`^(?:export\s+)?(?:abstract\s+)?class\s+(\w+)(?:\s+extends\s+(\w+))?(?:\s+implements\s+([\w,\s]+))?`)
	tsInterfaceRe     = regexp.MustCompile(`^(?:export\s+)?interface\s+(\w+)(?:\s+extends\s+([\w,\s]+))?`)
	tsFieldRe         = regexp.MustCompile(`^\s*(?:private|public|protected|readonly|static|\s)*(\w+)\s*[?!]?\s*:\s*([\w<>\[\],\s|]+)`)
	tsMethodRe        = regexp.MustCompile(`^\s*(?:private|public|protected|static|abstract|async|\s)*(\w+)\s*\(([^)]*)\)\s*(?::\s*([\w<>\[\],\s|]+))?`)
	tsAbstractClassRe = regexp.MustCompile(`^(?:export\s+)?abstract\s+class\s+`)
	tsAbstractMethodRe = regexp.MustCompile(`^\s*abstract\s+`)
	tsStaticRe        = regexp.MustCompile(`^\s*static\s+`)
	tsPrivateRe       = regexp.MustCompile(`^\s*private\s+`)
	tsProtectedRe     = regexp.MustCompile(`^\s*protected\s+`)
)

// TypeScriptAnalyzer extracts facts from .ts and .tsx files using regex patterns.
type TypeScriptAnalyzer struct{}

// New creates a new TypeScriptAnalyzer.
func New() *TypeScriptAnalyzer { return &TypeScriptAnalyzer{} }

func (a *TypeScriptAnalyzer) Language() facts.Language { return facts.LangTypeScript }
func (a *TypeScriptAnalyzer) Extensions() []string     { return []string{".ts", ".tsx"} }

func (a *TypeScriptAnalyzer) Analyze(dir string, files []string) (*analyzers.AnalysisResult, error) {
	result := &analyzers.AnalysisResult{}
	result.TypeGraph = typegraph.New()
	for _, relPath := range files {
		absPath := filepath.Join(dir, relPath)
		if err := a.analyzeFile(absPath, relPath, result); err != nil {
			result.SkippedFiles = append(result.SkippedFiles, analyzers.SkippedFile{
				File:   relPath,
				Reason: fmt.Sprintf("analyze error: %v", err),
			})
			continue
		}
	}
	return result, nil
}

func (a *TypeScriptAnalyzer) analyzeFile(absPath, relPath string, result *analyzers.AnalysisResult) error {
	f, err := os.Open(absPath)
	if err != nil {
		return err
	}
	defer f.Close()

	// Next.js API route detection (file-path based)
	if routePath, ok := common.IsNextAPIRoute(relPath); ok {
		// Will refine method below if exported function names are found
		nextMethods := []string{}
		scanForMethods := bufio.NewScanner(f)
		for scanForMethods.Scan() {
			if m := common.MatchNextExportMethod(strings.TrimSpace(scanForMethods.Text())); m != "" {
				nextMethods = append(nextMethods, m)
			}
		}
		if len(nextMethods) == 0 {
			nextMethods = []string{"ANY"}
		}
		for _, m := range nextMethods {
			if fact, err := facts.NewRouteFact(facts.LangTypeScript, relPath, facts.Span{Start: 1, End: 1}, m, routePath, "", nil); err == nil {
				fact.Quality = facts.QualityHeuristic
				result.Routes = append(result.Routes, fact)
			}
		}
		// Reset file for normal scanning
		if _, err := f.Seek(0, 0); err != nil {
			return err
		}
	}

	isTest := isTestFile(relPath)
	scanner := bufio.NewScanner(f)
	lineNum := 0
	inBlockComment := false

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Multi-line comment tracking
		if inBlockComment {
			if idx := strings.Index(trimmed, "*/"); idx >= 0 {
				inBlockComment = false
				// Rest of line after */ could have code, but for simplicity skip entire line
			}
			continue
		}
		if strings.HasPrefix(trimmed, "/*") {
			if !strings.Contains(trimmed, "*/") {
				inBlockComment = true
			}
			continue
		}

		// Skip single-line comments
		if strings.HasPrefix(trimmed, "//") {
			continue
		}

		// ES imports
		if imp := common.MatchESImport(trimmed); imp != "" {
			if fact, err := facts.NewImportFact(facts.LangTypeScript, relPath, facts.Span{Start: lineNum, End: lineNum}, imp, ""); err == nil {
				fact.Quality = facts.QualityStructural
				fact.Provenance = facts.ProvenanceAST
				result.Imports = append(result.Imports, fact)
			}
		}

		// Symbols (functions, classes, interfaces)
		if name, kind := common.MatchSymbolDecl(trimmed); name != "" {
			exported := common.IsExported(trimmed)
			if fact, err := facts.NewSymbolFact(facts.LangTypeScript, relPath, facts.Span{Start: lineNum, End: lineNum}, name, kind, exported); err == nil {
				fact.Quality = facts.QualityStructural
				fact.Provenance = facts.ProvenanceAST
				result.Symbols = append(result.Symbols, fact)
			}
		}

		// Express routes
		if method, path := common.MatchExpressRoute(trimmed); method != "" {
			prov := facts.ProvenanceAST
			if looksLikeStringLiteral(trimmed) {
				prov = facts.ProvenanceHeuristic
			}
			if fact, err := facts.NewRouteFact(facts.LangTypeScript, relPath, facts.Span{Start: lineNum, End: lineNum}, method, path, "", nil); err == nil {
				fact.Quality = facts.QualityStructural
				fact.Provenance = prov
				result.Routes = append(result.Routes, fact)
			}
		}

		// NestJS controller prefix
		if prefix := common.ExtractNestController(trimmed); prefix != "" {
			if fact, err := facts.NewRouteFact(facts.LangTypeScript, relPath, facts.Span{Start: lineNum, End: lineNum}, "PREFIX", "/"+strings.TrimPrefix(prefix, "/"), "", nil); err == nil {
				fact.Quality = facts.QualityStructural
				fact.Provenance = facts.ProvenanceAST
				result.Routes = append(result.Routes, fact)
			}
		}

		// NestJS route decorators
		if method, path, ok := common.ExtractNestRoute(trimmed); ok {
			if fact, err := facts.NewRouteFact(facts.LangTypeScript, relPath, facts.Span{Start: lineNum, End: lineNum}, method, path, "", nil); err == nil {
				fact.Quality = facts.QualityStructural
				fact.Provenance = facts.ProvenanceAST
				result.Routes = append(result.Routes, fact)
			}
		}

		// NestJS guards
		if guard := common.ExtractNestGuard(trimmed); guard != "" {
			if fact, err := facts.NewMiddlewareFact(facts.LangTypeScript, relPath, facts.Span{Start: lineNum, End: lineNum}, guard, "nestjs-guard"); err == nil {
				fact.Quality = facts.QualityStructural
				fact.Provenance = facts.ProvenanceAST
				result.Middlewares = append(result.Middlewares, fact)
			}
		}

		// NestJS interceptors
		if ic := common.ExtractNestInterceptor(trimmed); ic != "" {
			if fact, err := facts.NewMiddlewareFact(facts.LangTypeScript, relPath, facts.Span{Start: lineNum, End: lineNum}, ic, "nestjs-interceptor"); err == nil {
				fact.Quality = facts.QualityStructural
				fact.Provenance = facts.ProvenanceAST
				result.Middlewares = append(result.Middlewares, fact)
			}
		}

		// NestJS @InjectRepository
		if entity := common.ExtractNestInjectRepo(trimmed); entity != "" {
			op := "@InjectRepository(" + entity + ")"
			if fact, err := facts.NewDataAccessFact(facts.LangTypeScript, relPath, facts.Span{Start: lineNum, End: lineNum}, op, "typeorm"); err == nil {
				fact.Quality = facts.QualityStructural
				result.DataAccess = append(result.DataAccess, fact)
			}
		}

		// Fastify routes
		if method, path, ok := common.ExtractFastifyRoute(trimmed); ok {
			if fact, err := facts.NewRouteFact(facts.LangTypeScript, relPath, facts.Span{Start: lineNum, End: lineNum}, method, path, "", nil); err == nil {
				fact.Quality = facts.QualityStructural
				fact.Provenance = facts.ProvenanceAST
				result.Routes = append(result.Routes, fact)
			}
		}

		// Fastify route objects
		if url := common.ExtractFastifyRouteObj(trimmed); url != "" {
			if fact, err := facts.NewRouteFact(facts.LangTypeScript, relPath, facts.Span{Start: lineNum, End: lineNum}, "ANY", url, "", nil); err == nil {
				fact.Quality = facts.QualityStructural
				fact.Provenance = facts.ProvenanceAST
				result.Routes = append(result.Routes, fact)
			}
		}

		// Fastify register (plugin as middleware)
		if plugin := common.ExtractFastifyRegister(trimmed); plugin != "" {
			if fact, err := facts.NewMiddlewareFact(facts.LangTypeScript, relPath, facts.Span{Start: lineNum, End: lineNum}, plugin, "fastify-plugin"); err == nil {
				fact.Quality = facts.QualityStructural
				fact.Provenance = facts.ProvenanceAST
				result.Middlewares = append(result.Middlewares, fact)
			}
		}

		// Fastify hooks
		if hook := common.ExtractFastifyHook(trimmed); hook != "" {
			if fact, err := facts.NewMiddlewareFact(facts.LangTypeScript, relPath, facts.Span{Start: lineNum, End: lineNum}, hook, "fastify-hook"); err == nil {
				fact.Quality = facts.QualityStructural
				fact.Provenance = facts.ProvenanceAST
				result.Middlewares = append(result.Middlewares, fact)
			}
		}

		// Koa routes
		if method, path, ok := common.ExtractKoaRoute(trimmed); ok {
			if fact, err := facts.NewRouteFact(facts.LangTypeScript, relPath, facts.Span{Start: lineNum, End: lineNum}, method, path, "", nil); err == nil {
				fact.Quality = facts.QualityStructural
				fact.Provenance = facts.ProvenanceAST
				result.Routes = append(result.Routes, fact)
			}
		}

		// Hapi routes
		if method, path, ok := common.ExtractHapiRoute(trimmed); ok {
			if fact, err := facts.NewRouteFact(facts.LangTypeScript, relPath, facts.Span{Start: lineNum, End: lineNum}, method, path, "", nil); err == nil {
				fact.Quality = facts.QualityStructural
				fact.Provenance = facts.ProvenanceAST
				result.Routes = append(result.Routes, fact)
			}
		}

		// Hapi extensions
		if ext := common.ExtractHapiExt(trimmed); ext != "" {
			if fact, err := facts.NewMiddlewareFact(facts.LangTypeScript, relPath, facts.Span{Start: lineNum, End: lineNum}, ext, "hapi-ext"); err == nil {
				fact.Quality = facts.QualityStructural
				fact.Provenance = facts.ProvenanceAST
				result.Middlewares = append(result.Middlewares, fact)
			}
		}

		// Hapi register
		if plugin := common.ExtractHapiRegister(trimmed); plugin != "" {
			if fact, err := facts.NewMiddlewareFact(facts.LangTypeScript, relPath, facts.Span{Start: lineNum, End: lineNum}, plugin, "hapi-plugin"); err == nil {
				fact.Quality = facts.QualityStructural
				fact.Provenance = facts.ProvenanceAST
				result.Middlewares = append(result.Middlewares, fact)
			}
		}

		// Express middleware (also catches Koa app.use)
		if mw := common.MatchExpressMiddleware(trimmed); mw != "" {
			if fact, err := facts.NewMiddlewareFact(facts.LangTypeScript, relPath, facts.Span{Start: lineNum, End: lineNum}, mw, "express"); err == nil {
				fact.Quality = facts.QualityStructural
				fact.Provenance = facts.ProvenanceAST
				result.Middlewares = append(result.Middlewares, fact)
			}
		}

		// Data access
		if op, backend := common.MatchDataAccess(trimmed); op != "" {
			if fact, err := facts.NewDataAccessFact(facts.LangTypeScript, relPath, facts.Span{Start: lineNum, End: lineNum}, op, backend); err == nil {
				fact.Quality = facts.QualityStructural
				result.DataAccess = append(result.DataAccess, fact)
			}
		}

		// Secrets
		if kind := common.MatchSecret(trimmed); kind != "" {
			if fact, err := facts.NewSecretFact(facts.LangTypeScript, relPath, facts.Span{Start: lineNum, End: lineNum}, kind, ""); err == nil {
				fact.Quality = facts.QualityStructural
				fact.Provenance = facts.ProvenanceAST
				result.Secrets = append(result.Secrets, fact)
			}
		}

		// Test functions in test files
		if isTest {
			if testName := matchTestDecl(trimmed); testName != "" {
				if fact, err := facts.NewTestFact(facts.LangTypeScript, relPath, facts.Span{Start: lineNum, End: lineNum}, testName, "", ""); err == nil {
					fact.Quality = facts.QualityStructural
					result.Tests = append(result.Tests, fact)
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		result.DiscardFactsForFile(relPath)
		result.SkippedFiles = append(result.SkippedFiles, analyzers.SkippedFile{
			File:   relPath,
			Reason: fmt.Sprintf("scanner error (partial data discarded): %v", err),
		})
		return nil
	}

	// File fact — only added if scan completed fully
	if fact, err := facts.NewFileFact(facts.LangTypeScript, relPath, lineNum); err == nil {
		fact.Quality = facts.QualityStructural
		result.Files = append(result.Files, fact)
	}

	// TypeGraph extraction — re-read file for type analysis
	if lines, err := readFileLines(absPath); err == nil {
		extractTSTypeGraph(lines, relPath, result.TypeGraph)
	}
	return nil
}

func readFileLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func extractTSTypeGraph(lines []string, relPath string, tg *typegraph.TypeGraph) {
	i := 0
	for i < len(lines) {
		trimmed := strings.TrimSpace(lines[i])

		// Interface detection
		if m := tsInterfaceRe.FindStringSubmatch(trimmed); m != nil {
			name := m[1]
			exported := common.IsExported(trimmed)
			startLine := i + 1
			endLine := findClosingBrace(lines, i)
			tn := &typegraph.TypeNode{
				Name:     name,
				Kind:     "interface",
				File:     relPath,
				Language: "typescript",
				Exported: exported,
				Span:     typegraph.Span{Start: startLine, End: endLine},
			}
			// Extract extends for interfaces
			if m[2] != "" {
				for _, ext := range strings.Split(m[2], ",") {
					ext = strings.TrimSpace(ext)
					if ext != "" {
						tn.Implements = append(tn.Implements, ext)
					}
				}
			}
			// Extract method signatures from interface body
			for j := i + 1; j < endLine && j < len(lines); j++ {
				methodLine := strings.TrimSpace(lines[j])
				if mm := tsMethodRe.FindStringSubmatch(methodLine); mm != nil && mm[1] != "" {
					if mm[1] == "}" || mm[1] == "{" {
						continue
					}
					mi := typegraph.MethodInfo{
						Name:       mm[1],
						IsAbstract: true,
						IsPublic:   true,
						ReturnType: strings.TrimSpace(mm[3]),
					}
					mi.Params = parseTSParams(mm[2])
					tn.Methods = append(tn.Methods, mi)
				}
			}
			tg.AddNode(tn)
			i = endLine
			continue
		}

		// Class detection
		if m := tsClassRe.FindStringSubmatch(trimmed); m != nil {
			name := m[1]
			exported := common.IsExported(trimmed)
			isAbstract := tsAbstractClassRe.MatchString(trimmed)
			kind := "class"
			if isAbstract {
				kind = "abstract_class"
			}
			startLine := i + 1
			endLine := findClosingBrace(lines, i)

			tn := &typegraph.TypeNode{
				Name:     name,
				Kind:     kind,
				File:     relPath,
				Language: "typescript",
				Exported: exported,
				Extends:  strings.TrimSpace(m[2]),
				Span:     typegraph.Span{Start: startLine, End: endLine},
			}
			// Parse implements
			if m[3] != "" {
				for _, impl := range strings.Split(m[3], ",") {
					impl = strings.TrimSpace(impl)
					if impl != "" {
						tn.Implements = append(tn.Implements, impl)
					}
				}
			}

			// Extract fields and methods from class body
			for j := i + 1; j < endLine && j < len(lines); j++ {
				bodyLine := strings.TrimSpace(lines[j])
				if bodyLine == "" || bodyLine == "{" || bodyLine == "}" {
					continue
				}
				isStatic := tsStaticRe.MatchString(bodyLine)
				isPrivate := tsPrivateRe.MatchString(bodyLine) || tsProtectedRe.MatchString(bodyLine)
				isAbstractMethod := tsAbstractMethodRe.MatchString(bodyLine)

				// Try method first (methods contain parens)
				if mm := tsMethodRe.FindStringSubmatch(bodyLine); mm != nil && mm[1] != "" && strings.Contains(bodyLine, "(") {
					if mm[1] == "constructor" || mm[1] == "}" || mm[1] == "{" {
						continue
					}
					mi := typegraph.MethodInfo{
						Name:       mm[1],
						IsAbstract: isAbstractMethod,
						IsStatic:   isStatic,
						IsPublic:   !isPrivate,
						ReturnType: strings.TrimSpace(mm[3]),
					}
					mi.Params = parseTSParams(mm[2])
					tn.Methods = append(tn.Methods, mi)
					continue
				}
				// Try field
				if fm := tsFieldRe.FindStringSubmatch(bodyLine); fm != nil && fm[1] != "" {
					if fm[1] == "}" || fm[1] == "{" || fm[1] == "constructor" {
						continue
					}
					fi := typegraph.FieldInfo{
						Name:     fm[1],
						TypeName: strings.TrimSpace(strings.TrimRight(fm[2], ";,")),
						IsPublic: !isPrivate,
						IsStatic: isStatic,
					}
					tn.Fields = append(tn.Fields, fi)
				}
			}
			tg.AddNode(tn)
			i = endLine
			continue
		}
		i++
	}
}

func findClosingBrace(lines []string, startIdx int) int {
	depth := 0
	for i := startIdx; i < len(lines); i++ {
		for _, ch := range lines[i] {
			if ch == '{' {
				depth++
			} else if ch == '}' {
				depth--
				if depth == 0 {
					return i + 1
				}
			}
		}
	}
	return len(lines)
}

func parseTSParams(paramStr string) []typegraph.ParamInfo {
	paramStr = strings.TrimSpace(paramStr)
	if paramStr == "" {
		return nil
	}
	var params []typegraph.ParamInfo
	for _, p := range strings.Split(paramStr, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		parts := strings.SplitN(p, ":", 2)
		name := strings.TrimSpace(strings.TrimLeft(parts[0], "?.!"))
		typeName := ""
		if len(parts) == 2 {
			typeName = strings.TrimSpace(parts[1])
		}
		params = append(params, typegraph.ParamInfo{Name: name, TypeName: typeName})
	}
	return params
}

// looksLikeStringLiteral returns true if the trimmed line appears to contain
// the relevant code pattern inside a string literal (e.g., const x = "app.get(...)").
func looksLikeStringLiteral(trimmed string) bool {
	// Simple heuristic: if the line starts with a variable declaration
	// and the pattern appears after a quote, it's likely inside a string.
	for _, prefix := range []string{`= "`, `= '`, "= `"} {
		idx := strings.Index(trimmed, prefix)
		if idx >= 0 {
			// Check if an express-like pattern appears after the string start
			afterQuote := trimmed[idx+len(prefix):]
			if strings.Contains(afterQuote, ".get(") || strings.Contains(afterQuote, ".post(") ||
				strings.Contains(afterQuote, ".put(") || strings.Contains(afterQuote, ".delete(") ||
				strings.Contains(afterQuote, ".patch(") || strings.Contains(afterQuote, ".use(") {
				return true
			}
		}
	}
	return false
}

func isTestFile(path string) bool {
	base := filepath.Base(path)
	return strings.Contains(base, ".test.") || strings.Contains(base, ".spec.")
}

func matchTestDecl(line string) string {
	for _, prefix := range []string{"it(", "test(", "describe("} {
		idx := strings.Index(line, prefix)
		if idx < 0 {
			continue
		}
		rest := line[idx+len(prefix):]
		if len(rest) < 2 {
			continue
		}
		quote := rest[0]
		if quote != '\'' && quote != '"' && quote != '`' {
			continue
		}
		end := strings.IndexByte(rest[1:], quote)
		if end < 0 {
			continue
		}
		return rest[1 : end+1]
	}
	return ""
}
