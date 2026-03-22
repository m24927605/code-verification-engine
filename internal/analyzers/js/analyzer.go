package js

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
	jsClassRe      = regexp.MustCompile(`^(?:export\s+)?class\s+(\w+)(?:\s+extends\s+(\w+))?`)
	jsMethodRe     = regexp.MustCompile(`^\s*(?:static\s+)?(?:async\s+)?(?:get\s+|set\s+)?(\w+)\s*\(([^)]*)\)`)
	jsThisFieldRe  = regexp.MustCompile(`this\.(\w+)\s*=`)
	jsStaticFieldRe = regexp.MustCompile(`^\s*static\s+(\w+)\s*=`)
)

// JavaScriptAnalyzer extracts facts from .js and .jsx files using regex patterns.
type JavaScriptAnalyzer struct{}

// New creates a new JavaScriptAnalyzer.
func New() *JavaScriptAnalyzer { return &JavaScriptAnalyzer{} }

func (a *JavaScriptAnalyzer) Language() facts.Language { return facts.LangJavaScript }
func (a *JavaScriptAnalyzer) Extensions() []string     { return []string{".js", ".jsx"} }

func (a *JavaScriptAnalyzer) Analyze(dir string, files []string) (*analyzers.AnalysisResult, error) {
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

func (a *JavaScriptAnalyzer) analyzeFile(absPath, relPath string, result *analyzers.AnalysisResult) error {
	f, err := os.Open(absPath)
	if err != nil {
		return err
	}
	defer f.Close()

	// Next.js API route detection (file-path based)
	if routePath, ok := common.IsNextAPIRoute(relPath); ok {
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
			if fact, err := facts.NewRouteFact(facts.LangJavaScript, relPath, facts.Span{Start: 1, End: 1}, m, routePath, "", nil); err == nil {
				result.Routes = append(result.Routes, fact)
			}
		}
		if _, err := f.Seek(0, 0); err != nil {
			return err
		}
	}

	isTest := isTestFile(relPath)
	scanner := bufio.NewScanner(f)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// ES imports
		if imp := common.MatchESImport(trimmed); imp != "" {
			if fact, err := facts.NewImportFact(facts.LangJavaScript, relPath, facts.Span{Start: lineNum, End: lineNum}, imp, ""); err == nil {
				result.Imports = append(result.Imports, fact)
			}
		}

		// require() imports
		if imp := common.MatchRequireImport(trimmed); imp != "" {
			if fact, err := facts.NewImportFact(facts.LangJavaScript, relPath, facts.Span{Start: lineNum, End: lineNum}, imp, ""); err == nil {
				result.Imports = append(result.Imports, fact)
			}
		}

		// Symbols (functions, classes)
		if name, kind := common.MatchSymbolDecl(trimmed); name != "" {
			exported := common.IsExported(trimmed)
			if fact, err := facts.NewSymbolFact(facts.LangJavaScript, relPath, facts.Span{Start: lineNum, End: lineNum}, name, kind, exported); err == nil {
				result.Symbols = append(result.Symbols, fact)
			}
		}

		// Express routes
		if method, path := common.MatchExpressRoute(trimmed); method != "" {
			if fact, err := facts.NewRouteFact(facts.LangJavaScript, relPath, facts.Span{Start: lineNum, End: lineNum}, method, path, "", nil); err == nil {
				result.Routes = append(result.Routes, fact)
			}
		}

		// Fastify routes
		if method, path, ok := common.ExtractFastifyRoute(trimmed); ok {
			if fact, err := facts.NewRouteFact(facts.LangJavaScript, relPath, facts.Span{Start: lineNum, End: lineNum}, method, path, "", nil); err == nil {
				result.Routes = append(result.Routes, fact)
			}
		}

		// Fastify route objects
		if url := common.ExtractFastifyRouteObj(trimmed); url != "" {
			if fact, err := facts.NewRouteFact(facts.LangJavaScript, relPath, facts.Span{Start: lineNum, End: lineNum}, "ANY", url, "", nil); err == nil {
				result.Routes = append(result.Routes, fact)
			}
		}

		// Fastify register (plugin as middleware)
		if plugin := common.ExtractFastifyRegister(trimmed); plugin != "" {
			if fact, err := facts.NewMiddlewareFact(facts.LangJavaScript, relPath, facts.Span{Start: lineNum, End: lineNum}, plugin, "fastify-plugin"); err == nil {
				result.Middlewares = append(result.Middlewares, fact)
			}
		}

		// Fastify hooks
		if hook := common.ExtractFastifyHook(trimmed); hook != "" {
			if fact, err := facts.NewMiddlewareFact(facts.LangJavaScript, relPath, facts.Span{Start: lineNum, End: lineNum}, hook, "fastify-hook"); err == nil {
				result.Middlewares = append(result.Middlewares, fact)
			}
		}

		// Koa routes
		if method, path, ok := common.ExtractKoaRoute(trimmed); ok {
			if fact, err := facts.NewRouteFact(facts.LangJavaScript, relPath, facts.Span{Start: lineNum, End: lineNum}, method, path, "", nil); err == nil {
				result.Routes = append(result.Routes, fact)
			}
		}

		// Hapi routes
		if method, path, ok := common.ExtractHapiRoute(trimmed); ok {
			if fact, err := facts.NewRouteFact(facts.LangJavaScript, relPath, facts.Span{Start: lineNum, End: lineNum}, method, path, "", nil); err == nil {
				result.Routes = append(result.Routes, fact)
			}
		}

		// Hapi extensions
		if ext := common.ExtractHapiExt(trimmed); ext != "" {
			if fact, err := facts.NewMiddlewareFact(facts.LangJavaScript, relPath, facts.Span{Start: lineNum, End: lineNum}, ext, "hapi-ext"); err == nil {
				result.Middlewares = append(result.Middlewares, fact)
			}
		}

		// Hapi register
		if plugin := common.ExtractHapiRegister(trimmed); plugin != "" {
			if fact, err := facts.NewMiddlewareFact(facts.LangJavaScript, relPath, facts.Span{Start: lineNum, End: lineNum}, plugin, "hapi-plugin"); err == nil {
				result.Middlewares = append(result.Middlewares, fact)
			}
		}

		// Express middleware (also catches Koa app.use)
		if mw := common.MatchExpressMiddleware(trimmed); mw != "" {
			if fact, err := facts.NewMiddlewareFact(facts.LangJavaScript, relPath, facts.Span{Start: lineNum, End: lineNum}, mw, "express"); err == nil {
				result.Middlewares = append(result.Middlewares, fact)
			}
		}

		// Data access
		if op, backend := common.MatchDataAccess(trimmed); op != "" {
			if fact, err := facts.NewDataAccessFact(facts.LangJavaScript, relPath, facts.Span{Start: lineNum, End: lineNum}, op, backend); err == nil {
				result.DataAccess = append(result.DataAccess, fact)
			}
		}

		// Secrets
		if kind := common.MatchSecret(trimmed); kind != "" {
			if fact, err := facts.NewSecretFact(facts.LangJavaScript, relPath, facts.Span{Start: lineNum, End: lineNum}, kind, ""); err == nil {
				result.Secrets = append(result.Secrets, fact)
			}
		}

		// Test functions in test files
		if isTest {
			if testName := matchTestDecl(trimmed); testName != "" {
				if fact, err := facts.NewTestFact(facts.LangJavaScript, relPath, facts.Span{Start: lineNum, End: lineNum}, testName, "", ""); err == nil {
					result.Tests = append(result.Tests, fact)
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		// Scanner failed mid-file — discard ALL facts collected from this file
		// to prevent partial data from causing false verified passes on not_exists rules.
		result.DiscardFactsForFile(relPath)
		result.SkippedFiles = append(result.SkippedFiles, analyzers.SkippedFile{
			File:   relPath,
			Reason: fmt.Sprintf("scanner error (partial data discarded): %v", err),
		})
		return nil
	}

	// File fact — only added if scan completed fully
	if fact, err := facts.NewFileFact(facts.LangJavaScript, relPath, lineNum); err == nil {
		result.Files = append(result.Files, fact)
	}

	// TypeGraph extraction — re-read file for type analysis
	if lines, err := readFileLines(absPath); err == nil {
		extractJSTypeGraph(lines, relPath, result.TypeGraph)
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

func extractJSTypeGraph(lines []string, relPath string, tg *typegraph.TypeGraph) {
	i := 0
	for i < len(lines) {
		trimmed := strings.TrimSpace(lines[i])

		if m := jsClassRe.FindStringSubmatch(trimmed); m != nil {
			name := m[1]
			exported := common.IsExported(trimmed)
			startLine := i + 1
			endLine := findClosingBrace(lines, i)

			tn := &typegraph.TypeNode{
				Name:     name,
				Kind:     "class",
				File:     relPath,
				Language: "javascript",
				Exported: exported,
				Extends:  strings.TrimSpace(m[2]),
				Span:     typegraph.Span{Start: startLine, End: endLine},
			}

			// Track fields from this.x = ... in constructor and static fields
			seenFields := make(map[string]bool)
			for j := i + 1; j < endLine && j < len(lines); j++ {
				bodyLine := strings.TrimSpace(lines[j])
				if bodyLine == "" || bodyLine == "{" || bodyLine == "}" {
					continue
				}

				isStatic := strings.HasPrefix(bodyLine, "static ")

				// Static field
				if fm := jsStaticFieldRe.FindStringSubmatch(bodyLine); fm != nil {
					if !seenFields[fm[1]] {
						seenFields[fm[1]] = true
						tn.Fields = append(tn.Fields, typegraph.FieldInfo{
							Name:     fm[1],
							IsPublic: true,
							IsStatic: true,
						})
					}
					continue
				}

				// this.field assignments
				if matches := jsThisFieldRe.FindAllStringSubmatch(bodyLine, -1); matches != nil {
					for _, fm := range matches {
						if !seenFields[fm[1]] {
							seenFields[fm[1]] = true
							isPrivate := strings.HasPrefix(fm[1], "_")
							tn.Fields = append(tn.Fields, typegraph.FieldInfo{
								Name:     fm[1],
								IsPublic: !isPrivate,
							})
						}
					}
					continue
				}

				// Method
				if mm := jsMethodRe.FindStringSubmatch(bodyLine); mm != nil && mm[1] != "" {
					if mm[1] == "constructor" || mm[1] == "}" || mm[1] == "{" {
						continue
					}
					mi := typegraph.MethodInfo{
						Name:     mm[1],
						IsStatic: isStatic,
						IsPublic: !strings.HasPrefix(mm[1], "_"),
					}
					if mm[2] != "" {
						for _, p := range strings.Split(mm[2], ",") {
							p = strings.TrimSpace(p)
							if p != "" {
								mi.Params = append(mi.Params, typegraph.ParamInfo{Name: p})
							}
						}
					}
					tn.Methods = append(tn.Methods, mi)
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
