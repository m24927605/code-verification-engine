package python

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/verabase/code-verification-engine/internal/analyzers"
	"github.com/verabase/code-verification-engine/internal/facts"
	"github.com/verabase/code-verification-engine/internal/typegraph"
)

var (
	pyClassBasesRe    = regexp.MustCompile(`^(\s*)class\s+(\w+)\s*\(([^)]*)\)\s*:`)
	pyMethodDefRe     = regexp.MustCompile(`^(\s+)def\s+(\w+)\s*\(\s*(?:self|cls)\s*(?:,\s*(.+))?\)\s*(?:->\s*(\w[\w\[\], ]*))?\s*:`)
	pySelfFieldRe     = regexp.MustCompile(`self\.(\w+)\s*(?::\s*(\w[\w\[\], ]*))?(?:\s*=|$)`)
	pyAbstractRe      = regexp.MustCompile(`@abstractmethod`)
	pyStaticMethodRe  = regexp.MustCompile(`@staticmethod`)
	pyClassMethodRe   = regexp.MustCompile(`@classmethod`)
)

var (
	funcDefRe    = regexp.MustCompile(`^(\s*)def\s+(\w+)\s*\(`)
	classDefRe   = regexp.MustCompile(`^(\s*)class\s+(\w+)\s*[\(:]`)
	importRe     = regexp.MustCompile(`^import\s+(.+)`)
	fromImportRe = regexp.MustCompile(`^from\s+(\S+)\s+import\s+(.+)`)

	// Route patterns
	fastapiRouteRe = regexp.MustCompile(`@\w+\.(get|post|put|delete|patch)\s*\(\s*"([^"]+)"`)
	flaskRouteRe   = regexp.MustCompile(`@\w+\.route\s*\(\s*"([^"]+)"`)

	// Middleware patterns
	dependsRe       = regexp.MustCompile(`Depends\s*\(\s*(\w+)`)
	addMiddlewareRe     = regexp.MustCompile(`add_middleware\s*\(\s*(\w+)`)
	djangoMiddlewareRe  = regexp.MustCompile(`['"][\w.]+[Mm]iddleware['"]`)

	// Django route patterns
	djangoPathRe   = regexp.MustCompile(`path\s*\(\s*['"]([^'"]+)['"]`)
	djangoUrlRe    = regexp.MustCompile(`url\s*\(\s*r?['"]([^'"]+)['"]`)
	djangoRePathRe = regexp.MustCompile(`re_path\s*\(\s*r?['"]([^'"]+)['"]`)

	// Starlette route patterns
	starletteRouteRe = regexp.MustCompile(`Route\s*\(\s*['"]([^'"]+)['"]`)

	// Data access patterns
	sqlalchemyImportRe = regexp.MustCompile(`(?:from\s+sqlalchemy|import\s+sqlalchemy)`)
	psycopg2ImportRe   = regexp.MustCompile(`(?:from\s+psycopg2|import\s+psycopg2)`)
	sqlalchemyUsageRe  = regexp.MustCompile(`Session|session\b`)
	djangoOrmRe        = regexp.MustCompile(`\.objects\.(filter|get|create|all|exclude|update|delete|aggregate|annotate)`)
	tortoiseImportRe   = regexp.MustCompile(`(?:from\s+tortoise|import\s+tortoise)`)

	// Django test pattern
	djangoTestImportRe = regexp.MustCompile(`from\s+django\.test\s+import`)

	// Secret patterns
	secretAssignRe = regexp.MustCompile(`(?i)^(\w*(?:SECRET|PASSWORD|PASSWD|TOKEN|API_KEY|APIKEY|CREDENTIAL|DATABASE_URL)\w*)\s*=\s*["']([^"']+)["']`)
)

// PythonAnalyzer extracts facts from Python source files using regex patterns.
type PythonAnalyzer struct{}

// New creates a new PythonAnalyzer.
func New() *PythonAnalyzer {
	return &PythonAnalyzer{}
}

// Language returns the language this analyzer handles.
func (a *PythonAnalyzer) Language() facts.Language {
	return facts.LangPython
}

// Extensions returns file extensions handled by this analyzer.
func (a *PythonAnalyzer) Extensions() []string {
	return []string{".py"}
}

// Analyze parses Python files and extracts normalized facts.
func (a *PythonAnalyzer) Analyze(dir string, files []string) (*analyzers.AnalysisResult, error) {
	result := &analyzers.AnalysisResult{}
	result.TypeGraph = typegraph.New()

	for _, relPath := range files {
		absPath := filepath.Join(dir, relPath)
		lines, err := readLines(absPath)
		if err != nil {
			result.SkippedFiles = append(result.SkippedFiles, analyzers.SkippedFile{
				File:   relPath,
				Reason: fmt.Sprintf("read error: %v", err),
			})
			continue
		}

		// FileFact
		ff, err := facts.NewFileFact(facts.LangPython, relPath, len(lines))
		if err != nil {
			continue
		}
		result.Files = append(result.Files, ff)

		isTestFile := isTestFileName(relPath)
		hasSQLAlchemyImport := false
		hasPsycopg2Import := false
		hasDjangoOrmImport := false
		hasTortoiseImport := false
		hasDjangoTestImport := false

		// Track Depends() references for middleware detection
		dependsRefs := make(map[string]bool)

		for i, line := range lines {
			lineNum := i + 1
			trimmed := strings.TrimSpace(line)

			// Imports
			if m := fromImportRe.FindStringSubmatch(trimmed); m != nil {
				module := m[1]
				imported := strings.Split(m[2], ",")
				for _, imp := range imported {
					imp = strings.TrimSpace(imp)
					if imp == "" {
						continue
					}
					// Handle "as" alias
					parts := strings.Fields(imp)
					name := parts[0]
					alias := ""
					if len(parts) >= 3 && parts[1] == "as" {
						alias = parts[2]
					}
					span := facts.Span{Start: lineNum, End: lineNum}
					impFact, err := facts.NewImportFact(facts.LangPython, relPath, span, module, alias)
					if err == nil {
						result.Imports = append(result.Imports, impFact)
					}
					_ = name
				}
				if sqlalchemyImportRe.MatchString(trimmed) {
					hasSQLAlchemyImport = true
				}
				if strings.Contains(trimmed, "django.db") {
					hasDjangoOrmImport = true
				}
				if tortoiseImportRe.MatchString(trimmed) {
					hasTortoiseImport = true
				}
				if djangoTestImportRe.MatchString(trimmed) {
					hasDjangoTestImport = true
				}
			} else if m := importRe.FindStringSubmatch(trimmed); m != nil {
				modules := strings.Split(m[1], ",")
				for _, mod := range modules {
					mod = strings.TrimSpace(mod)
					if mod == "" {
						continue
					}
					parts := strings.Fields(mod)
					importPath := parts[0]
					alias := ""
					if len(parts) >= 3 && parts[1] == "as" {
						alias = parts[2]
					}
					span := facts.Span{Start: lineNum, End: lineNum}
					impFact, err := facts.NewImportFact(facts.LangPython, relPath, span, importPath, alias)
					if err == nil {
						result.Imports = append(result.Imports, impFact)
					}
				}
				if sqlalchemyImportRe.MatchString(trimmed) {
					hasSQLAlchemyImport = true
				}
				if psycopg2ImportRe.MatchString(trimmed) {
					hasPsycopg2Import = true
				}
				if tortoiseImportRe.MatchString(trimmed) {
					hasTortoiseImport = true
				}
			}

			// FastAPI route decorators
			if m := fastapiRouteRe.FindStringSubmatch(trimmed); m != nil {
				method := strings.ToUpper(m[1])
				path := m[2]
				// Next non-empty line should be the handler function
				handler := ""
				for j := i + 1; j < len(lines); j++ {
					nextTrimmed := strings.TrimSpace(lines[j])
					if nextTrimmed == "" {
						continue
					}
					if fm := funcDefRe.FindStringSubmatch(lines[j]); fm != nil {
						handler = fm[2]
					}
					break
				}
				span := facts.Span{Start: lineNum, End: lineNum}
				rf, err := facts.NewRouteFact(facts.LangPython, relPath, span, method, path, handler, nil)
				if err == nil {
					result.Routes = append(result.Routes, rf)
				}
			}

			// Flask route decorators
			if m := flaskRouteRe.FindStringSubmatch(trimmed); m != nil {
				path := m[1]
				handler := ""
				for j := i + 1; j < len(lines); j++ {
					nextTrimmed := strings.TrimSpace(lines[j])
					if nextTrimmed == "" {
						continue
					}
					if fm := funcDefRe.FindStringSubmatch(lines[j]); fm != nil {
						handler = fm[2]
					}
					break
				}
				span := facts.Span{Start: lineNum, End: lineNum}
				rf, err := facts.NewRouteFact(facts.LangPython, relPath, span, "ANY", path, handler, nil)
				if err == nil {
					result.Routes = append(result.Routes, rf)
				}
			}

			// Django route patterns: path(), url(), re_path()
			for _, re := range []*regexp.Regexp{djangoPathRe, djangoUrlRe, djangoRePathRe} {
				if m := re.FindStringSubmatch(trimmed); m != nil {
					span := facts.Span{Start: lineNum, End: lineNum}
					rf, err := facts.NewRouteFact(facts.LangPython, relPath, span, "ANY", m[1], "", nil)
					if err == nil {
						result.Routes = append(result.Routes, rf)
					}
				}
			}

			// Starlette Route() pattern
			if m := starletteRouteRe.FindStringSubmatch(trimmed); m != nil {
				span := facts.Span{Start: lineNum, End: lineNum}
				rf, err := facts.NewRouteFact(facts.LangPython, relPath, span, "ANY", m[1], "", nil)
				if err == nil {
					result.Routes = append(result.Routes, rf)
				}
			}

			// Starlette add_middleware() pattern
			if m := addMiddlewareRe.FindStringSubmatch(trimmed); m != nil {
				span := facts.Span{Start: lineNum, End: lineNum}
				mf, err := facts.NewMiddlewareFact(facts.LangPython, relPath, span, m[1], "starlette")
				if err == nil {
					result.Middlewares = append(result.Middlewares, mf)
				}
			}

			// Django MIDDLEWARE list entries
			if djangoMiddlewareRe.MatchString(trimmed) && strings.Contains(filepath.Base(relPath), "settings") {
				matches := djangoMiddlewareRe.FindAllString(trimmed, -1)
				for _, match := range matches {
					name := strings.Trim(match, `'"`)
					span := facts.Span{Start: lineNum, End: lineNum}
					mf, err := facts.NewMiddlewareFact(facts.LangPython, relPath, span, name, "django")
					if err == nil {
						result.Middlewares = append(result.Middlewares, mf)
					}
				}
			}

			// Depends() middleware references
			if matches := dependsRe.FindAllStringSubmatch(trimmed, -1); matches != nil {
				for _, m := range matches {
					dependsRefs[m[1]] = true
				}
			}

			// Functions
			if m := funcDefRe.FindStringSubmatch(line); m != nil {
				indent := m[1]
				name := m[2]
				endLine := findBlockEnd(lines, i, len(indent))
				span := facts.Span{Start: lineNum, End: endLine}
				exported := !strings.HasPrefix(name, "_")
				sf, err := facts.NewSymbolFact(facts.LangPython, relPath, span, name, "function", exported)
				if err == nil {
					result.Symbols = append(result.Symbols, sf)
				}

				// TestFact: test_ prefixed functions in test files
				if isTestFile && strings.HasPrefix(name, "test_") {
					tf, err := facts.NewTestFact(facts.LangPython, relPath, span, name, "", "")
					if err == nil {
						result.Tests = append(result.Tests, tf)
					}
				}
			}

			// Classes
			if m := classDefRe.FindStringSubmatch(line); m != nil {
				indent := m[1]
				name := m[2]
				endLine := findBlockEnd(lines, i, len(indent))
				span := facts.Span{Start: lineNum, End: endLine}
				exported := !strings.HasPrefix(name, "_")
				sf, err := facts.NewSymbolFact(facts.LangPython, relPath, span, name, "class", exported)
				if err == nil {
					result.Symbols = append(result.Symbols, sf)
				}

				// Check for test methods inside test classes
				if isTestFile && strings.HasPrefix(name, "Test") {
					baseIndent := len(indent)
					for j := i + 1; j < len(lines); j++ {
						if mMethod := funcDefRe.FindStringSubmatch(lines[j]); mMethod != nil {
							methodIndent := len(mMethod[1])
							if methodIndent > baseIndent && strings.HasPrefix(mMethod[2], "test_") {
								methodEnd := findBlockEnd(lines, j, methodIndent)
								mSpan := facts.Span{Start: j + 1, End: methodEnd}
								tf, err := facts.NewTestFact(facts.LangPython, relPath, mSpan, mMethod[2], "", "")
								if err == nil {
									result.Tests = append(result.Tests, tf)
								}
							}
						}
						// Stop if we leave the class
						if j > i && len(strings.TrimSpace(lines[j])) > 0 {
							lineIndent := countIndent(lines[j])
							if lineIndent <= baseIndent && !strings.HasPrefix(strings.TrimSpace(lines[j]), "#") {
								break
							}
						}
					}
				}
			}

			// Secret detection
			if m := secretAssignRe.FindStringSubmatch(trimmed); m != nil {
				varName := m[1]
				value := m[2]
				// Skip env var lookups like os.environ.get
				if strings.Contains(trimmed, "os.environ") || strings.Contains(trimmed, "os.getenv") {
					continue
				}
				// Skip DEBUG or non-sensitive names
				if strings.EqualFold(varName, "DEBUG") {
					continue
				}
				_ = value
				span := facts.Span{Start: lineNum, End: lineNum}
				sf, err := facts.NewSecretFact(facts.LangPython, relPath, span, "hardcoded_secret", varName)
				if err == nil {
					result.Secrets = append(result.Secrets, sf)
				}
			}
		}

		// Data access detection based on imports
		if hasSQLAlchemyImport {
			// Check for Session usage
			for i, line := range lines {
				if sqlalchemyUsageRe.MatchString(line) {
					span := facts.Span{Start: i + 1, End: i + 1}
					da, err := facts.NewDataAccessFact(facts.LangPython, relPath, span, "session", "sqlalchemy")
					if err == nil {
						result.DataAccess = append(result.DataAccess, da)
					}
					break // One per file is enough
				}
			}
		}
		if hasPsycopg2Import {
			span := facts.Span{Start: 1, End: 1}
			da, err := facts.NewDataAccessFact(facts.LangPython, relPath, span, "cursor", "psycopg2")
			if err == nil {
				result.DataAccess = append(result.DataAccess, da)
			}
		}

		// Django ORM detection
		if hasDjangoOrmImport {
			for i, line := range lines {
				if m := djangoOrmRe.FindStringSubmatch(line); m != nil {
					span := facts.Span{Start: i + 1, End: i + 1}
					da, err := facts.NewDataAccessFact(facts.LangPython, relPath, span, m[1], "django-orm")
					if err == nil {
						result.DataAccess = append(result.DataAccess, da)
					}
				}
			}
		}

		// Tortoise ORM detection
		if hasTortoiseImport {
			span := facts.Span{Start: 1, End: 1}
			da, err := facts.NewDataAccessFact(facts.LangPython, relPath, span, "query", "tortoise")
			if err == nil {
				result.DataAccess = append(result.DataAccess, da)
			}
		}

		// Django TestCase detection
		if hasDjangoTestImport && isTestFile {
			for i, line := range lines {
				if m := classDefRe.FindStringSubmatch(line); m != nil {
					if strings.Contains(line, "TestCase") || strings.HasPrefix(m[2], "Test") {
						indent := m[1]
						endLine := findBlockEnd(lines, i, len(indent))
						span := facts.Span{Start: i + 1, End: endLine}
						tf, err := facts.NewTestFact(facts.LangPython, relPath, span, m[2], "", "")
						if err == nil {
							result.Tests = append(result.Tests, tf)
						}
					}
				}
			}
		}

		// Middleware facts from Depends() references
		for name := range dependsRefs {
			span := facts.Span{Start: 1, End: 1}
			mf, err := facts.NewMiddlewareFact(facts.LangPython, relPath, span, name, "fastapi_depends")
			if err == nil {
				result.Middlewares = append(result.Middlewares, mf)
			}
		}

		// TypeGraph extraction
		extractPyTypeGraph(lines, relPath, result.TypeGraph)
	}

	return result, nil
}

func isTestFileName(path string) bool {
	base := filepath.Base(path)
	return strings.HasPrefix(base, "test_") || strings.HasSuffix(base, "_test.py")
}

func readLines(path string) ([]string, error) {
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

func findBlockEnd(lines []string, startIdx int, baseIndent int) int {
	for i := startIdx + 1; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := countIndent(line)
		if indent <= baseIndent {
			return i
		}
	}
	return len(lines)
}

func countIndent(line string) int {
	count := 0
	for _, ch := range line {
		if ch == ' ' {
			count++
		} else if ch == '\t' {
			count += 4
		} else {
			break
		}
	}
	return count
}

func extractPyTypeGraph(lines []string, relPath string, tg *typegraph.TypeGraph) {
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)

		// Match class with bases: class Foo(Base1, Base2):
		m := pyClassBasesRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		indent := m[1]
		name := m[2]
		basesStr := m[3]
		baseIndent := len(indent)

		endLine := findBlockEnd(lines, i, baseIndent)
		startLine := i + 1

		isAbstract := false
		extends := ""
		var implements []string

		// Parse bases
		bases := strings.Split(basesStr, ",")
		for _, b := range bases {
			b = strings.TrimSpace(b)
			if b == "" {
				continue
			}
			if b == "ABC" || b == "abc.ABC" {
				isAbstract = true
				continue
			}
			if b == "metaclass=ABCMeta" || b == "metaclass=abc.ABCMeta" {
				isAbstract = true
				continue
			}
			// First non-ABC base is the extends
			if extends == "" {
				extends = b
			} else {
				implements = append(implements, b)
			}
		}

		kind := "class"
		if isAbstract {
			kind = "abstract_class"
		}

		tn := &typegraph.TypeNode{
			Name:       name,
			Kind:       kind,
			File:       relPath,
			Language:   "python",
			Exported:   !strings.HasPrefix(name, "_"),
			Extends:    extends,
			Implements: implements,
			Span:       typegraph.Span{Start: startLine, End: endLine},
		}

		// Extract methods and fields from class body
		seenFields := make(map[string]bool)
		pendingAbstract := false
		pendingStatic := false

		for j := i + 1; j < endLine && j < len(lines); j++ {
			bodyLine := lines[j]
			bodyTrimmed := strings.TrimSpace(bodyLine)

			if bodyTrimmed == "" || strings.HasPrefix(bodyTrimmed, "#") {
				continue
			}

			lineIndent := countIndent(bodyLine)
			if lineIndent <= baseIndent && bodyTrimmed != "" {
				break
			}

			// Check decorators
			if pyAbstractRe.MatchString(bodyTrimmed) {
				pendingAbstract = true
				continue
			}
			if pyStaticMethodRe.MatchString(bodyTrimmed) {
				pendingStatic = true
				continue
			}
			if pyClassMethodRe.MatchString(bodyTrimmed) {
				pendingStatic = true
				continue
			}
			// Skip other decorators
			if strings.HasPrefix(bodyTrimmed, "@") {
				continue
			}

			// Method def
			if mm := pyMethodDefRe.FindStringSubmatch(bodyLine); mm != nil {
				methodName := mm[2]
				paramsStr := mm[3]
				returnType := strings.TrimSpace(mm[4])

				mi := typegraph.MethodInfo{
					Name:       methodName,
					IsAbstract: pendingAbstract,
					IsStatic:   pendingStatic,
					IsPublic:   !strings.HasPrefix(methodName, "_"),
					ReturnType: returnType,
				}

				// Parse params
				if paramsStr != "" {
					for _, p := range strings.Split(paramsStr, ",") {
						p = strings.TrimSpace(p)
						if p == "" {
							continue
						}
						parts := strings.SplitN(p, ":", 2)
						pName := strings.TrimSpace(parts[0])
						pType := ""
						if len(parts) == 2 {
							pType = strings.TrimSpace(parts[1])
							// Remove default values
							if eqIdx := strings.Index(pType, "="); eqIdx > 0 {
								pType = strings.TrimSpace(pType[:eqIdx])
							}
						}
						// Remove default value from name
						if eqIdx := strings.Index(pName, "="); eqIdx > 0 {
							pName = strings.TrimSpace(pName[:eqIdx])
						}
						mi.Params = append(mi.Params, typegraph.ParamInfo{Name: pName, TypeName: pType})
					}
				}

				tn.Methods = append(tn.Methods, mi)
				pendingAbstract = false
				pendingStatic = false

				// If this is __init__, extract self.field assignments
				if methodName == "__init__" {
					methodEnd := findBlockEnd(lines, j, lineIndent)
					for k := j + 1; k < methodEnd && k < len(lines); k++ {
						initLine := strings.TrimSpace(lines[k])
						if fm := pySelfFieldRe.FindStringSubmatch(initLine); fm != nil {
							fieldName := fm[1]
							fieldType := fm[2]
							if !seenFields[fieldName] {
								seenFields[fieldName] = true
								tn.Fields = append(tn.Fields, typegraph.FieldInfo{
									Name:     fieldName,
									TypeName: fieldType,
									IsPublic: !strings.HasPrefix(fieldName, "_"),
								})
							}
						}
					}
				}
				continue
			}
			pendingAbstract = false
			pendingStatic = false
		}

		_ = trimmed
		tg.AddNode(tn)
	}
}
