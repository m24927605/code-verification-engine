package common

import (
	"strings"

	"github.com/verabase/code-verification-engine/internal/facts"
)

// ExtractImportsStructural extracts import facts from structurally-filtered code.
// It uses the tokenizer to strip strings and comments, then applies regex on
// code-only lines, ensuring imports inside strings/comments are not extracted.
func ExtractImportsStructural(source string, lang string, file string) []facts.ImportFact {
	tokens := Tokenize(source, lang)
	commentStripped := StripCommentsOnly(tokens)
	lines := strings.Split(commentStripped, "\n")

	var result []facts.ImportFact
	factLang := langToFacts(lang)

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		switch lang {
		case "javascript", "typescript":
			if imp := MatchESImport(trimmed); imp != "" {
				if f, err := facts.NewImportFact(factLang, file, facts.Span{Start: lineNum, End: lineNum}, imp, ""); err == nil {
					f.Provenance = facts.ProvenanceStructural
					result = append(result, f)
				}
			}
			if imp := MatchRequireImport(trimmed); imp != "" {
				if f, err := facts.NewImportFact(factLang, file, facts.Span{Start: lineNum, End: lineNum}, imp, ""); err == nil {
					f.Provenance = facts.ProvenanceStructural
					result = append(result, f)
				}
			}
		case "python":
			if m := pyFromImportRe.FindStringSubmatch(trimmed); m != nil {
				module := m[1]
				if f, err := facts.NewImportFact(factLang, file, facts.Span{Start: lineNum, End: lineNum}, module, ""); err == nil {
					f.Provenance = facts.ProvenanceStructural
					result = append(result, f)
				}
			} else if m := pyImportRe.FindStringSubmatch(trimmed); m != nil {
				modules := strings.Split(m[1], ",")
				for _, mod := range modules {
					mod = strings.TrimSpace(mod)
					if mod == "" {
						continue
					}
					parts := strings.Fields(mod)
					importPath := parts[0]
					if f, err := facts.NewImportFact(factLang, file, facts.Span{Start: lineNum, End: lineNum}, importPath, ""); err == nil {
						f.Provenance = facts.ProvenanceStructural
						result = append(result, f)
					}
				}
			}
		}
	}
	return result
}

// ExtractRoutesStructural extracts route facts from structurally-filtered code.
func ExtractRoutesStructural(source string, lang string, file string) []facts.RouteFact {
	tokens := Tokenize(source, lang)
	commentStripped := StripCommentsOnly(tokens)
	lines := strings.Split(commentStripped, "\n")

	var result []facts.RouteFact
	factLang := langToFacts(lang)

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		switch lang {
		case "javascript", "typescript":
			if method, path := MatchExpressRoute(trimmed); method != "" {
				if f, err := facts.NewRouteFact(factLang, file, facts.Span{Start: lineNum, End: lineNum}, method, path, "", nil); err == nil {
					f.Provenance = facts.ProvenanceStructural
					result = append(result, f)
				}
			}
			if method, path, ok := ExtractFastifyRoute(trimmed); ok {
				if f, err := facts.NewRouteFact(factLang, file, facts.Span{Start: lineNum, End: lineNum}, method, path, "", nil); err == nil {
					f.Provenance = facts.ProvenanceStructural
					result = append(result, f)
				}
			}
			if url := ExtractFastifyRouteObj(trimmed); url != "" {
				if f, err := facts.NewRouteFact(factLang, file, facts.Span{Start: lineNum, End: lineNum}, "ANY", url, "", nil); err == nil {
					f.Provenance = facts.ProvenanceStructural
					result = append(result, f)
				}
			}
			if method, path, ok := ExtractKoaRoute(trimmed); ok {
				if f, err := facts.NewRouteFact(factLang, file, facts.Span{Start: lineNum, End: lineNum}, method, path, "", nil); err == nil {
					f.Provenance = facts.ProvenanceStructural
					result = append(result, f)
				}
			}
			if method, path, ok := ExtractHapiRoute(trimmed); ok {
				if f, err := facts.NewRouteFact(factLang, file, facts.Span{Start: lineNum, End: lineNum}, method, path, "", nil); err == nil {
					f.Provenance = facts.ProvenanceStructural
					result = append(result, f)
				}
			}
			// NestJS (TypeScript-specific)
			if lang == "typescript" {
				if method, path, ok := ExtractNestRoute(trimmed); ok {
					if f, err := facts.NewRouteFact(factLang, file, facts.Span{Start: lineNum, End: lineNum}, method, path, "", nil); err == nil {
						f.Provenance = facts.ProvenanceStructural
						result = append(result, f)
					}
				}
				if prefix := ExtractNestController(trimmed); prefix != "" {
					if f, err := facts.NewRouteFact(factLang, file, facts.Span{Start: lineNum, End: lineNum}, "PREFIX", "/"+strings.TrimPrefix(prefix, "/"), "", nil); err == nil {
						f.Provenance = facts.ProvenanceStructural
						result = append(result, f)
					}
				}
			}
		case "python":
			if m := pyFastapiRouteRe.FindStringSubmatch(trimmed); m != nil {
				method := strings.ToUpper(m[1])
				path := m[2]
				if f, err := facts.NewRouteFact(factLang, file, facts.Span{Start: lineNum, End: lineNum}, method, path, "", nil); err == nil {
					f.Provenance = facts.ProvenanceStructural
					result = append(result, f)
				}
			}
			if m := pyFlaskRouteRe.FindStringSubmatch(trimmed); m != nil {
				path := m[1]
				if f, err := facts.NewRouteFact(factLang, file, facts.Span{Start: lineNum, End: lineNum}, "ANY", path, "", nil); err == nil {
					f.Provenance = facts.ProvenanceStructural
					result = append(result, f)
				}
			}
		}
	}
	return result
}

// ExtractMiddlewaresStructural extracts middleware facts from structurally-filtered code.
func ExtractMiddlewaresStructural(source string, lang string, file string) []facts.MiddlewareFact {
	tokens := Tokenize(source, lang)
	commentStripped := StripCommentsOnly(tokens)
	lines := strings.Split(commentStripped, "\n")

	var result []facts.MiddlewareFact
	factLang := langToFacts(lang)

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		switch lang {
		case "javascript", "typescript":
			if mw := MatchExpressMiddleware(trimmed); mw != "" {
				if f, err := facts.NewMiddlewareFact(factLang, file, facts.Span{Start: lineNum, End: lineNum}, mw, "express"); err == nil {
					f.Provenance = facts.ProvenanceStructural
					result = append(result, f)
				}
			}
			if plugin := ExtractFastifyRegister(trimmed); plugin != "" {
				if f, err := facts.NewMiddlewareFact(factLang, file, facts.Span{Start: lineNum, End: lineNum}, plugin, "fastify-plugin"); err == nil {
					f.Provenance = facts.ProvenanceStructural
					result = append(result, f)
				}
			}
			if hook := ExtractFastifyHook(trimmed); hook != "" {
				if f, err := facts.NewMiddlewareFact(factLang, file, facts.Span{Start: lineNum, End: lineNum}, hook, "fastify-hook"); err == nil {
					f.Provenance = facts.ProvenanceStructural
					result = append(result, f)
				}
			}
			if ext := ExtractHapiExt(trimmed); ext != "" {
				if f, err := facts.NewMiddlewareFact(factLang, file, facts.Span{Start: lineNum, End: lineNum}, ext, "hapi-ext"); err == nil {
					f.Provenance = facts.ProvenanceStructural
					result = append(result, f)
				}
			}
			if plugin := ExtractHapiRegister(trimmed); plugin != "" {
				if f, err := facts.NewMiddlewareFact(factLang, file, facts.Span{Start: lineNum, End: lineNum}, plugin, "hapi-plugin"); err == nil {
					f.Provenance = facts.ProvenanceStructural
					result = append(result, f)
				}
			}
			// NestJS guards and interceptors
			if lang == "typescript" {
				if guard := ExtractNestGuard(trimmed); guard != "" {
					if f, err := facts.NewMiddlewareFact(factLang, file, facts.Span{Start: lineNum, End: lineNum}, guard, "nestjs-guard"); err == nil {
						f.Provenance = facts.ProvenanceStructural
						result = append(result, f)
					}
				}
				if ic := ExtractNestInterceptor(trimmed); ic != "" {
					if f, err := facts.NewMiddlewareFact(factLang, file, facts.Span{Start: lineNum, End: lineNum}, ic, "nestjs-interceptor"); err == nil {
						f.Provenance = facts.ProvenanceStructural
						result = append(result, f)
					}
				}
			}
		}
	}
	return result
}

// ExtractSecretsStructural extracts secret facts from structurally-filtered code.
// Secret detection needs the original source (to see string values) but only matches
// lines that have code content (not entirely inside strings/comments).
func ExtractSecretsStructural(source string, lang string, file string) []facts.SecretFact {
	tokens := Tokenize(source, lang)
	codeSource := CodeOnly(tokens)
	codeLines := strings.Split(codeSource, "\n")
	origLines := strings.Split(source, "\n")

	var result []facts.SecretFact
	factLang := langToFacts(lang)

	for i, codeLine := range codeLines {
		lineNum := i + 1
		codeTrimmed := strings.TrimSpace(codeLine)
		if codeTrimmed == "" {
			continue
		}
		// Use the original line for the actual regex match (needs string values)
		if i >= len(origLines) {
			continue
		}
		origTrimmed := strings.TrimSpace(origLines[i])

		switch lang {
		case "javascript", "typescript":
			if kind := MatchSecret(origTrimmed); kind != "" {
				if f, err := facts.NewSecretFact(factLang, file, facts.Span{Start: lineNum, End: lineNum}, kind, ""); err == nil {
					f.Provenance = facts.ProvenanceStructural
					result = append(result, f)
				}
			}
		case "python":
			if m := pySecretAssignRe.FindStringSubmatch(origTrimmed); m != nil {
				varName := m[1]
				if strings.Contains(origTrimmed, "os.environ") || strings.Contains(origTrimmed, "os.getenv") {
					continue
				}
				if strings.EqualFold(varName, "DEBUG") {
					continue
				}
				if f, err := facts.NewSecretFact(factLang, file, facts.Span{Start: lineNum, End: lineNum}, "hardcoded_secret", varName); err == nil {
					f.Provenance = facts.ProvenanceStructural
					result = append(result, f)
				}
			}
		}
	}
	return result
}

// langToFacts converts a language string to a facts.Language.
func langToFacts(lang string) facts.Language {
	switch lang {
	case "javascript":
		return facts.LangJavaScript
	case "typescript":
		return facts.LangTypeScript
	case "python":
		return facts.LangPython
	default:
		return facts.Language(lang)
	}
}

// Re-export Python regex patterns from the python analyzer for use here.
// These are compiled regexes that match Python import and route patterns.
var (
	pyFromImportRe    = fromImportReExported
	pyImportRe        = importReExported
	pyFastapiRouteRe  = fastapiRouteReExported
	pyFlaskRouteRe    = flaskRouteReExported
	pySecretAssignRe  = secretAssignReExported
)
