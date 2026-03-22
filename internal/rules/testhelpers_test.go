package rules

import (
	"path/filepath"

	"github.com/verabase/code-verification-engine/internal/facts"
)

func testdataPath(name string) string {
	return filepath.Join("..", "..", "testdata", "rules", name)
}

func sym(name, kind, file string, lang facts.Language, exported bool, start, end int) facts.SymbolFact {
	return facts.SymbolFact{
		Name: name, Kind: kind, File: file, Language: lang,
		Exported: exported, Span: facts.Span{Start: start, End: end},
	}
}

func imp(importPath, alias, file string, lang facts.Language) facts.ImportFact {
	return facts.ImportFact{
		ImportPath: importPath, Alias: alias, File: file, Language: lang,
		Span: facts.Span{Start: 1, End: 1},
	}
}

func mw(name, kind, file string, lang facts.Language) facts.MiddlewareFact {
	return facts.MiddlewareFact{
		Name: name, Kind: kind, File: file, Language: lang,
		Span: facts.Span{Start: 1, End: 1},
	}
}

func route(method, path, handler, file string, lang facts.Language, middlewares []string) facts.RouteFact {
	return facts.RouteFact{
		Method: method, Path: path, Handler: handler, File: file,
		Language: lang, Middlewares: middlewares, Span: facts.Span{Start: 1, End: 1},
	}
}

func testFact(testName, file string, lang facts.Language, targetModule string) facts.TestFact {
	return facts.TestFact{
		TestName: testName, File: file, Language: lang, TargetModule: targetModule,
		Span: facts.Span{Start: 1, End: 1},
	}
}

func dataAccess(operation, file string, lang facts.Language) facts.DataAccessFact {
	return facts.DataAccessFact{
		Operation: operation, File: file, Language: lang,
		Span: facts.Span{Start: 1, End: 1},
	}
}

func secret(kind, file string, lang facts.Language, start int) facts.SecretFact {
	return facts.SecretFact{
		Kind: kind, File: file, Language: lang,
		Span: facts.Span{Start: start, End: start},
	}
}

func fileFact(file string, lang facts.Language) facts.FileFact {
	return facts.FileFact{File: file, Language: lang}
}
