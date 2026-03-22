package goanalyzer

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"testing"

	"github.com/verabase/code-verification-engine/internal/typegraph"
)

// writeGoFile writes a Go source file into the given directory and returns
// its path relative to dir (suitable for Analyze).
func writeGoFile(t *testing.T, dir, relPath, content string) {
	t.Helper()
	abs := filepath.Join(dir, relPath)
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(abs, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// parseSource is a helper that parses Go source and returns fset + AST.
func parseSource(t *testing.T, src string) (*token.FileSet, *ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, "test.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return fset, node
}

// ---------------------------------------------------------------------------
// extractTypeGraph
// ---------------------------------------------------------------------------

func TestExtractTypeGraph_StructWithFields(t *testing.T) {
	src := `package foo

type User struct {
	Name  string
	Email string
	age   int
}
`
	fset, node := parseSource(t, src)
	tg := typegraph.New()
	extractTypeGraph(fset, node, "foo.go", tg)

	nodes := tg.FindByName("User")
	if len(nodes) != 1 {
		t.Fatalf("expected 1 User node, got %d", len(nodes))
	}
	n := nodes[0]
	if n.Kind != "struct" {
		t.Errorf("expected struct, got %s", n.Kind)
	}
	if !n.Exported {
		t.Error("User should be exported")
	}
	if len(n.Fields) != 3 {
		t.Fatalf("expected 3 fields, got %d", len(n.Fields))
	}
	// Name field
	if n.Fields[0].Name != "Name" || n.Fields[0].TypeName != "string" || !n.Fields[0].IsPublic {
		t.Errorf("unexpected field 0: %+v", n.Fields[0])
	}
	// age field (unexported)
	if n.Fields[2].Name != "age" || n.Fields[2].IsPublic {
		t.Errorf("unexpected field 2: %+v", n.Fields[2])
	}
}

func TestExtractTypeGraph_StructWithEmbeddedType(t *testing.T) {
	src := `package foo

type Base struct{}

type Child struct {
	Base
	Name string
}
`
	fset, node := parseSource(t, src)
	tg := typegraph.New()
	extractTypeGraph(fset, node, "foo.go", tg)

	nodes := tg.FindByName("Child")
	if len(nodes) != 1 {
		t.Fatalf("expected 1 Child node, got %d", len(nodes))
	}
	n := nodes[0]
	if len(n.Implements) != 1 || n.Implements[0] != "Base" {
		t.Errorf("expected embedded Base in Implements, got %v", n.Implements)
	}
	if len(n.Fields) != 1 || n.Fields[0].Name != "Name" {
		t.Errorf("expected 1 named field Name, got %+v", n.Fields)
	}
}

func TestExtractTypeGraph_InterfaceWithMethods(t *testing.T) {
	src := `package foo

type Reader interface {
	Read(p []byte) (int, error)
	Close() error
}
`
	fset, node := parseSource(t, src)
	tg := typegraph.New()
	extractTypeGraph(fset, node, "foo.go", tg)

	ifaces := tg.FindInterfaces()
	if len(ifaces) != 1 {
		t.Fatalf("expected 1 interface, got %d", len(ifaces))
	}
	n := ifaces[0]
	if n.Name != "Reader" {
		t.Errorf("expected Reader, got %s", n.Name)
	}
	if len(n.Methods) != 2 {
		t.Fatalf("expected 2 methods, got %d", len(n.Methods))
	}
	// Read method
	read := n.Methods[0]
	if read.Name != "Read" {
		t.Errorf("expected Read, got %s", read.Name)
	}
	if !read.IsAbstract {
		t.Error("interface methods should be abstract")
	}
	if !read.IsPublic {
		t.Error("Read should be public")
	}
	if len(read.Params) != 1 || read.Params[0].Name != "p" || read.Params[0].TypeName != "[]byte" {
		t.Errorf("unexpected Read params: %+v", read.Params)
	}
	if read.ReturnType != "int" {
		t.Errorf("expected return type int (first), got %s", read.ReturnType)
	}
	// Close method
	close := n.Methods[1]
	if close.Name != "Close" || close.ReturnType != "error" {
		t.Errorf("unexpected Close method: %+v", close)
	}
}

func TestExtractTypeGraph_InterfaceWithEmbeddedInterface(t *testing.T) {
	src := `package foo

type Reader interface {
	Read() error
}

type ReadWriter interface {
	Reader
	Write() error
}
`
	fset, node := parseSource(t, src)
	tg := typegraph.New()
	extractTypeGraph(fset, node, "foo.go", tg)

	nodes := tg.FindByName("ReadWriter")
	if len(nodes) != 1 {
		t.Fatalf("expected 1 ReadWriter, got %d", len(nodes))
	}
	// Embedded interfaces (no Names) are skipped, only Write should appear
	if len(nodes[0].Methods) != 1 || nodes[0].Methods[0].Name != "Write" {
		t.Errorf("expected only Write method, got %+v", nodes[0].Methods)
	}
}

func TestExtractTypeGraph_MethodsWithPointerReceiver(t *testing.T) {
	src := `package foo

type Service struct{}

func (s *Service) Start() error {
	return nil
}

func (s Service) Name() string {
	return ""
}
`
	fset, node := parseSource(t, src)
	tg := typegraph.New()
	extractTypeGraph(fset, node, "foo.go", tg)

	nodes := tg.FindByName("Service")
	if len(nodes) != 1 {
		t.Fatalf("expected 1 Service node, got %d", len(nodes))
	}
	n := nodes[0]
	if len(n.Methods) != 2 {
		t.Fatalf("expected 2 methods, got %d", len(n.Methods))
	}

	methodNames := map[string]bool{}
	for _, m := range n.Methods {
		methodNames[m.Name] = true
	}
	if !methodNames["Start"] {
		t.Error("missing Start method (pointer receiver)")
	}
	if !methodNames["Name"] {
		t.Error("missing Name method (value receiver)")
	}

	// Check return types
	for _, m := range n.Methods {
		if m.Name == "Start" && m.ReturnType != "error" {
			t.Errorf("Start should return error, got %s", m.ReturnType)
		}
		if m.Name == "Name" && m.ReturnType != "string" {
			t.Errorf("Name should return string, got %s", m.ReturnType)
		}
	}
}

func TestExtractTypeGraph_MethodOnUndeclaredType(t *testing.T) {
	// Method receiver type not declared in same file -> should be ignored
	src := `package foo

func (s *Unknown) DoStuff() {}
`
	fset, node := parseSource(t, src)
	tg := typegraph.New()
	extractTypeGraph(fset, node, "foo.go", tg)

	if len(tg.Nodes) != 0 {
		t.Errorf("expected 0 nodes, got %d", len(tg.Nodes))
	}
}

func TestExtractTypeGraph_UnexportedStruct(t *testing.T) {
	src := `package foo

type config struct {
	Host string
	port int
}
`
	fset, node := parseSource(t, src)
	tg := typegraph.New()
	extractTypeGraph(fset, node, "foo.go", tg)

	nodes := tg.FindByName("config")
	if len(nodes) != 1 {
		t.Fatalf("expected 1 config node, got %d", len(nodes))
	}
	if nodes[0].Exported {
		t.Error("config should not be exported")
	}
}

// ---------------------------------------------------------------------------
// extractReceiverName
// ---------------------------------------------------------------------------

func TestExtractReceiverName_PointerReceiver(t *testing.T) {
	src := `package foo
type T struct{}
func (t *T) M() {}
`
	fset, node := parseSource(t, src)
	_ = fset
	for _, decl := range node.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Recv == nil {
			continue
		}
		name := extractReceiverName(fd.Recv)
		if name != "T" {
			t.Errorf("expected T, got %s", name)
		}
	}
}

func TestExtractReceiverName_ValueReceiver(t *testing.T) {
	src := `package foo
type S struct{}
func (s S) M() {}
`
	fset, node := parseSource(t, src)
	_ = fset
	for _, decl := range node.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Recv == nil {
			continue
		}
		name := extractReceiverName(fd.Recv)
		if name != "S" {
			t.Errorf("expected S, got %s", name)
		}
	}
}

func TestExtractReceiverName_NilFieldList(t *testing.T) {
	name := extractReceiverName(nil)
	if name != "" {
		t.Errorf("expected empty, got %s", name)
	}
}

func TestExtractReceiverName_EmptyFieldList(t *testing.T) {
	name := extractReceiverName(&ast.FieldList{})
	if name != "" {
		t.Errorf("expected empty, got %s", name)
	}
}

// ---------------------------------------------------------------------------
// extractParams
// ---------------------------------------------------------------------------

func TestExtractParams_NamedParams(t *testing.T) {
	src := `package foo
func F(a int, b string) {}
`
	_, node := parseSource(t, src)
	for _, decl := range node.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		params := extractParams(fd.Type)
		if len(params) != 2 {
			t.Fatalf("expected 2 params, got %d", len(params))
		}
		if params[0].Name != "a" || params[0].TypeName != "int" {
			t.Errorf("param 0: %+v", params[0])
		}
		if params[1].Name != "b" || params[1].TypeName != "string" {
			t.Errorf("param 1: %+v", params[1])
		}
	}
}

func TestExtractParams_UnnamedParams(t *testing.T) {
	src := `package foo
type I interface {
	Do(int, string)
}
`
	_, node := parseSource(t, src)
	for _, decl := range node.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gd.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok {
				continue
			}
			iface, ok := ts.Type.(*ast.InterfaceType)
			if !ok {
				continue
			}
			for _, m := range iface.Methods.List {
				ft, ok := m.Type.(*ast.FuncType)
				if !ok {
					continue
				}
				params := extractParams(ft)
				if len(params) != 2 {
					t.Fatalf("expected 2 params, got %d", len(params))
				}
				if params[0].Name != "" || params[0].TypeName != "int" {
					t.Errorf("param 0: %+v", params[0])
				}
				if params[1].Name != "" || params[1].TypeName != "string" {
					t.Errorf("param 1: %+v", params[1])
				}
			}
		}
	}
}

func TestExtractParams_NilParams(t *testing.T) {
	ft := &ast.FuncType{Params: nil}
	params := extractParams(ft)
	if params != nil {
		t.Errorf("expected nil, got %v", params)
	}
}

func TestExtractParams_MultipleNamesOneType(t *testing.T) {
	src := `package foo
func F(a, b int) {}
`
	_, node := parseSource(t, src)
	for _, decl := range node.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		params := extractParams(fd.Type)
		if len(params) != 2 {
			t.Fatalf("expected 2 params, got %d", len(params))
		}
		if params[0].Name != "a" || params[1].Name != "b" {
			t.Errorf("params: %+v", params)
		}
		if params[0].TypeName != "int" || params[1].TypeName != "int" {
			t.Errorf("both should be int: %+v", params)
		}
	}
}

// ---------------------------------------------------------------------------
// extractReturnType
// ---------------------------------------------------------------------------

func TestExtractReturnType_Single(t *testing.T) {
	src := `package foo
func F() error { return nil }
`
	_, node := parseSource(t, src)
	for _, decl := range node.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		rt := extractReturnType(fd.Type)
		if rt != "error" {
			t.Errorf("expected error, got %s", rt)
		}
	}
}

func TestExtractReturnType_Multiple(t *testing.T) {
	src := `package foo
func F() (int, error) { return 0, nil }
`
	_, node := parseSource(t, src)
	for _, decl := range node.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		rt := extractReturnType(fd.Type)
		// Returns first result type
		if rt != "int" {
			t.Errorf("expected int, got %s", rt)
		}
	}
}

func TestExtractReturnType_None(t *testing.T) {
	src := `package foo
func F() {}
`
	_, node := parseSource(t, src)
	for _, decl := range node.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		rt := extractReturnType(fd.Type)
		if rt != "" {
			t.Errorf("expected empty, got %s", rt)
		}
	}
}

// ---------------------------------------------------------------------------
// typeString — all type expression branches
// ---------------------------------------------------------------------------

func TestTypeString_Ident(t *testing.T) {
	src := `package foo; var x int`
	_, node := parseSource(t, src)
	for _, decl := range node.Decls {
		gd := decl.(*ast.GenDecl)
		vs := gd.Specs[0].(*ast.ValueSpec)
		if got := typeString(vs.Type); got != "int" {
			t.Errorf("expected int, got %s", got)
		}
	}
}

func TestTypeString_SelectorExpr(t *testing.T) {
	src := `package foo; import "net/http"; var x http.Handler`
	_, node := parseSource(t, src)
	for _, decl := range node.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || vs.Type == nil {
				continue
			}
			if got := typeString(vs.Type); got != "http.Handler" {
				t.Errorf("expected http.Handler, got %s", got)
			}
		}
	}
}

func TestTypeString_StarExpr(t *testing.T) {
	src := `package foo; var x *int`
	_, node := parseSource(t, src)
	for _, decl := range node.Decls {
		gd := decl.(*ast.GenDecl)
		vs := gd.Specs[0].(*ast.ValueSpec)
		if got := typeString(vs.Type); got != "*int" {
			t.Errorf("expected *int, got %s", got)
		}
	}
}

func TestTypeString_ArrayType(t *testing.T) {
	src := `package foo; var x []string`
	_, node := parseSource(t, src)
	for _, decl := range node.Decls {
		gd := decl.(*ast.GenDecl)
		vs := gd.Specs[0].(*ast.ValueSpec)
		if got := typeString(vs.Type); got != "[]string" {
			t.Errorf("expected []string, got %s", got)
		}
	}
}

func TestTypeString_MapType(t *testing.T) {
	src := `package foo; var x map[string]int`
	_, node := parseSource(t, src)
	for _, decl := range node.Decls {
		gd := decl.(*ast.GenDecl)
		vs := gd.Specs[0].(*ast.ValueSpec)
		if got := typeString(vs.Type); got != "map[string]int" {
			t.Errorf("expected map[string]int, got %s", got)
		}
	}
}

func TestTypeString_InterfaceType(t *testing.T) {
	src := `package foo; var x interface{}`
	_, node := parseSource(t, src)
	for _, decl := range node.Decls {
		gd := decl.(*ast.GenDecl)
		vs := gd.Specs[0].(*ast.ValueSpec)
		if got := typeString(vs.Type); got != "interface{}" {
			t.Errorf("expected interface{}, got %s", got)
		}
	}
}

func TestTypeString_FuncType(t *testing.T) {
	src := `package foo; var x func(int) string`
	_, node := parseSource(t, src)
	for _, decl := range node.Decls {
		gd := decl.(*ast.GenDecl)
		vs := gd.Specs[0].(*ast.ValueSpec)
		if got := typeString(vs.Type); got != "func(...)" {
			t.Errorf("expected func(...), got %s", got)
		}
	}
}

func TestTypeString_Ellipsis(t *testing.T) {
	src := `package foo
func F(args ...int) {}
`
	_, node := parseSource(t, src)
	for _, decl := range node.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		for _, field := range fd.Type.Params.List {
			if got := typeString(field.Type); got != "...int" {
				t.Errorf("expected ...int, got %s", got)
			}
		}
	}
}

func TestTypeString_ChanType(t *testing.T) {
	src := `package foo; var x chan int`
	_, node := parseSource(t, src)
	for _, decl := range node.Decls {
		gd := decl.(*ast.GenDecl)
		vs := gd.Specs[0].(*ast.ValueSpec)
		if got := typeString(vs.Type); got != "chan int" {
			t.Errorf("expected chan int, got %s", got)
		}
	}
}

func TestTypeString_Nil(t *testing.T) {
	if got := typeString(nil); got != "" {
		t.Errorf("expected empty, got %s", got)
	}
}

// ---------------------------------------------------------------------------
// extractUseMiddlewares
// ---------------------------------------------------------------------------

func TestExtractUseMiddlewares_NamedArg(t *testing.T) {
	src := `package foo

import "github.com/gofiber/fiber/v2"

func setup(app *fiber.App) {
	app.Use(Logger)
}
`
	fset, node := parseSource(t, src)
	mws := extractUseMiddlewares(fset, node, "foo.go")
	if len(mws) != 1 {
		t.Fatalf("expected 1 middleware, got %d", len(mws))
	}
	if mws[0].Name != "Logger" {
		t.Errorf("expected Logger, got %s", mws[0].Name)
	}
}

func TestExtractUseMiddlewares_AnonymousArg(t *testing.T) {
	src := `package foo

import "github.com/gofiber/fiber/v2"

func setup(app *fiber.App) {
	app.Use(func(c *fiber.Ctx) error {
		return c.Next()
	})
}
`
	fset, node := parseSource(t, src)
	mws := extractUseMiddlewares(fset, node, "foo.go")
	if len(mws) != 1 {
		t.Fatalf("expected 1 middleware, got %d", len(mws))
	}
	if mws[0].Name != "anonymous" {
		t.Errorf("expected anonymous, got %s", mws[0].Name)
	}
}

func TestExtractUseMiddlewares_SelectorExprArg(t *testing.T) {
	src := `package foo

import "github.com/gofiber/fiber/v2"

func setup(app *fiber.App) {
	app.Use(cors.New())
}
`
	fset, node := parseSource(t, src)
	mws := extractUseMiddlewares(fset, node, "foo.go")
	// cors.New() is a CallExpr, not an Ident or SelectorExpr directly — extractIdent returns ""
	if len(mws) != 1 {
		t.Fatalf("expected 1 middleware, got %d", len(mws))
	}
	if mws[0].Name != "anonymous" {
		t.Errorf("expected anonymous for call expr, got %s", mws[0].Name)
	}
}

func TestExtractUseMiddlewares_NoUseCall(t *testing.T) {
	src := `package foo

func setup() {
	x := 1
	_ = x
}
`
	fset, node := parseSource(t, src)
	mws := extractUseMiddlewares(fset, node, "foo.go")
	if len(mws) != 0 {
		t.Errorf("expected 0 middlewares, got %d", len(mws))
	}
}

// ---------------------------------------------------------------------------
// isFiberHandlerSignature
// ---------------------------------------------------------------------------

func TestIsFiberHandlerSignature_ReturnsFiberHandler(t *testing.T) {
	src := `package foo

import "github.com/gofiber/fiber/v2"

func NewAuth() fiber.Handler {
	return nil
}
`
	_, node := parseSource(t, src)
	for _, decl := range node.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if !isFiberHandlerSignature(fd) {
			t.Error("expected true for func returning fiber.Handler")
		}
	}
}

func TestIsFiberHandlerSignature_NoResults(t *testing.T) {
	src := `package foo
func F() {}
`
	_, node := parseSource(t, src)
	for _, decl := range node.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if isFiberHandlerSignature(fd) {
			t.Error("expected false for func with no results")
		}
	}
}

func TestIsFiberHandlerSignature_ReturnsNonHandler(t *testing.T) {
	src := `package foo
func F() error { return nil }
`
	_, node := parseSource(t, src)
	for _, decl := range node.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if isFiberHandlerSignature(fd) {
			t.Error("expected false for func returning error")
		}
	}
}

// ---------------------------------------------------------------------------
// hasImportContaining
// ---------------------------------------------------------------------------

func TestHasImportContaining_Match(t *testing.T) {
	imports := map[string]bool{
		"github.com/jmoiron/sqlx": true,
		"fmt":                     true,
	}
	if !hasImportContaining(imports, "sqlx") {
		t.Error("expected match for sqlx")
	}
}

func TestHasImportContaining_NoMatch(t *testing.T) {
	imports := map[string]bool{
		"fmt":     true,
		"net/http": true,
	}
	if hasImportContaining(imports, "gorm") {
		t.Error("expected no match for gorm")
	}
}

func TestHasImportContaining_EmptyMap(t *testing.T) {
	imports := map[string]bool{}
	if hasImportContaining(imports, "anything") {
		t.Error("expected no match on empty map")
	}
}

// ---------------------------------------------------------------------------
// hasHardcodedValue
// ---------------------------------------------------------------------------

func TestHasHardcodedValue_StringLit(t *testing.T) {
	src := `package foo
var secret = "hardcoded"
`
	_, node := parseSource(t, src)
	for _, decl := range node.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, val := range vs.Values {
				if !hasHardcodedValue(val) {
					t.Error("expected true for string literal")
				}
			}
		}
	}
}

func TestHasHardcodedValue_ByteSliceCall(t *testing.T) {
	src := `package foo
var secret = []byte("hardcoded")
`
	_, node := parseSource(t, src)
	for _, decl := range node.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, val := range vs.Values {
				if !hasHardcodedValue(val) {
					t.Error("expected true for []byte(\"...\")")
				}
			}
		}
	}
}

func TestHasHardcodedValue_CompositeLit(t *testing.T) {
	src := `package foo
var secret = []byte{0x01, 0x02}
`
	_, node := parseSource(t, src)
	for _, decl := range node.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, val := range vs.Values {
				if hasHardcodedValue(val) {
					t.Error("expected false for []byte{...} composite literal")
				}
			}
		}
	}
}

func TestHasHardcodedValue_IntLit(t *testing.T) {
	src := `package foo
var x = 42
`
	_, node := parseSource(t, src)
	for _, decl := range node.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, val := range vs.Values {
				if hasHardcodedValue(val) {
					t.Error("expected false for int literal")
				}
			}
		}
	}
}

func TestHasHardcodedValue_CallExprMultipleArgs(t *testing.T) {
	// CallExpr with >1 arg should return false
	src := `package foo
var x = make([]byte, 32)
`
	_, node := parseSource(t, src)
	for _, decl := range node.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, val := range vs.Values {
				if hasHardcodedValue(val) {
					t.Error("expected false for make(...) with multiple args")
				}
			}
		}
	}
}

// ---------------------------------------------------------------------------
// extractIdent
// ---------------------------------------------------------------------------

func TestExtractIdent_Ident(t *testing.T) {
	src := `package foo
var x = myFunc
`
	_, node := parseSource(t, src)
	for _, decl := range node.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, val := range vs.Values {
				name := extractIdent(val)
				if name != "myFunc" {
					t.Errorf("expected myFunc, got %s", name)
				}
			}
		}
	}
}

func TestExtractIdent_SelectorExpr(t *testing.T) {
	src := `package foo
import "net/http"
var x = http.StatusOK
`
	_, node := parseSource(t, src)
	for _, decl := range node.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Values) == 0 {
				continue
			}
			name := extractIdent(vs.Values[0])
			if name != "StatusOK" {
				t.Errorf("expected StatusOK, got %s", name)
			}
		}
	}
}

func TestExtractIdent_Other(t *testing.T) {
	src := `package foo
var x = "a string"
`
	_, node := parseSource(t, src)
	for _, decl := range node.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, val := range vs.Values {
				name := extractIdent(val)
				if name != "" {
					t.Errorf("expected empty for string lit, got %s", name)
				}
			}
		}
	}
}

// ---------------------------------------------------------------------------
// extractStringLit
// ---------------------------------------------------------------------------

func TestExtractStringLit_StringLit(t *testing.T) {
	src := `package foo
var x = "hello"
`
	_, node := parseSource(t, src)
	for _, decl := range node.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, val := range vs.Values {
				s := extractStringLit(val)
				if s != "hello" {
					t.Errorf("expected hello, got %s", s)
				}
			}
		}
	}
}

func TestExtractStringLit_NonStringLit(t *testing.T) {
	src := `package foo
var x = 42
`
	_, node := parseSource(t, src)
	for _, decl := range node.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, val := range vs.Values {
				s := extractStringLit(val)
				if s != "" {
					t.Errorf("expected empty for int lit, got %s", s)
				}
			}
		}
	}
}

func TestExtractStringLit_IdentExpr(t *testing.T) {
	src := `package foo
var y = "world"
var x = y
`
	_, node := parseSource(t, src)
	for _, decl := range node.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Names) == 0 || vs.Names[0].Name != "x" {
				continue
			}
			s := extractStringLit(vs.Values[0])
			if s != "" {
				t.Errorf("expected empty for ident, got %s", s)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Integration: full Analyze with temp dir covering all branches
// ---------------------------------------------------------------------------

func TestAnalyze_TempDir_FullCoverage(t *testing.T) {
	dir := t.TempDir()

	// File with structs, interfaces, methods, various types
	writeGoFile(t, dir, "models.go", `package myapp

type Logger interface {
	Log(msg string) error
	Debug(args ...interface{})
}

type BaseModel struct {
	ID   int
	Name string
}

type User struct {
	BaseModel
	Email    string
	Tags     []string
	Metadata map[string]interface{}
	done     chan int
	handler  func(int) string
	Ref      *User
}

func (u *User) Save() error {
	return nil
}

func (u User) FullName() string {
	return u.Name
}
`)

	// File with fiber handler, middleware Use(), secrets, routes
	writeGoFile(t, dir, "server.go", `package myapp

import (
	"net/http"
	"github.com/gofiber/fiber/v2"
)

func NewRateLimiter() fiber.Handler {
	return nil
}

func AuthMiddleware(next http.Handler) http.Handler {
	return next
}

func SetupRoutes(app *fiber.App) {
	app.Use(AuthMiddleware)
	app.Use(func(c *fiber.Ctx) error {
		return c.Next()
	})
	app.Get("/health", healthHandler)
	app.Post("/users", createUser)
}

func healthHandler(c *fiber.Ctx) error {
	return c.SendString("ok")
}

func createUser(c *fiber.Ctx) error {
	return nil
}

var apiSecret = "super-secret-key"
var apiToken = []byte("token-value")
var apiPassword = []byte{0x01, 0x02}
var normalVar = "not-a-secret"
`)

	// File with database access
	writeGoFile(t, dir, "repo.go", `package myapp

import "database/sql"

func GetUsers(db *sql.DB) {
	db.Query("SELECT * FROM users")
	db.QueryRow("SELECT id FROM users WHERE id = ?", 1)
	db.Exec("DELETE FROM users WHERE id = ?", 1)
}
`)

	// Test file to verify TestFact extraction
	writeGoFile(t, dir, "models_test.go", `package myapp

import "testing"

func TestUserSave(t *testing.T) {}
func TestUserFullName(t *testing.T) {}
`)

	files := []string{"models.go", "server.go", "repo.go", "models_test.go"}

	a := New()
	result, err := a.Analyze(dir, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	// Files
	if len(result.Files) != 4 {
		t.Errorf("expected 4 files, got %d", len(result.Files))
	}

	// TypeGraph: structs
	userNodes := result.TypeGraph.FindByName("User")
	if len(userNodes) != 1 {
		t.Fatalf("expected 1 User type node, got %d", len(userNodes))
	}
	un := userNodes[0]
	if un.Kind != "struct" {
		t.Errorf("expected struct, got %s", un.Kind)
	}
	// User should embed BaseModel
	if len(un.Implements) != 1 || un.Implements[0] != "BaseModel" {
		t.Errorf("expected BaseModel in Implements, got %v", un.Implements)
	}
	// User should have fields with various types
	fieldTypes := map[string]string{}
	for _, f := range un.Fields {
		fieldTypes[f.Name] = f.TypeName
	}
	expectations := map[string]string{
		"Email":    "string",
		"Tags":     "[]string",
		"Metadata": "map[string]interface{}",
		"done":     "chan int",
		"handler":  "func(...)",
		"Ref":      "*User",
	}
	for name, expected := range expectations {
		if got, ok := fieldTypes[name]; !ok {
			t.Errorf("missing field %s", name)
		} else if got != expected {
			t.Errorf("field %s: expected %s, got %s", name, expected, got)
		}
	}

	// Methods on User (pointer and value receiver)
	if len(un.Methods) != 2 {
		t.Errorf("expected 2 methods on User, got %d", len(un.Methods))
	}
	methodMap := map[string]bool{}
	for _, m := range un.Methods {
		methodMap[m.Name] = true
	}
	if !methodMap["Save"] {
		t.Error("missing Save method")
	}
	if !methodMap["FullName"] {
		t.Error("missing FullName method")
	}

	// TypeGraph: interfaces
	ifaces := result.TypeGraph.FindInterfaces()
	foundLogger := false
	for _, iface := range ifaces {
		if iface.Name == "Logger" {
			foundLogger = true
			if len(iface.Methods) != 2 {
				t.Errorf("Logger should have 2 methods, got %d", len(iface.Methods))
			}
		}
	}
	if !foundLogger {
		t.Error("missing Logger interface in type graph")
	}

	// Middlewares
	if len(result.Middlewares) < 3 {
		t.Errorf("expected at least 3 middlewares, got %d", len(result.Middlewares))
	}
	mwNames := map[string]bool{}
	for _, mw := range result.Middlewares {
		mwNames[mw.Name] = true
	}
	if !mwNames["AuthMiddleware"] {
		t.Error("missing AuthMiddleware")
	}
	if !mwNames["anonymous"] {
		t.Error("missing anonymous middleware from app.Use()")
	}
	if !mwNames["NewRateLimiter"] {
		t.Error("missing NewRateLimiter (fiber handler signature)")
	}

	// Secrets
	if len(result.Secrets) < 2 {
		t.Errorf("expected at least 2 secrets, got %d", len(result.Secrets))
	}
	secretValues := map[string]bool{}
	for _, s := range result.Secrets {
		secretValues[s.Value] = true
	}
	if !secretValues["apiSecret"] {
		t.Error("missing apiSecret")
	}
	if !secretValues["apiToken"] {
		t.Error("missing apiToken")
	}
	// apiPassword is []byte{...} composite lit -> should NOT be a secret
	if secretValues["apiPassword"] {
		t.Error("apiPassword should not be detected as secret (composite literal)")
	}

	// Routes
	foundHealth := false
	foundUsers := false
	for _, r := range result.Routes {
		if r.Path == "/health" {
			foundHealth = true
		}
		if r.Path == "/users" {
			foundUsers = true
		}
	}
	if !foundHealth {
		t.Error("missing /health route")
	}
	if !foundUsers {
		t.Error("missing /users route")
	}

	// Data access
	if len(result.DataAccess) < 3 {
		t.Errorf("expected at least 3 data access facts, got %d", len(result.DataAccess))
	}

	// Tests
	foundTestUserSave := false
	for _, tf := range result.Tests {
		if tf.TestName == "TestUserSave" {
			foundTestUserSave = true
		}
	}
	if !foundTestUserSave {
		t.Error("missing TestUserSave test fact")
	}
}

// Test Analyze with a file that has parse errors (should be skipped).
func TestAnalyze_ParseError(t *testing.T) {
	dir := t.TempDir()
	writeGoFile(t, dir, "bad.go", `package foo
func broken( {
`)
	a := New()
	result, err := a.Analyze(dir, []string{"bad.go"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.SkippedFiles) == 0 {
		t.Error("expected skipped file for parse error")
	}
}

// Test with middleware name containing "middleware" in name (case insensitive).
func TestAnalyze_MiddlewareByNamePattern(t *testing.T) {
	dir := t.TempDir()
	writeGoFile(t, dir, "mw.go", `package foo

func loggingMiddleware() {}
`)
	a := New()
	result, err := a.Analyze(dir, []string{"mw.go"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, mw := range result.Middlewares {
		if mw.Name == "loggingMiddleware" {
			found = true
		}
	}
	if !found {
		t.Error("expected middleware detected by name pattern")
	}
}

// Test extractUseMiddlewares with Use call argument that is a SelectorExpr
func TestExtractUseMiddlewares_SelectorIdentArg(t *testing.T) {
	src := `package foo

import "github.com/gofiber/fiber/v2"

func setup(app *fiber.App) {
	app.Use(middleware.Logger)
}
`
	fset, node := parseSource(t, src)
	mws := extractUseMiddlewares(fset, node, "foo.go")
	if len(mws) != 1 {
		t.Fatalf("expected 1 middleware, got %d", len(mws))
	}
	// SelectorExpr: extractIdent returns Sel.Name
	if mws[0].Name != "Logger" {
		t.Errorf("expected Logger, got %s", mws[0].Name)
	}
}

// Test isMiddlewareSignature for non-matching signature
func TestIsMiddlewareSignature_NoParams(t *testing.T) {
	src := `package foo
func F() {}
`
	_, node := parseSource(t, src)
	for _, decl := range node.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if isMiddlewareSignature(fd) {
			t.Error("expected false for func with no params/results")
		}
	}
}

func TestIsMiddlewareSignature_WrongParamCount(t *testing.T) {
	src := `package foo
import "net/http"
func F(a http.Handler, b http.Handler) http.Handler { return nil }
`
	_, node := parseSource(t, src)
	for _, decl := range node.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if isMiddlewareSignature(fd) {
			t.Error("expected false for func with 2 params")
		}
	}
}

// Test struct with multiple fields sharing one type declaration line
func TestExtractTypeGraph_StructMultiFieldSameLine(t *testing.T) {
	src := `package foo

type Point struct {
	X, Y, Z float64
}
`
	fset, node := parseSource(t, src)
	tg := typegraph.New()
	extractTypeGraph(fset, node, "foo.go", tg)

	nodes := tg.FindByName("Point")
	if len(nodes) != 1 {
		t.Fatalf("expected 1 Point, got %d", len(nodes))
	}
	if len(nodes[0].Fields) != 3 {
		t.Fatalf("expected 3 fields, got %d", len(nodes[0].Fields))
	}
	for _, f := range nodes[0].Fields {
		if f.TypeName != "float64" {
			t.Errorf("expected float64, got %s", f.TypeName)
		}
	}
}
