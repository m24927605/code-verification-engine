package goanalyzer

// coverage_gap_test.go — targeted tests to push the go analyzer package above 95%.
// These are white-box tests (internal package) covering:
//   - matchRouteCall: gorilla/fiber/chi-style routes and edge cases
//   - extractDataAccess: gorm, sqlx, ent backends
//   - findEnclosingFunc: not-found and nested cases
//   - extractReceiverName: generic / non-ident receiver
//   - typeString: all branches (star, array, map, interface{}, func, ellipsis, chan)

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"testing"
)

// --- matchRouteCall ---

func TestMatchRouteCall_HandleFunc(t *testing.T) {
	src := `package main
import "net/http"
func init() {
	http.HandleFunc("/health", healthHandler)
}
`
	fset, node := mustParse(t, src)
	routes := extractRoutes(fset, node, "main.go")
	if len(routes) == 0 {
		t.Fatal("expected at least 1 route from HandleFunc")
	}
	found := false
	for _, r := range routes {
		if r.Path == "/health" {
			found = true
			if r.Method != "ANY" {
				t.Errorf("HandleFunc should produce method=ANY, got %q", r.Method)
			}
		}
	}
	if !found {
		t.Error("expected route /health")
	}
}

func TestMatchRouteCall_Handle(t *testing.T) {
	src := `package main
import "net/http"
func init() {
	http.Handle("/static", staticHandler)
}
`
	fset, node := mustParse(t, src)
	routes := extractRoutes(fset, node, "main.go")
	found := false
	for _, r := range routes {
		if r.Path == "/static" {
			found = true
		}
	}
	if !found {
		t.Error("expected route /static from Handle")
	}
}

func TestMatchRouteCall_UpperCaseGET(t *testing.T) {
	// Gorilla mux / Fiber-style: router.GET("/path", handler)
	src := `package main
func init() {
	router.GET("/api/users", getUsers)
}
`
	fset, node := mustParse(t, src)
	routes := extractRoutes(fset, node, "main.go")
	found := false
	for _, r := range routes {
		if r.Path == "/api/users" && r.Method == "GET" {
			found = true
		}
	}
	if !found {
		t.Error("expected route GET /api/users from router.GET")
	}
}

func TestMatchRouteCall_LowerCaseGet(t *testing.T) {
	// Chi-style: r.Get("/path", handler)
	src := `package main
func init() {
	r.Get("/api/items", listItems)
}
`
	fset, node := mustParse(t, src)
	routes := extractRoutes(fset, node, "main.go")
	found := false
	for _, r := range routes {
		if r.Path == "/api/items" && r.Method == "GET" {
			found = true
		}
	}
	if !found {
		t.Error("expected route GET /api/items from r.Get")
	}
}

func TestMatchRouteCall_PostPutDeletePatch(t *testing.T) {
	src := `package main
func init() {
	router.POST("/users", createUser)
	router.PUT("/users/:id", updateUser)
	router.DELETE("/users/:id", deleteUser)
	router.PATCH("/users/:id", patchUser)
	router.Post("/items", addItem)
	router.Put("/items/:id", editItem)
	router.Delete("/items/:id", removeItem)
	router.Patch("/items/:id", changeItem)
}
`
	fset, node := mustParse(t, src)
	routes := extractRoutes(fset, node, "main.go")
	if len(routes) < 8 {
		t.Errorf("expected 8 routes, got %d", len(routes))
	}
}

func TestMatchRouteCall_WithMiddleware(t *testing.T) {
	// Route with middlewares between path and handler (Gorilla-style: Args[1..n-1])
	src := `package main
func init() {
	router.GET("/admin", authMiddleware, adminHandler)
}
`
	fset, node := mustParse(t, src)
	routes := extractRoutes(fset, node, "main.go")
	found := false
	for _, r := range routes {
		if r.Path == "/admin" {
			found = true
			if len(r.Middlewares) == 0 {
				t.Error("expected middleware to be captured")
			}
		}
	}
	if !found {
		t.Error("expected route /admin with middleware")
	}
}

func TestMatchRouteCall_NotARoute(t *testing.T) {
	// Call that doesn't match any route pattern
	src := `package main
func init() {
	db.Connect("localhost")
	logger.Info("started")
}
`
	fset, node := mustParse(t, src)
	routes := extractRoutes(fset, node, "main.go")
	if len(routes) != 0 {
		t.Errorf("expected 0 routes, got %d", len(routes))
	}
}

func TestMatchRouteCall_TooFewArgs(t *testing.T) {
	// HandleFunc with only 1 arg — should not produce a route
	src := `package main
func init() {
	http.HandleFunc("/only-path")
}
`
	fset, node := mustParse(t, src)
	routes := extractRoutes(fset, node, "main.go")
	if len(routes) != 0 {
		t.Errorf("expected 0 routes for single-arg HandleFunc, got %d", len(routes))
	}
}

// --- extractDataAccess backends ---

func TestExtractDataAccess_GORM(t *testing.T) {
	dir, cleanup := tempGoDir(t, "gorm_test", `package dao
import "gorm.io/gorm"

var db *gorm.DB

func ListUsers() {
	var users []User
	db.Find(&users)
	db.Where("name = ?", "foo").First(&users)
}
`)
	defer cleanup()
	a := New()
	result, err := a.Analyze(dir, []string{"gorm_test.go"})
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	found := false
	for _, da := range result.DataAccess {
		if da.Backend == "gorm" {
			found = true
		}
	}
	if !found {
		t.Error("expected gorm data access facts")
	}
}

func TestExtractDataAccess_SQLX(t *testing.T) {
	dir, cleanup := tempGoDir(t, "sqlx_test", `package dao
import "github.com/jmoiron/sqlx"

var db *sqlx.DB

func QueryUsers() {
	db.Query("SELECT * FROM users")
}
`)
	defer cleanup()
	a := New()
	result, err := a.Analyze(dir, []string{"sqlx_test.go"})
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	found := false
	for _, da := range result.DataAccess {
		if da.Backend == "sqlx" {
			found = true
		}
	}
	if !found {
		t.Error("expected sqlx data access facts")
	}
}

func TestExtractDataAccess_Ent(t *testing.T) {
	dir, cleanup := tempGoDir(t, "ent_test", `package dao
import "entgo.io/ent"

var client *ent.Client

func GetUsers() {
	client.Query()
}
`)
	defer cleanup()
	a := New()
	result, err := a.Analyze(dir, []string{"ent_test.go"})
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	found := false
	for _, da := range result.DataAccess {
		if da.Backend == "ent" {
			found = true
		}
	}
	if !found {
		t.Error("expected ent data access facts")
	}
}

func TestExtractDataAccess_NoDBImport(t *testing.T) {
	// File with no DB imports should return nil / empty data access
	src := `package main
import "fmt"
func main() { fmt.Println("hello") }
`
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, "main.go", src, 0)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	imports := collectFileImports(node)
	accesses := extractDataAccess(fset, node, "main.go", imports)
	if len(accesses) != 0 {
		t.Errorf("expected 0 data accesses without DB import, got %d", len(accesses))
	}
}

// --- findEnclosingFunc ---

func TestFindEnclosingFunc_Found(t *testing.T) {
	spans := []funcSpan{
		{name: "DoThing", kind: "function", startLine: 10, endLine: 20},
		{name: "OtherFunc", kind: "function", startLine: 25, endLine: 40},
	}
	fs := findEnclosingFunc(spans, 15)
	if fs == nil {
		t.Fatal("expected to find enclosing func")
	}
	if fs.name != "DoThing" {
		t.Errorf("expected DoThing, got %q", fs.name)
	}
}

func TestFindEnclosingFunc_NotFound(t *testing.T) {
	spans := []funcSpan{
		{name: "DoThing", kind: "function", startLine: 10, endLine: 20},
	}
	fs := findEnclosingFunc(spans, 5)
	if fs != nil {
		t.Errorf("expected nil for line before any function, got %+v", fs)
	}
}

func TestFindEnclosingFunc_Empty(t *testing.T) {
	fs := findEnclosingFunc(nil, 10)
	if fs != nil {
		t.Errorf("expected nil for empty spans, got %+v", fs)
	}
}

func TestFindEnclosingFunc_LineAtBoundary(t *testing.T) {
	spans := []funcSpan{
		{name: "BoundaryFunc", kind: "function", startLine: 5, endLine: 10},
	}
	// Exactly at start
	fs := findEnclosingFunc(spans, 5)
	if fs == nil || fs.name != "BoundaryFunc" {
		t.Error("expected to find enclosing func at start boundary")
	}
	// Exactly at end
	fs = findEnclosingFunc(spans, 10)
	if fs == nil || fs.name != "BoundaryFunc" {
		t.Error("expected to find enclosing func at end boundary")
	}
	// Just outside
	fs = findEnclosingFunc(spans, 11)
	if fs != nil {
		t.Error("expected nil for line just after end boundary")
	}
}

// --- extractReceiverName: non-ident receiver (generic / unusual AST) ---

func TestExtractReceiverName_NilRecv(t *testing.T) {
	// Test via a source with pointer receiver (common case) and a value receiver
	src := `package mypkg
type MyStruct struct{}
func (s MyStruct) ValueMethod() {}
func (s *MyStruct) PtrMethod() {}
`
	fset, node := mustParse(t, src)
	// Use buildFuncSpans to indirectly exercise extractReceiverName
	spans := buildFuncSpans(fset, node)
	if len(spans) < 2 {
		t.Fatalf("expected 2 function spans, got %d", len(spans))
	}
	for _, s := range spans {
		if s.kind != "method" {
			t.Errorf("expected method kind, got %q for %q", s.kind, s.name)
		}
	}
}

// --- typeString: cover all type expression branches ---

func TestTypeString_AllBranches(t *testing.T) {
	// Parse a synthetic file that exercises all typeString branches
	src := `package myp

import "net/http"

type MyInterface interface{}

// Struct with various field types to exercise typeString
type MyStruct struct {
	// *T  (StarExpr)
	Ptr *http.Request
	// []T (ArrayType)
	Slice []string
	// map[K]V (MapType)
	Map map[string]int
	// interface{} (InterfaceType) via embedded
	Iface interface{}
}

// func returns interface{} — InterfaceType
func ReturnsIface() interface{} { return nil }

// func returning func(...) — FuncType
func ReturnsFunc() func(string) int { return nil }

// func with variadic param — Ellipsis
func Variadic(args ...string) {}

// func with chan param — ChanType
func UseChan(ch chan int) {}

// function matching http.Handler signature (SelectorExpr in param and result)
func WrapHandler(h http.Handler) http.Handler { return h }
`
	_, node := mustParse(t, src)

	// Exercise isMiddlewareSignature (which calls typeString for SelectorExpr)
	for _, decl := range node.Decls {
		funcDecl, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		_ = isMiddlewareSignature(funcDecl)
		_ = isFiberHandlerSignature(funcDecl)
	}

	// Exercise typeString directly on various expressions
	cases := []struct {
		expr ast.Expr
		want string
	}{
		{&ast.Ident{Name: "string"}, "string"},
		{&ast.SelectorExpr{X: &ast.Ident{Name: "http"}, Sel: &ast.Ident{Name: "Handler"}}, "http.Handler"},
		{&ast.StarExpr{X: &ast.Ident{Name: "MyStruct"}}, "*MyStruct"},
		{&ast.ArrayType{Elt: &ast.Ident{Name: "int"}}, "[]int"},
		{&ast.MapType{Key: &ast.Ident{Name: "string"}, Value: &ast.Ident{Name: "int"}}, "map[string]int"},
		{&ast.InterfaceType{Methods: &ast.FieldList{}}, "interface{}"},
		{&ast.FuncType{}, "func(...)"},
		{&ast.Ellipsis{Elt: &ast.Ident{Name: "string"}}, "...string"},
		{&ast.ChanType{Value: &ast.Ident{Name: "int"}}, "chan int"},
	}

	for _, tc := range cases {
		got := typeString(tc.expr)
		if got != tc.want {
			t.Errorf("typeString(%T) = %q, want %q", tc.expr, got, tc.want)
		}
	}

	// Also test the nil/unknown case
	got := typeString(nil)
	if got != "" {
		t.Errorf("typeString(nil) = %q, want empty", got)
	}
}

func TestTypeString_SelectorExpr_NonIdentX(t *testing.T) {
	// SelectorExpr where X is not an Ident — should fall back to just Sel.Name
	expr := &ast.SelectorExpr{
		X:   &ast.StarExpr{X: &ast.Ident{Name: "pkg"}}, // X is not an Ident
		Sel: &ast.Ident{Name: "Handler"},
	}
	got := typeString(expr)
	if got != "Handler" {
		t.Errorf("typeString(non-ident SelectorExpr) = %q, want %q", got, "Handler")
	}
}

// --- helpers ---

func mustParse(t *testing.T, src string) (*token.FileSet, *ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, "test.go", src, 0)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return fset, node
}

// tempGoDir creates a temporary directory with a single .go file for testing.
// Returns the dir path and a cleanup function.
func tempGoDir(t *testing.T, filename, content string) (string, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("", "goanalyzer-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	path := filepath.Join(dir, filename+".go")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		os.RemoveAll(dir)
		t.Fatalf("failed to write test file: %v", err)
	}
	return dir, func() { os.RemoveAll(dir) }
}
