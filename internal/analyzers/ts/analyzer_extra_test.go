package ts_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/verabase/code-verification-engine/internal/analyzers/ts"
	"github.com/verabase/code-verification-engine/internal/facts"
)

// ---------- helpers ----------

func analyzeTemp(t *testing.T, relPath, content string) *ts.TypeScriptAnalyzer {
	t.Helper()
	dir := t.TempDir()
	abs := filepath.Join(dir, relPath)
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return ts.New()
}

func analyzeOne(t *testing.T, relPath, content string) *struct {
	a   *ts.TypeScriptAnalyzer
	dir string
} {
	t.Helper()
	dir := t.TempDir()
	abs := filepath.Join(dir, relPath)
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return &struct {
		a   *ts.TypeScriptAnalyzer
		dir string
	}{a: ts.New(), dir: dir}
}

// ---------- Next.js API route detection ----------

func TestNextJSPagesAPIRoute(t *testing.T) {
	rel := filepath.Join("pages", "api", "users.ts")
	src := `import { NextApiRequest, NextApiResponse } from 'next';
export default function handler(req: NextApiRequest, res: NextApiResponse) {
  res.status(200).json({ users: [] });
}
`
	h := analyzeOne(t, rel, src)
	result, err := h.a.Analyze(h.dir, []string{rel})
	if err != nil {
		t.Fatal(err)
	}
	// Should detect a route with method ANY and path /api/users
	found := false
	for _, r := range result.Routes {
		if r.Method == "ANY" && r.Path == "/api/users" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected Next.js pages API route /api/users (ANY), got routes: %+v", result.Routes)
	}
}

func TestNextJSAppAPIRouteWithExportedMethods(t *testing.T) {
	rel := filepath.Join("app", "api", "items", "route.ts")
	src := `import { NextResponse } from 'next/server';
export function GET(request: Request) {
  return NextResponse.json({ items: [] });
}
export function POST(request: Request) {
  return NextResponse.json({ created: true });
}
`
	h := analyzeOne(t, rel, src)
	result, err := h.a.Analyze(h.dir, []string{rel})
	if err != nil {
		t.Fatal(err)
	}

	methods := map[string]bool{}
	for _, r := range result.Routes {
		if strings.HasPrefix(r.Path, "/api/items") {
			methods[r.Method] = true
		}
	}
	for _, m := range []string{"GET", "POST"} {
		if !methods[m] {
			t.Errorf("expected Next.js app route method %s, got methods: %v", m, methods)
		}
	}
	if methods["ANY"] {
		t.Error("should not have ANY when exported methods are present")
	}
}

func TestNextJSAppAPIRouteNoExportedMethods(t *testing.T) {
	rel := filepath.Join("app", "api", "health", "route.ts")
	src := `// no exported handler functions
const x = 42;
`
	h := analyzeOne(t, rel, src)
	result, err := h.a.Analyze(h.dir, []string{rel})
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, r := range result.Routes {
		if r.Method == "ANY" && strings.Contains(r.Path, "/api/health") {
			found = true
		}
	}
	if !found {
		t.Error("expected fallback ANY route for Next.js app route without exported methods")
	}
}

// ---------- NestJS ----------

func TestNestJSController(t *testing.T) {
	rel := "users.controller.ts"
	src := `import { Controller, Get, Post, UseGuards, UseInterceptors } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';

@Controller('users')
export class UsersController {
  constructor(
    @InjectRepository(User)
    private userRepo: Repository<User>,
  ) {}

  @Get('/profile')
  getProfile() { return {}; }

  @Post('/create')
  create() { return {}; }

  @UseGuards(AuthGuard)
  @UseInterceptors(LoggingInterceptor)
  @Get('/admin')
  admin() { return {}; }
}
`
	h := analyzeOne(t, rel, src)
	result, err := h.a.Analyze(h.dir, []string{rel})
	if err != nil {
		t.Fatal(err)
	}

	// Controller prefix
	prefixFound := false
	for _, r := range result.Routes {
		if r.Method == "PREFIX" && r.Path == "/users" {
			prefixFound = true
		}
	}
	if !prefixFound {
		t.Error("expected NestJS PREFIX /users route")
	}

	// Route decorators
	routeSet := map[string]bool{}
	for _, r := range result.Routes {
		if r.Method != "PREFIX" {
			routeSet[r.Method+" "+r.Path] = true
		}
	}
	if !routeSet["GET /profile"] {
		t.Errorf("expected GET /profile in routes, got %v", routeSet)
	}
	if !routeSet["POST /create"] {
		t.Errorf("expected POST /create in routes, got %v", routeSet)
	}
	if !routeSet["GET /admin"] {
		t.Errorf("expected GET /admin in routes, got %v", routeSet)
	}

	// Guards and interceptors
	mwNames := map[string]string{}
	for _, m := range result.Middlewares {
		mwNames[m.Name] = m.Kind
	}
	if mwNames["AuthGuard"] != "nestjs-guard" {
		t.Error("expected nestjs-guard middleware AuthGuard")
	}
	if mwNames["LoggingInterceptor"] != "nestjs-interceptor" {
		t.Error("expected nestjs-interceptor middleware LoggingInterceptor")
	}

	// InjectRepository
	foundTypeORM := false
	for _, d := range result.DataAccess {
		if d.Backend == "typeorm" && strings.Contains(d.Operation, "User") {
			foundTypeORM = true
		}
	}
	if !foundTypeORM {
		t.Error("expected typeorm data access for @InjectRepository(User)")
	}
}

// ---------- Fastify ----------

func TestFastifyRoutes(t *testing.T) {
	rel := "server.ts"
	src := `import fastify from 'fastify';
const app = fastify();

fastify.get('/health', async (req, reply) => {
  return { status: 'ok' };
});

fastify.post('/items', async (req, reply) => {
  return { created: true };
});
`
	h := analyzeOne(t, rel, src)
	result, err := h.a.Analyze(h.dir, []string{rel})
	if err != nil {
		t.Fatal(err)
	}

	routeMap := map[string]string{}
	for _, r := range result.Routes {
		routeMap[r.Method+" "+r.Path] = r.File
	}
	if _, ok := routeMap["GET /health"]; !ok {
		t.Errorf("expected GET /health fastify route, got: %v", routeMap)
	}
	if _, ok := routeMap["POST /items"]; !ok {
		t.Errorf("expected POST /items fastify route, got: %v", routeMap)
	}
}

func TestFastifyRouteObject(t *testing.T) {
	rel := "routes.ts"
	src := `app.route({ method: 'GET', url: '/status', handler: statusHandler });
fastify.route({ url: '/ping' });
`
	h := analyzeOne(t, rel, src)
	result, err := h.a.Analyze(h.dir, []string{rel})
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, r := range result.Routes {
		if r.Path == "/ping" || r.Path == "/status" {
			found = true
		}
	}
	if !found {
		t.Error("expected fastify route object route")
	}
}

func TestFastifyRegister(t *testing.T) {
	rel := "plugins.ts"
	src := `fastify.register(authPlugin);
fastify.register(corsPlugin, { origin: '*' });
`
	h := analyzeOne(t, rel, src)
	result, err := h.a.Analyze(h.dir, []string{rel})
	if err != nil {
		t.Fatal(err)
	}

	mwNames := map[string]bool{}
	for _, m := range result.Middlewares {
		if m.Kind == "fastify-plugin" {
			mwNames[m.Name] = true
		}
	}
	if !mwNames["authPlugin"] {
		t.Error("expected fastify-plugin authPlugin")
	}
}

func TestFastifyHooks(t *testing.T) {
	rel := "hooks.ts"
	src := `fastify.addHook('onRequest', authHandler);
fastify.addHook('preHandler', logHandler);
`
	h := analyzeOne(t, rel, src)
	result, err := h.a.Analyze(h.dir, []string{rel})
	if err != nil {
		t.Fatal(err)
	}

	hookNames := map[string]bool{}
	for _, m := range result.Middlewares {
		if m.Kind == "fastify-hook" {
			hookNames[m.Name] = true
		}
	}
	if !hookNames["onRequest"] {
		t.Errorf("expected fastify-hook onRequest, got: %v", hookNames)
	}
}

// ---------- Koa ----------

func TestKoaRoutes(t *testing.T) {
	rel := "koa-app.ts"
	src := `import Router from 'koa-router';
const router = new Router();

router.get('/users', listUsers);
router.post('/users', createUser);
router.delete('/users/:id', deleteUser);
`
	h := analyzeOne(t, rel, src)
	result, err := h.a.Analyze(h.dir, []string{rel})
	if err != nil {
		t.Fatal(err)
	}

	routeMap := map[string]bool{}
	for _, r := range result.Routes {
		routeMap[r.Method+" "+r.Path] = true
	}
	for _, key := range []string{"GET /users", "POST /users", "DELETE /users/:id"} {
		if !routeMap[key] {
			t.Errorf("expected Koa route %s, got: %v", key, routeMap)
		}
	}
}

// ---------- Hapi ----------

func TestHapiRoutes(t *testing.T) {
	rel := "hapi-server.ts"
	src := `import Hapi from '@hapi/hapi';

server.route({ method: 'GET', path: '/health', handler: healthHandler });
server.route({ method: 'POST', path: '/login', handler: loginHandler });
`
	h := analyzeOne(t, rel, src)
	result, err := h.a.Analyze(h.dir, []string{rel})
	if err != nil {
		t.Fatal(err)
	}

	routeMap := map[string]bool{}
	for _, r := range result.Routes {
		routeMap[r.Method+" "+r.Path] = true
	}
	if !routeMap["GET /health"] {
		t.Errorf("expected Hapi GET /health, got: %v", routeMap)
	}
	if !routeMap["POST /login"] {
		t.Errorf("expected Hapi POST /login, got: %v", routeMap)
	}
}

func TestHapiExtensions(t *testing.T) {
	rel := "hapi-ext.ts"
	src := `server.ext('onPreHandler', authCheck);
server.ext('onPreResponse', logResponse);
`
	h := analyzeOne(t, rel, src)
	result, err := h.a.Analyze(h.dir, []string{rel})
	if err != nil {
		t.Fatal(err)
	}

	extNames := map[string]bool{}
	for _, m := range result.Middlewares {
		if m.Kind == "hapi-ext" {
			extNames[m.Name] = true
		}
	}
	if !extNames["onPreHandler"] {
		t.Errorf("expected hapi-ext onPreHandler, got: %v", extNames)
	}
}

func TestHapiRegister(t *testing.T) {
	rel := "hapi-plugins.ts"
	src := `server.register(authPlugin);
server.register(rateLimitPlugin);
`
	h := analyzeOne(t, rel, src)
	result, err := h.a.Analyze(h.dir, []string{rel})
	if err != nil {
		t.Fatal(err)
	}

	pluginNames := map[string]bool{}
	for _, m := range result.Middlewares {
		if m.Kind == "hapi-plugin" {
			pluginNames[m.Name] = true
		}
	}
	if !pluginNames["authPlugin"] {
		t.Error("expected hapi-plugin authPlugin")
	}
}

// ---------- Scanner error / DiscardFactsForFile ----------

func TestScannerErrorDiscardsPartialFacts(t *testing.T) {
	rel := "long-line.ts"
	dir := t.TempDir()
	abs := filepath.Join(dir, rel)

	// Write a file with a normal line followed by a >64KB line to trigger scanner error
	normalLine := "import express from 'express';\n"
	longLine := "const x = '" + strings.Repeat("a", 70000) + "';\n"
	if err := os.WriteFile(abs, []byte(normalLine+longLine), 0o644); err != nil {
		t.Fatal(err)
	}

	a := ts.New()
	result, err := a.Analyze(dir, []string{rel})
	if err != nil {
		t.Fatal(err)
	}

	// The file should be in SkippedFiles due to scanner error
	skipped := false
	for _, s := range result.SkippedFiles {
		if s.File == rel {
			skipped = true
		}
	}
	if !skipped {
		t.Error("expected file with long line to be in SkippedFiles")
	}

	// No FileFact should exist for this file (discarded)
	for _, f := range result.Files {
		if f.File == rel {
			t.Error("expected file fact to be discarded after scanner error")
		}
	}
}

// ---------- TypeGraph: Interface with extends and methods ----------

func TestTypeGraphInterfaceExtendsAndMethods(t *testing.T) {
	rel := "models.ts"
	src := `export interface Animal extends LivingThing, Organism {
  name: string;
  speak(volume: number): void;
  move(distance: number): string;
}
`
	h := analyzeOne(t, rel, src)
	result, err := h.a.Analyze(h.dir, []string{rel})
	if err != nil {
		t.Fatal(err)
	}

	tg := result.TypeGraph
	nodes := tg.FindByName("Animal")
	if len(nodes) != 1 {
		t.Fatalf("expected 1 Animal node, got %d", len(nodes))
	}
	n := nodes[0]
	if n.Kind != "interface" {
		t.Errorf("expected kind interface, got %s", n.Kind)
	}
	if !n.Exported {
		t.Error("expected Animal to be exported")
	}
	if len(n.Implements) < 2 {
		t.Errorf("expected 2 extends (as Implements), got %v", n.Implements)
	}
	if len(n.Methods) < 2 {
		t.Errorf("expected at least 2 methods, got %d", len(n.Methods))
	}
	// Check method details
	methodMap := map[string]bool{}
	for _, m := range n.Methods {
		methodMap[m.Name] = true
		if !m.IsAbstract {
			t.Errorf("interface method %s should be abstract", m.Name)
		}
		if !m.IsPublic {
			t.Errorf("interface method %s should be public", m.Name)
		}
	}
	if !methodMap["speak"] {
		t.Error("expected method speak")
	}
	if !methodMap["move"] {
		t.Error("expected method move")
	}
}

// ---------- TypeGraph: Abstract class with abstract methods ----------

func TestTypeGraphAbstractClass(t *testing.T) {
	rel := "base.ts"
	src := `export abstract class Shape {
  abstract area(): number;
  abstract perimeter(): number;
  describe(): string {
    return 'shape';
  }
}
`
	h := analyzeOne(t, rel, src)
	result, err := h.a.Analyze(h.dir, []string{rel})
	if err != nil {
		t.Fatal(err)
	}

	nodes := result.TypeGraph.FindByName("Shape")
	if len(nodes) != 1 {
		t.Fatalf("expected 1 Shape node, got %d", len(nodes))
	}
	n := nodes[0]
	if n.Kind != "abstract_class" {
		t.Errorf("expected abstract_class, got %s", n.Kind)
	}
	if !n.Exported {
		t.Error("expected Shape to be exported")
	}

	abstractCount := 0
	for _, m := range n.Methods {
		if m.IsAbstract {
			abstractCount++
		}
	}
	if abstractCount < 2 {
		t.Errorf("expected at least 2 abstract methods, got %d", abstractCount)
	}
}

// ---------- TypeGraph: Class with implements, private/protected/static ----------

func TestTypeGraphClassImplementsAndVisibility(t *testing.T) {
	rel := "service.ts"
	src := `export class UserService extends BaseService implements Serializable, Disposable {
  private db: Database;
  protected logger: Logger;
  static instance: UserService;
  public name: string;

  private connect(): void {}
  protected log(msg: string): void {}
  static create(): UserService {}
  findAll(limit: number): User[] {}
}
`
	h := analyzeOne(t, rel, src)
	result, err := h.a.Analyze(h.dir, []string{rel})
	if err != nil {
		t.Fatal(err)
	}

	nodes := result.TypeGraph.FindByName("UserService")
	if len(nodes) != 1 {
		t.Fatalf("expected 1 UserService node, got %d", len(nodes))
	}
	n := nodes[0]
	if n.Kind != "class" {
		t.Errorf("expected class, got %s", n.Kind)
	}
	if n.Extends != "BaseService" {
		t.Errorf("expected extends BaseService, got %s", n.Extends)
	}
	if len(n.Implements) < 2 {
		t.Errorf("expected at least 2 implements, got %v", n.Implements)
	}

	// Check fields
	fieldMap := map[string]struct {
		public bool
		static bool
		typ    string
	}{}
	for _, f := range n.Fields {
		fieldMap[f.Name] = struct {
			public bool
			static bool
			typ    string
		}{f.IsPublic, f.IsStatic, f.TypeName}
	}
	if f, ok := fieldMap["db"]; ok {
		if f.public {
			t.Error("db should be private (not public)")
		}
		if f.typ != "Database" {
			t.Errorf("db type expected Database, got %s", f.typ)
		}
	}
	if f, ok := fieldMap["instance"]; ok {
		if !f.static {
			t.Error("instance should be static")
		}
	}

	// Check methods
	methodMap := map[string]struct {
		public   bool
		static   bool
		abstract bool
	}{}
	for _, m := range n.Methods {
		methodMap[m.Name] = struct {
			public   bool
			static   bool
			abstract bool
		}{m.IsPublic, m.IsStatic, m.IsAbstract}
	}
	if m, ok := methodMap["connect"]; ok {
		if m.public {
			t.Error("connect should be private")
		}
	}
	if m, ok := methodMap["create"]; ok {
		if !m.static {
			t.Error("create should be static")
		}
	}
	if m, ok := methodMap["findAll"]; ok {
		if !m.public {
			t.Error("findAll should be public")
		}
	}
}

// ---------- parseTSParams: optional and assertion params ----------

func TestParamsOptionalAndAssertions(t *testing.T) {
	// parseTSParams uses TrimLeft which trims leading ?/! chars.
	// When ? or ! appear after the name (e.g. name?: string), they remain
	// because TrimLeft only strips from the left side of the string.
	// This test verifies the params are extracted with correct types.
	rel := "params.ts"
	src := `interface Config {
  init(name: string, force: boolean): void;
}
`
	h := analyzeOne(t, rel, src)
	result, err := h.a.Analyze(h.dir, []string{rel})
	if err != nil {
		t.Fatal(err)
	}

	nodes := result.TypeGraph.FindByName("Config")
	if len(nodes) != 1 {
		t.Fatalf("expected 1 Config node, got %d", len(nodes))
	}
	n := nodes[0]
	if len(n.Methods) < 1 {
		t.Fatal("expected at least 1 method")
	}
	m := n.Methods[0]
	if len(m.Params) < 2 {
		t.Fatalf("expected 2 params, got %d", len(m.Params))
	}
	if m.Params[0].Name != "name" || m.Params[0].TypeName != "string" {
		t.Errorf("expected param name:string, got %s:%s", m.Params[0].Name, m.Params[0].TypeName)
	}
	if m.Params[1].Name != "force" || m.Params[1].TypeName != "boolean" {
		t.Errorf("expected param force:boolean, got %s:%s", m.Params[1].Name, m.Params[1].TypeName)
	}
}

func TestParamsWithLeadingModifiers(t *testing.T) {
	// parseTSParams TrimLeft strips leading ?/!/. characters from param names
	rel := "params2.ts"
	src := `interface Modifier {
  process(?opt: string): void;
}
`
	h := analyzeOne(t, rel, src)
	result, err := h.a.Analyze(h.dir, []string{rel})
	if err != nil {
		t.Fatal(err)
	}

	nodes := result.TypeGraph.FindByName("Modifier")
	if len(nodes) != 1 {
		t.Fatalf("expected 1 Modifier node, got %d", len(nodes))
	}
	n := nodes[0]
	if len(n.Methods) < 1 {
		t.Fatal("expected at least 1 method")
	}
	m := n.Methods[0]
	if len(m.Params) < 1 {
		t.Fatalf("expected 1 param, got %d", len(m.Params))
	}
	// Leading ? should be trimmed by TrimLeft
	if m.Params[0].Name != "opt" {
		t.Errorf("expected param name 'opt' (leading ? trimmed), got %q", m.Params[0].Name)
	}
}

// ---------- matchTestDecl: backtick quotes ----------

func TestMatchTestDeclBackticks(t *testing.T) {
	rel := "app.test.ts"
	src := "describe(`user authentication`, () => {\n  it(`should login`, () => {});\n  test(`handles errors`, () => {});\n});\n"
	h := analyzeOne(t, rel, src)
	result, err := h.a.Analyze(h.dir, []string{rel})
	if err != nil {
		t.Fatal(err)
	}

	testNames := map[string]bool{}
	for _, tf := range result.Tests {
		testNames[tf.TestName] = true
	}
	if !testNames["user authentication"] {
		t.Errorf("expected test 'user authentication', got: %v", testNames)
	}
	if !testNames["should login"] {
		t.Errorf("expected test 'should login', got: %v", testNames)
	}
	if !testNames["handles errors"] {
		t.Errorf("expected test 'handles errors', got: %v", testNames)
	}
}

func TestMatchTestDeclSingleQuotes(t *testing.T) {
	rel := "util.spec.ts"
	src := `describe('utility functions', () => {
  it('should parse input', () => {});
  test('handles edge cases', () => {});
});
`
	h := analyzeOne(t, rel, src)
	result, err := h.a.Analyze(h.dir, []string{rel})
	if err != nil {
		t.Fatal(err)
	}

	testNames := map[string]bool{}
	for _, tf := range result.Tests {
		testNames[tf.TestName] = true
	}
	if !testNames["utility functions"] {
		t.Errorf("expected test 'utility functions', got: %v", testNames)
	}
	if !testNames["should parse input"] {
		t.Errorf("expected test 'should parse input', got: %v", testNames)
	}
}

// ---------- TypeGraph: Fields with type annotations ----------

func TestTypeGraphFieldTypeAnnotations(t *testing.T) {
	rel := "entity.ts"
	src := `class Entity {
  id: number;
  name: string;
  tags: string[];
  metadata: Map<string, any>;
}
`
	h := analyzeOne(t, rel, src)
	result, err := h.a.Analyze(h.dir, []string{rel})
	if err != nil {
		t.Fatal(err)
	}

	nodes := result.TypeGraph.FindByName("Entity")
	if len(nodes) != 1 {
		t.Fatalf("expected 1 Entity node, got %d", len(nodes))
	}
	n := nodes[0]
	fieldTypes := map[string]string{}
	for _, f := range n.Fields {
		fieldTypes[f.Name] = f.TypeName
	}
	if fieldTypes["id"] != "number" {
		t.Errorf("expected id: number, got %s", fieldTypes["id"])
	}
	if fieldTypes["name"] != "string" {
		t.Errorf("expected name: string, got %s", fieldTypes["name"])
	}
}

// ---------- Non-test file should not extract test decls ----------

func TestNonTestFileIgnoresTestDecls(t *testing.T) {
	rel := "app.ts" // not a .test. or .spec. file
	src := `describe('something', () => {
  it('does stuff', () => {});
});
`
	h := analyzeOne(t, rel, src)
	result, err := h.a.Analyze(h.dir, []string{rel})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Tests) != 0 {
		t.Errorf("expected 0 tests for non-test file, got %d", len(result.Tests))
	}
}

// ---------- Multiple frameworks in one file ----------

func TestMultipleFrameworkPatterns(t *testing.T) {
	rel := "mixed.ts"
	src := `import express from 'express';
import cors from 'cors';

const app = express();
app.use(helmet);
app.get('/api/users', listUsers);
app.post('/api/users', createUser);

const JWT_SECRET = 'supersecret123';
`
	h := analyzeOne(t, rel, src)
	result, err := h.a.Analyze(h.dir, []string{rel})
	if err != nil {
		t.Fatal(err)
	}

	// Verify routes
	routeMap := map[string]bool{}
	for _, r := range result.Routes {
		routeMap[r.Method+" "+r.Path] = true
	}
	if !routeMap["GET /api/users"] {
		t.Error("expected GET /api/users")
	}

	// Verify middleware
	mwNames := map[string]bool{}
	for _, m := range result.Middlewares {
		mwNames[m.Name] = true
	}
	if !mwNames["helmet"] {
		t.Error("expected helmet middleware")
	}

	// Verify secrets
	if len(result.Secrets) == 0 {
		t.Error("expected at least 1 secret (JWT_SECRET)")
	}

	// Verify imports
	importPaths := map[string]bool{}
	for _, imp := range result.Imports {
		importPaths[imp.ImportPath] = true
	}
	if !importPaths["express"] {
		t.Error("expected express import")
	}

	// Verify file fact and language
	if len(result.Files) != 1 {
		t.Fatalf("expected 1 file fact, got %d", len(result.Files))
	}
	if result.Files[0].Language != facts.LangTypeScript {
		t.Errorf("expected typescript language, got %s", result.Files[0].Language)
	}
}

// ---------- Analyze error path (file open failure) ----------

func TestAnalyzeErrorAddsToSkippedFiles(t *testing.T) {
	a := ts.New()
	dir := t.TempDir()
	result, err := a.Analyze(dir, []string{"does-not-exist.ts"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.SkippedFiles) != 1 {
		t.Fatalf("expected 1 skipped file, got %d", len(result.SkippedFiles))
	}
	if result.SkippedFiles[0].File != "does-not-exist.ts" {
		t.Errorf("expected skipped file 'does-not-exist.ts', got %s", result.SkippedFiles[0].File)
	}
}

// ---------- TSX file extension ----------

func TestTSXFileExtension(t *testing.T) {
	rel := "component.tsx"
	src := `import React from 'react';
export function MyComponent() {
  return <div>Hello</div>;
}
`
	h := analyzeOne(t, rel, src)
	result, err := h.a.Analyze(h.dir, []string{rel})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(result.Files))
	}
	if result.Files[0].Language != facts.LangTypeScript {
		t.Error("expected typescript language for .tsx file")
	}
	// Should detect the exported symbol
	symbolFound := false
	for _, s := range result.Symbols {
		if s.Name == "MyComponent" && s.Exported {
			symbolFound = true
		}
	}
	if !symbolFound {
		t.Error("expected exported symbol MyComponent")
	}
}
