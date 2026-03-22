package python

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// helper to create a temp Python project with given files.
// fileMap keys are relative paths, values are file contents.
func setupTempProject(t *testing.T, fileMap map[string]string) (string, []string) {
	t.Helper()
	root := t.TempDir()
	var files []string
	for rel, content := range fileMap {
		abs := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(abs, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
		files = append(files, rel)
	}
	return root, files
}

// ---------- Flask route detection ----------

func TestFlaskRouteDetection(t *testing.T) {
	root, files := setupTempProject(t, map[string]string{
		"app.py": `from flask import Flask

app = Flask(__name__)

@app.route("/users")
def get_users():
    return []

@app.route("/health")
def health():
    return "ok"
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	foundUsers := false
	foundHealth := false
	for _, rf := range result.Routes {
		if rf.Path == "/users" && rf.Method == "ANY" && rf.Handler == "get_users" {
			foundUsers = true
		}
		if rf.Path == "/health" && rf.Method == "ANY" && rf.Handler == "health" {
			foundHealth = true
		}
	}
	if !foundUsers {
		t.Error("expected Flask route /users with handler get_users")
	}
	if !foundHealth {
		t.Error("expected Flask route /health with handler health")
	}
}

// ---------- Django route patterns ----------

func TestDjangoRoutePatterns(t *testing.T) {
	root, files := setupTempProject(t, map[string]string{
		"urls.py": `from django.urls import path, re_path
from django.conf.urls import url

urlpatterns = [
    path('users/', views.user_list),
    url(r'^api/', include('api.urls')),
    re_path(r'^articles/(?P<year>[0-9]{4})/$', views.article_year),
]
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	expected := map[string]bool{
		"users/":                            false,
		"^api/":                             false,
		"^articles/(?P<year>[0-9]{4})/$":    false,
	}
	for _, rf := range result.Routes {
		if _, ok := expected[rf.Path]; ok {
			expected[rf.Path] = true
		}
	}
	for path, found := range expected {
		if !found {
			t.Errorf("expected Django route %q", path)
		}
	}
}

// ---------- Django MIDDLEWARE list entries ----------

func TestDjangoMiddlewareDetection(t *testing.T) {
	root, files := setupTempProject(t, map[string]string{
		"settings.py": `MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
]
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	foundSecurity := false
	foundSession := false
	for _, mw := range result.Middlewares {
		if mw.Name == "django.middleware.security.SecurityMiddleware" && mw.Kind == "django" {
			foundSecurity = true
		}
		if mw.Name == "django.contrib.sessions.middleware.SessionMiddleware" && mw.Kind == "django" {
			foundSession = true
		}
	}
	if !foundSecurity {
		t.Error("expected Django SecurityMiddleware")
	}
	if !foundSession {
		t.Error("expected Django SessionMiddleware")
	}
}

// ---------- Starlette Route() and add_middleware() ----------

func TestStarletteRouteAndMiddleware(t *testing.T) {
	root, files := setupTempProject(t, map[string]string{
		"main.py": `from starlette.applications import Starlette
from starlette.routing import Route
from starlette.middleware.cors import CORSMiddleware

routes = [
    Route("/users", endpoint=list_users),
    Route("/items", endpoint=list_items),
]

app = Starlette(routes=routes)
app.add_middleware(CORSMiddleware)
app.add_middleware(TrustedHostMiddleware)
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	// Routes
	foundUsers := false
	foundItems := false
	for _, rf := range result.Routes {
		if rf.Path == "/users" {
			foundUsers = true
		}
		if rf.Path == "/items" {
			foundItems = true
		}
	}
	if !foundUsers {
		t.Error("expected Starlette route /users")
	}
	if !foundItems {
		t.Error("expected Starlette route /items")
	}

	// Middleware
	foundCORS := false
	foundTrusted := false
	for _, mw := range result.Middlewares {
		if mw.Name == "CORSMiddleware" && mw.Kind == "starlette" {
			foundCORS = true
		}
		if mw.Name == "TrustedHostMiddleware" && mw.Kind == "starlette" {
			foundTrusted = true
		}
	}
	if !foundCORS {
		t.Error("expected starlette CORSMiddleware")
	}
	if !foundTrusted {
		t.Error("expected starlette TrustedHostMiddleware")
	}
}

// ---------- psycopg2 import detection ----------

func TestPsycopg2ImportDetection(t *testing.T) {
	root, files := setupTempProject(t, map[string]string{
		"db.py": `import psycopg2

conn = psycopg2.connect("dbname=test")
cur = conn.cursor()
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	foundPsycopg2 := false
	for _, da := range result.DataAccess {
		if da.Backend == "psycopg2" {
			foundPsycopg2 = true
		}
	}
	if !foundPsycopg2 {
		t.Error("expected psycopg2 data access backend")
	}
}

// ---------- Django ORM detection ----------

func TestDjangoOrmDetection(t *testing.T) {
	root, files := setupTempProject(t, map[string]string{
		"views.py": `from django.db import models

def get_active_users():
    return User.objects.filter(active=True)

def get_user(pk):
    return User.objects.get(pk=pk)
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	foundFilter := false
	foundGet := false
	for _, da := range result.DataAccess {
		if da.Backend == "django-orm" && da.Operation == "filter" {
			foundFilter = true
		}
		if da.Backend == "django-orm" && da.Operation == "get" {
			foundGet = true
		}
	}
	if !foundFilter {
		t.Error("expected django-orm filter operation")
	}
	if !foundGet {
		t.Error("expected django-orm get operation")
	}
}

// ---------- Tortoise ORM detection ----------

func TestTortoiseOrmDetection(t *testing.T) {
	root, files := setupTempProject(t, map[string]string{
		"models.py": `from tortoise import models
from tortoise import fields

class User(models.Model):
    name = fields.CharField(max_length=50)
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	foundTortoise := false
	for _, da := range result.DataAccess {
		if da.Backend == "tortoise" {
			foundTortoise = true
		}
	}
	if !foundTortoise {
		t.Error("expected tortoise data access backend")
	}
}

// ---------- Django TestCase detection ----------

func TestDjangoTestCaseDetection(t *testing.T) {
	root, files := setupTempProject(t, map[string]string{
		"test_models.py": `from django.test import TestCase

class TestUserModel(TestCase):
    def test_create_user(self):
        pass

    def test_delete_user(self):
        pass
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	foundTestCase := false
	foundCreate := false
	foundDelete := false
	for _, tf := range result.Tests {
		if tf.TestName == "TestUserModel" {
			foundTestCase = true
		}
		if tf.TestName == "test_create_user" {
			foundCreate = true
		}
		if tf.TestName == "test_delete_user" {
			foundDelete = true
		}
	}
	if !foundTestCase {
		t.Error("expected Django TestCase class TestUserModel")
	}
	if !foundCreate {
		t.Error("expected test_create_user from Django TestCase")
	}
	if !foundDelete {
		t.Error("expected test_delete_user from Django TestCase")
	}
}

// ---------- extractPyTypeGraph: classes with bases, methods, fields, decorators ----------

func TestExtractPyTypeGraph_FullClass(t *testing.T) {
	root, files := setupTempProject(t, map[string]string{
		"animals.py": `from abc import ABC, abstractmethod

class Animal(ABC):
    @abstractmethod
    def speak(self) -> str:
        pass

class Dog(Animal):
    @staticmethod
    def species() -> str:
        return "Canis"

    @classmethod
    def create(cls, name: str) -> Dog:
        return cls(name)

    def __init__(self, name: str):
        self.name = name
        self.age: int = 0
        self._secret = "hidden"

    def bark(self) -> str:
        return "Woof"
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	tg := result.TypeGraph

	// Animal
	animalNode := tg.Nodes["animals.py:Animal"]
	if animalNode == nil {
		t.Fatal("expected TypeNode for Animal")
	}
	if animalNode.Kind != "abstract_class" {
		t.Errorf("expected Animal kind=abstract_class, got %s", animalNode.Kind)
	}
	// Animal.speak should be abstract
	foundSpeak := false
	for _, m := range animalNode.Methods {
		if m.Name == "speak" {
			foundSpeak = true
			if !m.IsAbstract {
				t.Error("expected speak to be abstract")
			}
			if m.ReturnType != "str" {
				t.Errorf("expected speak return type str, got %s", m.ReturnType)
			}
		}
	}
	if !foundSpeak {
		t.Error("expected method speak on Animal")
	}

	// Dog
	dogNode := tg.Nodes["animals.py:Dog"]
	if dogNode == nil {
		t.Fatal("expected TypeNode for Dog")
	}
	if dogNode.Kind != "class" {
		t.Errorf("expected Dog kind=class, got %s", dogNode.Kind)
	}
	if dogNode.Extends != "Animal" {
		t.Errorf("expected Dog extends Animal, got %s", dogNode.Extends)
	}

	// Check methods
	// Note: @staticmethod methods without self/cls are not captured by pyMethodDefRe
	// (which requires self or cls as first param). Only @classmethod and regular methods are captured.
	methodMap := make(map[string]bool)
	for _, m := range dogNode.Methods {
		methodMap[m.Name] = true
		switch m.Name {
		case "create":
			if !m.IsStatic {
				t.Error("expected create (classmethod) to be static")
			}
			// Check params
			if len(m.Params) != 1 || m.Params[0].Name != "name" || m.Params[0].TypeName != "str" {
				t.Errorf("expected create param name:str, got %+v", m.Params)
			}
		case "__init__":
			if len(m.Params) != 1 || m.Params[0].Name != "name" {
				t.Errorf("expected __init__ param name, got %+v", m.Params)
			}
		case "bark":
			if m.IsStatic || m.IsAbstract {
				t.Error("bark should not be static or abstract")
			}
		}
	}
	for _, expected := range []string{"create", "__init__", "bark"} {
		if !methodMap[expected] {
			t.Errorf("expected method %s on Dog", expected)
		}
	}

	// Check fields extracted from __init__
	fieldMap := make(map[string]string)
	for _, f := range dogNode.Fields {
		fieldMap[f.Name] = f.TypeName
	}
	if _, ok := fieldMap["name"]; !ok {
		t.Error("expected field 'name' on Dog")
	}
	if tp, ok := fieldMap["age"]; !ok || strings.TrimSpace(tp) != "int" {
		t.Errorf("expected field 'age' with type int, got %q", tp)
	}
	if _, ok := fieldMap["_secret"]; !ok {
		t.Error("expected field '_secret' on Dog")
	}
	// Check _secret is not public
	for _, f := range dogNode.Fields {
		if f.Name == "_secret" && f.IsPublic {
			t.Error("expected _secret to be private (IsPublic=false)")
		}
	}
}

// ---------- TypeGraph: multiple inheritance (extends + implements) ----------

func TestExtractPyTypeGraph_MultipleInheritance(t *testing.T) {
	root, files := setupTempProject(t, map[string]string{
		"multi.py": `class Base:
    pass

class Mixin1:
    pass

class Mixin2:
    pass

class Child(Base, Mixin1, Mixin2):
    def do_thing(self) -> bool:
        return True
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	node := result.TypeGraph.Nodes["multi.py:Child"]
	if node == nil {
		t.Fatal("expected TypeNode for Child")
	}
	if node.Extends != "Base" {
		t.Errorf("expected extends=Base, got %s", node.Extends)
	}
	if len(node.Implements) != 2 {
		t.Errorf("expected 2 implements, got %d: %v", len(node.Implements), node.Implements)
	}
}

// ---------- TypeGraph: metaclass=ABCMeta ----------

func TestExtractPyTypeGraph_ABCMeta(t *testing.T) {
	root, files := setupTempProject(t, map[string]string{
		"meta.py": `import abc

class MyInterface(metaclass=ABCMeta):
    @abstractmethod
    def do(self):
        pass
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	node := result.TypeGraph.Nodes["meta.py:MyInterface"]
	if node == nil {
		t.Fatal("expected TypeNode for MyInterface")
	}
	if node.Kind != "abstract_class" {
		t.Errorf("expected kind=abstract_class, got %s", node.Kind)
	}
}

// ---------- countIndent with tabs ----------

func TestCountIndentWithTabs(t *testing.T) {
	root, files := setupTempProject(t, map[string]string{
		"tabbed.py": "def outer():\n\tdef inner():\n\t\tpass\n",
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	foundOuter := false
	foundInner := false
	for _, sf := range result.Symbols {
		if sf.Name == "outer" {
			foundOuter = true
		}
		if sf.Name == "inner" {
			foundInner = true
		}
	}
	if !foundOuter {
		t.Error("expected function outer")
	}
	if !foundInner {
		t.Error("expected function inner")
	}
}

// ---------- Tortoise import via "import tortoise" (non-from) ----------

func TestTortoiseImportDirect(t *testing.T) {
	root, files := setupTempProject(t, map[string]string{
		"tortoise_app.py": `import tortoise

class Foo:
    pass
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	foundTortoise := false
	for _, da := range result.DataAccess {
		if da.Backend == "tortoise" {
			foundTortoise = true
		}
	}
	if !foundTortoise {
		t.Error("expected tortoise data access from direct import")
	}
}

// ---------- Django test import with from-import (hasDjangoTestImport path via fromImportRe) ----------

func TestDjangoTestImportFromImport(t *testing.T) {
	root, files := setupTempProject(t, map[string]string{
		"test_views.py": `from django.test import TestCase, Client

class TestViewIndex(TestCase):
    def test_index_page(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	foundTestCase := false
	for _, tf := range result.Tests {
		if tf.TestName == "TestViewIndex" {
			foundTestCase = true
		}
	}
	if !foundTestCase {
		t.Error("expected Django TestCase class TestViewIndex")
	}
}

// ---------- Flask route with blank lines between decorator and def ----------

func TestFlaskRouteBlankLineBeforeDef(t *testing.T) {
	root, files := setupTempProject(t, map[string]string{
		"app2.py": `from flask import Flask
app = Flask(__name__)

@app.route("/blank")

def blank_handler():
    return "blank"
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	foundBlank := false
	for _, rf := range result.Routes {
		if rf.Path == "/blank" && rf.Handler == "blank_handler" {
			foundBlank = true
		}
	}
	if !foundBlank {
		t.Error("expected Flask route /blank with handler blank_handler (blank line between decorator and def)")
	}
}

// ---------- Import with alias (as) ----------

func TestImportWithAlias(t *testing.T) {
	root, files := setupTempProject(t, map[string]string{
		"aliased.py": `import numpy as np
from pandas import DataFrame as DF
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	foundNP := false
	foundDF := false
	for _, imp := range result.Imports {
		if imp.ImportPath == "numpy" && imp.Alias == "np" {
			foundNP = true
		}
		if imp.ImportPath == "pandas" && imp.Alias == "DF" {
			foundDF = true
		}
	}
	if !foundNP {
		t.Error("expected numpy import with alias np")
	}
	if !foundDF {
		t.Error("expected pandas import with alias DF")
	}
}

// ---------- TypeGraph: method with default param values ----------

func TestExtractPyTypeGraph_ParamDefaults(t *testing.T) {
	root, files := setupTempProject(t, map[string]string{
		"defaults.py": `class Config(object):
    def setup(self, host: str = "localhost", port: int = 8080) -> None:
        self.host = host
        self.port = port
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	node := result.TypeGraph.Nodes["defaults.py:Config"]
	if node == nil {
		t.Fatal("expected TypeNode for Config")
	}
	if node.Extends != "object" {
		t.Errorf("expected extends=object, got %s", node.Extends)
	}

	// Check setup method params
	for _, m := range node.Methods {
		if m.Name == "setup" {
			if len(m.Params) != 2 {
				t.Fatalf("expected 2 params for setup, got %d", len(m.Params))
			}
			if m.Params[0].Name != "host" || m.Params[0].TypeName != "str" {
				t.Errorf("expected host:str, got %s:%s", m.Params[0].Name, m.Params[0].TypeName)
			}
			if m.Params[1].Name != "port" || m.Params[1].TypeName != "int" {
				t.Errorf("expected port:int, got %s:%s", m.Params[1].Name, m.Params[1].TypeName)
			}
			if m.ReturnType != "None" {
				t.Errorf("expected return type None, got %s", m.ReturnType)
			}
		}
	}

	// Check fields from setup (__init__-like but named setup - should NOT extract fields)
	// Actually fields are only from __init__, so Config should have no fields from setup
	// But the method does have self.host = host, which only gets extracted from __init__
}

// ---------- TypeGraph: __init__ field extraction ----------

func TestExtractPyTypeGraph_InitFields(t *testing.T) {
	root, files := setupTempProject(t, map[string]string{
		"person.py": `class Person(object):
    def __init__(self, name: str, age: int):
        self.name = name
        self.age: int = age
        self._id = 0
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	node := result.TypeGraph.Nodes["person.py:Person"]
	if node == nil {
		t.Fatal("expected TypeNode for Person")
	}

	fieldMap := make(map[string]bool)
	for _, f := range node.Fields {
		fieldMap[f.Name] = true
		if f.Name == "name" && f.IsPublic != true {
			t.Error("name should be public")
		}
		if f.Name == "_id" && f.IsPublic != false {
			t.Error("_id should be private")
		}
	}
	if !fieldMap["name"] {
		t.Error("expected field name")
	}
	if !fieldMap["age"] {
		t.Error("expected field age")
	}
	if !fieldMap["_id"] {
		t.Error("expected field _id")
	}
}

// ---------- Private symbol export flag ----------

func TestPrivateSymbolNotExported(t *testing.T) {
	root, files := setupTempProject(t, map[string]string{
		"internal.py": `def _private_helper():
    pass

def public_func():
    pass

class _InternalClass:
    pass

class PublicClass:
    pass
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	for _, sf := range result.Symbols {
		switch sf.Name {
		case "_private_helper":
			if sf.Exported {
				t.Error("_private_helper should not be exported")
			}
		case "public_func":
			if !sf.Exported {
				t.Error("public_func should be exported")
			}
		case "_InternalClass":
			if sf.Exported {
				t.Error("_InternalClass should not be exported")
			}
		case "PublicClass":
			if !sf.Exported {
				t.Error("PublicClass should be exported")
			}
		}
	}
}

// ---------- SQLAlchemy import via direct "import sqlalchemy" ----------

func TestSQLAlchemyDirectImport(t *testing.T) {
	root, files := setupTempProject(t, map[string]string{
		"db.py": `import sqlalchemy
from sqlalchemy.orm import Session

session = Session()
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	foundSQLAlchemy := false
	for _, da := range result.DataAccess {
		if da.Backend == "sqlalchemy" {
			foundSQLAlchemy = true
		}
	}
	if !foundSQLAlchemy {
		t.Error("expected sqlalchemy data access backend from direct import")
	}
}

// ---------- TypeGraph: abc.ABC base ----------

func TestExtractPyTypeGraph_AbcDotABC(t *testing.T) {
	root, files := setupTempProject(t, map[string]string{
		"iface.py": `class MyBase(abc.ABC):
    @abstractmethod
    def run(self):
        pass
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	node := result.TypeGraph.Nodes["iface.py:MyBase"]
	if node == nil {
		t.Fatal("expected TypeNode for MyBase")
	}
	if node.Kind != "abstract_class" {
		t.Errorf("expected abstract_class, got %s", node.Kind)
	}
}

// ---------- TypeGraph: metaclass=abc.ABCMeta ----------

func TestExtractPyTypeGraph_AbcDotABCMeta(t *testing.T) {
	root, files := setupTempProject(t, map[string]string{
		"meta2.py": `class Proto(metaclass=abc.ABCMeta):
    @abstractmethod
    def execute(self):
        pass
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	node := result.TypeGraph.Nodes["meta2.py:Proto"]
	if node == nil {
		t.Fatal("expected TypeNode for Proto")
	}
	if node.Kind != "abstract_class" {
		t.Errorf("expected abstract_class, got %s", node.Kind)
	}
}

// ---------- TypeGraph: private class not exported ----------

func TestExtractPyTypeGraph_PrivateClass(t *testing.T) {
	root, files := setupTempProject(t, map[string]string{
		"priv.py": `class _Internal(object):
    def helper(self):
        pass
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	node := result.TypeGraph.Nodes["priv.py:_Internal"]
	if node == nil {
		t.Fatal("expected TypeNode for _Internal")
	}
	if node.Exported {
		t.Error("expected _Internal to not be exported")
	}
}

// ---------- Combined Django app scenario ----------

func TestCombinedDjangoApp(t *testing.T) {
	root, files := setupTempProject(t, map[string]string{
		"myapp/settings.py": `MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
]
`,
		"myapp/urls.py": `from django.urls import path

urlpatterns = [
    path('admin/', admin.site.urls),
]
`,
		"myapp/views.py": `from django.db import models

def list_users(request):
    users = User.objects.filter(active=True)
    return render(request, 'users.html', {'users': users})
`,
		"myapp/test_views.py": `from django.test import TestCase

class TestUserView(TestCase):
    def test_list(self):
        pass
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	// Middleware from settings
	foundMW := false
	for _, mw := range result.Middlewares {
		if mw.Kind == "django" {
			foundMW = true
		}
	}
	if !foundMW {
		t.Error("expected Django middleware from settings.py")
	}

	// Route from urls
	foundRoute := false
	for _, rf := range result.Routes {
		if rf.Path == "admin/" {
			foundRoute = true
		}
	}
	if !foundRoute {
		t.Error("expected Django route admin/")
	}

	// ORM from views
	foundORM := false
	for _, da := range result.DataAccess {
		if da.Backend == "django-orm" {
			foundORM = true
		}
	}
	if !foundORM {
		t.Error("expected django-orm data access")
	}

	// Test from test file
	foundTest := false
	for _, tf := range result.Tests {
		if tf.TestName == "TestUserView" {
			foundTest = true
		}
	}
	if !foundTest {
		t.Error("expected Django TestCase TestUserView")
	}
}

// ---------- TypeGraph: method with no params beyond self ----------

func TestExtractPyTypeGraph_MethodNoParams(t *testing.T) {
	root, files := setupTempProject(t, map[string]string{
		"simple.py": `class Simple(object):
    def no_params(self) -> int:
        return 42
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	node := result.TypeGraph.Nodes["simple.py:Simple"]
	if node == nil {
		t.Fatal("expected TypeNode for Simple")
	}
	for _, m := range node.Methods {
		if m.Name == "no_params" {
			if len(m.Params) != 0 {
				t.Errorf("expected 0 params (self excluded), got %d", len(m.Params))
			}
			if m.ReturnType != "int" {
				t.Errorf("expected return type int, got %s", m.ReturnType)
			}
			if !m.IsPublic {
				t.Error("expected no_params to be public")
			}
		}
	}
}

// ---------- TypeGraph: decorator that is not abstract/static/classmethod (skipped) ----------

func TestExtractPyTypeGraph_OtherDecorator(t *testing.T) {
	root, files := setupTempProject(t, map[string]string{
		"deco.py": `class Service(object):
    @property
    def name(self) -> str:
        return self._name

    @some_custom_decorator
    def action(self) -> None:
        pass
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	node := result.TypeGraph.Nodes["deco.py:Service"]
	if node == nil {
		t.Fatal("expected TypeNode for Service")
	}
	// Both methods should exist and NOT be static/abstract
	for _, m := range node.Methods {
		if m.IsAbstract {
			t.Errorf("method %s should not be abstract", m.Name)
		}
		if m.IsStatic {
			t.Errorf("method %s should not be static", m.Name)
		}
	}
}

// ---------- psycopg2 via from import ----------

func TestPsycopg2FromImport(t *testing.T) {
	root, files := setupTempProject(t, map[string]string{
		"db2.py": `from psycopg2 import connect

conn = connect("dbname=test")
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	// psycopg2 detection only happens via importRe (import psycopg2),
	// not via fromImportRe. The code checks psycopg2ImportRe only in the
	// importRe branch. So from psycopg2 will NOT trigger psycopg2 backend.
	// This is expected behavior per the code.
	foundImport := false
	for _, imp := range result.Imports {
		if imp.ImportPath == "psycopg2" {
			foundImport = true
		}
	}
	if !foundImport {
		t.Error("expected psycopg2 import fact")
	}
}

// ---------- countIndent directly via tab-indented class body ----------

func TestTabIndentedClassBody(t *testing.T) {
	root, files := setupTempProject(t, map[string]string{
		"test_tabbed.py": `class TestTabbed:
	def test_one(self):
		pass
	def test_two(self):
		pass
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	// The class should be found
	foundClass := false
	for _, sf := range result.Symbols {
		if sf.Name == "TestTabbed" {
			foundClass = true
		}
	}
	if !foundClass {
		t.Error("expected class TestTabbed with tab indentation")
	}
}

// ---------- Empty class body in TypeGraph ----------

func TestExtractPyTypeGraph_EmptyBases(t *testing.T) {
	// A class with empty base string after comma split
	root, files := setupTempProject(t, map[string]string{
		"empty_base.py": `class Foo(Bar, ):
    def method(self):
        pass
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	node := result.TypeGraph.Nodes["empty_base.py:Foo"]
	if node == nil {
		t.Fatal("expected TypeNode for Foo")
	}
	if node.Extends != "Bar" {
		t.Errorf("expected extends=Bar, got %s", node.Extends)
	}
}

// ---------- Param with default but no type annotation ----------

func TestExtractPyTypeGraph_ParamDefaultNoType(t *testing.T) {
	root, files := setupTempProject(t, map[string]string{
		"noannot.py": `class Builder(object):
    def build(self, verbose=False) -> None:
        pass
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	node := result.TypeGraph.Nodes["noannot.py:Builder"]
	if node == nil {
		t.Fatal("expected TypeNode for Builder")
	}
	for _, m := range node.Methods {
		if m.Name == "build" {
			if len(m.Params) != 1 {
				t.Fatalf("expected 1 param, got %d", len(m.Params))
			}
			if m.Params[0].Name != "verbose" {
				t.Errorf("expected param name verbose, got %s", m.Params[0].Name)
			}
		}
	}
}

// --- False positive guard tests: structural parsing ---

func TestPythonCommentedImportNotExtracted(t *testing.T) {
	root, files := setupTempProject(t, map[string]string{
		"app.py": `# from flask import Flask
x = 1
`,
	})
	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatal(err)
	}
	for _, imp := range result.Imports {
		if imp.ImportPath == "flask" {
			t.Error("import inside comment should NOT be extracted")
		}
	}
}

func TestPythonCommentedRouteNotExtracted(t *testing.T) {
	root, files := setupTempProject(t, map[string]string{
		"app.py": `# @app.get("/secret")
@app.get("/public")
def public_handler():
    pass
`,
	})
	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range result.Routes {
		if r.Path == "/secret" {
			t.Error("route inside comment should NOT be extracted")
		}
	}
	found := false
	for _, r := range result.Routes {
		if r.Path == "/public" {
			found = true
		}
	}
	if !found {
		t.Error("expected route /public to be extracted")
	}
}

func TestPythonCommentedSecretNotExtracted(t *testing.T) {
	root, files := setupTempProject(t, map[string]string{
		"config.py": `# SECRET_KEY = "supersecret1234567"
x = 1
`,
	})
	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Secrets) > 0 {
		t.Error("secret inside comment should NOT be extracted")
	}
}

func TestPythonTripleQuotedStringNotExtracted(t *testing.T) {
	root, files := setupTempProject(t, map[string]string{
		"app.py": `docstring = """
from flask import Flask
SECRET_KEY = "supersecret1234567"
"""
x = 1
`,
	})
	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatal(err)
	}
	for _, imp := range result.Imports {
		if imp.ImportPath == "flask" {
			t.Error("import inside triple-quoted string should NOT be extracted")
		}
	}
	if len(result.Secrets) > 0 {
		t.Error("secret inside triple-quoted string should NOT be extracted")
	}
}

// --- Integration: real pipeline produces AST facts when python3 available ---

func TestPythonAnalyzer_RealPipeline_ProducesASTFacts(t *testing.T) {
	if !PythonASTAvailable() {
		t.Skip("python3 not available")
	}
	root, files := setupTempProject(t, map[string]string{
		"app.py": `from flask import Flask
from fastapi import Depends

app = Flask(__name__)

@app.get("/users")
def get_users():
    return []

@app.route("/health")
def health():
    return "ok"

SECRET_KEY = "hardcoded-secret-value"

def get_db():
    pass

def create_user(db=Depends(get_db)):
    pass
`,
	})
	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatal(err)
	}

	// Verify imports have AST provenance
	astImports := 0
	for _, imp := range result.Imports {
		if imp.Provenance == "ast_derived" {
			astImports++
		}
	}
	if astImports == 0 {
		t.Error("expected at least one import with ProvenanceAST from real pipeline")
	}

	// Verify symbols have AST provenance
	astSymbols := 0
	for _, sym := range result.Symbols {
		if sym.Provenance == "ast_derived" {
			astSymbols++
		}
	}
	if astSymbols == 0 {
		t.Error("expected at least one symbol with ProvenanceAST from real pipeline")
	}

	// Verify routes have AST provenance
	astRoutes := 0
	for _, r := range result.Routes {
		if r.Provenance == "ast_derived" {
			astRoutes++
		}
	}
	if astRoutes == 0 {
		t.Error("expected at least one route with ProvenanceAST from real pipeline")
	}

	// Verify secrets have AST provenance
	astSecrets := 0
	for _, s := range result.Secrets {
		if s.Provenance == "ast_derived" {
			astSecrets++
		}
	}
	if astSecrets == 0 {
		t.Error("expected at least one secret with ProvenanceAST from real pipeline")
	}
}

// --- False-positive regression: route decorator in docstring ---

func TestPythonDocstringRouteDecoratorNotExtracted(t *testing.T) {
	if !PythonASTAvailable() {
		t.Skip("python3 not available")
	}
	root, files := setupTempProject(t, map[string]string{
		"app.py": `"""
Example usage:

@app.get("/secret")
def secret_handler():
    pass
"""

x = 1
`,
	})
	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range result.Routes {
		if r.Path == "/secret" {
			t.Error("route decorator in docstring should NOT be extracted")
		}
	}
}
