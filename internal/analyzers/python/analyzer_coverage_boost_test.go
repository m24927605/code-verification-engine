package python

// analyzer_coverage_boost_test.go — tests to push coverage from 72.8% to 95%+.
//
// Main targets:
//   - Analyze (25.7%): Force regex path via findPython3Func override; exercise all branches
//   - isTripleQuoteLine (42.9%): Various triple-quote styles
//   - findPython3 (62.5%): Common-path miss + LookPath miss
//   - ensureScript (81.8%): WriteString failure
//   - ParsePythonAST (86.7%): CreateTemp failure for source file
//   - projectGlobalMiddlewares (88.2%): Duplicate and flask_before_request

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
)

// ── isTripleQuoteLine ─────────────────────────────────────────────────────────

func TestIsTripleQuoteLine_EnterDoubleQuote(t *testing.T) {
	inTQ := false
	// Line that starts a multi-line """
	got := isTripleQuoteLine(`    """`, &inTQ)
	if !got {
		t.Error("expected true for opening triple double-quote")
	}
	if !inTQ {
		t.Error("expected inTripleQuote to be true after opening")
	}
}

func TestIsTripleQuoteLine_EnterSingleQuote(t *testing.T) {
	inTQ := false
	got := isTripleQuoteLine(`    '''`, &inTQ)
	if !got {
		t.Error("expected true for opening triple single-quote")
	}
	if !inTQ {
		t.Error("expected inTripleQuote to be true after opening")
	}
}

func TestIsTripleQuoteLine_ExitDoubleQuote(t *testing.T) {
	inTQ := true
	got := isTripleQuoteLine(`    some text """`, &inTQ)
	if !got {
		t.Error("expected true for line inside triple-quote (even if closing)")
	}
	if inTQ {
		t.Error("expected inTripleQuote to be false after closing")
	}
}

func TestIsTripleQuoteLine_ExitSingleQuote(t *testing.T) {
	inTQ := true
	got := isTripleQuoteLine(`    some text '''`, &inTQ)
	if !got {
		t.Error("expected true for line inside triple-quote (even if closing)")
	}
	if inTQ {
		t.Error("expected inTripleQuote to be false after closing")
	}
}

func TestIsTripleQuoteLine_InsideTripleQuote_NoClose(t *testing.T) {
	inTQ := true
	got := isTripleQuoteLine(`    just a regular line`, &inTQ)
	if !got {
		t.Error("expected true for line inside triple-quote block")
	}
	if !inTQ {
		t.Error("expected inTripleQuote to remain true")
	}
}

func TestIsTripleQuoteLine_SingleLineTripleQuote(t *testing.T) {
	inTQ := false
	// """docstring""" on one line — should return false (it's a complete single-line triple-quote)
	got := isTripleQuoteLine(`    """This is a docstring"""`, &inTQ)
	if got {
		t.Error("expected false for single-line triple-quote (both open and close on same line)")
	}
	if inTQ {
		t.Error("expected inTripleQuote to remain false for single-line triple-quote")
	}
}

func TestIsTripleQuoteLine_SingleLineSingleQuote(t *testing.T) {
	inTQ := false
	got := isTripleQuoteLine(`    '''single line docstring'''`, &inTQ)
	if got {
		t.Error("expected false for single-line triple single-quote")
	}
	if inTQ {
		t.Error("expected inTripleQuote to remain false")
	}
}

func TestIsTripleQuoteLine_NormalLine(t *testing.T) {
	inTQ := false
	got := isTripleQuoteLine(`x = 1`, &inTQ)
	if got {
		t.Error("expected false for normal line")
	}
	if inTQ {
		t.Error("expected inTripleQuote to remain false")
	}
}

func TestIsTripleQuoteLine_PrefixedTripleQuote(t *testing.T) {
	// Lines like r""", f""" — the trimmed line starts with r/f then """
	inTQ := false
	got := isTripleQuoteLine(`    r"""raw string starts here`, &inTQ)
	if !got {
		t.Error("expected true for r\"\"\" opening multi-line")
	}
	if !inTQ {
		t.Error("expected inTripleQuote to be true after r\"\"\" opening")
	}
}

func TestIsTripleQuoteLine_EmptyLine(t *testing.T) {
	inTQ := false
	got := isTripleQuoteLine("", &inTQ)
	if got {
		t.Error("expected false for empty line")
	}
}

// ── Analyze regex path (force AST off) ────────────────────────────────────────

// forceRegexPath disables AST mode by overriding findPython3Func.
// Returns a cleanup function to restore the original.
func forceRegexPath() func() {
	findPython3Func = func() string { return "" }
	return func() { findPython3Func = nil }
}

func TestAnalyzeRegex_FlaskApp(t *testing.T) {
	cleanup := forceRegexPath()
	defer cleanup()

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

	if len(result.Files) == 0 {
		t.Fatal("expected at least one FileFact")
	}
	if len(result.Imports) == 0 {
		t.Fatal("expected imports")
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
		t.Error("expected Flask route /users")
	}
	if !foundHealth {
		t.Error("expected Flask route /health")
	}
}

func TestAnalyzeRegex_FastAPIWithDependsAndSecrets(t *testing.T) {
	cleanup := forceRegexPath()
	defer cleanup()

	root, files := setupTempProject(t, map[string]string{
		"main.py": `from fastapi import FastAPI, Depends

app = FastAPI()

def auth_required():
    pass

@app.get("/items")
def list_items(user=Depends(auth_required)):
    return []

@app.post("/items")
def create_item():
    pass

@app.put("/items/{id}")
def update_item():
    pass

@app.delete("/items/{id}")
def delete_item():
    pass

@app.patch("/items/{id}")
def patch_item():
    pass

SECRET_KEY = "my-secret-123"
API_KEY = "sk-abc123"
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	// Routes
	methods := make(map[string]bool)
	for _, rf := range result.Routes {
		methods[rf.Method] = true
	}
	for _, want := range []string{"GET", "POST", "PUT", "DELETE", "PATCH"} {
		if !methods[want] {
			t.Errorf("expected %s route", want)
		}
	}

	// Middleware
	foundAuth := false
	for _, mw := range result.Middlewares {
		if mw.Name == "auth_required" && mw.Kind == "fastapi_depends" {
			foundAuth = true
		}
	}
	if !foundAuth {
		t.Error("expected auth_required middleware via Depends")
	}

	// Secrets
	if len(result.Secrets) < 2 {
		t.Errorf("expected at least 2 secrets, got %d", len(result.Secrets))
	}
}

func TestAnalyzeRegex_DjangoSettings(t *testing.T) {
	cleanup := forceRegexPath()
	defer cleanup()

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

func TestAnalyzeRegex_DjangoRoutes(t *testing.T) {
	cleanup := forceRegexPath()
	defer cleanup()

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
		"users/":                         false,
		"^api/":                          false,
		"^articles/(?P<year>[0-9]{4})/$": false,
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

func TestAnalyzeRegex_StarletteRouteAndMiddleware(t *testing.T) {
	cleanup := forceRegexPath()
	defer cleanup()

	root, files := setupTempProject(t, map[string]string{
		"main.py": `from starlette.routing import Route

routes = [
    Route("/users", endpoint=list_users),
    Route("/items", endpoint=list_items),
]

app.add_middleware(CORSMiddleware)
app.add_middleware(TrustedHostMiddleware)
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

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

func TestAnalyzeRegex_SQLAlchemyDataAccess(t *testing.T) {
	cleanup := forceRegexPath()
	defer cleanup()

	root, files := setupTempProject(t, map[string]string{
		"db.py": `from sqlalchemy.orm import Session

def get_user(db: Session, user_id: int):
    return db.query(Session).filter_by(id=user_id).first()
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, da := range result.DataAccess {
		if da.Backend == "sqlalchemy" {
			found = true
		}
	}
	if !found {
		t.Error("expected sqlalchemy DataAccessFact")
	}
}

func TestAnalyzeRegex_Psycopg2DataAccess(t *testing.T) {
	cleanup := forceRegexPath()
	defer cleanup()

	root, files := setupTempProject(t, map[string]string{
		"db.py": `import psycopg2

conn = psycopg2.connect("dbname=test")
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, da := range result.DataAccess {
		if da.Backend == "psycopg2" {
			found = true
		}
	}
	if !found {
		t.Error("expected psycopg2 DataAccessFact")
	}
}

func TestAnalyzeRegex_DjangoORM(t *testing.T) {
	cleanup := forceRegexPath()
	defer cleanup()

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

	ops := make(map[string]bool)
	for _, da := range result.DataAccess {
		if da.Backend == "django-orm" {
			ops[da.Operation] = true
		}
	}
	if !ops["filter"] {
		t.Error("expected django-orm filter")
	}
	if !ops["get"] {
		t.Error("expected django-orm get")
	}
}

func TestAnalyzeRegex_TortoiseORM(t *testing.T) {
	cleanup := forceRegexPath()
	defer cleanup()

	root, files := setupTempProject(t, map[string]string{
		"models.py": `from tortoise import fields

class User(Model):
    name = fields.CharField(max_length=50)
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, da := range result.DataAccess {
		if da.Backend == "tortoise" {
			found = true
		}
	}
	if !found {
		t.Error("expected tortoise DataAccessFact")
	}
}

func TestAnalyzeRegex_DjangoTestCase(t *testing.T) {
	cleanup := forceRegexPath()
	defer cleanup()

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

	testNames := make(map[string]bool)
	for _, tf := range result.Tests {
		testNames[tf.TestName] = true
	}
	if !testNames["TestUserModel"] {
		t.Error("expected Django TestCase TestUserModel")
	}
	if !testNames["test_create_user"] {
		t.Error("expected test_create_user")
	}
	if !testNames["test_delete_user"] {
		t.Error("expected test_delete_user")
	}
}

func TestAnalyzeRegex_TestMethodsInTestClass(t *testing.T) {
	cleanup := forceRegexPath()
	defer cleanup()

	root, files := setupTempProject(t, map[string]string{
		"test_service.py": `class TestUserService:
    def test_get_user(self):
        pass

    def test_create_user(self):
        pass

    def helper_method(self):
        pass
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	testNames := make(map[string]bool)
	for _, tf := range result.Tests {
		testNames[tf.TestName] = true
	}
	if !testNames["test_get_user"] {
		t.Error("expected test_get_user from TestUserService class")
	}
	if !testNames["test_create_user"] {
		t.Error("expected test_create_user from TestUserService class")
	}
	if testNames["helper_method"] {
		t.Error("helper_method should not be a test")
	}
}

func TestAnalyzeRegex_SecretSkipsEnvVar(t *testing.T) {
	cleanup := forceRegexPath()
	defer cleanup()

	root, files := setupTempProject(t, map[string]string{
		"config.py": `SECRET_KEY = os.environ.get("SECRET_KEY", "fallback")
API_KEY = os.getenv("API_KEY")
TOKEN = "hardcoded-token"
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	for _, s := range result.Secrets {
		if s.Value == "SECRET_KEY" {
			t.Error("os.environ.get should not be flagged")
		}
		if s.Value == "API_KEY" {
			t.Error("os.getenv should not be flagged")
		}
	}
	foundToken := false
	for _, s := range result.Secrets {
		if s.Value == "TOKEN" {
			foundToken = true
		}
	}
	if !foundToken {
		t.Error("expected TOKEN to be flagged as hardcoded secret")
	}
}

func TestAnalyzeRegex_SecretSkipsDebug(t *testing.T) {
	cleanup := forceRegexPath()
	defer cleanup()

	root, files := setupTempProject(t, map[string]string{
		"config.py": `DEBUG = "true"
SECRET_KEY = "real-secret"
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	for _, s := range result.Secrets {
		if s.Value == "DEBUG" {
			t.Error("DEBUG should not be flagged")
		}
	}
	foundSecret := false
	for _, s := range result.Secrets {
		if s.Value == "SECRET_KEY" {
			foundSecret = true
		}
	}
	if !foundSecret {
		t.Error("expected SECRET_KEY")
	}
}

func TestAnalyzeRegex_ImportWithAlias(t *testing.T) {
	cleanup := forceRegexPath()
	defer cleanup()

	root, files := setupTempProject(t, map[string]string{
		"app.py": `import numpy as np
from datetime import datetime as dt
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	foundNP := false
	foundDT := false
	for _, imp := range result.Imports {
		if imp.ImportPath == "numpy" && imp.Alias == "np" {
			foundNP = true
		}
		if imp.ImportPath == "datetime" && imp.Alias == "dt" {
			foundDT = true
		}
	}
	if !foundNP {
		t.Error("expected numpy import with alias np")
	}
	if !foundDT {
		t.Error("expected datetime import with alias dt")
	}
}

func TestAnalyzeRegex_SkipsComments(t *testing.T) {
	cleanup := forceRegexPath()
	defer cleanup()

	root, files := setupTempProject(t, map[string]string{
		"app.py": `# from flask import Flask
# SECRET_KEY = "should-not-be-detected"
x = 1
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(result.Imports) != 0 {
		t.Errorf("expected no imports from commented lines, got %d", len(result.Imports))
	}
	if len(result.Secrets) != 0 {
		t.Errorf("expected no secrets from commented lines, got %d", len(result.Secrets))
	}
}

func TestAnalyzeRegex_SkipsTripleQuotedContent(t *testing.T) {
	cleanup := forceRegexPath()
	defer cleanup()

	root, files := setupTempProject(t, map[string]string{
		"app.py": `x = 1
"""
from flask import Flask
SECRET_KEY = "inside-triple-quote"
@app.get("/fake")
def fake():
    pass
"""
def real_func():
    pass
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	// Should NOT find imports/secrets/routes from inside triple-quotes
	if len(result.Imports) != 0 {
		t.Errorf("expected no imports from triple-quoted block, got %d", len(result.Imports))
	}
	if len(result.Secrets) != 0 {
		t.Errorf("expected no secrets from triple-quoted block, got %d", len(result.Secrets))
	}
	// Only real_func should be found as a symbol
	foundReal := false
	foundFake := false
	for _, sym := range result.Symbols {
		if sym.Name == "real_func" {
			foundReal = true
		}
		if sym.Name == "fake" {
			foundFake = true
		}
	}
	if !foundReal {
		t.Error("expected real_func symbol")
	}
	if foundFake {
		t.Error("fake function inside triple-quote should not be detected")
	}
}

func TestAnalyzeRegex_MultipleImportStyles(t *testing.T) {
	cleanup := forceRegexPath()
	defer cleanup()

	root, files := setupTempProject(t, map[string]string{
		"app.py": `import os, sys
from pathlib import Path
import json
from collections import OrderedDict as OD
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	names := make(map[string]bool)
	for _, imp := range result.Imports {
		names[imp.ImportPath] = true
	}
	for _, want := range []string{"os", "sys", "pathlib", "json", "collections"} {
		if !names[want] {
			t.Errorf("expected import %q", want)
		}
	}
}

func TestAnalyzeRegex_FileReadError(t *testing.T) {
	cleanup := forceRegexPath()
	defer cleanup()

	a := New()
	result, err := a.Analyze("/tmp", []string{"nonexistent_file.py"})
	if err != nil {
		t.Fatalf("Analyze should not return error: %v", err)
	}
	if len(result.SkippedFiles) == 0 {
		t.Error("expected skipped file for nonexistent path")
	}
}

func TestAnalyzeRegex_EmptyFileList(t *testing.T) {
	cleanup := forceRegexPath()
	defer cleanup()

	a := New()
	result, err := a.Analyze("/tmp", nil)
	if err != nil {
		t.Fatalf("Analyze should not return error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestAnalyzeRegex_PrivateSymbols(t *testing.T) {
	cleanup := forceRegexPath()
	defer cleanup()

	root, files := setupTempProject(t, map[string]string{
		"util.py": `def _private_func():
    pass

class _PrivateClass:
    pass

def public_func():
    pass
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	for _, sym := range result.Symbols {
		if sym.Name == "_private_func" && sym.Exported {
			t.Error("_private_func should not be exported")
		}
		if sym.Name == "_PrivateClass" && sym.Exported {
			t.Error("_PrivateClass should not be exported")
		}
		if sym.Name == "public_func" && !sym.Exported {
			t.Error("public_func should be exported")
		}
	}
}

func TestAnalyzeRegex_TypeGraphExtraction(t *testing.T) {
	cleanup := forceRegexPath()
	defer cleanup()

	root, files := setupTempProject(t, map[string]string{
		"animals.py": `from abc import ABC, abstractmethod

class Animal(ABC):
    @abstractmethod
    def speak(self) -> str:
        pass

class Dog(Animal):
    def __init__(self, name: str):
        self.name = name
        self.age: int = 0

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
	animalNode := tg.Nodes["animals.py:Animal"]
	if animalNode == nil {
		t.Fatal("expected TypeNode for Animal")
	}
	if animalNode.Kind != "abstract_class" {
		t.Errorf("expected abstract_class, got %s", animalNode.Kind)
	}

	dogNode := tg.Nodes["animals.py:Dog"]
	if dogNode == nil {
		t.Fatal("expected TypeNode for Dog")
	}
	if dogNode.Extends != "Animal" {
		t.Errorf("expected Dog extends Animal, got %s", dogNode.Extends)
	}
}

func TestAnalyzeRegex_MultipleFilesFullCoverage(t *testing.T) {
	cleanup := forceRegexPath()
	defer cleanup()

	root, files := setupTempProject(t, map[string]string{
		"app.py": `from fastapi import FastAPI, Depends
from starlette.middleware.cors import CORSMiddleware
import sqlalchemy

app = FastAPI()
app.add_middleware(CORSMiddleware)

SECRET_KEY = "hardcoded"

def require_auth():
    pass

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/users")
def create_user(auth=Depends(require_auth)):
    session = Session()
    return {}
`,
		"test_app.py": `def test_health():
    assert True

def test_create_user():
    assert True

class TestAPI:
    def test_get(self):
        pass
`,
		"views.py": `from django.db import models

def list_items():
    return Item.objects.filter(active=True)
`,
		"models.py": `from tortoise import fields
import psycopg2

class Item(Model):
    name = fields.CharField(max_length=100)
`,
		"settings.py": `MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
]
`,
		"urls.py": `from django.urls import path, re_path
from django.conf.urls import url

urlpatterns = [
    path('items/', views.item_list),
    url(r'^api/', include('api.urls')),
    re_path(r'^articles/$', views.articles),
]
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(result.Files) != 6 {
		t.Errorf("expected 6 FileFacts, got %d", len(result.Files))
	}
	if len(result.Imports) == 0 {
		t.Error("expected imports")
	}
	if len(result.Symbols) == 0 {
		t.Error("expected symbols")
	}
	if len(result.Routes) == 0 {
		t.Error("expected routes")
	}
	if len(result.Middlewares) == 0 {
		t.Error("expected middlewares")
	}
	if len(result.DataAccess) == 0 {
		t.Error("expected data access facts")
	}
	if len(result.Secrets) == 0 {
		t.Error("expected secrets")
	}
	if len(result.Tests) == 0 {
		t.Error("expected tests")
	}
}

func TestAnalyzeRegex_SQLAlchemyImportDirectStyle(t *testing.T) {
	cleanup := forceRegexPath()
	defer cleanup()

	root, files := setupTempProject(t, map[string]string{
		"db.py": `import sqlalchemy
session = Session()
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, da := range result.DataAccess {
		if da.Backend == "sqlalchemy" {
			found = true
		}
	}
	if !found {
		t.Error("expected sqlalchemy data access via 'import sqlalchemy'")
	}
}

func TestAnalyzeRegex_TortoiseImportDirectStyle(t *testing.T) {
	cleanup := forceRegexPath()
	defer cleanup()

	root, files := setupTempProject(t, map[string]string{
		"db.py": `import tortoise
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, da := range result.DataAccess {
		if da.Backend == "tortoise" {
			found = true
		}
	}
	if !found {
		t.Error("expected tortoise data access via 'import tortoise'")
	}
}

func TestAnalyzeRegex_FastAPIRouteNoHandler(t *testing.T) {
	// Route decorator at end of file with no following def
	cleanup := forceRegexPath()
	defer cleanup()

	root, files := setupTempProject(t, map[string]string{
		"main.py": `from fastapi import FastAPI
app = FastAPI()

@app.get("/ping")
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, rf := range result.Routes {
		if rf.Path == "/ping" && rf.Method == "GET" {
			found = true
		}
	}
	if !found {
		t.Error("expected GET /ping route")
	}
}

func TestAnalyzeRegex_FastAPIRouteBlankLineBeforeDef(t *testing.T) {
	cleanup := forceRegexPath()
	defer cleanup()

	root, files := setupTempProject(t, map[string]string{
		"main.py": `from fastapi import FastAPI
app = FastAPI()

@app.get("/ping")

def ping():
    return "pong"
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, rf := range result.Routes {
		if rf.Path == "/ping" && rf.Handler == "ping" {
			found = true
		}
	}
	if !found {
		t.Error("expected GET /ping with handler ping")
	}
}

func TestAnalyzeRegex_FlaskRouteBlankLineBeforeDef(t *testing.T) {
	cleanup := forceRegexPath()
	defer cleanup()

	root, files := setupTempProject(t, map[string]string{
		"app.py": `from flask import Flask
app = Flask(__name__)

@app.route("/about")

def about():
    return "about"
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, rf := range result.Routes {
		if rf.Path == "/about" && rf.Handler == "about" {
			found = true
		}
	}
	if !found {
		t.Error("expected Flask /about with handler about")
	}
}

func TestAnalyzeRegex_EmptyPythonFile(t *testing.T) {
	cleanup := forceRegexPath()
	defer cleanup()

	root, files := setupTempProject(t, map[string]string{
		"empty.py": "",
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Files) == 0 {
		t.Error("expected FileFact even for empty file")
	}
}

// ── projectGlobalMiddlewares ──────────────────────────────────────────────────

func TestAnalyzeRegex_GlobalMiddlewareProjectedIntoRoutes(t *testing.T) {
	cleanup := forceRegexPath()
	defer cleanup()

	root, files := setupTempProject(t, map[string]string{
		"main.py": `from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

app = FastAPI()
app.add_middleware(CORSMiddleware)

@app.get("/items")
def list_items():
    return []

@app.get("/health")
def health():
    return "ok"
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	// Every route should have CORSMiddleware projected
	for _, rf := range result.Routes {
		hasCORS := false
		for _, mw := range rf.Middlewares {
			if mw == "CORSMiddleware" {
				hasCORS = true
			}
		}
		if !hasCORS {
			t.Errorf("route %s should have CORSMiddleware projected, got %v", rf.Path, rf.Middlewares)
		}
	}
}

func TestAnalyzeRegex_GlobalMiddlewareDuplicateAvoidance(t *testing.T) {
	cleanup := forceRegexPath()
	defer cleanup()

	// Route that already has a Depends and also has global middleware
	root, files := setupTempProject(t, map[string]string{
		"main.py": `from fastapi import FastAPI, Depends
from starlette.middleware.cors import CORSMiddleware

app = FastAPI()
app.add_middleware(CORSMiddleware)

def auth():
    pass

@app.get("/items")
def list_items(user=Depends(auth)):
    return []
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	for _, rf := range result.Routes {
		if rf.Path == "/items" {
			corsCount := 0
			for _, mw := range rf.Middlewares {
				if mw == "CORSMiddleware" {
					corsCount++
				}
			}
			if corsCount != 1 {
				t.Errorf("expected CORSMiddleware exactly once in route, got %d", corsCount)
			}
		}
	}
}

func TestAnalyzeRegex_NoGlobalMiddleware(t *testing.T) {
	cleanup := forceRegexPath()
	defer cleanup()

	root, files := setupTempProject(t, map[string]string{
		"main.py": `from fastapi import FastAPI

app = FastAPI()

@app.get("/items")
def list_items():
    return []
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	// Without global middleware, routes should not get any projected
	for _, rf := range result.Routes {
		if rf.Path == "/items" && len(rf.Middlewares) > 0 {
			// This is fine — route-level middleware from Depends etc.
			// Just making sure no starlette or flask_before_request is there
			for _, mw := range rf.Middlewares {
				if mw == "CORSMiddleware" {
					t.Error("unexpected CORSMiddleware on route without global middleware")
				}
			}
		}
	}
}

// ── findPython3 additional coverage ────────────────────────────────────────────

func TestFindPython3_NotFound(t *testing.T) {
	findPython3Func = func() string { return "" }
	defer func() { findPython3Func = nil }()

	got := findPython3()
	if got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

func TestFindPython3_CustomPath(t *testing.T) {
	findPython3Func = func() string { return "/opt/custom/python3" }
	defer func() { findPython3Func = nil }()

	got := findPython3()
	if got != "/opt/custom/python3" {
		t.Errorf("expected /opt/custom/python3, got %q", got)
	}
}

// ── ensureScript additional coverage ──────────────────────────────────────────

func TestEnsureScript_WriteStringFails(t *testing.T) {
	resetScriptCache()
	defer resetScriptCache()

	// Create a file that's closed immediately — WriteString will fail
	createTempFunc = func(dir, pattern string) (*os.File, error) {
		f, err := os.CreateTemp(dir, pattern)
		if err != nil {
			return nil, err
		}
		// Set permissions so Chmod succeeds
		f.Chmod(0o600)
		// Close the file so WriteString fails
		f.Close()
		return f, nil
	}
	defer func() { createTempFunc = nil }()

	_, err := ensureScript()
	if err == nil {
		t.Skip("platform did not error on WriteString to closed fd")
	}
	// If it does error, we've covered that branch
}

// ── ParsePythonAST additional coverage ────────────────────────────────────────

func TestParsePythonAST_DeadlineExceeded(t *testing.T) {
	if !PythonASTAvailable() {
		t.Skip("python3 not available")
	}

	resetScriptCache()
	defer func() {
		runCommandFunc = nil
		resetScriptCache()
	}()

	// Override runCommand to simulate context.DeadlineExceeded
	// The ParsePythonAST function checks ctx.Err() == context.DeadlineExceeded
	// Since we can't control the internal ctx, we simulate the command returning
	// a deadline exceeded error
	runCommandFunc = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return nil, fmt.Errorf("signal: killed")
	}

	_, err := ParsePythonAST("x = 1")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestParsePythonAST_ValidJSON(t *testing.T) {
	if !PythonASTAvailable() {
		t.Skip("python3 not available")
	}

	resetScriptCache()
	defer func() {
		runCommandFunc = nil
		resetScriptCache()
	}()

	// Return valid JSON with an error field
	errMsg := "syntax error"
	runCommandFunc = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return []byte(`{"imports":[],"symbols":[],"routes":[],"middlewares":[],"data_access":[],"secrets":[],"classes":[],"error":"` + errMsg + `"}`), nil
	}

	result, err := ParsePythonAST("x = 1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Error == nil || *result.Error != errMsg {
		t.Error("expected error field in result")
	}
}

// ── Analyze with AST error fallback ───────────────────────────────────────────

func TestAnalyze_ASTErrorFallsToRegex(t *testing.T) {
	if !PythonASTAvailable() {
		t.Skip("python3 not available")
	}

	// File with syntax error triggers AST fail, falls to regex
	root, files := setupTempProject(t, map[string]string{
		"broken.py": `def broken(
    x = 1

SECRET_KEY = "hardcoded"
import os
def real_func():
    pass
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze should not error: %v", err)
	}
	if len(result.Files) == 0 {
		t.Error("expected at least one FileFact from regex fallback")
	}
}

// ── Analyze with various TripleQuote scenarios through the Analyze function ──

func TestAnalyzeRegex_TripleQuoteSingleQuotes(t *testing.T) {
	cleanup := forceRegexPath()
	defer cleanup()

	root, files := setupTempProject(t, map[string]string{
		"app.py": `x = 1
'''
import os
SECRET_KEY = "inside-triple-quote"
'''
def real_func():
    pass
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(result.Imports) != 0 {
		t.Errorf("expected no imports from inside triple single-quotes, got %d", len(result.Imports))
	}
	foundReal := false
	for _, sym := range result.Symbols {
		if sym.Name == "real_func" {
			foundReal = true
		}
	}
	if !foundReal {
		t.Error("expected real_func symbol after triple-quote block")
	}
}

func TestAnalyzeRegex_StarletteRouteOnly(t *testing.T) {
	cleanup := forceRegexPath()
	defer cleanup()

	root, files := setupTempProject(t, map[string]string{
		"main.py": `from starlette.routing import Route

routes = [
    Route("/api/v1/users", endpoint=users),
]
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, rf := range result.Routes {
		if rf.Path == "/api/v1/users" {
			found = true
		}
	}
	if !found {
		t.Error("expected Starlette route /api/v1/users")
	}
}

func TestAnalyzeRegex_DjangoMiddlewareNotInNonSettings(t *testing.T) {
	cleanup := forceRegexPath()
	defer cleanup()

	root, files := setupTempProject(t, map[string]string{
		"views.py": `    'django.middleware.security.SecurityMiddleware',
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	for _, mw := range result.Middlewares {
		if mw.Kind == "django" {
			t.Error("django middleware should not be detected in non-settings file")
		}
	}
}

func TestAnalyzeRegex_EmptyImportParts(t *testing.T) {
	cleanup := forceRegexPath()
	defer cleanup()

	root, files := setupTempProject(t, map[string]string{
		"app.py": `from flask import Flask, , Depends
import os, , sys
`,
	})

	a := New()
	result, err := a.Analyze(root, files)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	// Should still parse valid parts, empty parts skipped
	if len(result.Imports) == 0 {
		t.Error("expected at least some imports despite empty parts")
	}
}

// ── convertASTToFacts coverage ────────────────────────────────────────────────

func TestConvertASTToFacts_RoutesWithNilMiddlewares(t *testing.T) {
	a := New()
	result := newTestResult()

	ast := &ASTResult{
		Routes: []ASTRoute{
			{Method: "GET", Path: "/test", Handler: "test_handler", Line: 1, Middlewares: nil},
		},
	}

	a.convertASTToFacts("app.py", []string{"@app.get(\"/test\")", "def test_handler():", "    pass"}, "", ast, result)

	if len(result.Routes) == 0 {
		t.Fatal("expected at least one route")
	}
	// Middlewares should be []string{} not nil
	if result.Routes[0].Middlewares == nil {
		t.Error("expected non-nil Middlewares (empty slice)")
	}
}

func TestConvertASTToFacts_DataAccessImportsDirect(t *testing.T) {
	a := New()
	result := newTestResult()

	ast := &ASTResult{
		Imports: []ASTImport{
			{Module: "sqlalchemy.orm", Line: 1},
			{Module: "psycopg2", Line: 2},
		},
		DataAccess: []ASTDataAccess{
			{Operation: "query", Backend: "sqlalchemy", Line: 3, Caller: "get_user"},
			{Operation: "cursor", Backend: "psycopg2", Line: 4, Caller: "connect_db"},
			{Operation: "query", Backend: "django-orm", Line: 5, Caller: "list_items"},
		},
	}

	a.convertASTToFacts("db.py", []string{}, "", ast, result)

	for _, da := range result.DataAccess {
		switch da.Backend {
		case "sqlalchemy":
			if !da.ImportsDirect {
				t.Error("expected ImportsDirect=true for sqlalchemy")
			}
		case "psycopg2":
			if !da.ImportsDirect {
				t.Error("expected ImportsDirect=true for psycopg2")
			}
		case "django-orm":
			if !da.ImportsDirect {
				t.Error("expected ImportsDirect=true for django-orm (default)")
			}
		}
	}
}

func TestConvertASTToFacts_SymbolEndLineZero(t *testing.T) {
	a := New()
	result := newTestResult()

	ast := &ASTResult{
		Symbols: []ASTSymbol{
			{Name: "my_func", Kind: "function", Line: 5, EndLine: 0, Exported: true},
		},
	}

	a.convertASTToFacts("app.py", []string{}, "", ast, result)

	if len(result.Symbols) == 0 {
		t.Fatal("expected at least one symbol")
	}
	// When EndLine is 0, it should default to Line
	sym := result.Symbols[0]
	if sym.Span.End != 5 {
		t.Errorf("expected span end=5 (same as start when EndLine=0), got %d", sym.Span.End)
	}
}

func TestConvertASTToFacts_DjangoTestImportInAST(t *testing.T) {
	a := New()
	result := newTestResult()

	lines := strings.Split(`from django.test import TestCase

class TestUserModel(TestCase):
    def test_create(self):
        pass`, "\n")

	ast := &ASTResult{
		Symbols: []ASTSymbol{
			{Name: "TestUserModel", Kind: "class", Line: 3, EndLine: 5, Exported: true},
		},
	}

	a.convertASTToFacts("test_models.py", lines, strings.Join(lines, "\n"), ast, result)

	foundTestCase := false
	for _, tf := range result.Tests {
		if tf.TestName == "TestUserModel" {
			foundTestCase = true
		}
	}
	if !foundTestCase {
		t.Error("expected TestUserModel as TestFact from Django TestCase detection in convertASTToFacts")
	}
}

func TestConvertASTToFacts_StarletteRouteInAST(t *testing.T) {
	a := New()
	result := newTestResult()

	lines := []string{
		`    Route("/api", endpoint=api_handler),`,
	}

	ast := &ASTResult{}

	a.convertASTToFacts("main.py", lines, lines[0], ast, result)

	found := false
	for _, rf := range result.Routes {
		if rf.Path == "/api" {
			found = true
		}
	}
	if !found {
		t.Error("expected Starlette route /api from supplementary regex in convertASTToFacts")
	}
}

func TestConvertASTToFacts_DjangoMiddlewareInAST(t *testing.T) {
	a := New()
	result := newTestResult()

	lines := []string{
		"MIDDLEWARE = [",
		"    'django.middleware.security.SecurityMiddleware',",
		"]",
	}

	ast := &ASTResult{}

	a.convertASTToFacts("settings.py", lines, strings.Join(lines, "\n"), ast, result)

	found := false
	for _, mw := range result.Middlewares {
		if mw.Name == "django.middleware.security.SecurityMiddleware" && mw.Kind == "django" {
			found = true
		}
	}
	if !found {
		t.Error("expected Django SecurityMiddleware from supplementary regex in convertASTToFacts")
	}
}

func TestConvertASTToFacts_TestFunctionInTestFile(t *testing.T) {
	a := New()
	result := newTestResult()

	lines := []string{
		"def test_something():",
		"    assert True",
	}

	ast := &ASTResult{}

	a.convertASTToFacts("test_app.py", lines, strings.Join(lines, "\n"), ast, result)

	found := false
	for _, tf := range result.Tests {
		if tf.TestName == "test_something" {
			found = true
		}
	}
	if !found {
		t.Error("expected test_something from supplementary regex in convertASTToFacts")
	}
}

func TestConvertASTToFacts_DjangoRouteInAST(t *testing.T) {
	a := New()
	result := newTestResult()

	lines := []string{
		"    path('users/', views.user_list),",
		"    url(r'^api/', include('api.urls')),",
		"    re_path(r'^articles/$', views.articles),",
	}

	ast := &ASTResult{}

	a.convertASTToFacts("urls.py", lines, strings.Join(lines, "\n"), ast, result)

	if len(result.Routes) != 3 {
		t.Errorf("expected 3 Django routes from supplementary regex, got %d", len(result.Routes))
	}
}
