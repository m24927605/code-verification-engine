package skills

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/facts"
	"github.com/verabase/code-verification-engine/internal/rules"
)

func TestDeriveSkills(t *testing.T) {
	tests := []struct {
		name    string
		signals []Signal
		want    []string
	}{
		{"nil signals", nil, nil},
		{"empty signals", []Signal{}, nil},
		{"all unsupported", []Signal{
			{SkillID: "a", Status: StatusUnsupported},
			{SkillID: "b", Status: StatusUnsupported},
		}, nil},
		{"mixed statuses", []Signal{
			{SkillID: "z_skill", Status: StatusObserved},
			{SkillID: "a_skill", Status: StatusInferred},
			{SkillID: "m_skill", Status: StatusUnsupported},
		}, []string{"a_skill", "z_skill"}},
		{"deduplicates", []Signal{
			{SkillID: "dup", Status: StatusObserved},
			{SkillID: "dup", Status: StatusInferred},
		}, []string{"dup"}},
		{"skips empty skill_id", []Signal{
			{SkillID: "", Status: StatusObserved},
			{SkillID: "valid", Status: StatusObserved},
		}, []string{"valid"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := deriveSkills(tc.signals)
			if len(got) != len(tc.want) {
				t.Fatalf("deriveSkills() = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("deriveSkills()[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestDeriveLanguages(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"nil", nil, nil},
		{"empty", []string{}, nil},
		{"deduplicates and sorts", []string{"go", "typescript", "go"}, []string{"go", "typescript"}},
		{"trims whitespace", []string{" go ", "  ", "typescript"}, []string{"go", "typescript"}},
		{"skips empty", []string{"", "python", ""}, []string{"python"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := deriveLanguages(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("deriveLanguages() = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("deriveLanguages()[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestDeriveTechnologies_NilFactSet(t *testing.T) {
	got := deriveTechnologies(nil)
	if got != nil {
		t.Fatalf("expected nil, got %v", got)
	}
}

func TestDeriveTechnologies_EmptyFactSet(t *testing.T) {
	got := deriveTechnologies(&rules.FactSet{})
	if len(got) != 0 {
		t.Fatalf("expected empty, got %v", got)
	}
}

func TestDeriveTechnologies_Imports(t *testing.T) {
	tests := []struct {
		importPath string
		wantName   string
		wantKind   string
	}{
		{"github.com/gin-gonic/gin", "gin", "framework"},
		{"github.com/labstack/echo/v4", "echo", "framework"},
		{"fastapi", "fastapi", "framework"},
		{"@nestjs/core", "nestjs", "framework"},
		{"express", "express", "framework"},
		{"fastify", "fastify", "framework"},
		{"@hapi/hapi", "hapi", "framework"},
		{"hapi", "hapi", "framework"},
		{"koa", "koa", "framework"},
		{"/koa", "koa", "framework"},
		{"next/router", "nextjs", "framework"},
		{"next", "nextjs", "framework"},
		{"react-router-dom", "react-router", "router"},
		{"vue-router", "vue-router", "router"},
		{"react", "react", "library"},
		{"react-dom", "react", "library"},
		{"vue", "vue", "library"},
		{"django.views", "django", "framework"},
		{"flask", "flask", "framework"},
		{"@prisma/client", "prisma", "orm"},
		{"typeorm", "typeorm", "orm"},
		{"sequelize", "sequelize", "orm"},
		{"mongoose", "mongoose", "orm"},
		{"pg", "pg", "database_driver"},
		{"helmet", "helmet", "middleware_package"},
		{"cors", "cors", "middleware_package"},
	}
	for _, tc := range tests {
		t.Run(tc.importPath, func(t *testing.T) {
			fs := &rules.FactSet{
				Imports: []facts.ImportFact{{ImportPath: tc.importPath}},
			}
			got := deriveTechnologies(fs)
			if len(got) != 1 {
				t.Fatalf("expected 1 technology, got %v", got)
			}
			if got[0].Name != tc.wantName {
				t.Errorf("name = %q, want %q", got[0].Name, tc.wantName)
			}
			if got[0].Kind != tc.wantKind {
				t.Errorf("kind = %q, want %q", got[0].Kind, tc.wantKind)
			}
		})
	}
}

func TestDeriveTechnologies_UnknownImport(t *testing.T) {
	fs := &rules.FactSet{
		Imports: []facts.ImportFact{{ImportPath: "unknown-random-lib"}},
	}
	got := deriveTechnologies(fs)
	if len(got) != 0 {
		t.Fatalf("expected 0 technologies for unknown import, got %v", got)
	}
}

func TestDeriveTechnologies_Middlewares(t *testing.T) {
	tests := []struct {
		kind     string
		wantName string
	}{
		{"express", "express"},
		{"fastify-plugin", "fastify"},
		{"hapi-plugin", "hapi"},
		{"fastapi_depends", "fastapi"},
	}
	for _, tc := range tests {
		t.Run(tc.kind, func(t *testing.T) {
			fs := &rules.FactSet{
				Middlewares: []facts.MiddlewareFact{{Kind: tc.kind}},
			}
			got := deriveTechnologies(fs)
			if len(got) != 1 {
				t.Fatalf("expected 1 technology, got %v", got)
			}
			if got[0].Name != tc.wantName {
				t.Errorf("name = %q, want %q", got[0].Name, tc.wantName)
			}
			if got[0].Kind != "framework" {
				t.Errorf("kind = %q, want framework", got[0].Kind)
			}
		})
	}
}

func TestDeriveTechnologies_UnknownMiddleware(t *testing.T) {
	fs := &rules.FactSet{
		Middlewares: []facts.MiddlewareFact{{Kind: "unknown"}},
	}
	got := deriveTechnologies(fs)
	if len(got) != 0 {
		t.Fatalf("expected 0 technologies for unknown middleware, got %v", got)
	}
}

func TestDeriveTechnologies_DataAccess(t *testing.T) {
	tests := []struct {
		backend  string
		wantName string
		wantKind string
	}{
		{"prisma", "prisma", "orm"},
		{"typeorm", "typeorm", "orm"},
		{"sequelize", "sequelize", "orm"},
		{"mongoose", "mongoose", "orm"},
		{"postgres", "postgresql", "database"},
		{"postgresql", "postgresql", "database"},
		{"mysql", "mysql", "database"},
		{"mongodb", "mongodb", "database"},
	}
	for _, tc := range tests {
		t.Run(tc.backend, func(t *testing.T) {
			fs := &rules.FactSet{
				DataAccess: []facts.DataAccessFact{{Backend: tc.backend}},
			}
			got := deriveTechnologies(fs)
			if len(got) != 1 {
				t.Fatalf("expected 1 technology, got %v", got)
			}
			if got[0].Name != tc.wantName {
				t.Errorf("name = %q, want %q", got[0].Name, tc.wantName)
			}
			if got[0].Kind != tc.wantKind {
				t.Errorf("kind = %q, want %q", got[0].Kind, tc.wantKind)
			}
		})
	}
}

func TestDeriveTechnologies_UnknownDataAccess(t *testing.T) {
	fs := &rules.FactSet{
		DataAccess: []facts.DataAccessFact{{Backend: "unknown"}},
	}
	got := deriveTechnologies(fs)
	if len(got) != 0 {
		t.Fatalf("expected 0 technologies for unknown backend, got %v", got)
	}
}

func TestDeriveTechnologies_Deduplicates(t *testing.T) {
	fs := &rules.FactSet{
		Imports: []facts.ImportFact{
			{ImportPath: "express"},
			{ImportPath: "express"},
		},
		Middlewares: []facts.MiddlewareFact{
			{Kind: "express"},
		},
	}
	got := deriveTechnologies(fs)
	if len(got) != 1 {
		t.Fatalf("expected 1 (deduplicated), got %v", got)
	}
	if got[0].Name != "express" {
		t.Errorf("name = %q, want express", got[0].Name)
	}
}

func TestDeriveTechnologies_SortOrder(t *testing.T) {
	fs := &rules.FactSet{
		Imports: []facts.ImportFact{
			{ImportPath: "react"},
			{ImportPath: "express"},
			{ImportPath: "cors"},
		},
	}
	got := deriveTechnologies(fs)
	if len(got) != 3 {
		t.Fatalf("expected 3 technologies, got %v", got)
	}
	// Sorted by kind first, then name
	// framework:express, library:react, middleware_package:cors
	if got[0].Kind != "framework" || got[0].Name != "express" {
		t.Errorf("[0] = %v, want express/framework", got[0])
	}
	if got[1].Kind != "library" || got[1].Name != "react" {
		t.Errorf("[1] = %v, want react/library", got[1])
	}
	if got[2].Kind != "middleware_package" || got[2].Name != "cors" {
		t.Errorf("[2] = %v, want cors/middleware_package", got[2])
	}
}

func TestDeriveFrameworks(t *testing.T) {
	tests := []struct {
		name string
		tech []Technology
		want []string
	}{
		{"nil", nil, nil},
		{"empty", []Technology{}, nil},
		{"filters frameworks only", []Technology{
			{Name: "express", Kind: "framework"},
			{Name: "react", Kind: "library"},
			{Name: "gin", Kind: "framework"},
		}, []string{"express", "gin"}},
		{"no frameworks", []Technology{
			{Name: "react", Kind: "library"},
		}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := deriveFrameworks(tc.tech)
			if len(got) != len(tc.want) {
				t.Fatalf("deriveFrameworks() = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("deriveFrameworks()[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestSortedKeys(t *testing.T) {
	tests := []struct {
		name string
		in   map[string]bool
		want []string
	}{
		{"nil", nil, nil},
		{"empty", map[string]bool{}, nil},
		{"sorted", map[string]bool{"c": true, "a": true, "b": true}, []string{"a", "b", "c"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := sortedKeys(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("sortedKeys() = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("sortedKeys()[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}
