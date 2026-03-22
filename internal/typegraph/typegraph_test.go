package typegraph

import (
	"testing"
)

func TestAddNodeAndFindByName(t *testing.T) {
	g := New()
	node := &TypeNode{
		Name:     "UserService",
		Kind:     "class",
		File:     "src/user.ts",
		Language: "typescript",
		Exported: true,
		Span:     Span{Start: 1, End: 20},
	}
	g.AddNode(node)

	found := g.FindByName("UserService")
	if len(found) != 1 {
		t.Fatalf("expected 1 node, got %d", len(found))
	}
	if found[0].Name != "UserService" {
		t.Errorf("expected name UserService, got %s", found[0].Name)
	}

	found = g.FindByName("NotExist")
	if len(found) != 0 {
		t.Errorf("expected 0 nodes for non-existent name, got %d", len(found))
	}
}

func TestFindImplementors(t *testing.T) {
	g := New()
	g.AddNode(&TypeNode{
		Name:       "Logger",
		Kind:       "interface",
		File:       "pkg/log.go",
		Language:   "go",
		Exported:   true,
		Span:       Span{Start: 1, End: 5},
	})
	g.AddNode(&TypeNode{
		Name:       "FileLogger",
		Kind:       "struct",
		File:       "pkg/file_logger.go",
		Language:   "go",
		Exported:   true,
		Implements: []string{"Logger"},
		Span:       Span{Start: 1, End: 30},
	})
	g.AddNode(&TypeNode{
		Name:       "ConsoleLogger",
		Kind:       "struct",
		File:       "pkg/console_logger.go",
		Language:   "go",
		Exported:   true,
		Implements: []string{"Logger"},
		Span:       Span{Start: 1, End: 20},
	})
	g.AddNode(&TypeNode{
		Name:     "Config",
		Kind:     "struct",
		File:     "pkg/config.go",
		Language: "go",
		Exported: true,
		Span:     Span{Start: 1, End: 10},
	})

	impls := g.FindImplementors("Logger")
	if len(impls) != 2 {
		t.Fatalf("expected 2 implementors, got %d", len(impls))
	}

	impls = g.FindImplementors("NotExist")
	if len(impls) != 0 {
		t.Errorf("expected 0 implementors for non-existent interface, got %d", len(impls))
	}
}

func TestFindSubclasses(t *testing.T) {
	g := New()
	g.AddNode(&TypeNode{
		Name:     "Animal",
		Kind:     "class",
		File:     "src/animal.ts",
		Language: "typescript",
		Exported: true,
		Span:     Span{Start: 1, End: 10},
	})
	g.AddNode(&TypeNode{
		Name:     "Dog",
		Kind:     "class",
		File:     "src/dog.ts",
		Language: "typescript",
		Exported: true,
		Extends:  "Animal",
		Span:     Span{Start: 1, End: 20},
	})
	g.AddNode(&TypeNode{
		Name:     "Cat",
		Kind:     "class",
		File:     "src/cat.ts",
		Language: "typescript",
		Exported: true,
		Extends:  "Animal",
		Span:     Span{Start: 1, End: 15},
	})

	subs := g.FindSubclasses("Animal")
	if len(subs) != 2 {
		t.Fatalf("expected 2 subclasses, got %d", len(subs))
	}

	subs = g.FindSubclasses("NotExist")
	if len(subs) != 0 {
		t.Errorf("expected 0 subclasses for non-existent class, got %d", len(subs))
	}
}

func TestFindInterfacesAndClasses(t *testing.T) {
	g := New()
	g.AddNode(&TypeNode{Name: "Repo", Kind: "interface", File: "a.go", Language: "go", Span: Span{Start: 1, End: 5}})
	g.AddNode(&TypeNode{Name: "User", Kind: "struct", File: "b.go", Language: "go", Span: Span{Start: 1, End: 10}})
	g.AddNode(&TypeNode{Name: "Service", Kind: "class", File: "c.ts", Language: "typescript", Span: Span{Start: 1, End: 20}})
	g.AddNode(&TypeNode{Name: "Base", Kind: "abstract_class", File: "d.ts", Language: "typescript", Span: Span{Start: 1, End: 15}})

	ifaces := g.FindInterfaces()
	if len(ifaces) != 1 {
		t.Errorf("expected 1 interface, got %d", len(ifaces))
	}

	classes := g.FindClasses()
	if len(classes) != 3 {
		t.Errorf("expected 3 classes (struct+class+abstract_class), got %d", len(classes))
	}
}

func TestTypeNodeHelpers(t *testing.T) {
	node := &TypeNode{
		Name:       "Decorator",
		Kind:       "class",
		File:       "src/decorator.ts",
		Language:   "typescript",
		Implements: []string{"Component"},
		Fields: []FieldInfo{
			{Name: "component", TypeName: "Component", IsPublic: false},
			{Name: "name", TypeName: "string", IsPublic: true},
		},
		Methods: []MethodInfo{
			{Name: "execute", ReturnType: "void", IsPublic: true},
			{Name: "create", ReturnType: "Component", IsPublic: true},
			{Name: "build", ReturnType: "Component", IsPublic: true, IsAbstract: true},
		},
		Span: Span{Start: 1, End: 30},
	}

	if !node.HasMethodNamed("execute") {
		t.Error("expected HasMethodNamed('execute') to be true")
	}
	if node.HasMethodNamed("notExist") {
		t.Error("expected HasMethodNamed('notExist') to be false")
	}

	if !node.HasFieldOfType("Component") {
		t.Error("expected HasFieldOfType('Component') to be true")
	}
	if node.HasFieldOfType("NotExist") {
		t.Error("expected HasFieldOfType('NotExist') to be false")
	}

	iface, ok := node.HasFieldOfSameInterface()
	if !ok || iface != "Component" {
		t.Errorf("expected HasFieldOfSameInterface to return ('Component', true), got (%s, %v)", iface, ok)
	}

	if count := node.CountMethodsReturning("Component"); count != 2 {
		t.Errorf("expected CountMethodsReturning('Component') = 2, got %d", count)
	}

	abstracts := node.GetAbstractMethods()
	if len(abstracts) != 1 || abstracts[0].Name != "build" {
		t.Errorf("expected 1 abstract method 'build', got %v", abstracts)
	}

	names := node.MethodNames()
	if len(names) != 3 {
		t.Errorf("expected 3 method names, got %d", len(names))
	}
}
