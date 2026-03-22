package rules

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/facts"
	"github.com/verabase/code-verification-engine/internal/typegraph"
)

// ---------------------------------------------------------------------------
// matchGoFPattern
// ---------------------------------------------------------------------------

func TestMatchGoFPattern_NilTypeGraph(t *testing.T) {
	rule := Rule{ID: "T-001", Languages: []string{"go"}, Target: "gof.singleton"}
	fs := &FactSet{TypeGraph: nil}
	f := matchGoFPattern(rule, fs)
	if f.Status != StatusUnknown {
		t.Errorf("expected unknown, got %s", f.Status)
	}
}

func TestMatchGoFPattern_EmptyTypeGraph(t *testing.T) {
	rule := Rule{ID: "T-001", Languages: []string{"go"}, Target: "gof.singleton"}
	tg := typegraph.New()
	fs := &FactSet{TypeGraph: tg}
	f := matchGoFPattern(rule, fs)
	if f.Status != StatusUnknown {
		t.Errorf("expected unknown, got %s", f.Status)
	}
}

func TestMatchGoFPattern_PassWithEvidence(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "DBPool", Kind: "class", File: "db.go", Language: "go",
		Methods: []typegraph.MethodInfo{
			{Name: "getInstance", IsStatic: true, IsPublic: true},
		},
		Fields: []typegraph.FieldInfo{
			{Name: "instance", TypeName: "DBPool", IsStatic: true},
		},
		Span: typegraph.Span{Start: 1, End: 20},
	})
	rule := Rule{ID: "T-001", Languages: []string{"go"}, Target: "gof.singleton"}
	fs := &FactSet{TypeGraph: tg}
	f := matchGoFPattern(rule, fs)
	if f.Status != StatusPass {
		t.Errorf("expected pass, got %s", f.Status)
	}
	if len(f.Evidence) == 0 {
		t.Error("expected evidence")
	}
}

func TestMatchGoFPattern_Fail(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Foo", Kind: "class", File: "foo.go", Language: "go",
		Span: typegraph.Span{Start: 1, End: 5},
	})
	rule := Rule{ID: "T-001", Languages: []string{"go"}, Target: "gof.singleton"}
	fs := &FactSet{TypeGraph: tg}
	f := matchGoFPattern(rule, fs)
	if f.Status != StatusFail {
		t.Errorf("expected fail, got %s", f.Status)
	}
}

func TestMatchGoFPattern_UnknownTarget(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "X", Kind: "class", File: "x.go", Language: "go",
		Span: typegraph.Span{Start: 1, End: 5},
	})
	rule := Rule{ID: "T-001", Languages: []string{"go"}, Target: "gof.nonexistent"}
	fs := &FactSet{TypeGraph: tg}
	f := matchGoFPattern(rule, fs)
	if f.Status != StatusFail {
		t.Errorf("expected fail for unknown target, got %s", f.Status)
	}
}

// ---------------------------------------------------------------------------
// Creational: Singleton
// ---------------------------------------------------------------------------

func TestFindSingletonPattern_Positive_StaticGetInstance(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "DatabasePool", Kind: "class", File: "db.go", Language: "go",
		Methods: []typegraph.MethodInfo{
			{Name: "getInstance", IsStatic: true, IsPublic: true},
		},
		Fields: []typegraph.FieldInfo{
			{Name: "instance", TypeName: "DatabasePool", IsStatic: true},
		},
		Span: typegraph.Span{Start: 1, End: 20},
	})
	rule := Rule{ID: "T-001", Languages: []string{"go"}, Target: "gof.singleton"}
	fs := &FactSet{TypeGraph: tg, Symbols: []facts.SymbolFact{sym("x", "var", "db.go", facts.LangGo, false, 1, 1)}}
	ev := findSingletonPattern(rule, fs)
	if len(ev) == 0 {
		t.Error("expected singleton evidence")
	}
}

func TestFindSingletonPattern_Positive_PrivateConstructor(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Config", Kind: "class", File: "config.go", Language: "go",
		Methods: []typegraph.MethodInfo{
			{Name: "GetInstance", IsStatic: true, IsPublic: true},
			{Name: "constructor", IsPublic: false},
		},
		Span: typegraph.Span{Start: 1, End: 30},
	})
	rule := Rule{ID: "T-002", Languages: []string{"go"}, Target: "gof.singleton"}
	fs := &FactSet{TypeGraph: tg}
	ev := findSingletonPattern(rule, fs)
	if len(ev) == 0 {
		t.Error("expected singleton evidence with private constructor")
	}
}

func TestFindSingletonPattern_Positive_GoPattern(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "config", Kind: "struct", File: "cfg.go", Language: "go", Exported: false,
		Span: typegraph.Span{Start: 5, End: 15},
	})
	rule := Rule{ID: "T-003", Languages: []string{"go"}, Target: "gof.singleton"}
	fs := &FactSet{
		TypeGraph: tg,
		Symbols:   []facts.SymbolFact{sym("NewConfig", "function", "cfg.go", facts.LangGo, true, 20, 25)},
	}
	ev := findSingletonPattern(rule, fs)
	if len(ev) == 0 {
		t.Error("expected Go singleton evidence")
	}
}

func TestFindSingletonPattern_Negative(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Foo", Kind: "class", File: "foo.go", Language: "go",
		Methods: []typegraph.MethodInfo{{Name: "DoStuff", IsPublic: true}},
		Span:    typegraph.Span{Start: 1, End: 10},
	})
	rule := Rule{ID: "T-004", Languages: []string{"go"}, Target: "gof.singleton"}
	fs := &FactSet{TypeGraph: tg}
	ev := findSingletonPattern(rule, fs)
	if len(ev) != 0 {
		t.Error("expected no singleton evidence")
	}
}

func TestFindSingletonPattern_Negative_LanguageMismatch(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "DatabasePool", Kind: "class", File: "db.java", Language: "java",
		Methods: []typegraph.MethodInfo{{Name: "getInstance", IsStatic: true}},
		Fields:  []typegraph.FieldInfo{{Name: "instance", TypeName: "DatabasePool", IsStatic: true}},
		Span:    typegraph.Span{Start: 1, End: 20},
	})
	rule := Rule{ID: "T-005", Languages: []string{"go"}, Target: "gof.singleton"}
	fs := &FactSet{TypeGraph: tg}
	ev := findSingletonPattern(rule, fs)
	if len(ev) != 0 {
		t.Error("expected no evidence for language mismatch")
	}
}

// ---------------------------------------------------------------------------
// Creational: Factory Method
// ---------------------------------------------------------------------------

func TestFindFactoryMethodPattern_Positive(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "ShapeFactory", Kind: "interface", File: "factory.go", Language: "go",
		Methods: []typegraph.MethodInfo{{Name: "createShape", ReturnType: "Shape"}},
		Span:    typegraph.Span{Start: 1, End: 10},
	})
	tg.AddNode(&typegraph.TypeNode{
		Name: "CircleFactory", Kind: "class", File: "circle.go", Language: "go",
		Implements: []string{"ShapeFactory"},
		Span:       typegraph.Span{Start: 1, End: 15},
	})
	rule := Rule{ID: "T-010", Languages: []string{"go"}, Target: "gof.factory_method"}
	fs := &FactSet{TypeGraph: tg}
	ev := findFactoryMethodPattern(rule, fs)
	if len(ev) == 0 {
		t.Error("expected factory method evidence")
	}
}

func TestFindFactoryMethodPattern_Positive_StandaloneFunc(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Reader", Kind: "interface", File: "reader.go", Language: "go",
		Methods: []typegraph.MethodInfo{{Name: "Read"}},
		Span:    typegraph.Span{Start: 1, End: 5},
	})
	rule := Rule{ID: "T-011", Languages: []string{"go"}, Target: "gof.factory_method"}
	fs := &FactSet{
		TypeGraph: tg,
		Symbols:   []facts.SymbolFact{sym("NewReader", "function", "reader.go", facts.LangGo, true, 10, 15)},
	}
	ev := findFactoryMethodPattern(rule, fs)
	if len(ev) == 0 {
		t.Error("expected factory function evidence")
	}
}

func TestFindFactoryMethodPattern_Negative(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Util", Kind: "interface", File: "util.go", Language: "go",
		Methods: []typegraph.MethodInfo{{Name: "doSomething"}},
		Span:    typegraph.Span{Start: 1, End: 5},
	})
	rule := Rule{ID: "T-012", Languages: []string{"go"}, Target: "gof.factory_method"}
	fs := &FactSet{TypeGraph: tg}
	ev := findFactoryMethodPattern(rule, fs)
	if len(ev) != 0 {
		t.Error("expected no factory method evidence")
	}
}

// ---------------------------------------------------------------------------
// Creational: Abstract Factory
// ---------------------------------------------------------------------------

func TestFindAbstractFactoryPattern_Positive(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "GUIFactory", Kind: "interface", File: "gui.go", Language: "go",
		Methods: []typegraph.MethodInfo{
			{Name: "createButton", ReturnType: "Button"},
			{Name: "createCheckbox", ReturnType: "Checkbox"},
		},
		Span: typegraph.Span{Start: 1, End: 10},
	})
	rule := Rule{ID: "T-020", Languages: []string{"go"}, Target: "gof.abstract_factory"}
	fs := &FactSet{TypeGraph: tg}
	ev := findAbstractFactoryPattern(rule, fs)
	if len(ev) == 0 {
		t.Error("expected abstract factory evidence")
	}
}

func TestFindAbstractFactoryPattern_Negative_SameReturnType(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Factory", Kind: "interface", File: "f.go", Language: "go",
		Methods: []typegraph.MethodInfo{
			{Name: "createA", ReturnType: "Widget"},
			{Name: "createB", ReturnType: "Widget"},
		},
		Span: typegraph.Span{Start: 1, End: 10},
	})
	rule := Rule{ID: "T-021", Languages: []string{"go"}, Target: "gof.abstract_factory"}
	fs := &FactSet{TypeGraph: tg}
	ev := findAbstractFactoryPattern(rule, fs)
	if len(ev) != 0 {
		t.Error("expected no evidence when return types are the same")
	}
}

func TestFindAbstractFactoryPattern_Negative_OnlyOneMethod(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Factory", Kind: "interface", File: "f.go", Language: "go",
		Methods: []typegraph.MethodInfo{
			{Name: "createWidget", ReturnType: "Widget"},
		},
		Span: typegraph.Span{Start: 1, End: 10},
	})
	rule := Rule{ID: "T-022", Languages: []string{"go"}, Target: "gof.abstract_factory"}
	fs := &FactSet{TypeGraph: tg}
	ev := findAbstractFactoryPattern(rule, fs)
	if len(ev) != 0 {
		t.Error("expected no evidence with only one factory method")
	}
}

// ---------------------------------------------------------------------------
// Creational: Builder
// ---------------------------------------------------------------------------

func TestFindBuilderPattern_Positive(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "QueryBuilder", Kind: "class", File: "qb.go", Language: "go",
		Methods: []typegraph.MethodInfo{
			{Name: "Build", ReturnType: "Query"},
			{Name: "WithTable", ReturnType: "*QueryBuilder"},
			{Name: "SetLimit", ReturnType: "*QueryBuilder"},
		},
		Span: typegraph.Span{Start: 1, End: 30},
	})
	rule := Rule{ID: "T-030", Languages: []string{"go"}, Target: "gof.builder"}
	fs := &FactSet{TypeGraph: tg}
	ev := findBuilderPattern(rule, fs)
	if len(ev) == 0 {
		t.Error("expected builder evidence")
	}
}

func TestFindBuilderPattern_Negative_NoBuildMethod(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Config", Kind: "class", File: "c.go", Language: "go",
		Methods: []typegraph.MethodInfo{
			{Name: "WithTimeout", ReturnType: "*Config"},
			{Name: "SetRetries", ReturnType: "*Config"},
		},
		Span: typegraph.Span{Start: 1, End: 10},
	})
	rule := Rule{ID: "T-031", Languages: []string{"go"}, Target: "gof.builder"}
	fs := &FactSet{TypeGraph: tg}
	ev := findBuilderPattern(rule, fs)
	if len(ev) != 0 {
		t.Error("expected no builder evidence without Build method")
	}
}

// ---------------------------------------------------------------------------
// Creational: Prototype
// ---------------------------------------------------------------------------

func TestFindPrototypePattern_Positive(t *testing.T) {
	names := []string{"Clone", "clone", "Copy", "copy", "DeepCopy", "deepCopy", "DeepClone", "deepClone"}
	for _, name := range names {
		tg := typegraph.New()
		tg.AddNode(&typegraph.TypeNode{
			Name: "Shape", Kind: "class", File: "s.go", Language: "go",
			Methods: []typegraph.MethodInfo{{Name: name}},
			Span:    typegraph.Span{Start: 1, End: 10},
		})
		rule := Rule{ID: "T-040", Languages: []string{"go"}, Target: "gof.prototype"}
		fs := &FactSet{TypeGraph: tg}
		ev := findPrototypePattern(rule, fs)
		if len(ev) == 0 {
			t.Errorf("expected prototype evidence for method %s", name)
		}
	}
}

func TestFindPrototypePattern_Negative(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Shape", Kind: "class", File: "s.go", Language: "go",
		Methods: []typegraph.MethodInfo{{Name: "Draw"}},
		Span:    typegraph.Span{Start: 1, End: 10},
	})
	rule := Rule{ID: "T-041", Languages: []string{"go"}, Target: "gof.prototype"}
	fs := &FactSet{TypeGraph: tg}
	ev := findPrototypePattern(rule, fs)
	if len(ev) != 0 {
		t.Error("expected no prototype evidence")
	}
}

// ---------------------------------------------------------------------------
// Structural: Adapter
// ---------------------------------------------------------------------------

func TestFindAdapterPattern_Positive(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Target", Kind: "interface", File: "target.go", Language: "go",
		Span: typegraph.Span{Start: 1, End: 5},
	})
	tg.AddNode(&typegraph.TypeNode{
		Name: "Adaptee", Kind: "class", File: "adaptee.go", Language: "go",
		Span: typegraph.Span{Start: 1, End: 10},
	})
	tg.AddNode(&typegraph.TypeNode{
		Name: "Adapter", Kind: "class", File: "adapter.go", Language: "go",
		Implements: []string{"Target"},
		Fields:     []typegraph.FieldInfo{{Name: "adaptee", TypeName: "Adaptee"}},
		Span:       typegraph.Span{Start: 1, End: 15},
	})
	rule := Rule{ID: "T-050", Languages: []string{"go"}, Target: "gof.adapter"}
	fs := &FactSet{TypeGraph: tg}
	ev := findAdapterPattern(rule, fs)
	if len(ev) == 0 {
		t.Error("expected adapter evidence")
	}
}

func TestFindAdapterPattern_Negative_PrimitiveField(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Adapter", Kind: "class", File: "a.go", Language: "go",
		Implements: []string{"Target"},
		Fields:     []typegraph.FieldInfo{{Name: "val", TypeName: "string"}},
		Span:       typegraph.Span{Start: 1, End: 10},
	})
	rule := Rule{ID: "T-051", Languages: []string{"go"}, Target: "gof.adapter"}
	fs := &FactSet{TypeGraph: tg}
	ev := findAdapterPattern(rule, fs)
	if len(ev) != 0 {
		t.Error("expected no adapter evidence for primitive field")
	}
}

func TestFindAdapterPattern_Negative_FieldIsSameInterface(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Target", Kind: "interface", File: "t.go", Language: "go",
		Span: typegraph.Span{Start: 1, End: 5},
	})
	tg.AddNode(&typegraph.TypeNode{
		Name: "Wrapper", Kind: "class", File: "w.go", Language: "go",
		Implements: []string{"Target"},
		Fields:     []typegraph.FieldInfo{{Name: "inner", TypeName: "Target"}},
		Span:       typegraph.Span{Start: 1, End: 10},
	})
	rule := Rule{ID: "T-052", Languages: []string{"go"}, Target: "gof.adapter"}
	fs := &FactSet{TypeGraph: tg}
	ev := findAdapterPattern(rule, fs)
	if len(ev) != 0 {
		t.Error("expected no adapter evidence when field is same as implemented interface")
	}
}

// ---------------------------------------------------------------------------
// Structural: Bridge
// ---------------------------------------------------------------------------

func TestFindBridgePattern_Positive(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Renderer", Kind: "interface", File: "r.go", Language: "go",
		Span: typegraph.Span{Start: 1, End: 5},
	})
	tg.AddNode(&typegraph.TypeNode{
		Name: "OpenGL", Kind: "class", File: "gl.go", Language: "go",
		Implements: []string{"Renderer"},
		Span:       typegraph.Span{Start: 1, End: 10},
	})
	tg.AddNode(&typegraph.TypeNode{
		Name: "Vulkan", Kind: "class", File: "vk.go", Language: "go",
		Implements: []string{"Renderer"},
		Span:       typegraph.Span{Start: 1, End: 10},
	})
	tg.AddNode(&typegraph.TypeNode{
		Name: "Shape", Kind: "class", File: "shape.go", Language: "go",
		Fields: []typegraph.FieldInfo{{Name: "renderer", TypeName: "Renderer"}},
		Span:   typegraph.Span{Start: 1, End: 15},
	})
	rule := Rule{ID: "T-060", Languages: []string{"go"}, Target: "gof.bridge"}
	fs := &FactSet{TypeGraph: tg}
	ev := findBridgePattern(rule, fs)
	if len(ev) == 0 {
		t.Error("expected bridge evidence")
	}
}

func TestFindBridgePattern_Negative_OnlyOneImplementor(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Renderer", Kind: "interface", File: "r.go", Language: "go",
		Span: typegraph.Span{Start: 1, End: 5},
	})
	tg.AddNode(&typegraph.TypeNode{
		Name: "OpenGL", Kind: "class", File: "gl.go", Language: "go",
		Implements: []string{"Renderer"},
		Span:       typegraph.Span{Start: 1, End: 10},
	})
	tg.AddNode(&typegraph.TypeNode{
		Name: "Shape", Kind: "class", File: "shape.go", Language: "go",
		Fields: []typegraph.FieldInfo{{Name: "renderer", TypeName: "Renderer"}},
		Span:   typegraph.Span{Start: 1, End: 15},
	})
	rule := Rule{ID: "T-061", Languages: []string{"go"}, Target: "gof.bridge"}
	fs := &FactSet{TypeGraph: tg}
	ev := findBridgePattern(rule, fs)
	if len(ev) != 0 {
		t.Error("expected no bridge evidence with only one implementor")
	}
}

// ---------------------------------------------------------------------------
// Structural: Composite
// ---------------------------------------------------------------------------

func TestFindCompositePattern_Positive(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Component", Kind: "interface", File: "c.go", Language: "go",
		Span: typegraph.Span{Start: 1, End: 5},
	})
	tg.AddNode(&typegraph.TypeNode{
		Name: "Composite", Kind: "class", File: "comp.go", Language: "go",
		Implements: []string{"Component"},
		Fields:     []typegraph.FieldInfo{{Name: "children", TypeName: "[]Component"}},
		Span:       typegraph.Span{Start: 1, End: 20},
	})
	rule := Rule{ID: "T-070", Languages: []string{"go"}, Target: "gof.composite"}
	fs := &FactSet{TypeGraph: tg}
	ev := findCompositePattern(rule, fs)
	if len(ev) == 0 {
		t.Error("expected composite evidence")
	}
}

func TestFindCompositePattern_Positive_PointerSlice(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Node", Kind: "class", File: "n.go", Language: "go",
		Implements: []string{"TreeNode"},
		Fields:     []typegraph.FieldInfo{{Name: "children", TypeName: "[]*TreeNode"}},
		Span:       typegraph.Span{Start: 1, End: 20},
	})
	rule := Rule{ID: "T-071", Languages: []string{"go"}, Target: "gof.composite"}
	fs := &FactSet{TypeGraph: tg}
	ev := findCompositePattern(rule, fs)
	if len(ev) == 0 {
		t.Error("expected composite evidence for []*Type")
	}
}

func TestFindCompositePattern_Negative(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Leaf", Kind: "class", File: "l.go", Language: "go",
		Implements: []string{"Component"},
		Fields:     []typegraph.FieldInfo{{Name: "value", TypeName: "string"}},
		Span:       typegraph.Span{Start: 1, End: 10},
	})
	rule := Rule{ID: "T-072", Languages: []string{"go"}, Target: "gof.composite"}
	fs := &FactSet{TypeGraph: tg}
	ev := findCompositePattern(rule, fs)
	if len(ev) != 0 {
		t.Error("expected no composite evidence")
	}
}

// ---------------------------------------------------------------------------
// Structural: Decorator
// ---------------------------------------------------------------------------

func TestFindDecoratorPattern_Positive(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "LoggingHandler", Kind: "class", File: "lh.go", Language: "go",
		Implements: []string{"Handler"},
		Fields:     []typegraph.FieldInfo{{Name: "inner", TypeName: "Handler"}},
		Span:       typegraph.Span{Start: 1, End: 20},
	})
	rule := Rule{ID: "T-080", Languages: []string{"go"}, Target: "gof.decorator"}
	fs := &FactSet{TypeGraph: tg}
	ev := findDecoratorPattern(rule, fs)
	if len(ev) == 0 {
		t.Error("expected decorator evidence")
	}
}

func TestFindDecoratorPattern_Negative(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Handler", Kind: "class", File: "h.go", Language: "go",
		Implements: []string{"Processor"},
		Fields:     []typegraph.FieldInfo{{Name: "name", TypeName: "string"}},
		Span:       typegraph.Span{Start: 1, End: 10},
	})
	rule := Rule{ID: "T-081", Languages: []string{"go"}, Target: "gof.decorator"}
	fs := &FactSet{TypeGraph: tg}
	ev := findDecoratorPattern(rule, fs)
	if len(ev) != 0 {
		t.Error("expected no decorator evidence")
	}
}

// ---------------------------------------------------------------------------
// Structural: Facade
// ---------------------------------------------------------------------------

func TestFindFacadePattern_Positive(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{Name: "UserService", Kind: "class", File: "u.go", Language: "go", Span: typegraph.Span{Start: 1, End: 5}})
	tg.AddNode(&typegraph.TypeNode{Name: "OrderService", Kind: "class", File: "o.go", Language: "go", Span: typegraph.Span{Start: 1, End: 5}})
	tg.AddNode(&typegraph.TypeNode{Name: "PaymentService", Kind: "class", File: "p.go", Language: "go", Span: typegraph.Span{Start: 1, End: 5}})
	tg.AddNode(&typegraph.TypeNode{
		Name: "AppFacade", Kind: "class", File: "facade.go", Language: "go",
		Fields: []typegraph.FieldInfo{
			{Name: "users", TypeName: "UserService"},
			{Name: "orders", TypeName: "OrderService"},
			{Name: "payments", TypeName: "PaymentService"},
		},
		Span: typegraph.Span{Start: 1, End: 30},
	})
	rule := Rule{ID: "T-090", Languages: []string{"go"}, Target: "gof.facade"}
	fs := &FactSet{TypeGraph: tg}
	ev := findFacadePattern(rule, fs)
	if len(ev) == 0 {
		t.Error("expected facade evidence")
	}
}

func TestFindFacadePattern_Negative_TooFewFields(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{Name: "A", Kind: "class", File: "a.go", Language: "go", Span: typegraph.Span{Start: 1, End: 5}})
	tg.AddNode(&typegraph.TypeNode{
		Name: "Svc", Kind: "class", File: "svc.go", Language: "go",
		Fields: []typegraph.FieldInfo{
			{Name: "a", TypeName: "A"},
			{Name: "b", TypeName: "string"},
		},
		Span: typegraph.Span{Start: 1, End: 10},
	})
	rule := Rule{ID: "T-091", Languages: []string{"go"}, Target: "gof.facade"}
	fs := &FactSet{TypeGraph: tg}
	ev := findFacadePattern(rule, fs)
	if len(ev) != 0 {
		t.Error("expected no facade evidence with fewer than 3 known-type fields")
	}
}

// ---------------------------------------------------------------------------
// Structural: Flyweight
// ---------------------------------------------------------------------------

func TestFindFlyweightPattern_Positive(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "IconFactory", Kind: "class", File: "icon.go", Language: "go",
		Fields:  []typegraph.FieldInfo{{Name: "cache", TypeName: "map[string]*Icon"}},
		Methods: []typegraph.MethodInfo{{Name: "getOrCreate"}},
		Span:    typegraph.Span{Start: 1, End: 20},
	})
	rule := Rule{ID: "T-100", Languages: []string{"go"}, Target: "gof.flyweight"}
	fs := &FactSet{TypeGraph: tg}
	ev := findFlyweightPattern(rule, fs)
	if len(ev) == 0 {
		t.Error("expected flyweight evidence")
	}
}

func TestFindFlyweightPattern_Negative_NoMap(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Factory", Kind: "class", File: "f.go", Language: "go",
		Fields:  []typegraph.FieldInfo{{Name: "items", TypeName: "[]Item"}},
		Methods: []typegraph.MethodInfo{{Name: "get"}},
		Span:    typegraph.Span{Start: 1, End: 10},
	})
	rule := Rule{ID: "T-101", Languages: []string{"go"}, Target: "gof.flyweight"}
	fs := &FactSet{TypeGraph: tg}
	ev := findFlyweightPattern(rule, fs)
	if len(ev) != 0 {
		t.Error("expected no flyweight evidence without map field")
	}
}

// ---------------------------------------------------------------------------
// Structural: Proxy
// ---------------------------------------------------------------------------

func TestFindProxyPattern_Positive(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "CachingProxy", Kind: "class", File: "proxy.go", Language: "go",
		Implements: []string{"DataSource"},
		Fields:     []typegraph.FieldInfo{{Name: "real", TypeName: "DataSource"}},
		Span:       typegraph.Span{Start: 1, End: 20},
	})
	rule := Rule{ID: "T-110", Languages: []string{"go"}, Target: "gof.proxy"}
	fs := &FactSet{TypeGraph: tg}
	ev := findProxyPattern(rule, fs)
	if len(ev) == 0 {
		t.Error("expected proxy evidence")
	}
}

func TestFindProxyPattern_Negative(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Simple", Kind: "class", File: "s.go", Language: "go",
		Implements: []string{"Iface"},
		Fields:     []typegraph.FieldInfo{{Name: "val", TypeName: "int"}},
		Span:       typegraph.Span{Start: 1, End: 10},
	})
	rule := Rule{ID: "T-111", Languages: []string{"go"}, Target: "gof.proxy"}
	fs := &FactSet{TypeGraph: tg}
	ev := findProxyPattern(rule, fs)
	if len(ev) != 0 {
		t.Error("expected no proxy evidence")
	}
}

// ---------------------------------------------------------------------------
// Structural: isPrimitiveType / isCollectionOf
// ---------------------------------------------------------------------------

func TestIsPrimitiveType(t *testing.T) {
	primitives := []string{"string", "int", "bool", "float64", "error", "any", "void", "None"}
	for _, p := range primitives {
		if !isPrimitiveType(p) {
			t.Errorf("expected %q to be primitive", p)
		}
	}
	nonPrimitives := []string{"MyClass", "Handler", "io.Reader", ""}
	for _, np := range nonPrimitives {
		if isPrimitiveType(np) {
			t.Errorf("expected %q to not be primitive", np)
		}
	}
}

func TestIsCollectionOf(t *testing.T) {
	cases := []struct {
		typeName, elem string
		want           bool
	}{
		{"[]Foo", "Foo", true},
		{"[]*Foo", "Foo", true},
		{"List<Foo>", "Foo", true},
		{"ArrayList<Foo>", "Foo", true},
		{"Array<Foo>", "Foo", true},
		{"string", "Foo", false},
		{"[]Bar", "Foo", false},
		{"int", "int", false},
	}
	for _, c := range cases {
		got := isCollectionOf(c.typeName, c.elem)
		if got != c.want {
			t.Errorf("isCollectionOf(%q, %q) = %v, want %v", c.typeName, c.elem, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Behavioral: Chain of Responsibility
// ---------------------------------------------------------------------------

func TestFindChainOfResponsibilityPattern_Positive(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "AuthHandler", Kind: "class", File: "auth.go", Language: "go",
		Fields:  []typegraph.FieldInfo{{Name: "next", TypeName: "*AuthHandler"}},
		Methods: []typegraph.MethodInfo{{Name: "handle"}},
		Span:    typegraph.Span{Start: 1, End: 20},
	})
	rule := Rule{ID: "T-120", Languages: []string{"go"}, Target: "gof.chain_of_responsibility"}
	fs := &FactSet{TypeGraph: tg}
	ev := findChainOfResponsibilityPattern(rule, fs)
	if len(ev) == 0 {
		t.Error("expected chain of responsibility evidence")
	}
}

func TestFindChainOfResponsibilityPattern_Positive_Interface(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Logger", Kind: "class", File: "log.go", Language: "go",
		Implements: []string{"Handler"},
		Fields:     []typegraph.FieldInfo{{Name: "next", TypeName: "Handler"}},
		Methods:    []typegraph.MethodInfo{{Name: "process"}},
		Span:       typegraph.Span{Start: 1, End: 20},
	})
	rule := Rule{ID: "T-121", Languages: []string{"go"}, Target: "gof.chain_of_responsibility"}
	fs := &FactSet{TypeGraph: tg}
	ev := findChainOfResponsibilityPattern(rule, fs)
	if len(ev) == 0 {
		t.Error("expected chain evidence via interface field")
	}
}

func TestFindChainOfResponsibilityPattern_Negative(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Worker", Kind: "class", File: "w.go", Language: "go",
		Fields:  []typegraph.FieldInfo{{Name: "name", TypeName: "string"}},
		Methods: []typegraph.MethodInfo{{Name: "handle"}},
		Span:    typegraph.Span{Start: 1, End: 10},
	})
	rule := Rule{ID: "T-122", Languages: []string{"go"}, Target: "gof.chain_of_responsibility"}
	fs := &FactSet{TypeGraph: tg}
	ev := findChainOfResponsibilityPattern(rule, fs)
	if len(ev) != 0 {
		t.Error("expected no chain evidence without next field")
	}
}

// ---------------------------------------------------------------------------
// Behavioral: Command
// ---------------------------------------------------------------------------

func TestFindCommandPattern_Positive(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Command", Kind: "interface", File: "cmd.go", Language: "go",
		Methods: []typegraph.MethodInfo{{Name: "Execute"}},
		Span:    typegraph.Span{Start: 1, End: 5},
	})
	tg.AddNode(&typegraph.TypeNode{
		Name: "PrintCmd", Kind: "class", File: "print.go", Language: "go",
		Implements: []string{"Command"},
		Span:       typegraph.Span{Start: 1, End: 10},
	})
	rule := Rule{ID: "T-130", Languages: []string{"go"}, Target: "gof.command"}
	fs := &FactSet{TypeGraph: tg}
	ev := findCommandPattern(rule, fs)
	if len(ev) == 0 {
		t.Error("expected command evidence")
	}
}

func TestFindCommandPattern_Negative_TwoMethods(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Action", Kind: "interface", File: "a.go", Language: "go",
		Methods: []typegraph.MethodInfo{{Name: "Execute"}, {Name: "Undo"}},
		Span:    typegraph.Span{Start: 1, End: 5},
	})
	rule := Rule{ID: "T-131", Languages: []string{"go"}, Target: "gof.command"}
	fs := &FactSet{TypeGraph: tg}
	ev := findCommandPattern(rule, fs)
	if len(ev) != 0 {
		t.Error("expected no command evidence for interface with 2 methods")
	}
}

func TestFindCommandPattern_Negative_WrongMethodName(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Task", Kind: "interface", File: "t.go", Language: "go",
		Methods: []typegraph.MethodInfo{{Name: "Process"}},
		Span:    typegraph.Span{Start: 1, End: 5},
	})
	tg.AddNode(&typegraph.TypeNode{
		Name: "MyTask", Kind: "class", File: "mt.go", Language: "go",
		Implements: []string{"Task"},
		Span:       typegraph.Span{Start: 1, End: 10},
	})
	rule := Rule{ID: "T-132", Languages: []string{"go"}, Target: "gof.command"}
	fs := &FactSet{TypeGraph: tg}
	ev := findCommandPattern(rule, fs)
	if len(ev) != 0 {
		t.Error("expected no command evidence for non-execute method")
	}
}

// ---------------------------------------------------------------------------
// Behavioral: Interpreter
// ---------------------------------------------------------------------------

func TestFindInterpreterPattern_Positive(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Expression", Kind: "interface", File: "expr.go", Language: "go",
		Methods: []typegraph.MethodInfo{{Name: "interpret"}},
		Span:    typegraph.Span{Start: 1, End: 5},
	})
	tg.AddNode(&typegraph.TypeNode{
		Name: "AddExpr", Kind: "class", File: "add.go", Language: "go",
		Implements: []string{"Expression"},
		Span:       typegraph.Span{Start: 1, End: 10},
	})
	tg.AddNode(&typegraph.TypeNode{
		Name: "SubExpr", Kind: "class", File: "sub.go", Language: "go",
		Implements: []string{"Expression"},
		Span:       typegraph.Span{Start: 1, End: 10},
	})
	rule := Rule{ID: "T-140", Languages: []string{"go"}, Target: "gof.interpreter"}
	fs := &FactSet{TypeGraph: tg}
	ev := findInterpreterPattern(rule, fs)
	if len(ev) == 0 {
		t.Error("expected interpreter evidence")
	}
}

func TestFindInterpreterPattern_Negative_OneImplementor(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Expr", Kind: "interface", File: "e.go", Language: "go",
		Methods: []typegraph.MethodInfo{{Name: "evaluate"}},
		Span:    typegraph.Span{Start: 1, End: 5},
	})
	tg.AddNode(&typegraph.TypeNode{
		Name: "Lit", Kind: "class", File: "l.go", Language: "go",
		Implements: []string{"Expr"},
		Span:       typegraph.Span{Start: 1, End: 10},
	})
	rule := Rule{ID: "T-141", Languages: []string{"go"}, Target: "gof.interpreter"}
	fs := &FactSet{TypeGraph: tg}
	ev := findInterpreterPattern(rule, fs)
	if len(ev) != 0 {
		t.Error("expected no interpreter evidence with only one implementor")
	}
}

// ---------------------------------------------------------------------------
// Behavioral: Iterator
// ---------------------------------------------------------------------------

func TestFindIteratorPattern_Positive(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "ListIter", Kind: "class", File: "iter.go", Language: "go",
		Methods: []typegraph.MethodInfo{{Name: "Next"}, {Name: "HasNext"}},
		Span:    typegraph.Span{Start: 1, End: 15},
	})
	rule := Rule{ID: "T-150", Languages: []string{"go"}, Target: "gof.iterator"}
	fs := &FactSet{TypeGraph: tg}
	ev := findIteratorPattern(rule, fs)
	if len(ev) == 0 {
		t.Error("expected iterator evidence")
	}
}

func TestFindIteratorPattern_Negative_OnlyNext(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Iter", Kind: "class", File: "i.go", Language: "go",
		Methods: []typegraph.MethodInfo{{Name: "Next"}},
		Span:    typegraph.Span{Start: 1, End: 10},
	})
	rule := Rule{ID: "T-151", Languages: []string{"go"}, Target: "gof.iterator"}
	fs := &FactSet{TypeGraph: tg}
	ev := findIteratorPattern(rule, fs)
	if len(ev) != 0 {
		t.Error("expected no iterator evidence with only Next")
	}
}

// ---------------------------------------------------------------------------
// Behavioral: Mediator
// ---------------------------------------------------------------------------

func TestFindMediatorPattern_Positive(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{Name: "UserService", Kind: "class", File: "u.go", Language: "go", Span: typegraph.Span{Start: 1, End: 5}})
	tg.AddNode(&typegraph.TypeNode{Name: "OrderService", Kind: "class", File: "o.go", Language: "go", Span: typegraph.Span{Start: 1, End: 5}})
	tg.AddNode(&typegraph.TypeNode{
		Name: "EventMediator", Kind: "class", File: "med.go", Language: "go",
		Fields: []typegraph.FieldInfo{
			{Name: "users", TypeName: "UserService"},
			{Name: "orders", TypeName: "OrderService"},
		},
		Span: typegraph.Span{Start: 1, End: 25},
	})
	rule := Rule{ID: "T-160", Languages: []string{"go"}, Target: "gof.mediator"}
	fs := &FactSet{TypeGraph: tg}
	ev := findMediatorPattern(rule, fs)
	if len(ev) == 0 {
		t.Error("expected mediator evidence")
	}
}

func TestFindMediatorPattern_Negative_WrongName(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{Name: "A", Kind: "class", File: "a.go", Language: "go", Span: typegraph.Span{Start: 1, End: 5}})
	tg.AddNode(&typegraph.TypeNode{Name: "B", Kind: "class", File: "b.go", Language: "go", Span: typegraph.Span{Start: 1, End: 5}})
	tg.AddNode(&typegraph.TypeNode{
		Name: "Manager", Kind: "class", File: "m.go", Language: "go",
		Fields: []typegraph.FieldInfo{
			{Name: "a", TypeName: "A"},
			{Name: "b", TypeName: "B"},
		},
		Span: typegraph.Span{Start: 1, End: 20},
	})
	rule := Rule{ID: "T-161", Languages: []string{"go"}, Target: "gof.mediator"}
	fs := &FactSet{TypeGraph: tg}
	ev := findMediatorPattern(rule, fs)
	if len(ev) != 0 {
		t.Error("expected no mediator evidence for class not named mediator/hub/coordinator")
	}
}

// ---------------------------------------------------------------------------
// Behavioral: Memento
// ---------------------------------------------------------------------------

func TestFindMementoPattern_Positive(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Editor", Kind: "class", File: "editor.go", Language: "go",
		Methods: []typegraph.MethodInfo{
			{Name: "save"},
			{Name: "restore"},
		},
		Span: typegraph.Span{Start: 1, End: 30},
	})
	rule := Rule{ID: "T-170", Languages: []string{"go"}, Target: "gof.memento"}
	fs := &FactSet{TypeGraph: tg}
	ev := findMementoPattern(rule, fs)
	if len(ev) == 0 {
		t.Error("expected memento evidence")
	}
}

func TestFindMementoPattern_Positive_Snapshot(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "State", Kind: "class", File: "state.go", Language: "go",
		Methods: []typegraph.MethodInfo{
			{Name: "snapshot"},
			{Name: "undo"},
		},
		Span: typegraph.Span{Start: 1, End: 20},
	})
	rule := Rule{ID: "T-171", Languages: []string{"go"}, Target: "gof.memento"}
	fs := &FactSet{TypeGraph: tg}
	ev := findMementoPattern(rule, fs)
	if len(ev) == 0 {
		t.Error("expected memento evidence for snapshot/undo")
	}
}

func TestFindMementoPattern_Negative(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Editor", Kind: "class", File: "e.go", Language: "go",
		Methods: []typegraph.MethodInfo{{Name: "save"}},
		Span:    typegraph.Span{Start: 1, End: 10},
	})
	rule := Rule{ID: "T-172", Languages: []string{"go"}, Target: "gof.memento"}
	fs := &FactSet{TypeGraph: tg}
	ev := findMementoPattern(rule, fs)
	if len(ev) != 0 {
		t.Error("expected no memento evidence without restore")
	}
}

// ---------------------------------------------------------------------------
// Behavioral: Observer
// ---------------------------------------------------------------------------

func TestFindObserverPattern_Positive(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "EventBus", Kind: "class", File: "bus.go", Language: "go",
		Methods: []typegraph.MethodInfo{
			{Name: "subscribe"},
			{Name: "notify"},
		},
		Span: typegraph.Span{Start: 1, End: 30},
	})
	rule := Rule{ID: "T-180", Languages: []string{"go"}, Target: "gof.observer"}
	fs := &FactSet{TypeGraph: tg}
	ev := findObserverPattern(rule, fs)
	if len(ev) == 0 {
		t.Error("expected observer evidence")
	}
}

func TestFindObserverPattern_Positive_EmitPublish(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Emitter", Kind: "class", File: "em.go", Language: "go",
		Methods: []typegraph.MethodInfo{
			{Name: "register"},
			{Name: "emit"},
		},
		Span: typegraph.Span{Start: 1, End: 20},
	})
	rule := Rule{ID: "T-181", Languages: []string{"go"}, Target: "gof.observer"}
	fs := &FactSet{TypeGraph: tg}
	ev := findObserverPattern(rule, fs)
	if len(ev) == 0 {
		t.Error("expected observer evidence for register/emit")
	}
}

func TestFindObserverPattern_Negative(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Logger", Kind: "class", File: "l.go", Language: "go",
		Methods: []typegraph.MethodInfo{{Name: "notify"}},
		Span:    typegraph.Span{Start: 1, End: 10},
	})
	rule := Rule{ID: "T-182", Languages: []string{"go"}, Target: "gof.observer"}
	fs := &FactSet{TypeGraph: tg}
	ev := findObserverPattern(rule, fs)
	if len(ev) != 0 {
		t.Error("expected no observer evidence without subscribe/attach")
	}
}

// ---------------------------------------------------------------------------
// Behavioral: State
// ---------------------------------------------------------------------------

func TestFindStatePattern_Positive(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "ConnectionState", Kind: "interface", File: "cs.go", Language: "go",
		Span: typegraph.Span{Start: 1, End: 5},
	})
	tg.AddNode(&typegraph.TypeNode{
		Name: "Connection", Kind: "class", File: "conn.go", Language: "go",
		Fields: []typegraph.FieldInfo{{Name: "state", TypeName: "ConnectionState"}},
		Methods: []typegraph.MethodInfo{
			{Name: "setState"},
		},
		Span: typegraph.Span{Start: 1, End: 30},
	})
	rule := Rule{ID: "T-190", Languages: []string{"go"}, Target: "gof.state"}
	fs := &FactSet{TypeGraph: tg}
	ev := findStatePattern(rule, fs)
	if len(ev) == 0 {
		t.Error("expected state evidence")
	}
}

func TestFindStatePattern_Negative_NoSetState(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "State", Kind: "interface", File: "s.go", Language: "go",
		Span: typegraph.Span{Start: 1, End: 5},
	})
	tg.AddNode(&typegraph.TypeNode{
		Name: "Ctx", Kind: "class", File: "ctx.go", Language: "go",
		Fields:  []typegraph.FieldInfo{{Name: "state", TypeName: "State"}},
		Methods: []typegraph.MethodInfo{{Name: "doWork"}},
		Span:    typegraph.Span{Start: 1, End: 20},
	})
	rule := Rule{ID: "T-191", Languages: []string{"go"}, Target: "gof.state"}
	fs := &FactSet{TypeGraph: tg}
	ev := findStatePattern(rule, fs)
	if len(ev) != 0 {
		t.Error("expected no state evidence without setState method")
	}
}

func TestFindStatePattern_Negative_NonInterfaceField(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Machine", Kind: "class", File: "m.go", Language: "go",
		Fields:  []typegraph.FieldInfo{{Name: "state", TypeName: "string"}},
		Methods: []typegraph.MethodInfo{{Name: "setState"}},
		Span:    typegraph.Span{Start: 1, End: 20},
	})
	rule := Rule{ID: "T-192", Languages: []string{"go"}, Target: "gof.state"}
	fs := &FactSet{TypeGraph: tg}
	ev := findStatePattern(rule, fs)
	if len(ev) != 0 {
		t.Error("expected no state evidence for non-interface state field")
	}
}

// ---------------------------------------------------------------------------
// Behavioral: Strategy
// ---------------------------------------------------------------------------

func TestFindStrategyPattern_Positive(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "SortStrategy", Kind: "interface", File: "sort.go", Language: "go",
		Span: typegraph.Span{Start: 1, End: 5},
	})
	tg.AddNode(&typegraph.TypeNode{
		Name: "Sorter", Kind: "class", File: "sorter.go", Language: "go",
		Fields: []typegraph.FieldInfo{{Name: "strategy", TypeName: "SortStrategy"}},
		Span:   typegraph.Span{Start: 1, End: 20},
	})
	rule := Rule{ID: "T-200", Languages: []string{"go"}, Target: "gof.strategy"}
	fs := &FactSet{TypeGraph: tg}
	ev := findStrategyPattern(rule, fs)
	if len(ev) == 0 {
		t.Error("expected strategy evidence")
	}
}

func TestFindStrategyPattern_Positive_PolicyName(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "RetryPolicy", Kind: "interface", File: "rp.go", Language: "go",
		Span: typegraph.Span{Start: 1, End: 5},
	})
	tg.AddNode(&typegraph.TypeNode{
		Name: "Client", Kind: "class", File: "client.go", Language: "go",
		Fields: []typegraph.FieldInfo{{Name: "retryPolicy", TypeName: "RetryPolicy"}},
		Span:   typegraph.Span{Start: 1, End: 20},
	})
	rule := Rule{ID: "T-201", Languages: []string{"go"}, Target: "gof.strategy"}
	fs := &FactSet{TypeGraph: tg}
	ev := findStrategyPattern(rule, fs)
	if len(ev) == 0 {
		t.Error("expected strategy evidence for policy-named field")
	}
}

func TestFindStrategyPattern_Negative_NoKeyword(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Iface", Kind: "interface", File: "i.go", Language: "go",
		Span: typegraph.Span{Start: 1, End: 5},
	})
	tg.AddNode(&typegraph.TypeNode{
		Name: "Impl", Kind: "class", File: "impl.go", Language: "go",
		Fields: []typegraph.FieldInfo{{Name: "dep", TypeName: "Iface"}},
		Span:   typegraph.Span{Start: 1, End: 10},
	})
	rule := Rule{ID: "T-202", Languages: []string{"go"}, Target: "gof.strategy"}
	fs := &FactSet{TypeGraph: tg}
	ev := findStrategyPattern(rule, fs)
	if len(ev) != 0 {
		t.Error("expected no strategy evidence without strategy/policy/algorithm/handler keyword")
	}
}

// ---------------------------------------------------------------------------
// Behavioral: Template Method
// ---------------------------------------------------------------------------

func TestFindTemplateMethodPattern_Positive(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "DataMiner", Kind: "abstract_class", File: "dm.go", Language: "go",
		Methods: []typegraph.MethodInfo{
			{Name: "mine", IsAbstract: false},
			{Name: "extractData", IsAbstract: true},
		},
		Span: typegraph.Span{Start: 1, End: 30},
	})
	rule := Rule{ID: "T-210", Languages: []string{"go"}, Target: "gof.template_method"}
	fs := &FactSet{TypeGraph: tg}
	ev := findTemplateMethodPattern(rule, fs)
	if len(ev) == 0 {
		t.Error("expected template method evidence")
	}
}

func TestFindTemplateMethodPattern_Negative_NotAbstractClass(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Miner", Kind: "class", File: "m.go", Language: "go",
		Methods: []typegraph.MethodInfo{
			{Name: "mine", IsAbstract: false},
			{Name: "extract", IsAbstract: true},
		},
		Span: typegraph.Span{Start: 1, End: 20},
	})
	rule := Rule{ID: "T-211", Languages: []string{"go"}, Target: "gof.template_method"}
	fs := &FactSet{TypeGraph: tg}
	ev := findTemplateMethodPattern(rule, fs)
	if len(ev) != 0 {
		t.Error("expected no template method evidence for non-abstract class")
	}
}

func TestFindTemplateMethodPattern_Negative_AllAbstract(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Base", Kind: "abstract_class", File: "b.go", Language: "go",
		Methods: []typegraph.MethodInfo{
			{Name: "stepA", IsAbstract: true},
			{Name: "stepB", IsAbstract: true},
		},
		Span: typegraph.Span{Start: 1, End: 20},
	})
	rule := Rule{ID: "T-212", Languages: []string{"go"}, Target: "gof.template_method"}
	fs := &FactSet{TypeGraph: tg}
	ev := findTemplateMethodPattern(rule, fs)
	if len(ev) != 0 {
		t.Error("expected no template method evidence when all methods are abstract")
	}
}

// ---------------------------------------------------------------------------
// Behavioral: Visitor
// ---------------------------------------------------------------------------

func TestFindVisitorPattern_Positive_MultipleVisitMethods(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "ASTVisitor", Kind: "class", File: "visitor.go", Language: "go",
		Methods: []typegraph.MethodInfo{
			{Name: "visitExpr"},
			{Name: "visitStmt"},
		},
		Span: typegraph.Span{Start: 1, End: 30},
	})
	rule := Rule{ID: "T-220", Languages: []string{"go"}, Target: "gof.visitor"}
	fs := &FactSet{TypeGraph: tg}
	ev := findVisitorPattern(rule, fs)
	if len(ev) == 0 {
		t.Error("expected visitor evidence for multiple visit methods")
	}
}

func TestFindVisitorPattern_Positive_AcceptMethod(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "ExprNode", Kind: "class", File: "node.go", Language: "go",
		Methods: []typegraph.MethodInfo{
			{Name: "accept", Params: []typegraph.ParamInfo{{Name: "v", TypeName: "Visitor"}}},
		},
		Span: typegraph.Span{Start: 1, End: 15},
	})
	rule := Rule{ID: "T-221", Languages: []string{"go"}, Target: "gof.visitor"}
	fs := &FactSet{TypeGraph: tg}
	ev := findVisitorPattern(rule, fs)
	if len(ev) == 0 {
		t.Error("expected visitor evidence for accept method")
	}
}

func TestFindVisitorPattern_Negative(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Walker", Kind: "class", File: "w.go", Language: "go",
		Methods: []typegraph.MethodInfo{
			{Name: "visitNode"},
		},
		Span: typegraph.Span{Start: 1, End: 10},
	})
	rule := Rule{ID: "T-222", Languages: []string{"go"}, Target: "gof.visitor"}
	fs := &FactSet{TypeGraph: tg}
	ev := findVisitorPattern(rule, fs)
	if len(ev) != 0 {
		t.Error("expected no visitor evidence with only one visit method and no accept")
	}
}

func TestFindVisitorPattern_Negative_AcceptNoParams(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Node", Kind: "class", File: "n.go", Language: "go",
		Methods: []typegraph.MethodInfo{
			{Name: "accept", Params: nil},
		},
		Span: typegraph.Span{Start: 1, End: 10},
	})
	rule := Rule{ID: "T-223", Languages: []string{"go"}, Target: "gof.visitor"}
	fs := &FactSet{TypeGraph: tg}
	ev := findVisitorPattern(rule, fs)
	if len(ev) != 0 {
		t.Error("expected no visitor evidence for accept with no params")
	}
}

// ---------------------------------------------------------------------------
// findGoFEvidence — switch case dispatch coverage
// ---------------------------------------------------------------------------

func TestFindGoFEvidence_AllCreational(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Foo", Kind: "class", File: "foo.go", Language: "go",
		Span: typegraph.Span{Start: 1, End: 5},
	})
	fs := &FactSet{TypeGraph: tg}

	targets := []string{
		"gof.singleton", "gof.factory_method", "gof.abstract_factory",
		"gof.builder", "gof.prototype",
	}
	for _, target := range targets {
		rule := Rule{ID: "T-GOF", Languages: []string{"go"}, Target: target}
		// Just verify the dispatch works without panic
		_ = findGoFEvidence(rule, fs)
	}
}

func TestFindGoFEvidence_AllStructural(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Bar", Kind: "class", File: "bar.go", Language: "go",
		Span: typegraph.Span{Start: 1, End: 5},
	})
	fs := &FactSet{TypeGraph: tg}

	targets := []string{
		"gof.adapter", "gof.bridge", "gof.composite", "gof.decorator",
		"gof.facade", "gof.flyweight", "gof.proxy",
	}
	for _, target := range targets {
		rule := Rule{ID: "T-GOF", Languages: []string{"go"}, Target: target}
		_ = findGoFEvidence(rule, fs)
	}
}

func TestFindGoFEvidence_AllBehavioral(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Baz", Kind: "class", File: "baz.go", Language: "go",
		Span: typegraph.Span{Start: 1, End: 5},
	})
	fs := &FactSet{TypeGraph: tg}

	targets := []string{
		"gof.chain_of_responsibility", "gof.command", "gof.interpreter",
		"gof.iterator", "gof.mediator", "gof.memento", "gof.observer",
		"gof.state", "gof.strategy", "gof.template_method", "gof.visitor",
	}
	for _, target := range targets {
		rule := Rule{ID: "T-GOF", Languages: []string{"go"}, Target: target}
		_ = findGoFEvidence(rule, fs)
	}
}

func TestFindGoFEvidence_UnknownTarget(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "X", Kind: "class", File: "x.go", Language: "go",
		Span: typegraph.Span{Start: 1, End: 5},
	})
	fs := &FactSet{TypeGraph: tg}
	rule := Rule{ID: "T-GOF", Languages: []string{"go"}, Target: "gof.unknown"}
	ev := findGoFEvidence(rule, fs)
	if ev != nil {
		t.Errorf("expected nil for unknown GoF target, got %v", ev)
	}
}

// ---------------------------------------------------------------------------
// GoF pattern language filter branch coverage
// ---------------------------------------------------------------------------

func TestFindBridgePattern_LanguageFilter(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Renderer", Kind: "interface", File: "render.java", Language: "java",
		Methods: []typegraph.MethodInfo{{Name: "render"}},
		Span:    typegraph.Span{Start: 1, End: 5},
	})
	tg.AddNode(&typegraph.TypeNode{
		Name: "RendererA", Kind: "class", File: "a.java", Language: "java",
		Implements: []string{"Renderer"},
		Span:       typegraph.Span{Start: 1, End: 5},
	})
	tg.AddNode(&typegraph.TypeNode{
		Name: "RendererB", Kind: "class", File: "b.java", Language: "java",
		Implements: []string{"Renderer"},
		Span:       typegraph.Span{Start: 1, End: 5},
	})
	tg.AddNode(&typegraph.TypeNode{
		Name: "Shape", Kind: "class", File: "shape.java", Language: "java",
		Fields: []typegraph.FieldInfo{{Name: "renderer", TypeName: "Renderer"}},
		Span:   typegraph.Span{Start: 1, End: 10},
	})
	rule := Rule{ID: "T-BR", Languages: []string{"go"}, Target: "gof.bridge"}
	fs := &FactSet{TypeGraph: tg}
	ev := findBridgePattern(rule, fs)
	if len(ev) != 0 {
		t.Error("expected no evidence for language mismatch in bridge")
	}
}

func TestFindCompositePattern_LanguageFilter(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Component", Kind: "interface", File: "comp.java", Language: "java",
		Span: typegraph.Span{Start: 1, End: 5},
	})
	tg.AddNode(&typegraph.TypeNode{
		Name: "CompositeNode", Kind: "class", File: "comp.java", Language: "java",
		Implements: []string{"Component"},
		Fields:     []typegraph.FieldInfo{{Name: "children", TypeName: "[]Component"}},
		Span:       typegraph.Span{Start: 10, End: 20},
	})
	rule := Rule{ID: "T-COMP", Languages: []string{"go"}, Target: "gof.composite"}
	fs := &FactSet{TypeGraph: tg}
	ev := findCompositePattern(rule, fs)
	if len(ev) != 0 {
		t.Error("expected no evidence for language mismatch in composite")
	}
}

func TestFindDecoratorPattern_LanguageFilter(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Logger", Kind: "interface", File: "log.java", Language: "java",
		Span: typegraph.Span{Start: 1, End: 5},
	})
	tg.AddNode(&typegraph.TypeNode{
		Name: "LogDecorator", Kind: "class", File: "log.java", Language: "java",
		Implements: []string{"Logger"},
		Fields:     []typegraph.FieldInfo{{Name: "wrapped", TypeName: "Logger"}},
		Span:       typegraph.Span{Start: 10, End: 20},
	})
	rule := Rule{ID: "T-DEC", Languages: []string{"go"}, Target: "gof.decorator"}
	fs := &FactSet{TypeGraph: tg}
	ev := findDecoratorPattern(rule, fs)
	if len(ev) != 0 {
		t.Error("expected no evidence for language mismatch in decorator")
	}
}

func TestFindProxyPattern_LanguageFilter(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Service", Kind: "interface", File: "svc.java", Language: "java",
		Span: typegraph.Span{Start: 1, End: 5},
	})
	tg.AddNode(&typegraph.TypeNode{
		Name: "ServiceProxy", Kind: "class", File: "svc.java", Language: "java",
		Implements: []string{"Service"},
		Fields:     []typegraph.FieldInfo{{Name: "real", TypeName: "Service"}},
		Span:       typegraph.Span{Start: 10, End: 20},
	})
	rule := Rule{ID: "T-PRX", Languages: []string{"go"}, Target: "gof.proxy"}
	fs := &FactSet{TypeGraph: tg}
	ev := findProxyPattern(rule, fs)
	if len(ev) != 0 {
		t.Error("expected no evidence for language mismatch in proxy")
	}
}

func TestFindStrategyPattern_LanguageFilter(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Algorithm", Kind: "interface", File: "algo.java", Language: "java",
		Span: typegraph.Span{Start: 1, End: 5},
	})
	tg.AddNode(&typegraph.TypeNode{
		Name: "Context", Kind: "class", File: "ctx.java", Language: "java",
		Fields: []typegraph.FieldInfo{{Name: "strategy", TypeName: "Algorithm"}},
		Span:   typegraph.Span{Start: 1, End: 10},
	})
	rule := Rule{ID: "T-STRAT", Languages: []string{"go"}, Target: "gof.strategy"}
	fs := &FactSet{TypeGraph: tg}
	ev := findStrategyPattern(rule, fs)
	if len(ev) != 0 {
		t.Error("expected no evidence for language mismatch in strategy")
	}
}

func TestFindVisitorPattern_LanguageFilter(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Visitor", Kind: "class", File: "v.java", Language: "java",
		Methods: []typegraph.MethodInfo{
			{Name: "visitA"}, {Name: "visitB"},
		},
		Span: typegraph.Span{Start: 1, End: 10},
	})
	rule := Rule{ID: "T-VIS", Languages: []string{"go"}, Target: "gof.visitor"}
	fs := &FactSet{TypeGraph: tg}
	ev := findVisitorPattern(rule, fs)
	if len(ev) != 0 {
		t.Error("expected no evidence for language mismatch in visitor")
	}
}

func TestFindTemplateMethodPattern_LanguageFilter(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "AbstractBase", Kind: "abstract_class", File: "base.java", Language: "java",
		Methods: []typegraph.MethodInfo{
			{Name: "step1", IsAbstract: true},
			{Name: "execute", IsAbstract: false},
		},
		Span: typegraph.Span{Start: 1, End: 20},
	})
	rule := Rule{ID: "T-TMP", Languages: []string{"go"}, Target: "gof.template_method"}
	fs := &FactSet{TypeGraph: tg}
	ev := findTemplateMethodPattern(rule, fs)
	if len(ev) != 0 {
		t.Error("expected no evidence for language mismatch in template method")
	}
}

func TestFindCommandPattern_LanguageFilter(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Command", Kind: "interface", File: "cmd.java", Language: "java",
		Methods: []typegraph.MethodInfo{{Name: "execute"}},
		Span:    typegraph.Span{Start: 1, End: 5},
	})
	rule := Rule{ID: "T-CMD", Languages: []string{"go"}, Target: "gof.command"}
	fs := &FactSet{TypeGraph: tg}
	ev := findCommandPattern(rule, fs)
	if len(ev) != 0 {
		t.Error("expected no evidence for language mismatch in command")
	}
}

func TestFindInterpreterPattern_LanguageFilter(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Expr", Kind: "interface", File: "expr.java", Language: "java",
		Methods: []typegraph.MethodInfo{{Name: "interpret"}},
		Span:    typegraph.Span{Start: 1, End: 5},
	})
	rule := Rule{ID: "T-INT", Languages: []string{"go"}, Target: "gof.interpreter"}
	fs := &FactSet{TypeGraph: tg}
	ev := findInterpreterPattern(rule, fs)
	if len(ev) != 0 {
		t.Error("expected no evidence for language mismatch in interpreter")
	}
}

func TestFindIteratorPattern_LanguageFilter(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Iter", Kind: "interface", File: "iter.java", Language: "java",
		Methods: []typegraph.MethodInfo{{Name: "next"}, {Name: "hasNext"}},
		Span:    typegraph.Span{Start: 1, End: 5},
	})
	rule := Rule{ID: "T-ITER", Languages: []string{"go"}, Target: "gof.iterator"}
	fs := &FactSet{TypeGraph: tg}
	ev := findIteratorPattern(rule, fs)
	if len(ev) != 0 {
		t.Error("expected no evidence for language mismatch in iterator")
	}
}

func TestFindMediatorPattern_LanguageFilter(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Mediator", Kind: "interface", File: "m.java", Language: "java",
		Methods: []typegraph.MethodInfo{{Name: "notify"}},
		Span:    typegraph.Span{Start: 1, End: 5},
	})
	rule := Rule{ID: "T-MED", Languages: []string{"go"}, Target: "gof.mediator"}
	fs := &FactSet{TypeGraph: tg}
	ev := findMediatorPattern(rule, fs)
	if len(ev) != 0 {
		t.Error("expected no evidence for language mismatch in mediator")
	}
}

func TestFindMementoPattern_LanguageFilter(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Memento", Kind: "class", File: "m.java", Language: "java",
		Span: typegraph.Span{Start: 1, End: 5},
	})
	rule := Rule{ID: "T-MEM", Languages: []string{"go"}, Target: "gof.memento"}
	fs := &FactSet{TypeGraph: tg}
	ev := findMementoPattern(rule, fs)
	if len(ev) != 0 {
		t.Error("expected no evidence for language mismatch in memento")
	}
}

func TestFindObserverPattern_LanguageFilter(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "EventBus", Kind: "class", File: "bus.java", Language: "java",
		Methods: []typegraph.MethodInfo{{Name: "subscribe"}, {Name: "notify"}},
		Span:    typegraph.Span{Start: 1, End: 10},
	})
	rule := Rule{ID: "T-OBS", Languages: []string{"go"}, Target: "gof.observer"}
	fs := &FactSet{TypeGraph: tg}
	ev := findObserverPattern(rule, fs)
	if len(ev) != 0 {
		t.Error("expected no evidence for language mismatch in observer")
	}
}

func TestFindStatePattern_LanguageFilter(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "State", Kind: "interface", File: "s.java", Language: "java",
		Span: typegraph.Span{Start: 1, End: 5},
	})
	tg.AddNode(&typegraph.TypeNode{
		Name: "Machine", Kind: "class", File: "m.java", Language: "java",
		Fields: []typegraph.FieldInfo{{Name: "state", TypeName: "State"}},
		Methods: []typegraph.MethodInfo{{Name: "setState"}},
		Span:    typegraph.Span{Start: 1, End: 10},
	})
	rule := Rule{ID: "T-STATE", Languages: []string{"go"}, Target: "gof.state"}
	fs := &FactSet{TypeGraph: tg}
	ev := findStatePattern(rule, fs)
	if len(ev) != 0 {
		t.Error("expected no evidence for language mismatch in state")
	}
}

func TestFindChainOfResponsibilityPattern_LanguageFilter(t *testing.T) {
	tg := typegraph.New()
	tg.AddNode(&typegraph.TypeNode{
		Name: "Handler", Kind: "class", File: "h.java", Language: "java",
		Fields: []typegraph.FieldInfo{{Name: "next", TypeName: "Handler"}},
		Span:   typegraph.Span{Start: 1, End: 10},
	})
	rule := Rule{ID: "T-COR", Languages: []string{"go"}, Target: "gof.chain_of_responsibility"}
	fs := &FactSet{TypeGraph: tg}
	ev := findChainOfResponsibilityPattern(rule, fs)
	if len(ev) != 0 {
		t.Error("expected no evidence for language mismatch in chain of responsibility")
	}
}
