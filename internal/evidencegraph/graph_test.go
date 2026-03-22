package evidencegraph

import (
	"sort"
	"testing"

	"github.com/verabase/code-verification-engine/internal/analyzers"
	"github.com/verabase/code-verification-engine/internal/facts"
	"github.com/verabase/code-verification-engine/internal/rules"
)

func TestAddNodeDeduplication(t *testing.T) {
	g := New()
	node := &EvidenceNode{
		Type: "symbol", File: "main.go", LineStart: 10, LineEnd: 20,
		Symbol: "HandleLogin", Language: "go", Source: "analyzer",
	}
	g.AddNode(node)
	g.AddNode(node) // duplicate

	if g.NodeCount() != 1 {
		t.Errorf("expected 1 node after dedup, got %d", g.NodeCount())
	}
}

func TestAddNodeGeneratesID(t *testing.T) {
	g := New()
	node := &EvidenceNode{
		Type: "import", File: "auth.go", LineStart: 3, LineEnd: 3,
		Symbol: "github.com/golang-jwt/jwt", Language: "go", Source: "analyzer",
	}
	g.AddNode(node)

	if node.ID == "" {
		t.Error("expected non-empty ID after AddNode")
	}
	if _, ok := g.Nodes[node.ID]; !ok {
		t.Error("node not found in graph by generated ID")
	}
}

func TestAddEdge(t *testing.T) {
	g := New()
	g.AddNode(&EvidenceNode{ID: "a", Type: "import", File: "f.go"})
	g.AddNode(&EvidenceNode{ID: "b", Type: "symbol", File: "f.go"})
	g.AddEdge(EvidenceEdge{FromID: "a", ToID: "b", Relation: "supports", Weight: 1.0})

	if g.EdgeCount() != 1 {
		t.Errorf("expected 1 edge, got %d", g.EdgeCount())
	}
}

func TestNodesForFile(t *testing.T) {
	g := New()
	g.AddNode(&EvidenceNode{ID: "a", Type: "symbol", File: "auth.go"})
	g.AddNode(&EvidenceNode{ID: "b", Type: "import", File: "auth.go"})
	g.AddNode(&EvidenceNode{ID: "c", Type: "symbol", File: "main.go"})

	nodes := g.NodesForFile("auth.go")
	if len(nodes) != 2 {
		t.Errorf("expected 2 nodes for auth.go, got %d", len(nodes))
	}

	nodes = g.NodesForFile("main.go")
	if len(nodes) != 1 {
		t.Errorf("expected 1 node for main.go, got %d", len(nodes))
	}

	nodes = g.NodesForFile("nonexistent.go")
	if len(nodes) != 0 {
		t.Errorf("expected 0 nodes for nonexistent file, got %d", len(nodes))
	}
}

func TestSupportingNodes(t *testing.T) {
	g := New()
	g.AddNode(&EvidenceNode{ID: "ev1", Type: "import", File: "f.go"})
	g.AddNode(&EvidenceNode{ID: "ev2", Type: "symbol", File: "f.go"})
	g.AddNode(&EvidenceNode{ID: "finding1", Type: "finding", File: ""})
	g.AddEdge(EvidenceEdge{FromID: "ev1", ToID: "finding1", Relation: "supports", Weight: 1.0})
	g.AddEdge(EvidenceEdge{FromID: "ev2", ToID: "finding1", Relation: "related_to", Weight: 0.5})

	supporting := g.SupportingNodes("finding1")
	if len(supporting) != 1 {
		t.Errorf("expected 1 supporting node, got %d", len(supporting))
	}
	if supporting[0].ID != "ev1" {
		t.Errorf("expected supporting node ev1, got %s", supporting[0].ID)
	}
}

func TestContradictingNodes(t *testing.T) {
	g := New()
	g.AddNode(&EvidenceNode{ID: "ev1", Type: "import", File: "f.go"})
	g.AddNode(&EvidenceNode{ID: "ev2", Type: "symbol", File: "f.go"})
	g.AddNode(&EvidenceNode{ID: "finding1", Type: "finding", File: ""})
	g.AddEdge(EvidenceEdge{FromID: "ev1", ToID: "finding1", Relation: "contradicts", Weight: 1.0})
	g.AddEdge(EvidenceEdge{FromID: "ev2", ToID: "finding1", Relation: "supports", Weight: 1.0})

	contradicting := g.ContradictingNodes("finding1")
	if len(contradicting) != 1 {
		t.Errorf("expected 1 contradicting node, got %d", len(contradicting))
	}
	if contradicting[0].ID != "ev1" {
		t.Errorf("expected contradicting node ev1, got %s", contradicting[0].ID)
	}
}

func TestGenerateIDDeterminism(t *testing.T) {
	node := &EvidenceNode{
		Type: "symbol", File: "auth.go", LineStart: 10, LineEnd: 25,
		Symbol: "ValidateToken", Language: "go",
	}
	id1 := GenerateID(node)
	id2 := GenerateID(node)
	if id1 != id2 {
		t.Errorf("GenerateID not deterministic: %s != %s", id1, id2)
	}

	// Different content should produce different IDs
	node2 := &EvidenceNode{
		Type: "symbol", File: "auth.go", LineStart: 10, LineEnd: 25,
		Symbol: "ParseToken", Language: "go",
	}
	id3 := GenerateID(node2)
	if id1 == id3 {
		t.Error("different nodes should produce different IDs")
	}
}

func TestUniqueFiles(t *testing.T) {
	g := New()
	g.AddNode(&EvidenceNode{ID: "a", Type: "symbol", File: "auth.go"})
	g.AddNode(&EvidenceNode{ID: "b", Type: "import", File: "auth.go"})
	g.AddNode(&EvidenceNode{ID: "c", Type: "symbol", File: "main.go"})
	g.AddNode(&EvidenceNode{ID: "d", Type: "finding", File: ""}) // no file

	files := g.UniqueFiles()
	sort.Strings(files)
	if len(files) != 2 {
		t.Errorf("expected 2 unique files, got %d: %v", len(files), files)
	}
	if files[0] != "auth.go" || files[1] != "main.go" {
		t.Errorf("unexpected files: %v", files)
	}
}

func TestNodesForRule(t *testing.T) {
	g := New()
	g.AddNode(&EvidenceNode{ID: "ev1", Type: "import", File: "f.go"})
	g.AddNode(&EvidenceNode{ID: "ev2", Type: "symbol", File: "f.go"})
	g.AddEdge(EvidenceEdge{FromID: "ev1", ToID: "ev2", Relation: "supports", Rule: "AUTH-001", Weight: 1.0})

	nodes := g.NodesForRule("AUTH-001")
	if len(nodes) != 1 {
		t.Errorf("expected 1 node for rule AUTH-001, got %d", len(nodes))
	}
}

func TestBuildFromResults(t *testing.T) {
	results := []*analyzers.AnalysisResult{
		{
			Files: []facts.FileFact{
				{Language: facts.LangGo, File: "auth.go", LineCount: 100},
			},
			Symbols: []facts.SymbolFact{
				{Language: facts.LangGo, File: "auth.go", Span: facts.Span{Start: 10, End: 25}, Name: "ValidateToken", Kind: "function", Exported: true},
			},
			Imports: []facts.ImportFact{
				{Language: facts.LangGo, File: "auth.go", Span: facts.Span{Start: 3, End: 3}, ImportPath: "github.com/golang-jwt/jwt"},
			},
		},
	}

	findings := []rules.Finding{
		{
			RuleID:     "AUTH-001",
			Status:     rules.StatusPass,
			Confidence: rules.ConfidenceHigh,
			Message:    "JWT authentication found",
			Evidence: []rules.Evidence{
				{File: "auth.go", LineStart: 3, LineEnd: 3, Symbol: "jwt"},
			},
		},
	}

	graph := BuildFromResults(results, findings)

	// Should have: 1 file + 1 symbol + 1 import + 1 finding node = 4
	// The evidence from the finding matches the import node (same file/lines)
	if graph.NodeCount() < 4 {
		t.Errorf("expected at least 4 nodes, got %d", graph.NodeCount())
	}

	// Should have edges: import→symbol (implicit), evidence→finding
	if graph.EdgeCount() < 2 {
		t.Errorf("expected at least 2 edges, got %d", graph.EdgeCount())
	}

	// Check file index
	authNodes := graph.NodesForFile("auth.go")
	if len(authNodes) < 3 {
		t.Errorf("expected at least 3 nodes in auth.go, got %d", len(authNodes))
	}

	// Check finding node exists
	findingNode, ok := graph.Nodes["finding:AUTH-001"]
	if !ok {
		t.Error("expected finding:AUTH-001 node in graph")
	} else if findingNode.Metadata["status"] != "pass" {
		t.Errorf("expected finding status pass, got %s", findingNode.Metadata["status"])
	}
}

func TestBuildFromResultsFailFinding(t *testing.T) {
	results := []*analyzers.AnalysisResult{}
	findings := []rules.Finding{
		{
			RuleID:     "SEC-001",
			Status:     rules.StatusFail,
			Confidence: rules.ConfidenceMedium,
			Message:    "Hardcoded secret found",
			Evidence: []rules.Evidence{
				{File: "config.go", LineStart: 5, LineEnd: 5, Symbol: "API_KEY"},
			},
		},
	}

	graph := BuildFromResults(results, findings)

	// Should have: 1 rule_evidence node + 1 finding node
	if graph.NodeCount() != 2 {
		t.Errorf("expected 2 nodes, got %d", graph.NodeCount())
	}

	// Edge should be "contradicts" for fail status
	if graph.EdgeCount() != 1 {
		t.Fatalf("expected 1 edge, got %d", graph.EdgeCount())
	}
	if graph.Edges[0].Relation != "contradicts" {
		t.Errorf("expected contradicts relation for fail finding, got %s", graph.Edges[0].Relation)
	}
	if graph.Edges[0].Weight != 0.7 {
		t.Errorf("expected weight 0.7 for medium confidence, got %f", graph.Edges[0].Weight)
	}
}

func TestBuildFromResultsAllFactTypes(t *testing.T) {
	results := []*analyzers.AnalysisResult{
		{
			Files: []facts.FileFact{
				{Language: facts.LangGo, File: "main.go", LineCount: 50},
			},
			Symbols: []facts.SymbolFact{
				{Language: facts.LangGo, File: "main.go", Span: facts.Span{Start: 1, End: 10}, Name: "HandleRequest", Kind: "function", Exported: true},
			},
			Imports: []facts.ImportFact{
				{Language: facts.LangGo, File: "main.go", Span: facts.Span{Start: 3, End: 3}, ImportPath: "net/http"},
			},
			Routes: []facts.RouteFact{
				{Language: facts.LangGo, File: "main.go", Span: facts.Span{Start: 15, End: 15}, Method: "GET", Path: "/api/v1", Handler: "HandleRequest"},
			},
			Middlewares: []facts.MiddlewareFact{
				{Language: facts.LangGo, File: "main.go", Span: facts.Span{Start: 20, End: 25}, Name: "AuthMiddleware", Kind: "handler"},
			},
			Tests: []facts.TestFact{
				{Language: facts.LangGo, File: "main_test.go", Span: facts.Span{Start: 1, End: 20}, TestName: "TestHandleRequest", TargetModule: "main"},
			},
			DataAccess: []facts.DataAccessFact{
				{Language: facts.LangGo, File: "repo.go", Span: facts.Span{Start: 10, End: 15}, Operation: "SELECT", Backend: "postgres"},
			},
			Secrets: []facts.SecretFact{
				{Language: facts.LangGo, File: "config.go", Span: facts.Span{Start: 5, End: 5}, Kind: "api_key"},
			},
		},
	}

	graph := BuildFromResults(results, nil)

	// Should have: 1 file + 1 symbol + 1 import + 1 route + 1 middleware + 1 test + 1 data_access + 1 secret = 8
	if graph.NodeCount() != 8 {
		t.Errorf("expected 8 nodes, got %d", graph.NodeCount())
	}

	// Verify route node has metadata
	found := false
	for _, n := range graph.Nodes {
		if n.Type == "route" {
			found = true
			if n.Metadata["method"] != "GET" {
				t.Errorf("route method = %s, want GET", n.Metadata["method"])
			}
			if n.Metadata["path"] != "/api/v1" {
				t.Errorf("route path = %s, want /api/v1", n.Metadata["path"])
			}
		}
	}
	if !found {
		t.Error("route node not found")
	}

	// Verify middleware node
	for _, n := range graph.Nodes {
		if n.Type == "middleware" {
			if n.Symbol != "AuthMiddleware" {
				t.Errorf("middleware symbol = %s, want AuthMiddleware", n.Symbol)
			}
			if n.Metadata["kind"] != "handler" {
				t.Errorf("middleware kind = %s, want handler", n.Metadata["kind"])
			}
		}
	}

	// Verify test node
	for _, n := range graph.Nodes {
		if n.Type == "test" {
			if n.Metadata["target_module"] != "main" {
				t.Errorf("test target_module = %s, want main", n.Metadata["target_module"])
			}
		}
	}

	// Verify data_access node
	for _, n := range graph.Nodes {
		if n.Type == "data_access" {
			if n.Metadata["backend"] != "postgres" {
				t.Errorf("data_access backend = %s, want postgres", n.Metadata["backend"])
			}
		}
	}

	// Verify secret node
	for _, n := range graph.Nodes {
		if n.Type == "secret" {
			if n.Metadata["kind"] != "api_key" {
				t.Errorf("secret kind = %s, want api_key", n.Metadata["kind"])
			}
		}
	}
}

func TestBuildFromResultsLowConfidence(t *testing.T) {
	results := []*analyzers.AnalysisResult{}
	findings := []rules.Finding{
		{
			RuleID:     "TEST-001",
			Status:     rules.StatusPass,
			Confidence: rules.ConfidenceLow,
			Message:    "Weak evidence",
			Evidence: []rules.Evidence{
				{File: "test.go", LineStart: 1, LineEnd: 5, Symbol: "foo"},
			},
		},
	}

	graph := BuildFromResults(results, findings)

	// Should have low confidence weight = 0.4
	if graph.EdgeCount() != 1 {
		t.Fatalf("expected 1 edge, got %d", graph.EdgeCount())
	}
	if graph.Edges[0].Weight != 0.4 {
		t.Errorf("expected weight 0.4 for low confidence, got %f", graph.Edges[0].Weight)
	}
	if graph.Edges[0].Relation != "supports" {
		t.Errorf("expected supports relation, got %s", graph.Edges[0].Relation)
	}
}

func TestNewGraphEmptyEdges(t *testing.T) {
	g := New()
	if g.Edges == nil {
		t.Error("expected non-nil Edges slice")
	}
	if len(g.Edges) != 0 {
		t.Error("expected empty Edges slice")
	}
}
