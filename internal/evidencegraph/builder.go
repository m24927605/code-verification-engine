package evidencegraph

import (
	"fmt"

	"github.com/verabase/code-verification-engine/internal/analyzers"
	"github.com/verabase/code-verification-engine/internal/rules"
)

// BuildFromResults constructs an evidence graph from analyzer results and rule findings.
func BuildFromResults(results []*analyzers.AnalysisResult, findings []rules.Finding) *EvidenceGraph {
	g := New()

	for _, r := range results {
		addFactNodes(g, r)
	}

	for _, f := range findings {
		addFindingEdges(g, f)
	}

	addImplicitEdges(g)

	return g
}

func addFactNodes(g *EvidenceGraph, r *analyzers.AnalysisResult) {
	for _, f := range r.Files {
		g.AddNode(&EvidenceNode{
			Type: "file", File: f.File, LineStart: 1, LineEnd: f.LineCount,
			Language: string(f.Language), Source: "analyzer",
		})
	}
	for _, s := range r.Symbols {
		g.AddNode(&EvidenceNode{
			Type: "symbol", File: s.File, LineStart: s.Span.Start, LineEnd: s.Span.End,
			Symbol: s.Name, Language: string(s.Language), Source: "analyzer",
			Metadata: map[string]string{"kind": s.Kind, "exported": fmt.Sprintf("%v", s.Exported)},
		})
	}
	for _, i := range r.Imports {
		g.AddNode(&EvidenceNode{
			Type: "import", File: i.File, LineStart: i.Span.Start, LineEnd: i.Span.End,
			Symbol: i.ImportPath, Language: string(i.Language), Source: "analyzer",
		})
	}
	for _, route := range r.Routes {
		g.AddNode(&EvidenceNode{
			Type: "route", File: route.File, LineStart: route.Span.Start, LineEnd: route.Span.End,
			Symbol: route.Handler, Language: string(route.Language), Source: "analyzer",
			Metadata: map[string]string{"method": route.Method, "path": route.Path},
		})
	}
	for _, mw := range r.Middlewares {
		g.AddNode(&EvidenceNode{
			Type: "middleware", File: mw.File, LineStart: mw.Span.Start, LineEnd: mw.Span.End,
			Symbol: mw.Name, Language: string(mw.Language), Source: "analyzer",
			Metadata: map[string]string{"kind": mw.Kind},
		})
	}
	for _, test := range r.Tests {
		g.AddNode(&EvidenceNode{
			Type: "test", File: test.File, LineStart: test.Span.Start, LineEnd: test.Span.End,
			Symbol: test.TestName, Language: string(test.Language), Source: "analyzer",
			Metadata: map[string]string{"target_module": test.TargetModule},
		})
	}
	for _, da := range r.DataAccess {
		g.AddNode(&EvidenceNode{
			Type: "data_access", File: da.File, LineStart: da.Span.Start, LineEnd: da.Span.End,
			Symbol: da.Operation, Language: string(da.Language), Source: "analyzer",
			Metadata: map[string]string{"backend": da.Backend},
		})
	}
	for _, s := range r.Secrets {
		g.AddNode(&EvidenceNode{
			Type: "secret", File: s.File, LineStart: s.Span.Start, LineEnd: s.Span.End,
			Symbol: s.Kind, Language: string(s.Language), Source: "analyzer",
			Metadata: map[string]string{"kind": s.Kind},
		})
	}
}

func addFindingEdges(g *EvidenceGraph, f rules.Finding) {
	// Create a virtual node for each rule finding
	ruleNodeID := "finding:" + f.RuleID
	if _, exists := g.Nodes[ruleNodeID]; !exists {
		g.AddNode(&EvidenceNode{
			ID: ruleNodeID, Type: "finding",
			Symbol: f.RuleID, Source: "engine",
			Metadata: map[string]string{"status": string(f.Status)},
		})
	}

	for _, ev := range f.Evidence {
		// Find matching node by file + line range
		nodeID := ""
		for id, node := range g.Nodes {
			if node.File == ev.File && node.LineStart == ev.LineStart && node.LineEnd == ev.LineEnd {
				nodeID = id
				break
			}
		}
		if nodeID == "" {
			// Create node for evidence not from analyzer
			node := &EvidenceNode{
				Type: "rule_evidence", File: ev.File,
				LineStart: ev.LineStart, LineEnd: ev.LineEnd,
				Symbol: ev.Symbol, Source: "rule:" + f.RuleID,
				Excerpt: ev.Excerpt,
			}
			g.AddNode(node)
			nodeID = node.ID
		}

		relation := "supports"
		if f.Status == rules.StatusFail {
			relation = "contradicts"
		}
		weight := 1.0
		switch f.Confidence {
		case rules.ConfidenceMedium:
			weight = 0.7
		case rules.ConfidenceLow:
			weight = 0.4
		}

		g.AddEdge(EvidenceEdge{
			FromID: nodeID, ToID: ruleNodeID,
			Relation: relation, Rule: f.RuleID, Weight: weight,
		})
	}
}

func addImplicitEdges(g *EvidenceGraph) {
	imports := make(map[string][]*EvidenceNode)
	symbols := make(map[string][]*EvidenceNode)
	for _, n := range g.Nodes {
		switch n.Type {
		case "import":
			imports[n.File] = append(imports[n.File], n)
		case "symbol":
			symbols[n.File] = append(symbols[n.File], n)
		}
	}
	for file, fileImports := range imports {
		for _, imp := range fileImports {
			for _, sym := range symbols[file] {
				g.AddEdge(EvidenceEdge{
					FromID: imp.ID, ToID: sym.ID,
					Relation: "related_to", Weight: 0.3,
				})
			}
		}
	}
}
