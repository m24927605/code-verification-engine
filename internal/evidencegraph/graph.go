package evidencegraph

import (
	"crypto/sha256"
	"fmt"
)

// EvidenceNode represents a single piece of evidence in the graph.
type EvidenceNode struct {
	ID        string            `json:"id"`
	Type      string            `json:"type"`
	File      string            `json:"file"`
	LineStart int               `json:"line_start"`
	LineEnd   int               `json:"line_end"`
	Symbol    string            `json:"symbol,omitempty"`
	Excerpt   string            `json:"excerpt,omitempty"`
	Language  string            `json:"language"`
	Source    string            `json:"source"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// EvidenceEdge represents a relationship between evidence nodes.
type EvidenceEdge struct {
	FromID   string  `json:"from_id"`
	ToID     string  `json:"to_id"`
	Relation string  `json:"relation"`
	Rule     string  `json:"rule,omitempty"`
	Weight   float64 `json:"weight"`
}

// EvidenceGraph is the complete evidence structure for a scan.
type EvidenceGraph struct {
	Nodes map[string]*EvidenceNode `json:"nodes"`
	Edges []EvidenceEdge           `json:"edges"`

	nodesByFile map[string][]*EvidenceNode
	nodesByRule map[string][]*EvidenceNode
}

// New creates an empty evidence graph.
func New() *EvidenceGraph {
	return &EvidenceGraph{
		Nodes:       make(map[string]*EvidenceNode),
		Edges:       []EvidenceEdge{},
		nodesByFile: make(map[string][]*EvidenceNode),
		nodesByRule: make(map[string][]*EvidenceNode),
	}
}

// AddNode adds an evidence node. If a node with the same ID exists, it's deduplicated.
func (g *EvidenceGraph) AddNode(node *EvidenceNode) {
	if node.ID == "" {
		node.ID = GenerateID(node)
	}
	if _, exists := g.Nodes[node.ID]; exists {
		return
	}
	g.Nodes[node.ID] = node
	g.nodesByFile[node.File] = append(g.nodesByFile[node.File], node)
}

// AddEdge adds a relationship between two evidence nodes.
func (g *EvidenceGraph) AddEdge(edge EvidenceEdge) {
	g.Edges = append(g.Edges, edge)
	if edge.Rule != "" {
		if fromNode := g.Nodes[edge.FromID]; fromNode != nil {
			g.nodesByRule[edge.Rule] = append(g.nodesByRule[edge.Rule], fromNode)
		}
	}
}

// NodesForFile returns all evidence nodes in a given file.
func (g *EvidenceGraph) NodesForFile(file string) []*EvidenceNode {
	return g.nodesByFile[file]
}

// NodesForRule returns all evidence nodes associated with a rule.
func (g *EvidenceGraph) NodesForRule(ruleID string) []*EvidenceNode {
	return g.nodesByRule[ruleID]
}

// SupportingNodes returns nodes connected by "supports" edges to a given node.
func (g *EvidenceGraph) SupportingNodes(nodeID string) []*EvidenceNode {
	var result []*EvidenceNode
	for _, edge := range g.Edges {
		if edge.ToID == nodeID && edge.Relation == "supports" {
			if node, ok := g.Nodes[edge.FromID]; ok {
				result = append(result, node)
			}
		}
	}
	return result
}

// ContradictingNodes returns nodes connected by "contradicts" edges.
func (g *EvidenceGraph) ContradictingNodes(nodeID string) []*EvidenceNode {
	var result []*EvidenceNode
	for _, edge := range g.Edges {
		if edge.ToID == nodeID && edge.Relation == "contradicts" {
			if node, ok := g.Nodes[edge.FromID]; ok {
				result = append(result, node)
			}
		}
	}
	return result
}

// NodeCount returns the number of unique evidence nodes.
func (g *EvidenceGraph) NodeCount() int {
	return len(g.Nodes)
}

// EdgeCount returns the number of edges.
func (g *EvidenceGraph) EdgeCount() int {
	return len(g.Edges)
}

// UniqueFiles returns the set of files referenced in the graph.
func (g *EvidenceGraph) UniqueFiles() []string {
	files := make(map[string]bool)
	for _, n := range g.Nodes {
		if n.File != "" {
			files[n.File] = true
		}
	}
	result := make([]string, 0, len(files))
	for f := range files {
		result = append(result, f)
	}
	return result
}

// GenerateID creates a deterministic, content-derived identifier for an evidence node.
func GenerateID(node *EvidenceNode) string {
	content := fmt.Sprintf("%s:%s:%d:%d:%s:%s", node.Type, node.File, node.LineStart, node.LineEnd, node.Symbol, node.Language)
	hash := sha256.Sum256([]byte(content))
	return fmt.Sprintf("ev-%x", hash[:8])
}
