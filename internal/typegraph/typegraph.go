package typegraph

// TypeNode represents a class, struct, or interface in the codebase.
type TypeNode struct {
	Name       string       `json:"name"`
	Kind       string       `json:"kind"` // "class", "interface", "struct", "abstract_class"
	File       string       `json:"file"`
	Language   string       `json:"language"`
	Exported   bool         `json:"exported"`
	Implements []string     `json:"implements,omitempty"`  // interface names
	Extends    string       `json:"extends,omitempty"`     // parent class
	Fields     []FieldInfo  `json:"fields,omitempty"`
	Methods    []MethodInfo `json:"methods,omitempty"`
	Span       Span         `json:"span"`
}

type Span struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

type FieldInfo struct {
	Name     string `json:"name"`
	TypeName string `json:"type_name"`
	IsPublic bool   `json:"is_public"`
	IsStatic bool   `json:"is_static"`
}

type MethodInfo struct {
	Name       string      `json:"name"`
	Params     []ParamInfo `json:"params,omitempty"`
	ReturnType string      `json:"return_type,omitempty"`
	IsAbstract bool        `json:"is_abstract"`
	IsStatic   bool        `json:"is_static"`
	IsPublic   bool        `json:"is_public"`
}

type ParamInfo struct {
	Name     string `json:"name"`
	TypeName string `json:"type_name"`
}

// TypeGraph holds all type information extracted from a codebase.
type TypeGraph struct {
	Nodes map[string]*TypeNode // key = "file:TypeName"
}

// New creates an empty TypeGraph.
func New() *TypeGraph {
	return &TypeGraph{Nodes: make(map[string]*TypeNode)}
}

// AddNode adds a type node to the graph.
func (g *TypeGraph) AddNode(node *TypeNode) {
	key := node.File + ":" + node.Name
	g.Nodes[key] = node
}

// FindByName returns all nodes matching a given type name.
func (g *TypeGraph) FindByName(name string) []*TypeNode {
	var result []*TypeNode
	for _, n := range g.Nodes {
		if n.Name == name {
			result = append(result, n)
		}
	}
	return result
}

// FindInterfaces returns all interface nodes.
func (g *TypeGraph) FindInterfaces() []*TypeNode {
	var result []*TypeNode
	for _, n := range g.Nodes {
		if n.Kind == "interface" {
			result = append(result, n)
		}
	}
	return result
}

// FindImplementors returns all types that implement a given interface name.
func (g *TypeGraph) FindImplementors(interfaceName string) []*TypeNode {
	var result []*TypeNode
	for _, n := range g.Nodes {
		for _, impl := range n.Implements {
			if impl == interfaceName {
				result = append(result, n)
				break
			}
		}
	}
	return result
}

// FindSubclasses returns all types that extend a given class name.
func (g *TypeGraph) FindSubclasses(className string) []*TypeNode {
	var result []*TypeNode
	for _, n := range g.Nodes {
		if n.Extends == className {
			result = append(result, n)
		}
	}
	return result
}

// FindClasses returns all class/struct nodes (non-interface).
func (g *TypeGraph) FindClasses() []*TypeNode {
	var result []*TypeNode
	for _, n := range g.Nodes {
		if n.Kind == "class" || n.Kind == "struct" || n.Kind == "abstract_class" {
			result = append(result, n)
		}
	}
	return result
}

// HasMethodNamed checks if a type has a method with the given name.
func (n *TypeNode) HasMethodNamed(name string) bool {
	for _, m := range n.Methods {
		if m.Name == name {
			return true
		}
	}
	return false
}

// HasFieldOfType checks if a type has a field of the given type name.
func (n *TypeNode) HasFieldOfType(typeName string) bool {
	for _, f := range n.Fields {
		if f.TypeName == typeName {
			return true
		}
	}
	return false
}

// HasFieldOfSameInterface checks if a type has a field whose type is one of its implemented interfaces.
func (n *TypeNode) HasFieldOfSameInterface() (string, bool) {
	for _, f := range n.Fields {
		for _, impl := range n.Implements {
			if f.TypeName == impl {
				return impl, true
			}
		}
	}
	return "", false
}

// CountMethodsReturning counts methods that return the given type name.
func (n *TypeNode) CountMethodsReturning(typeName string) int {
	count := 0
	for _, m := range n.Methods {
		if m.ReturnType == typeName {
			count++
		}
	}
	return count
}

// GetAbstractMethods returns abstract/unimplemented methods.
func (n *TypeNode) GetAbstractMethods() []MethodInfo {
	var result []MethodInfo
	for _, m := range n.Methods {
		if m.IsAbstract {
			result = append(result, m)
		}
	}
	return result
}

// MethodNames returns all method names.
func (n *TypeNode) MethodNames() []string {
	names := make([]string, len(n.Methods))
	for i, m := range n.Methods {
		names[i] = m.Name
	}
	return names
}
