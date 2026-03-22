package rules

import "strings"

// findAdapterPattern detects the Adapter design pattern.
// Looks for: class that implements interface A AND has a field of type B (wrapping B to present as A).
func findAdapterPattern(rule Rule, fs *FactSet) []Evidence {
	var evidence []Evidence
	for _, node := range fs.TypeGraph.FindClasses() {
		if !languageMatch(node.Language, rule.Languages) {
			continue
		}
		if len(node.Implements) == 0 {
			continue
		}
		// Check if has a field whose type is another known class/interface (not primitive)
		for _, f := range node.Fields {
			// Skip primitive types
			if isPrimitiveType(f.TypeName) {
				continue
			}
			// Check it wraps a different type than what it implements
			isImplementedInterface := false
			for _, impl := range node.Implements {
				if f.TypeName == impl {
					isImplementedInterface = true
					break
				}
			}
			if !isImplementedInterface && fs.TypeGraph.FindByName(f.TypeName) != nil {
				evidence = append(evidence, Evidence{
					File:      node.File,
					LineStart: node.Span.Start,
					LineEnd:   node.Span.End,
					Symbol:    node.Name,
					Excerpt:   "Adapter pattern: implements interface while wrapping different type " + f.TypeName,
				})
				break
			}
		}
	}
	return evidence
}

// findBridgePattern detects the Bridge design pattern.
// Looks for: class with a field of interface type, where that interface has 2+ implementors.
func findBridgePattern(rule Rule, fs *FactSet) []Evidence {
	var evidence []Evidence
	interfaceNames := make(map[string]bool)
	for _, iface := range fs.TypeGraph.FindInterfaces() {
		interfaceNames[iface.Name] = true
	}
	for _, node := range fs.TypeGraph.FindClasses() {
		if !languageMatch(node.Language, rule.Languages) {
			continue
		}
		for _, f := range node.Fields {
			if !interfaceNames[f.TypeName] {
				continue
			}
			implementors := fs.TypeGraph.FindImplementors(f.TypeName)
			if len(implementors) >= 2 {
				evidence = append(evidence, Evidence{
					File:      node.File,
					LineStart: node.Span.Start,
					LineEnd:   node.Span.End,
					Symbol:    node.Name,
					Excerpt:   "Bridge pattern: class with interface field " + f.TypeName + " having multiple implementors",
				})
				break
			}
		}
	}
	return evidence
}

// findCompositePattern detects the Composite design pattern.
// Looks for: class implementing interface X + having a collection field of the same interface type.
func findCompositePattern(rule Rule, fs *FactSet) []Evidence {
	var evidence []Evidence
	for _, node := range fs.TypeGraph.FindClasses() {
		if !languageMatch(node.Language, rule.Languages) {
			continue
		}
		if len(node.Implements) == 0 {
			continue
		}
		for _, impl := range node.Implements {
			for _, f := range node.Fields {
				// Check for collection of the interface type: []Interface, List<Interface>, etc.
				if isCollectionOf(f.TypeName, impl) {
					evidence = append(evidence, Evidence{
						File:      node.File,
						LineStart: node.Span.Start,
						LineEnd:   node.Span.End,
						Symbol:    node.Name,
						Excerpt:   "Composite pattern: implements " + impl + " with collection field of same type",
					})
					break
				}
			}
		}
	}
	return evidence
}

// findDecoratorPattern detects the Decorator design pattern.
// Looks for: class implementing interface X + wrapping (field of) same interface X.
func findDecoratorPattern(rule Rule, fs *FactSet) []Evidence {
	var evidence []Evidence
	for _, node := range fs.TypeGraph.FindClasses() {
		if !languageMatch(node.Language, rule.Languages) {
			continue
		}
		if ifaceName, ok := node.HasFieldOfSameInterface(); ok {
			evidence = append(evidence, Evidence{
				File:      node.File,
				LineStart: node.Span.Start,
				LineEnd:   node.Span.End,
				Symbol:    node.Name,
				Excerpt:   "Decorator pattern: implements and wraps " + ifaceName,
			})
		}
	}
	return evidence
}

// findFacadePattern detects the Facade design pattern.
// Looks for: class that aggregates 3+ other classes/services as fields.
func findFacadePattern(rule Rule, fs *FactSet) []Evidence {
	var evidence []Evidence
	knownTypes := make(map[string]bool)
	for _, node := range fs.TypeGraph.Nodes {
		knownTypes[node.Name] = true
	}
	for _, node := range fs.TypeGraph.FindClasses() {
		if !languageMatch(node.Language, rule.Languages) {
			continue
		}
		classFieldCount := 0
		for _, f := range node.Fields {
			typeName := strings.TrimPrefix(f.TypeName, "*")
			if knownTypes[typeName] && typeName != node.Name {
				classFieldCount++
			}
		}
		if classFieldCount >= 3 {
			evidence = append(evidence, Evidence{
				File:      node.File,
				LineStart: node.Span.Start,
				LineEnd:   node.Span.End,
				Symbol:    node.Name,
				Excerpt:   "Facade pattern: aggregates 3+ other classes as fields",
			})
		}
	}
	return evidence
}

// findFlyweightPattern detects the Flyweight design pattern.
// Looks for: class with a cache map field + get/create methods.
func findFlyweightPattern(rule Rule, fs *FactSet) []Evidence {
	var evidence []Evidence
	for _, node := range fs.TypeGraph.FindClasses() {
		if !languageMatch(node.Language, rule.Languages) {
			continue
		}
		hasMapField := false
		for _, f := range node.Fields {
			if strings.Contains(f.TypeName, "map") || strings.Contains(f.TypeName, "Map") ||
				strings.Contains(f.TypeName, "dict") || strings.Contains(f.TypeName, "Dict") ||
				strings.Contains(f.TypeName, "HashMap") || strings.Contains(f.TypeName, "cache") ||
				strings.Contains(f.TypeName, "Cache") {
				hasMapField = true
				break
			}
		}
		if !hasMapField {
			continue
		}
		hasFactoryMethod := false
		for _, m := range node.Methods {
			nameLower := strings.ToLower(m.Name)
			if nameLower == "get" || nameLower == "getorcreate" || nameLower == "create" ||
				strings.HasPrefix(nameLower, "get") || nameLower == "acquire" {
				hasFactoryMethod = true
				break
			}
		}
		if hasFactoryMethod {
			evidence = append(evidence, Evidence{
				File:      node.File,
				LineStart: node.Span.Start,
				LineEnd:   node.Span.End,
				Symbol:    node.Name,
				Excerpt:   "Flyweight pattern: cache/map field with factory method",
			})
		}
	}
	return evidence
}

// findProxyPattern detects the Proxy design pattern.
// Same structure as Decorator: implements + wraps same interface.
func findProxyPattern(rule Rule, fs *FactSet) []Evidence {
	var evidence []Evidence
	for _, node := range fs.TypeGraph.FindClasses() {
		if !languageMatch(node.Language, rule.Languages) {
			continue
		}
		if ifaceName, ok := node.HasFieldOfSameInterface(); ok {
			evidence = append(evidence, Evidence{
				File:      node.File,
				LineStart: node.Span.Start,
				LineEnd:   node.Span.End,
				Symbol:    node.Name,
				Excerpt:   "Proxy pattern: implements and wraps " + ifaceName,
			})
		}
	}
	return evidence
}

// isPrimitiveType returns true for common primitive/built-in types.
func isPrimitiveType(typeName string) bool {
	primitives := map[string]bool{
		"string": true, "int": true, "int32": true, "int64": true,
		"float32": true, "float64": true, "bool": true, "byte": true,
		"error": true, "any": true, "interface{}": true,
		"String": true, "Integer": true, "Boolean": true, "Float": true, "Double": true,
		"number": true, "boolean": true, "void": true, "undefined": true, "null": true,
		"str": true, "float": true, "None": true,
	}
	return primitives[typeName]
}

// isCollectionOf checks if typeName represents a collection of the given element type.
func isCollectionOf(typeName string, elementType string) bool {
	return typeName == "[]"+elementType ||
		typeName == "[]*"+elementType ||
		strings.Contains(typeName, "List<"+elementType+">") ||
		strings.Contains(typeName, "ArrayList<"+elementType+">") ||
		strings.Contains(typeName, "[]"+elementType) ||
		strings.Contains(typeName, "Array<"+elementType+">") ||
		strings.Contains(typeName, "Slice<"+elementType+">") ||
		(strings.Contains(typeName, elementType) && (strings.Contains(typeName, "[]") || strings.Contains(typeName, "List")))
}
