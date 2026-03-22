package rules

import "strings"

// findSingletonPattern detects the Singleton design pattern.
// Looks for: private constructor + static getInstance method + static instance field,
// or Go pattern: unexported struct + exported New* function returning same type.
func findSingletonPattern(rule Rule, fs *FactSet) []Evidence {
	var evidence []Evidence
	for _, node := range fs.TypeGraph.Nodes {
		if !languageMatch(node.Language, rule.Languages) {
			continue
		}
		// Check for getInstance/GetInstance/Instance static method
		hasGetInstance := false
		for _, m := range node.Methods {
			nameLower := strings.ToLower(m.Name)
			if (nameLower == "getinstance" || nameLower == "instance") && m.IsStatic {
				hasGetInstance = true
				break
			}
		}
		// Check for static instance field
		hasStaticInstanceField := false
		for _, f := range node.Fields {
			if f.IsStatic && (strings.ToLower(f.Name) == "instance" || strings.Contains(strings.ToLower(f.TypeName), strings.ToLower(node.Name))) {
				hasStaticInstanceField = true
				break
			}
		}
		// Check for private/non-exported constructor pattern
		hasPrivateConstructor := false
		for _, m := range node.Methods {
			nameLower := strings.ToLower(m.Name)
			if (nameLower == "constructor" || nameLower == node.Name || strings.HasPrefix(nameLower, "__init")) && !m.IsPublic {
				hasPrivateConstructor = true
				break
			}
		}
		if hasGetInstance && (hasStaticInstanceField || hasPrivateConstructor) {
			evidence = append(evidence, Evidence{
				File:      node.File,
				LineStart: node.Span.Start,
				LineEnd:   node.Span.End,
				Symbol:    node.Name,
				Excerpt:   "Singleton pattern: static getInstance with private constructor or static instance field",
			})
		}
	}
	// Go pattern: look for unexported struct with New* function symbol returning that type
	if len(evidence) == 0 {
		for _, node := range fs.TypeGraph.Nodes {
			if node.Kind != "struct" || node.Exported {
				continue
			}
			for _, sym := range fs.Symbols {
				if sym.File != node.File {
					continue
				}
				if strings.HasPrefix(sym.Name, "New") && sym.Exported {
					evidence = append(evidence, Evidence{
						File:      node.File,
						LineStart: node.Span.Start,
						LineEnd:   node.Span.End,
						Symbol:    node.Name,
						Excerpt:   "Go singleton pattern: unexported struct with exported New* constructor",
					})
					break
				}
			}
		}
	}
	return evidence
}

// findFactoryMethodPattern detects the Factory Method design pattern.
// Looks for: interface with create*/make*/new* method with concrete subclass overrides,
// or standalone New* functions returning interface types.
func findFactoryMethodPattern(rule Rule, fs *FactSet) []Evidence {
	var evidence []Evidence
	for _, iface := range fs.TypeGraph.FindInterfaces() {
		if !languageMatch(iface.Language, rule.Languages) {
			continue
		}
		for _, m := range iface.Methods {
			nameLower := strings.ToLower(m.Name)
			if strings.HasPrefix(nameLower, "create") || strings.HasPrefix(nameLower, "make") || strings.HasPrefix(nameLower, "new") {
				implementors := fs.TypeGraph.FindImplementors(iface.Name)
				if len(implementors) > 0 {
					evidence = append(evidence, Evidence{
						File:      iface.File,
						LineStart: iface.Span.Start,
						LineEnd:   iface.Span.End,
						Symbol:    iface.Name + "." + m.Name,
						Excerpt:   "Factory method pattern: interface with factory method and implementors",
					})
				}
			}
		}
	}
	// Also match standalone factory functions returning interface types
	if len(evidence) == 0 {
		interfaceNames := make(map[string]bool)
		for _, iface := range fs.TypeGraph.FindInterfaces() {
			interfaceNames[iface.Name] = true
		}
		for _, sym := range fs.Symbols {
			if strings.HasPrefix(sym.Name, "New") && sym.Exported {
				// Check if any interface name is in the function name
				for ifName := range interfaceNames {
					if strings.Contains(sym.Name, ifName) {
						evidence = append(evidence, Evidence{
							File:      sym.File,
							LineStart: sym.Span.Start,
							LineEnd:   sym.Span.End,
							Symbol:    sym.Name,
							Excerpt:   "Factory function returning interface type",
						})
						break
					}
				}
			}
		}
	}
	return evidence
}

// findAbstractFactoryPattern detects the Abstract Factory design pattern.
// Looks for: interface with 2+ create*/make*/build* methods returning different types.
func findAbstractFactoryPattern(rule Rule, fs *FactSet) []Evidence {
	var evidence []Evidence
	for _, iface := range fs.TypeGraph.FindInterfaces() {
		if !languageMatch(iface.Language, rule.Languages) {
			continue
		}
		factoryMethods := 0
		returnTypes := make(map[string]bool)
		for _, m := range iface.Methods {
			nameLower := strings.ToLower(m.Name)
			if strings.HasPrefix(nameLower, "create") || strings.HasPrefix(nameLower, "make") || strings.HasPrefix(nameLower, "build") {
				factoryMethods++
				if m.ReturnType != "" {
					returnTypes[m.ReturnType] = true
				}
			}
		}
		if factoryMethods >= 2 && len(returnTypes) >= 2 {
			evidence = append(evidence, Evidence{
				File:      iface.File,
				LineStart: iface.Span.Start,
				LineEnd:   iface.Span.End,
				Symbol:    iface.Name,
				Excerpt:   "Abstract factory pattern: interface with multiple factory methods returning different types",
			})
		}
	}
	return evidence
}

// findBuilderPattern detects the Builder design pattern.
// Looks for: class with fluent/chain methods (return self type) + build()/Build() method,
// or WithX/SetX method pattern returning *Self.
func findBuilderPattern(rule Rule, fs *FactSet) []Evidence {
	var evidence []Evidence
	for _, node := range fs.TypeGraph.FindClasses() {
		if !languageMatch(node.Language, rule.Languages) {
			continue
		}
		hasBuild := false
		chainMethods := 0
		for _, m := range node.Methods {
			nameLower := strings.ToLower(m.Name)
			if nameLower == "build" {
				hasBuild = true
			}
			// Check for fluent methods returning self type
			if m.ReturnType == node.Name || m.ReturnType == "*"+node.Name {
				chainMethods++
			}
			// Check for With*/Set* pattern
			if strings.HasPrefix(m.Name, "With") || strings.HasPrefix(m.Name, "Set") {
				if m.ReturnType == node.Name || m.ReturnType == "*"+node.Name {
					chainMethods++
				}
			}
		}
		if hasBuild && chainMethods >= 2 {
			evidence = append(evidence, Evidence{
				File:      node.File,
				LineStart: node.Span.Start,
				LineEnd:   node.Span.End,
				Symbol:    node.Name,
				Excerpt:   "Builder pattern: fluent chain methods with Build() method",
			})
		}
	}
	return evidence
}

// findPrototypePattern detects the Prototype design pattern.
// Looks for: interface/class with clone()/Clone()/copy()/Copy()/DeepCopy() method.
func findPrototypePattern(rule Rule, fs *FactSet) []Evidence {
	var evidence []Evidence
	cloneNames := map[string]bool{
		"clone": true, "Clone": true,
		"copy": true, "Copy": true,
		"DeepCopy": true, "deepCopy": true,
		"DeepClone": true, "deepClone": true,
	}
	for _, node := range fs.TypeGraph.Nodes {
		if !languageMatch(node.Language, rule.Languages) {
			continue
		}
		for _, m := range node.Methods {
			if cloneNames[m.Name] {
				evidence = append(evidence, Evidence{
					File:      node.File,
					LineStart: node.Span.Start,
					LineEnd:   node.Span.End,
					Symbol:    node.Name + "." + m.Name,
					Excerpt:   "Prototype pattern: type with clone/copy method",
				})
				break
			}
		}
	}
	return evidence
}
