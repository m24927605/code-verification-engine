package rules

import "strings"

// findChainOfResponsibilityPattern detects the Chain of Responsibility design pattern.
// Looks for: class with a field of same type/interface (next handler) + handle/process method.
func findChainOfResponsibilityPattern(rule Rule, fs *FactSet) []Evidence {
	var evidence []Evidence
	for _, node := range fs.TypeGraph.FindClasses() {
		if !languageMatch(node.Language, rule.Languages) {
			continue
		}
		hasNextField := false
		for _, f := range node.Fields {
			typeName := strings.TrimPrefix(f.TypeName, "*")
			if typeName == node.Name {
				hasNextField = true
				break
			}
			for _, impl := range node.Implements {
				if f.TypeName == impl || typeName == impl {
					hasNextField = true
					break
				}
			}
			if hasNextField {
				break
			}
		}
		if !hasNextField {
			continue
		}
		for _, m := range node.Methods {
			nameLower := strings.ToLower(m.Name)
			if nameLower == "handle" || nameLower == "process" || nameLower == "execute" ||
				strings.HasPrefix(nameLower, "handle") || strings.HasPrefix(nameLower, "process") {
				evidence = append(evidence, Evidence{
					File:      node.File,
					LineStart: node.Span.Start,
					LineEnd:   node.Span.End,
					Symbol:    node.Name,
					Excerpt:   "Chain of responsibility: next handler field with handle/process method",
				})
				break
			}
		}
	}
	return evidence
}

// findCommandPattern detects the Command design pattern.
// Looks for: interface with a single execute/run method, multiple implementors.
func findCommandPattern(rule Rule, fs *FactSet) []Evidence {
	var evidence []Evidence
	for _, iface := range fs.TypeGraph.FindInterfaces() {
		if !languageMatch(iface.Language, rule.Languages) {
			continue
		}
		if len(iface.Methods) != 1 {
			continue
		}
		nameLower := strings.ToLower(iface.Methods[0].Name)
		if nameLower == "execute" || nameLower == "run" || nameLower == "do" || nameLower == "invoke" {
			implementors := fs.TypeGraph.FindImplementors(iface.Name)
			if len(implementors) >= 1 {
				evidence = append(evidence, Evidence{
					File:      iface.File,
					LineStart: iface.Span.Start,
					LineEnd:   iface.Span.End,
					Symbol:    iface.Name,
					Excerpt:   "Command pattern: single-method interface with execute/run method",
				})
			}
		}
	}
	return evidence
}

// findInterpreterPattern detects the Interpreter design pattern.
// Looks for: interface with interpret/evaluate method + multiple expression implementors.
func findInterpreterPattern(rule Rule, fs *FactSet) []Evidence {
	var evidence []Evidence
	for _, iface := range fs.TypeGraph.FindInterfaces() {
		if !languageMatch(iface.Language, rule.Languages) {
			continue
		}
		for _, m := range iface.Methods {
			nameLower := strings.ToLower(m.Name)
			if nameLower == "interpret" || nameLower == "evaluate" || nameLower == "eval" {
				implementors := fs.TypeGraph.FindImplementors(iface.Name)
				if len(implementors) >= 2 {
					evidence = append(evidence, Evidence{
						File:      iface.File,
						LineStart: iface.Span.Start,
						LineEnd:   iface.Span.End,
						Symbol:    iface.Name,
						Excerpt:   "Interpreter pattern: interpret/evaluate interface with multiple expression types",
					})
				}
				break
			}
		}
	}
	return evidence
}

// findIteratorPattern detects the Iterator design pattern.
// Looks for: type with next/hasNext or __next__/__iter__ methods.
func findIteratorPattern(rule Rule, fs *FactSet) []Evidence {
	var evidence []Evidence
	for _, node := range fs.TypeGraph.Nodes {
		if !languageMatch(node.Language, rule.Languages) {
			continue
		}
		hasNext := false
		hasHasNext := false
		for _, m := range node.Methods {
			nameLower := strings.ToLower(m.Name)
			if nameLower == "next" || nameLower == "__next__" {
				hasNext = true
			}
			if nameLower == "hasnext" || nameLower == "has_next" || nameLower == "__iter__" {
				hasHasNext = true
			}
		}
		if hasNext && hasHasNext {
			evidence = append(evidence, Evidence{
				File:      node.File,
				LineStart: node.Span.Start,
				LineEnd:   node.Span.End,
				Symbol:    node.Name,
				Excerpt:   "Iterator pattern: next + hasNext methods",
			})
		}
	}
	return evidence
}

// findMediatorPattern detects the Mediator design pattern.
// Looks for: class named *mediator/*hub/*coordinator that holds references to multiple colleague objects.
func findMediatorPattern(rule Rule, fs *FactSet) []Evidence {
	var evidence []Evidence
	knownTypes := make(map[string]bool)
	for _, node := range fs.TypeGraph.Nodes {
		knownTypes[node.Name] = true
	}
	for _, node := range fs.TypeGraph.FindClasses() {
		if !languageMatch(node.Language, rule.Languages) {
			continue
		}
		nameLower := strings.ToLower(node.Name)
		if !strings.Contains(nameLower, "mediator") && !strings.Contains(nameLower, "hub") && !strings.Contains(nameLower, "coordinator") {
			continue
		}
		colleagueCount := 0
		for _, f := range node.Fields {
			typeName := strings.TrimPrefix(f.TypeName, "*")
			if knownTypes[typeName] && typeName != node.Name {
				colleagueCount++
			}
		}
		if colleagueCount >= 2 {
			evidence = append(evidence, Evidence{
				File:      node.File,
				LineStart: node.Span.Start,
				LineEnd:   node.Span.End,
				Symbol:    node.Name,
				Excerpt:   "Mediator pattern: coordinates multiple colleague objects",
			})
		}
	}
	return evidence
}

// findMementoPattern detects the Memento design pattern.
// Looks for: class with save/restore or createMemento/setMemento methods.
func findMementoPattern(rule Rule, fs *FactSet) []Evidence {
	var evidence []Evidence
	for _, node := range fs.TypeGraph.FindClasses() {
		if !languageMatch(node.Language, rule.Languages) {
			continue
		}
		hasSave := false
		hasRestore := false
		for _, m := range node.Methods {
			nameLower := strings.ToLower(m.Name)
			if nameLower == "save" || nameLower == "creatememento" || nameLower == "create_memento" || nameLower == "snapshot" {
				hasSave = true
			}
			if nameLower == "restore" || nameLower == "setmemento" || nameLower == "set_memento" || nameLower == "undo" {
				hasRestore = true
			}
		}
		if hasSave && hasRestore {
			evidence = append(evidence, Evidence{
				File:      node.File,
				LineStart: node.Span.Start,
				LineEnd:   node.Span.End,
				Symbol:    node.Name,
				Excerpt:   "Memento pattern: save/restore state methods",
			})
		}
	}
	return evidence
}

// findObserverPattern detects the Observer design pattern.
// Looks for: class with subscribe/notify or addListener/removeListener methods.
func findObserverPattern(rule Rule, fs *FactSet) []Evidence {
	var evidence []Evidence
	for _, node := range fs.TypeGraph.FindClasses() {
		if !languageMatch(node.Language, rule.Languages) {
			continue
		}
		hasAdd := false
		hasNotify := false
		for _, m := range node.Methods {
			nameLower := strings.ToLower(m.Name)
			if nameLower == "subscribe" || nameLower == "attach" || nameLower == "addlistener" ||
				nameLower == "add_listener" || nameLower == "addobserver" || nameLower == "add_observer" ||
				nameLower == "register" || nameLower == "on" {
				hasAdd = true
			}
			if nameLower == "notify" || nameLower == "notifyall" || nameLower == "notify_all" ||
				nameLower == "emit" || nameLower == "fire" || nameLower == "publish" || nameLower == "dispatch" {
				hasNotify = true
			}
		}
		if hasAdd && hasNotify {
			evidence = append(evidence, Evidence{
				File:      node.File,
				LineStart: node.Span.Start,
				LineEnd:   node.Span.End,
				Symbol:    node.Name,
				Excerpt:   "Observer pattern: subscribe/notify methods",
			})
		}
	}
	return evidence
}

// findStatePattern detects the State design pattern.
// Looks for: class with interface-typed state field + setState/changeState method.
func findStatePattern(rule Rule, fs *FactSet) []Evidence {
	var evidence []Evidence
	interfaceNames := make(map[string]bool)
	for _, iface := range fs.TypeGraph.FindInterfaces() {
		interfaceNames[iface.Name] = true
	}
	for _, node := range fs.TypeGraph.FindClasses() {
		if !languageMatch(node.Language, rule.Languages) {
			continue
		}
		hasStateField := false
		for _, f := range node.Fields {
			typeName := strings.TrimPrefix(f.TypeName, "*")
			if interfaceNames[typeName] {
				nameLower := strings.ToLower(f.Name)
				if strings.Contains(nameLower, "state") || strings.Contains(nameLower, "status") {
					hasStateField = true
					break
				}
			}
		}
		if !hasStateField {
			continue
		}
		for _, m := range node.Methods {
			nameLower := strings.ToLower(m.Name)
			if nameLower == "setstate" || nameLower == "set_state" || nameLower == "changestate" ||
				nameLower == "change_state" || nameLower == "transitionto" || nameLower == "transition_to" {
				evidence = append(evidence, Evidence{
					File:      node.File,
					LineStart: node.Span.Start,
					LineEnd:   node.Span.End,
					Symbol:    node.Name,
					Excerpt:   "State pattern: state interface field with state transition method",
				})
				break
			}
		}
	}
	return evidence
}

// findStrategyPattern detects the Strategy design pattern.
// Looks for: class with an interface-typed field named strategy/policy/algorithm/handler.
func findStrategyPattern(rule Rule, fs *FactSet) []Evidence {
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
			typeName := strings.TrimPrefix(f.TypeName, "*")
			if !interfaceNames[typeName] {
				continue
			}
			nameLower := strings.ToLower(f.Name)
			if strings.Contains(nameLower, "strategy") || strings.Contains(nameLower, "policy") ||
				strings.Contains(nameLower, "algorithm") || strings.Contains(nameLower, "handler") {
				evidence = append(evidence, Evidence{
					File:      node.File,
					LineStart: node.Span.Start,
					LineEnd:   node.Span.End,
					Symbol:    node.Name,
					Excerpt:   "Strategy pattern: interface field named " + f.Name,
				})
				break
			}
		}
	}
	return evidence
}

// findTemplateMethodPattern detects the Template Method design pattern.
// Looks for: abstract class with both abstract and concrete methods.
func findTemplateMethodPattern(rule Rule, fs *FactSet) []Evidence {
	var evidence []Evidence
	for _, node := range fs.TypeGraph.FindClasses() {
		if !languageMatch(node.Language, rule.Languages) {
			continue
		}
		if node.Kind != "abstract_class" {
			continue
		}
		abstractMethods := node.GetAbstractMethods()
		concreteMethods := 0
		for _, m := range node.Methods {
			if !m.IsAbstract {
				concreteMethods++
			}
		}
		if len(abstractMethods) >= 1 && concreteMethods >= 1 {
			evidence = append(evidence, Evidence{
				File:      node.File,
				LineStart: node.Span.Start,
				LineEnd:   node.Span.End,
				Symbol:    node.Name,
				Excerpt:   "Template method pattern: abstract class with abstract + concrete methods",
			})
		}
	}
	return evidence
}

// findVisitorPattern detects the Visitor design pattern.
// Looks for: type with multiple visit* methods, or element classes with accept method.
func findVisitorPattern(rule Rule, fs *FactSet) []Evidence {
	var evidence []Evidence
	for _, node := range fs.TypeGraph.Nodes {
		if !languageMatch(node.Language, rule.Languages) {
			continue
		}
		visitMethods := 0
		for _, m := range node.Methods {
			if strings.HasPrefix(strings.ToLower(m.Name), "visit") {
				visitMethods++
			}
		}
		if visitMethods >= 2 {
			evidence = append(evidence, Evidence{
				File:      node.File,
				LineStart: node.Span.Start,
				LineEnd:   node.Span.End,
				Symbol:    node.Name,
				Excerpt:   "Visitor pattern: multiple visit* methods",
			})
		}
	}
	for _, node := range fs.TypeGraph.Nodes {
		if !languageMatch(node.Language, rule.Languages) {
			continue
		}
		for _, m := range node.Methods {
			if strings.ToLower(m.Name) == "accept" && len(m.Params) >= 1 {
				evidence = append(evidence, Evidence{
					File:      node.File,
					LineStart: node.Span.Start,
					LineEnd:   node.Span.End,
					Symbol:    node.Name + ".accept",
					Excerpt:   "Visitor pattern: accept method on element class",
				})
				break
			}
		}
	}
	return evidence
}
