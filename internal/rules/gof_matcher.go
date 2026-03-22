package rules

// matchGoFPattern dispatches to the appropriate GoF pattern matcher.
func matchGoFPattern(rule Rule, fs *FactSet) Finding {
	finding := Finding{
		RuleID:  rule.ID,
		Message: rule.Message,
	}

	if fs.TypeGraph == nil || len(fs.TypeGraph.Nodes) == 0 {
		finding.Status = StatusUnknown
		finding.Confidence = ConfidenceLow
		finding.VerificationLevel = VerificationWeakInference
		finding.UnknownReasons = []string{UnknownAnalyzerLimitation, "type graph not available for pattern detection"}
		return finding
	}

	evidence := findGoFEvidence(rule, fs)
	if len(evidence) > 0 {
		finding.Status = StatusPass
		finding.Confidence = ConfidenceMedium
		finding.VerificationLevel = VerificationStrongInference
		finding.Evidence = evidence
	} else {
		finding.Status = StatusFail
		finding.Confidence = ConfidenceMedium
		finding.VerificationLevel = VerificationStrongInference
	}
	return finding
}

func findGoFEvidence(rule Rule, fs *FactSet) []Evidence {
	switch rule.Target {
	// Creational
	case "gof.singleton":
		return findSingletonPattern(rule, fs)
	case "gof.factory_method":
		return findFactoryMethodPattern(rule, fs)
	case "gof.abstract_factory":
		return findAbstractFactoryPattern(rule, fs)
	case "gof.builder":
		return findBuilderPattern(rule, fs)
	case "gof.prototype":
		return findPrototypePattern(rule, fs)
	// Structural
	case "gof.adapter":
		return findAdapterPattern(rule, fs)
	case "gof.bridge":
		return findBridgePattern(rule, fs)
	case "gof.composite":
		return findCompositePattern(rule, fs)
	case "gof.decorator":
		return findDecoratorPattern(rule, fs)
	case "gof.facade":
		return findFacadePattern(rule, fs)
	case "gof.flyweight":
		return findFlyweightPattern(rule, fs)
	case "gof.proxy":
		return findProxyPattern(rule, fs)
	// Behavioral
	case "gof.chain_of_responsibility":
		return findChainOfResponsibilityPattern(rule, fs)
	case "gof.command":
		return findCommandPattern(rule, fs)
	case "gof.interpreter":
		return findInterpreterPattern(rule, fs)
	case "gof.iterator":
		return findIteratorPattern(rule, fs)
	case "gof.mediator":
		return findMediatorPattern(rule, fs)
	case "gof.memento":
		return findMementoPattern(rule, fs)
	case "gof.observer":
		return findObserverPattern(rule, fs)
	case "gof.state":
		return findStatePattern(rule, fs)
	case "gof.strategy":
		return findStrategyPattern(rule, fs)
	case "gof.template_method":
		return findTemplateMethodPattern(rule, fs)
	case "gof.visitor":
		return findVisitorPattern(rule, fs)
	default:
		return nil
	}
}
