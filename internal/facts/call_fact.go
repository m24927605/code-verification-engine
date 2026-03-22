package facts

import "fmt"

// CallFact represents a function/method call relationship.
type CallFact struct {
	Language   Language    `json:"language"`
	File       string      `json:"file"`
	Span       Span        `json:"span"`
	CallerName string      `json:"caller_name"`
	CallerFile string      `json:"caller_file,omitempty"`
	CalleeName string      `json:"callee_name"`
	CalleeFile string      `json:"callee_file,omitempty"`
	Quality    FactQuality `json:"quality,omitempty"`
}

// NewCallFact creates a validated CallFact.
func NewCallFact(lang Language, file string, span Span, callerName, callerFile, calleeName, calleeFile string) (CallFact, error) {
	if !lang.IsValid() {
		return CallFact{}, fmt.Errorf("unsupported language: %q", lang)
	}
	if file == "" {
		return CallFact{}, fmt.Errorf("file path is required")
	}
	if err := span.Validate(); err != nil {
		return CallFact{}, fmt.Errorf("invalid span: %w", err)
	}
	if callerName == "" {
		return CallFact{}, fmt.Errorf("caller name is required")
	}
	if calleeName == "" {
		return CallFact{}, fmt.Errorf("callee name is required")
	}
	return CallFact{
		Language:   lang,
		File:       file,
		Span:       span,
		CallerName: callerName,
		CallerFile: callerFile,
		CalleeName: calleeName,
		CalleeFile: calleeFile,
	}, nil
}
