package python

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"
)

//go:embed ast_extract.py
var astExtractScript string

// pythonScriptPath caches the temp file path for the embedded Python script.
var (
	pythonScriptOnce sync.Once
	pythonScriptPath string
	pythonScriptErr  error
)

// DI hooks for testing error paths. Production code leaves these nil.
var (
	// createTempFunc overrides os.CreateTemp when non-nil.
	createTempFunc func(dir, pattern string) (*os.File, error)
	// findPython3Func overrides findPython3 when non-nil.
	findPython3Func func() string
	// runCommandFunc overrides cmd.Output when non-nil.
	// Receives the command args and returns (stdout, error).
	runCommandFunc func(ctx context.Context, name string, args ...string) ([]byte, error)
)

// ASTResult holds the parsed output of the Python AST extraction script.
type ASTResult struct {
	Imports     []ASTImport     `json:"imports"`
	Symbols     []ASTSymbol     `json:"symbols"`
	Routes      []ASTRoute      `json:"routes"`
	Middlewares []ASTMiddleware `json:"middlewares"`
	DataAccess  []ASTDataAccess `json:"data_access"`
	Secrets     []ASTSecret     `json:"secrets"`
	Classes     []ASTClass      `json:"classes"`
	Error       *string         `json:"error"`
}

// ASTImport represents an import extracted by the Python AST parser.
type ASTImport struct {
	Module string   `json:"module"`
	Names  []string `json:"names"`
	Alias  string   `json:"alias"`
	Line   int      `json:"line"`
}

// ASTSymbol represents a symbol (function, class, method) extracted by AST.
type ASTSymbol struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Line        int    `json:"line"`
	EndLine     int    `json:"end_line"`
	Exported    bool   `json:"exported"`
	ParentClass string `json:"parent_class,omitempty"`
}

// ASTRoute represents an HTTP route extracted by AST.
type ASTRoute struct {
	Method      string   `json:"method"`
	Path        string   `json:"path"`
	Handler     string   `json:"handler"`
	Line        int      `json:"line"`
	Middlewares []string `json:"middlewares,omitempty"`
}

// ASTMiddleware represents middleware extracted by AST.
type ASTMiddleware struct {
	Name      string `json:"name"`
	Framework string `json:"framework"`
	Line      int    `json:"line"`
}

// ASTDataAccess represents data access patterns extracted by AST.
type ASTDataAccess struct {
	Operation  string `json:"operation"`
	Backend    string `json:"backend"`
	Line       int    `json:"line"`
	Caller     string `json:"caller,omitempty"`
	CallerKind string `json:"caller_kind,omitempty"`
}

// ASTSecret represents a detected secret extracted by AST.
type ASTSecret struct {
	Name string `json:"name"`
	Line int    `json:"line"`
}

// ASTClass represents class information extracted by AST.
type ASTClass struct {
	Name    string   `json:"name"`
	Line    int      `json:"line"`
	EndLine int      `json:"end_line"`
	Bases   []string `json:"bases"`
	Methods []string `json:"methods"`
}

// ensureScript writes the embedded Python script to a unique, per-process temp
// file with restrictive permissions. The file is created with os.CreateTemp to
// avoid predictable paths that could be tampered with by other local processes.
func ensureScript() (string, error) {
	pythonScriptOnce.Do(func() {
		mkTemp := os.CreateTemp
		if createTempFunc != nil {
			mkTemp = createTempFunc
		}
		f, err := mkTemp("", "verabase_ast_extract_*.py")
		if err != nil {
			pythonScriptErr = err
			return
		}
		path := f.Name()
		// Write with restrictive permissions: owner read/write only (0600).
		if err := f.Chmod(0o600); err != nil {
			f.Close()
			os.Remove(path)
			pythonScriptErr = err
			return
		}
		if _, err := f.WriteString(astExtractScript); err != nil {
			f.Close()
			os.Remove(path)
			pythonScriptErr = err
			return
		}
		f.Close()
		pythonScriptPath = path
	})
	return pythonScriptPath, pythonScriptErr
}

// resetScriptCache resets the sync.Once for testing.
func resetScriptCache() {
	pythonScriptOnce = sync.Once{}
	pythonScriptPath = ""
	pythonScriptErr = nil
}

// findPython3 returns the path to python3, or empty string if not found.
func findPython3() string {
	if findPython3Func != nil {
		return findPython3Func()
	}
	// Check common locations first
	for _, p := range []string{"/usr/bin/python3", "/usr/local/bin/python3"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	// Fall back to PATH lookup
	if p, err := exec.LookPath("python3"); err == nil {
		return p
	}
	return ""
}

// PythonASTAvailable returns true if python3 is available for AST parsing.
func PythonASTAvailable() bool {
	return findPython3() != ""
}

// ParsePythonAST parses a Python source string using the ast module via subprocess.
// Returns structured AST results or an error.
func ParsePythonAST(source string) (*ASTResult, error) {
	python3 := findPython3()
	if python3 == "" {
		return nil, fmt.Errorf("python3 not found")
	}

	scriptPath, err := ensureScript()
	if err != nil {
		return nil, fmt.Errorf("failed to write AST script: %w", err)
	}

	// Write source to temp file
	tmpFile, err := os.CreateTemp("", "verabase_py_src_*.py")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp source file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.WriteString(source); err != nil {
		tmpFile.Close()
		return nil, fmt.Errorf("failed to write temp source: %w", err)
	}
	tmpFile.Close()

	// Run with 5s timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var out []byte
	if runCommandFunc != nil {
		out, err = runCommandFunc(ctx, python3, scriptPath, tmpPath)
	} else {
		cmd := exec.CommandContext(ctx, python3, scriptPath, tmpPath)
		out, err = cmd.Output()
	}
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("python3 AST parse timed out after 5s")
		}
		return nil, fmt.Errorf("python3 AST parse failed: %w", err)
	}

	var result ASTResult
	if err := json.Unmarshal(out, &result); err != nil {
		return nil, fmt.Errorf("failed to parse AST JSON output: %w", err)
	}

	return &result, nil
}
