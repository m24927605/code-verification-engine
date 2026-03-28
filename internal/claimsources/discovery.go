package claimsources

import (
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/verabase/code-verification-engine/internal/repo"
)

// Discover returns deterministic source descriptors for all supported source classes
// present in the snapshot.
func Discover(snapshot Snapshot) []SourceDescriptor {
	descriptors := make([]SourceDescriptor, 0, len(snapshot.Files))
	for _, path := range snapshot.Files {
		desc, ok := classifySource(path)
		if !ok {
			continue
		}
		desc.IncludedInBoundary = true
		desc.SourceID = sourceDescriptorID(desc)
		descriptors = append(descriptors, desc)
	}

	sort.SliceStable(descriptors, func(i, j int) bool {
		if descriptors[i].SourceType != descriptors[j].SourceType {
			return sourceTypeRank(descriptors[i].SourceType) < sourceTypeRank(descriptors[j].SourceType)
		}
		if descriptors[i].Path != descriptors[j].Path {
			return descriptors[i].Path < descriptors[j].Path
		}
		if descriptors[i].Role != descriptors[j].Role {
			return descriptors[i].Role < descriptors[j].Role
		}
		return descriptors[i].SourceID < descriptors[j].SourceID
	})

	return descriptors
}

// DiscoverFromRepo adapts a repo metadata snapshot into source descriptors.
func DiscoverFromRepo(meta *repo.RepoMetadata) []SourceDescriptor {
	if meta == nil {
		return nil
	}
	return Discover(Snapshot{
		RepoPath:  meta.RepoPath,
		CommitSHA: meta.CommitSHA,
		Files:     append([]string(nil), meta.Files...),
	})
}

func classifySource(path string) (SourceDescriptor, bool) {
	clean := filepath.ToSlash(path)
	lower := strings.ToLower(clean)
	base := strings.ToLower(filepath.Base(clean))

	if isReadmePath(lower, base) {
		return SourceDescriptor{
			SourceType: SourceTypeReadme,
			Path:       clean,
			Language:   languageForPath(clean),
			Role:       "overview_readme",
		}, true
	}
	if isEvalPath(lower, base) {
		return SourceDescriptor{
			SourceType: SourceTypeEval,
			Path:       clean,
			Language:   languageForPath(clean),
			Role:       "eval_dataset",
		}, true
	}
	if isTestPath(lower, base) {
		return SourceDescriptor{
			SourceType: SourceTypeTest,
			Path:       clean,
			Language:   languageForPath(clean),
			Role:       testRoleForPath(lower, base),
		}, true
	}
	if isDocPath(lower, base) {
		return SourceDescriptor{
			SourceType: SourceTypeDoc,
			Path:       clean,
			Language:   languageForPath(clean),
			Role:       docRoleForPath(lower, base),
		}, true
	}
	if isCodePath(clean) {
		return SourceDescriptor{
			SourceType: SourceTypeCode,
			Path:       clean,
			Language:   languageForPath(clean),
			Role:       codeRoleForPath(lower, base),
		}, true
	}

	return SourceDescriptor{}, false
}

func isReadmePath(lower, base string) bool {
	return strings.HasPrefix(base, "readme") || strings.HasPrefix(base, "readme.")
}

func isEvalPath(lower, base string) bool {
	if strings.Contains(lower, "/eval/") || strings.HasPrefix(lower, "eval/") || strings.Contains(lower, "/evals/") || strings.HasPrefix(lower, "evals/") {
		return true
	}
	if strings.Contains(lower, "/benchmark/") || strings.HasPrefix(lower, "benchmark/") || strings.Contains(lower, "/benchmarks/") || strings.HasPrefix(lower, "benchmarks/") {
		return true
	}
	if strings.Contains(lower, "/adversarial/") || strings.HasPrefix(lower, "adversarial/") {
		return true
	}
	if strings.Contains(lower, "/calibration/") || strings.HasPrefix(lower, "calibration/") {
		return true
	}
	return strings.HasPrefix(base, "eval.") || strings.HasPrefix(base, "eval-") ||
		strings.HasPrefix(base, "benchmark.") || strings.HasPrefix(base, "benchmark-") ||
		strings.HasPrefix(base, "adversarial.") || strings.HasPrefix(base, "adversarial-") ||
		strings.HasPrefix(base, "calibration.") || strings.HasPrefix(base, "calibration-")
}

func isTestPath(lower, base string) bool {
	if strings.HasSuffix(lower, "_test.go") ||
		strings.HasSuffix(lower, "_test.py") ||
		strings.HasSuffix(lower, ".test.ts") ||
		strings.HasSuffix(lower, ".test.js") ||
		strings.HasSuffix(lower, ".test.tsx") ||
		strings.HasSuffix(lower, ".test.jsx") ||
		strings.HasSuffix(lower, ".spec.ts") ||
		strings.HasSuffix(lower, ".spec.js") ||
		strings.HasSuffix(lower, ".spec.tsx") ||
		strings.HasSuffix(lower, ".spec.jsx") {
		return true
	}
	if strings.Contains(lower, "/tests/") || strings.HasPrefix(lower, "tests/") || strings.Contains(lower, "/test/") || strings.HasPrefix(lower, "test/") {
		return true
	}
	if strings.HasPrefix(base, "test_") {
		return true
	}
	return false
}

func isDocPath(lower, base string) bool {
	if strings.Contains(lower, "/docs/") || strings.HasPrefix(lower, "docs/") || strings.Contains(lower, "/adr/") || strings.HasPrefix(lower, "adr/") {
		return true
	}
	if strings.HasSuffix(base, ".md") || strings.HasSuffix(base, ".mdx") || strings.HasSuffix(base, ".rst") || strings.HasSuffix(base, ".txt") {
		return isDocishBase(base)
	}
	return isDocishBase(base)
}

func isDocishBase(base string) bool {
	return strings.HasPrefix(base, "adr-") ||
		strings.HasPrefix(base, "architecture") ||
		strings.HasPrefix(base, "design") ||
		strings.HasPrefix(base, "spec") ||
		strings.HasPrefix(base, "guide") ||
		strings.HasPrefix(base, "runbook") ||
		strings.HasPrefix(base, "security") ||
		strings.HasPrefix(base, "ops") ||
		strings.HasPrefix(base, "operational")
}

func isCodePath(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".go", ".js", ".jsx", ".ts", ".tsx", ".py":
		return true
	default:
		return false
	}
}

func sourceDescriptorID(desc SourceDescriptor) string {
	h := sha256.Sum256([]byte(strings.Join([]string{
		string(desc.SourceType),
		desc.Path,
		desc.Language,
		desc.Role,
		fmt.Sprintf("%t", desc.IncludedInBoundary),
	}, "\x00")))
	return fmt.Sprintf("src-%x", h[:8])
}

func sourceTypeRank(t SourceType) int {
	switch t {
	case SourceTypeReadme:
		return 0
	case SourceTypeDoc:
		return 1
	case SourceTypeCode:
		return 2
	case SourceTypeTest:
		return 3
	case SourceTypeEval:
		return 4
	default:
		return 99
	}
}

func testRoleForPath(lower, base string) string {
	switch {
	case strings.Contains(lower, "security"):
		return "security_test"
	case strings.Contains(lower, "auth"):
		return "security_test"
	case strings.Contains(lower, "integration"):
		return "integration_test"
	case strings.Contains(lower, "e2e"):
		return "integration_test"
	case strings.Contains(lower, "acceptance"):
		return "integration_test"
	case strings.Contains(lower, "regression"):
		return "integration_test"
	default:
		return "unit_test"
	}
}

func docRoleForPath(lower, base string) string {
	switch {
	case strings.Contains(lower, "/adr/") || strings.HasPrefix(base, "adr-"):
		return "adr"
	case strings.Contains(lower, "architecture"):
		return "architecture_doc"
	case strings.Contains(lower, "security"):
		return "security_doc"
	case strings.Contains(lower, "design"):
		return "design_doc"
	case strings.Contains(lower, "ops") || strings.Contains(lower, "operational") || strings.Contains(lower, "runbook"):
		return "operational_doc"
	default:
		return "doc_section"
	}
}

func codeRoleForPath(lower, base string) string {
	switch {
	case strings.Contains(lower, "agent"):
		return "agent_module"
	case strings.Contains(lower, "pipeline"):
		return "pipeline"
	case strings.Contains(lower, "service"):
		return "service"
	case strings.Contains(lower, "route"), strings.Contains(lower, "handler"), strings.Contains(lower, "controller"):
		return "route"
	default:
		return "module"
	}
}

func languageForPath(path string) string {
	lower := strings.ToLower(filepath.ToSlash(path))
	base := strings.ToLower(filepath.Base(path))
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".go":
		return "go"
	case ".js", ".jsx":
		return "javascript"
	case ".ts", ".tsx":
		return "typescript"
	case ".py":
		return "python"
	case ".md", ".mdx":
		return "markdown"
	case ".json":
		return "json"
	case ".yaml", ".yml":
		return "yaml"
	case ".txt":
		return "text"
	case "":
		if strings.HasPrefix(base, "readme") ||
			strings.Contains(lower, "/docs/") ||
			strings.Contains(lower, "/adr/") ||
			isDocishBase(base) {
			return "markdown"
		}
		return "text"
	default:
		return "text"
	}
}
