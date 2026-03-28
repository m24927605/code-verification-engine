package claimsources

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/verabase/code-verification-engine/internal/repo"
)

const evidenceProducer = "claimsources@v1"

var (
	goFuncPattern      = regexp.MustCompile(`(?m)^func\s+(?:\([^\)]*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\(`)
	goTypePattern      = regexp.MustCompile(`(?m)^type\s+([A-Za-z_][A-Za-z0-9_]*)\b`)
	goConstPattern     = regexp.MustCompile(`(?m)^const\s+([A-Za-z_][A-Za-z0-9_]*)\b`)
	goVarPattern       = regexp.MustCompile(`(?m)^var\s+([A-Za-z_][A-Za-z0-9_]*)\b`)
	goTestPattern      = regexp.MustCompile(`(?m)^func\s+(Test[A-Za-z0-9_]+|Benchmark[A-Za-z0-9_]+|Example[A-Za-z0-9_]+)\s*\(`)
	pySymbolPattern    = regexp.MustCompile(`(?m)^def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(|^class\s+([A-Za-z_][A-Za-z0-9_]*)\b`)
	pyTestPattern      = regexp.MustCompile(`(?m)^def\s+(test_[A-Za-z0-9_]+)\s*\(`)
	jsTestPattern      = regexp.MustCompile(`(?m)\b(?:describe|it|test)\s*\(\s*['"]([^'"]+)['"]`)
	jsSymbolPattern    = regexp.MustCompile(`(?m)^(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(|^(?:export\s+)?class\s+([A-Za-z_][A-Za-z0-9_]*)\b|^(?:export\s+)?const\s+([A-Za-z_][A-Za-z0-9_]*)\s*=`)
	markdownHeadingPat = regexp.MustCompile(`^\s{0,3}#{1,6}\s+(.+?)\s*$`)
)

// Extract converts discovered descriptors into deterministic source evidence records.
func Extract(snapshot Snapshot, descriptors []SourceDescriptor) []SourceEvidenceRecord {
	if len(descriptors) == 0 {
		return nil
	}

	sorted := append([]SourceDescriptor(nil), descriptors...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].SourceType != sorted[j].SourceType {
			return sourceTypeRank(sorted[i].SourceType) < sourceTypeRank(sorted[j].SourceType)
		}
		if sorted[i].Path != sorted[j].Path {
			return sorted[i].Path < sorted[j].Path
		}
		if sorted[i].Role != sorted[j].Role {
			return sorted[i].Role < sorted[j].Role
		}
		return sorted[i].SourceID < sorted[j].SourceID
	})

	records := make([]SourceEvidenceRecord, 0, len(sorted))
	for _, desc := range sorted {
		content, ok := readSource(snapshot.RepoPath, desc.Path)
		if !ok {
			continue
		}

		switch desc.SourceType {
		case SourceTypeReadme, SourceTypeDoc:
			records = append(records, extractMarkdownEvidence(desc, content)...)
		case SourceTypeCode:
			records = append(records, extractCodeEvidence(desc, content))
		case SourceTypeTest:
			records = append(records, extractTestEvidence(desc, content))
		case SourceTypeEval:
			records = append(records, extractEvalEvidence(desc, content))
		}
	}

	for i := range records {
		records[i].EvidenceID = sourceEvidenceID(records[i])
	}

	sort.SliceStable(records, func(i, j int) bool {
		if records[i].SourceType != records[j].SourceType {
			return sourceTypeRank(records[i].SourceType) < sourceTypeRank(records[j].SourceType)
		}
		if records[i].Path != records[j].Path {
			return records[i].Path < records[j].Path
		}
		if records[i].Kind != records[j].Kind {
			return records[i].Kind < records[j].Kind
		}
		if len(records[i].Spans) > 0 && len(records[j].Spans) > 0 {
			if records[i].Spans[0].StartLine != records[j].Spans[0].StartLine {
				return records[i].Spans[0].StartLine < records[j].Spans[0].StartLine
			}
			if records[i].Spans[0].EndLine != records[j].Spans[0].EndLine {
				return records[i].Spans[0].EndLine < records[j].Spans[0].EndLine
			}
		}
		return records[i].EvidenceID < records[j].EvidenceID
	})

	return records
}

// ExtractFromRepo adapts repo metadata into an extraction snapshot.
func ExtractFromRepo(meta *repo.RepoMetadata, descriptors []SourceDescriptor) []SourceEvidenceRecord {
	if meta == nil {
		return nil
	}
	return Extract(Snapshot{
		RepoPath:  meta.RepoPath,
		CommitSHA: meta.CommitSHA,
		Files:     append([]string(nil), meta.Files...),
	}, descriptors)
}

// readSource loads a source file from the repository snapshot.
func readSource(repoPath, relPath string) (string, bool) {
	path := relPath
	if !filepath.IsAbs(relPath) {
		path = filepath.Join(repoPath, relPath)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	return normalizeLineEndings(string(data)), true
}

func extractMarkdownEvidence(desc SourceDescriptor, content string) []SourceEvidenceRecord {
	lines := strings.Split(content, "\n")
	sections := splitMarkdownSections(lines, desc.Path)
	records := make([]SourceEvidenceRecord, 0, len(sections))
	for _, sec := range sections {
		metadata := map[string]string{
			"section_title":   sec.Title,
			"section_index":   fmt.Sprintf("%d", sec.Index),
			"claim_fragments": sec.Fragment,
			"heading_level":   fmt.Sprintf("%d", sec.Level),
			"descriptor_role": desc.Role,
		}
		records = append(records, SourceEvidenceRecord{
			SourceType: desc.SourceType,
			Producer:   evidenceProducer,
			Path:       desc.Path,
			Kind:       markdownEvidenceKind(desc.SourceType),
			Summary:    boundedSummary(sec.Title, sec.Fragment),
			Spans:      []SourceSpan{{StartLine: sec.StartLine, EndLine: sec.EndLine}},
			EntityIDs:  []string{markdownEntityID(desc.Path, sec.Title, sec.Index)},
			Metadata:   metadata,
		})
	}
	return records
}

func extractCodeEvidence(desc SourceDescriptor, content string) SourceEvidenceRecord {
	lines := strings.Split(content, "\n")
	symbols := extractSymbols(desc.Language, lines)
	if len(symbols) == 0 {
		symbols = []string{desc.Path}
	}
	summary := desc.Role + " module"
	if len(symbols) > 0 {
		summary = fmt.Sprintf("%s module with symbols: %s", desc.Role, strings.Join(limitList(symbols, 4), ", "))
	}
	return SourceEvidenceRecord{
		SourceType: desc.SourceType,
		Producer:   evidenceProducer,
		Path:       desc.Path,
		Kind:       "code_module",
		Summary:    summary,
		Spans:      []SourceSpan{{StartLine: 1, EndLine: len(lines)}},
		EntityIDs:  append([]string(nil), symbols...),
		Metadata: map[string]string{
			"module_kind":      desc.Role,
			"language":         desc.Language,
			"exported_symbols": strings.Join(limitList(symbols, 8), ","),
		},
	}
}

func extractTestEvidence(desc SourceDescriptor, content string) SourceEvidenceRecord {
	lines := strings.Split(content, "\n")
	tests := extractTestNames(desc.Language, lines)
	if len(tests) == 0 {
		tests = []string{desc.Path}
	}
	target := targetModuleFromTestPath(desc.Path)
	summary := fmt.Sprintf("%s covering %s", desc.Role, target)
	if len(tests) > 0 {
		summary = fmt.Sprintf("%s covering %s: %s", desc.Role, target, strings.Join(limitList(tests, 4), ", "))
	}
	return SourceEvidenceRecord{
		SourceType: desc.SourceType,
		Producer:   evidenceProducer,
		Path:       desc.Path,
		Kind:       "test_file",
		Summary:    summary,
		Spans:      []SourceSpan{{StartLine: 1, EndLine: len(lines)}},
		EntityIDs:  append([]string(nil), tests...),
		Metadata: map[string]string{
			"test_kind":        desc.Role,
			"target_module":    target,
			"assertion_intent": summary,
		},
	}
}

func extractEvalEvidence(desc SourceDescriptor, content string) SourceEvidenceRecord {
	lines := strings.Split(content, "\n")
	purpose, adversarial := evalPurpose(content, desc.Path)
	datasetID := evalDatasetID(desc.Path)
	summary := fmt.Sprintf("%s eval asset %s", purpose, datasetID)
	return SourceEvidenceRecord{
		SourceType: desc.SourceType,
		Producer:   evidenceProducer,
		Path:       desc.Path,
		Kind:       "eval_asset",
		Summary:    summary,
		Spans:      []SourceSpan{{StartLine: 1, EndLine: len(lines)}},
		EntityIDs:  []string{datasetID},
		Metadata: map[string]string{
			"dataset_id":        datasetID,
			"benchmark_purpose": purpose,
			"adversarial_flag":  fmt.Sprintf("%t", adversarial),
			"descriptor_role":   desc.Role,
		},
	}
}

type markdownSection struct {
	Index     int
	Title     string
	Level     int
	StartLine int
	EndLine   int
	Fragment  string
}

func splitMarkdownSections(lines []string, path string) []markdownSection {
	var headings []struct {
		line  int
		level int
		title string
	}
	for i, line := range lines {
		if title, level, ok := parseMarkdownHeading(line); ok {
			headings = append(headings, struct {
				line  int
				level int
				title string
			}{line: i + 1, level: level, title: title})
		}
	}

	if len(headings) == 0 {
		return []markdownSection{{
			Index:     0,
			Title:     defaultMarkdownTitle(path),
			Level:     0,
			StartLine: 1,
			EndLine:   maxInt(1, len(lines)),
			Fragment:  firstNonEmptyFragment(lines, 0, len(lines)),
		}}
	}

	var sections []markdownSection
	for i, heading := range headings {
		start := heading.line
		end := len(lines)
		if i+1 < len(headings) {
			end = headings[i+1].line - 1
		}
		if end < start {
			end = start
		}
		fragment := firstNonEmptyFragment(lines, start, end)
		sections = append(sections, markdownSection{
			Index:     i,
			Title:     heading.title,
			Level:     heading.level,
			StartLine: start,
			EndLine:   end,
			Fragment:  fragment,
		})
	}
	return sections
}

func defaultMarkdownTitle(path string) string {
	base := filepath.Base(path)
	base = strings.TrimSuffix(base, filepath.Ext(base))
	base = strings.TrimSpace(base)
	if base == "" {
		return "document"
	}
	return base
}

func parseMarkdownHeading(line string) (string, int, bool) {
	m := markdownHeadingPat.FindStringSubmatch(line)
	if len(m) != 2 {
		return "", 0, false
	}
	level := 0
	for _, r := range strings.TrimLeft(line, " ") {
		if r == '#' {
			level++
			continue
		}
		break
	}
	return strings.TrimSpace(m[1]), level, true
}

func firstNonEmptyFragment(lines []string, start, end int) string {
	if start < 0 {
		start = 0
	}
	if end > len(lines) {
		end = len(lines)
	}
	if end < start {
		end = start
	}
	var parts []string
	for i := start; i < end; i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		if markdownHeadingPat.MatchString(line) {
			continue
		}
		parts = append(parts, line)
		if len(strings.Join(parts, " ")) >= 180 {
			break
		}
	}
	return boundedText(strings.Join(parts, " "), 180)
}

func markdownEvidenceKind(sourceType SourceType) string {
	if sourceType == SourceTypeReadme {
		return "readme_section"
	}
	return "doc_section"
}

func boundedSummary(title, fragment string) string {
	title = strings.TrimSpace(title)
	fragment = strings.TrimSpace(fragment)
	switch {
	case title == "":
		return boundedText(fragment, 180)
	case fragment == "":
		return boundedText(title, 180)
	default:
		return boundedText(title+": "+fragment, 180)
	}
}

func markdownEntityID(path, title string, index int) string {
	return slug(path) + "#section-" + fmt.Sprintf("%d", index) + "-" + slug(title)
}

func slug(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	lastDash := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash {
				b.WriteRune('-')
				lastDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

func extractSymbols(language string, lines []string) []string {
	content := strings.Join(lines, "\n")
	var matches []string
	switch strings.ToLower(language) {
	case "go":
		matches = append(matches, collectNamedMatches(goFuncPattern, content, 1)...)
		matches = append(matches, collectNamedMatches(goTypePattern, content, 1)...)
		matches = append(matches, collectNamedMatches(goConstPattern, content, 1)...)
		matches = append(matches, collectNamedMatches(goVarPattern, content, 1)...)
	case "javascript", "typescript":
		matches = append(matches, collectNamedMatches(jsSymbolPattern, content, 1, 2, 3)...)
	case "python":
		matches = append(matches, collectNamedMatches(pySymbolPattern, content, 1, 2)...)
	}
	return dedupeSorted(matches)
}

func extractTestNames(language string, lines []string) []string {
	content := strings.Join(lines, "\n")
	var matches []string
	switch strings.ToLower(language) {
	case "go":
		matches = append(matches, collectNamedMatches(goTestPattern, content, 1)...)
	case "python":
		matches = append(matches, collectNamedMatches(pyTestPattern, content, 1)...)
	case "javascript", "typescript":
		matches = append(matches, collectNamedMatches(jsTestPattern, content, 1)...)
	}
	return dedupeSorted(matches)
}

func collectNamedMatches(re *regexp.Regexp, content string, groups ...int) []string {
	matches := re.FindAllStringSubmatch(content, -1)
	if len(matches) == 0 {
		return nil
	}
	var out []string
	for _, m := range matches {
		for _, idx := range groups {
			if idx < len(m) && strings.TrimSpace(m[idx]) != "" {
				out = append(out, strings.TrimSpace(m[idx]))
				break
			}
		}
	}
	return out
}

func dedupeSorted(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func targetModuleFromTestPath(path string) string {
	clean := filepath.ToSlash(path)
	switch {
	case strings.HasSuffix(clean, "_test.go"):
		return strings.TrimSuffix(clean, "_test.go") + ".go"
	case strings.HasSuffix(clean, "_test.py"):
		return strings.TrimSuffix(clean, "_test.py") + ".py"
	case strings.Contains(clean, ".test."):
		return strings.Replace(clean, ".test.", ".", 1)
	case strings.Contains(clean, ".spec."):
		return strings.Replace(clean, ".spec.", ".", 1)
	default:
		return clean
	}
}

func evalPurpose(content, path string) (string, bool) {
	lower := strings.ToLower(content + "\n" + path)
	switch {
	case strings.Contains(lower, "adversarial"):
		return "adversarial", true
	case strings.Contains(lower, "calibration"):
		return "calibration", false
	case strings.Contains(lower, "benchmark"):
		return "benchmark", false
	default:
		return "evaluation", false
	}
}

func evalDatasetID(path string) string {
	return strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
}

func sourceEvidenceID(record SourceEvidenceRecord) string {
	parts := []string{
		string(record.SourceType),
		record.Producer,
		record.Path,
		record.Kind,
		record.Summary,
	}
	for _, span := range record.Spans {
		parts = append(parts, fmt.Sprintf("%d:%d", span.StartLine, span.EndLine))
	}
	entities := append([]string(nil), record.EntityIDs...)
	sort.Strings(entities)
	parts = append(parts, strings.Join(entities, ","))
	parts = append(parts, canonicalMetadata(record.Metadata))
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return fmt.Sprintf("sev-%x", h[:8])
}

func canonicalMetadata(metadata map[string]string) string {
	if len(metadata) == 0 {
		return ""
	}
	keys := make([]string, 0, len(metadata))
	for k := range metadata {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(metadata[k])
	}
	return b.String()
}

func boundedText(s string, limit int) string {
	s = normalizeWhitespace(s)
	if len(s) <= limit {
		return s
	}
	if limit <= 0 {
		return ""
	}
	return s[:limit]
}

func normalizeWhitespace(s string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n")), " ")
}

func normalizeLineEndings(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n")
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func limitList(values []string, limit int) []string {
	if len(values) <= limit {
		return values
	}
	return values[:limit]
}
