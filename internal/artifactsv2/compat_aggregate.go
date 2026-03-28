package artifactsv2

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/verabase/code-verification-engine/internal/report"
	"github.com/verabase/code-verification-engine/internal/rules"
)

type compatAggregationResult struct {
	Candidates     []IssueCandidate
	RuleToIssueIDs map[string][]string
}

type compatIssueCluster struct {
	Fingerprint        string
	RuleFamily         string
	MergeBasis         string
	Category           string
	Severity           string
	Status             string
	Title              string
	File               string
	Symbol             string
	StartLine          int
	EndLine            int
	EvidenceIDs        []string
	CounterEvidenceIDs []string
	Sources            []string
	RuleIDs            []string
	Confidence         float64
	Quality            float64
}

func buildIssues(scan report.ScanReport, verification VerificationSource, evidenceArtifact *EvidenceArtifact, evidenceIndex map[string]EvidenceRecord) compatAggregationResult {
	store := NewEvidenceStoreFromRecords(evidenceArtifact.Evidence)
	seeds := buildIssueSeeds(scan, verification, store, evidenceIndex)
	store.Finalize()
	evidenceArtifact.Evidence = store.All()
	clusters := clusterCompatIssues(seeds, evidenceIndex)
	issueCandidates := make([]IssueCandidate, 0, len(clusters))
	for _, cluster := range clusters {
		issueID := compatIssueID(cluster)
		cluster = overlayAgentResultsOnCluster(cluster, issueID, verification.AgentResults, evidenceIndex)
		breakdown := computeConfidenceBreakdown(cluster, scan, verification)
		confidenceClass := classifyConfidence(breakdown.Final)
		policyClass := deriveIssuePolicyClass(cluster, breakdown)
		issueCandidates = append(issueCandidates, IssueCandidate{
			ID:                  issueID,
			Fingerprint:         cluster.Fingerprint,
			RuleFamily:          cluster.RuleFamily,
			MergeBasis:          cluster.MergeBasis,
			Category:            cluster.Category,
			Title:               cluster.Title,
			Severity:            cluster.Severity,
			Confidence:          breakdown.Final,
			ConfidenceClass:     confidenceClass,
			PolicyClass:         policyClass,
			Status:              cluster.Status,
			RuleIDs:             dedupeStringsSorted(cluster.RuleIDs),
			EvidenceIDs:         dedupeStringsSorted(cluster.EvidenceIDs),
			CounterEvidenceIDs:  dedupeStringsSorted(cluster.CounterEvidenceIDs),
			SkillImpacts:        nil,
			Sources:             dedupeStringsSorted(cluster.Sources),
			SourceSummary:       computeIssueSourceSummary(cluster),
			ConfidenceBreakdown: breakdown,
		})
	}
	sort.Slice(issueCandidates, func(i, j int) bool { return issueCandidates[i].ID < issueCandidates[j].ID })
	ruleToIssueIDs := buildRuleToIssueIDs(issueCandidates)
	return compatAggregationResult{Candidates: issueCandidates, RuleToIssueIDs: ruleToIssueIDs}
}

func overlayAgentResultsOnCluster(cluster compatIssueCluster, issueID string, results []AgentResult, evidenceIndex map[string]EvidenceRecord) compatIssueCluster {
	if len(results) == 0 || issueID == "" {
		return cluster
	}
	for _, result := range results {
		if result.IssueID != issueID || result.Status != "completed" {
			continue
		}
		cluster.Sources = append(cluster.Sources, "agent")
		for _, record := range result.EmittedEvidence {
			if record.ID == "" {
				continue
			}
			cluster.EvidenceIDs = append(cluster.EvidenceIDs, record.ID)
		}
	}
	cluster.EvidenceIDs = dedupeStringsSorted(cluster.EvidenceIDs)
	cluster.CounterEvidenceIDs = collectCounterEvidenceIDs(cluster.EvidenceIDs, evidenceIndex)
	cluster.Sources = dedupeStringsSorted(cluster.Sources)
	return cluster
}

func buildIssueSeeds(scan report.ScanReport, verification VerificationSource, store *EvidenceStore, evidenceIndex map[string]EvidenceRecord) []IssueSeed {
	if len(verification.IssueSeeds) > 0 {
		return normalizeIssueSeeds(scan, verification, store, evidenceIndex)
	}
	seeds := IssueSeedsFromFindingsWithMetadata(verification.Findings, verification.RuleMetadata)
	seedCursor := 0
	for _, finding := range verification.Findings {
		if finding.Status == rules.StatusPass {
			continue
		}
		evIDs := make([]string, 0, len(finding.Evidence))
		for _, ev := range finding.Evidence {
			id := ev.ID
			if id == "" {
				id = compatEvidenceID(finding.RuleID, ev)
			}
			if _, ok := evidenceIndex[id]; ok {
				evIDs = append(evIDs, id)
			}
		}
		if len(evIDs) == 0 {
			id := compatSyntheticIssueEvidenceID(finding)
			synthetic := EvidenceRecord{
				ID:              id,
				Kind:            "rule_assertion",
				Source:          compatEvidenceSource(finding),
				ProducerID:      "rule:" + finding.RuleID,
				ProducerVersion: verification.ReportSchemaVersion,
				Repo:            scan.RepoName,
				Commit:          scan.CommitSHA,
				BoundaryHash:    compatBoundaryHash(scan),
				FactQuality:     compatFactQuality(finding),
				EntityIDs:       nil,
				Locations:       []LocationRef{{RepoRelPath: "unknown", StartLine: 1, EndLine: 1}},
				Claims:          []string{finding.RuleID},
				Payload:         map[string]any{"message": finding.Message, "status": string(finding.Status), "synthetic": true},
				Supports:        nil,
				Contradicts:     nil,
				DerivedFrom:     []string{finding.RuleID},
				CreatedAt:       scan.ScannedAt,
			}
			evidenceIndex[id] = synthetic
			store.Upsert(synthetic)
			evIDs = append(evIDs, id)
		}
		if seedCursor < len(seeds) {
			seeds[seedCursor].EvidenceIDs = dedupeStringsSorted(evIDs)
			seedCursor++
		}
	}
	return seeds
}

func normalizeIssueSeeds(scan report.ScanReport, verification VerificationSource, store *EvidenceStore, evidenceIndex map[string]EvidenceRecord) []IssueSeed {
	seeds := make([]IssueSeed, 0, len(verification.IssueSeeds))
	for _, seed := range verification.IssueSeeds {
		normalized := normalizeIssueSeedDefaults(seed)
		ensureIssueSeedEvidenceRecords(scan, verification, normalized, evidenceIndex)
		for _, id := range normalized.EvidenceIDs {
			if record, ok := evidenceIndex[id]; ok {
				store.Upsert(record)
			}
		}
		seeds = append(seeds, normalized)
	}
	return seeds
}

func compatPrimaryLocation(f rules.Finding) (file, symbol string, startLine, endLine int) {
	if len(f.Evidence) == 0 {
		return "unknown", "", 1, 1
	}
	evs := append([]rules.Evidence(nil), f.Evidence...)
	sort.Slice(evs, func(i, j int) bool {
		if evs[i].File != evs[j].File {
			return evs[i].File < evs[j].File
		}
		if evs[i].LineStart != evs[j].LineStart {
			return evs[i].LineStart < evs[j].LineStart
		}
		return evs[i].Symbol < evs[j].Symbol
	})
	ev := evs[0]
	return filepathToSlash(ev.File), ev.Symbol, max(1, ev.LineStart), max(ev.LineStart, ev.LineEnd)
}

func clusterCompatIssues(seeds []IssueSeed, evidenceIndex map[string]EvidenceRecord) []compatIssueCluster {
	sort.Slice(seeds, func(i, j int) bool {
		if seeds[i].File != seeds[j].File {
			return seeds[i].File < seeds[j].File
		}
		if seeds[i].StartLine != seeds[j].StartLine {
			return seeds[i].StartLine < seeds[j].StartLine
		}
		return seeds[i].RuleID < seeds[j].RuleID
	})

	var clusters []compatIssueCluster
	for _, seed := range seeds {
		matched := false
		for i := range clusters {
			if mergeBasis, ok := compatMergeBasis(clusters[i], seed); ok {
				clusters[i] = mergeCompatCluster(clusters[i], seed)
				clusters[i].MergeBasis = mergeBasis
				matched = true
				break
			}
		}
		if matched {
			continue
		}
		clusters = append(clusters, compatIssueCluster{
			Fingerprint:        compatClusterFingerprint(seed),
			RuleFamily:         compatRuleMergeFamily([]string{seed.RuleID}, seed.Category),
			MergeBasis:         compatInitialMergeBasis(seed),
			Category:           seed.Category,
			Severity:           seed.Severity,
			Status:             seed.Status,
			Title:              seed.Title,
			File:               seed.File,
			Symbol:             seed.Symbol,
			StartLine:          seed.StartLine,
			EndLine:            seed.EndLine,
			EvidenceIDs:        append([]string(nil), seed.EvidenceIDs...),
			CounterEvidenceIDs: nil,
			Sources:            []string{seed.Source},
			RuleIDs:            []string{seed.RuleID},
			Confidence:         seed.Confidence,
			Quality:            seed.Quality,
		})
	}
	for i := range clusters {
		clusters[i].EvidenceIDs = dedupeStringsSorted(clusters[i].EvidenceIDs)
		clusters[i].CounterEvidenceIDs = collectCounterEvidenceIDs(clusters[i].EvidenceIDs, evidenceIndex)
		clusters[i].Sources = dedupeStringsSorted(clusters[i].Sources)
		clusters[i].RuleIDs = dedupeStringsSorted(clusters[i].RuleIDs)
	}
	return clusters
}

func compatMergeBasis(cluster compatIssueCluster, seed IssueSeed) (string, bool) {
	if cluster.Status != seed.Status {
		return "", false
	}
	if cluster.File != seed.File {
		return "", false
	}
	clusterFamily := compatRuleMergeFamily(cluster.RuleIDs, cluster.Category)
	seedFamily := compatRuleMergeFamily([]string{seed.RuleID}, seed.Category)
	if cluster.Symbol != "" && seed.Symbol != "" {
		return "same_symbol", cluster.Symbol == seed.Symbol && sameSymbolMergeAllowed(clusterFamily, seedFamily)
	}
	if !lineOverlapMergeAllowed(clusterFamily, seedFamily) {
		return "", false
	}
	return "line_overlap", compatLineOverlap(cluster.StartLine, cluster.EndLine, seed.StartLine, seed.EndLine)
}

func compatInitialMergeBasis(seed IssueSeed) string {
	if seed.Symbol != "" {
		return "same_symbol"
	}
	return "line_overlap"
}

func mergeCompatCluster(cluster compatIssueCluster, seed IssueSeed) compatIssueCluster {
	cluster.EvidenceIDs = append(cluster.EvidenceIDs, seed.EvidenceIDs...)
	cluster.Sources = append(cluster.Sources, seed.Source)
	cluster.RuleIDs = append(cluster.RuleIDs, seed.RuleID)
	cluster.StartLine = minInt(cluster.StartLine, seed.StartLine)
	cluster.EndLine = max(cluster.EndLine, seed.EndLine)
	cluster.Confidence = math.Max(cluster.Confidence, seed.Confidence)
	cluster.Quality = math.Max(cluster.Quality, seed.Quality)
	cluster.Severity = higherSeverity(cluster.Severity, seed.Severity)
	cluster.Category = preferredCategory(cluster.Category, seed.Category)
	cluster.Title = chooseCompatTitle(cluster.Title, seed.Title)
	cluster.RuleFamily = compatRuleMergeFamily(cluster.RuleIDs, cluster.Category)
	cluster.Fingerprint = compatClusterFingerprintFromCluster(cluster)
	return cluster
}

func compatClusterFingerprint(seed IssueSeed) string {
	key := fmt.Sprintf("%s|%s|%s|%d|%d|%s", seed.Status, seed.File, seed.Symbol, seed.StartLine, seed.EndLine, compatRuleMergeFamily([]string{seed.RuleID}, seed.Category))
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:8])
}

func compatClusterFingerprintFromCluster(cluster compatIssueCluster) string {
	key := fmt.Sprintf("%s|%s|%s|%d|%d|%s", cluster.Status, cluster.File, cluster.Symbol, cluster.StartLine, cluster.EndLine, compatRuleMergeFamily(cluster.RuleIDs, cluster.Category))
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:8])
}

func compatIssueID(cluster compatIssueCluster) string {
	return "iss-" + cluster.Fingerprint
}

func computeIssueSourceSummary(cluster compatIssueCluster) IssueSourceSummary {
	distinctSources := dedupeStringsSorted(cluster.Sources)
	ruleCount := len(dedupeStringsSorted(cluster.RuleIDs))
	deterministicSources := 0
	agentSources := 0
	for _, source := range distinctSources {
		switch strings.ToLower(source) {
		case "rule", "analyzer":
			deterministicSources++
		case "agent":
			agentSources++
		}
	}
	totalSources := len(distinctSources)
	return IssueSourceSummary{
		RuleCount:            ruleCount,
		DeterministicSources: deterministicSources,
		AgentSources:         agentSources,
		TotalSources:         totalSources,
		MultiSource:          totalSources >= 2 || ruleCount >= 2,
	}
}

func compatLineOverlap(aStart, aEnd, bStart, bEnd int) bool {
	return aStart <= bEnd+2 && bStart <= aEnd+2
}

func higherSeverity(a, b string) string {
	rank := map[string]int{"low": 0, "medium": 1, "high": 2, "critical": 3}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

func chooseCompatTitle(a, b string) string {
	if len(b) > len(a) {
		return b
	}
	if len(b) < len(a) {
		return a
	}
	na := strings.ToLower(strings.TrimSpace(a))
	nb := strings.ToLower(strings.TrimSpace(b))
	if nb < na {
		return b
	}
	if nb > na {
		return a
	}
	if b < a {
		return b
	}
	return a
}

func preferredCategory(a, b string) string {
	rank := map[string]int{"security": 3, "design": 2, "bug": 1}
	if rank[b] > rank[a] {
		return b
	}
	if rank[b] < rank[a] {
		return a
	}
	na := strings.ToLower(strings.TrimSpace(a))
	nb := strings.ToLower(strings.TrimSpace(b))
	if na == "" && nb != "" {
		return b
	}
	if nb == "" && na != "" {
		return a
	}
	if nb < na {
		return b
	}
	if nb > na {
		return a
	}
	if b < a {
		return b
	}
	return a
}

func compatCategoryMergeFamily(category string) string {
	switch strings.ToLower(strings.TrimSpace(category)) {
	case "security", "frontend_security":
		return "security"
	case "architecture", "design":
		return "architecture_design"
	case "quality", "testing", "frontend_quality":
		return "quality_testing"
	case "bug", "":
		return "bug"
	default:
		return strings.ToLower(strings.TrimSpace(category))
	}
}

func expandRuleToIssueIDs(ruleIDs []string, ruleToIssueIDs map[string][]string) []string {
	var ids []string
	for _, ruleID := range ruleIDs {
		if mapped := ruleToIssueIDs[ruleID]; len(mapped) > 0 {
			ids = append(ids, mapped...)
			continue
		}
		ids = append(ids, "iss-"+strings.ToLower(strings.ReplaceAll(ruleID, "_", "-")))
	}
	return ids
}

func expandMappedRuleToIssueIDs(ruleIDs []string, ruleToIssueIDs map[string][]string) []string {
	var ids []string
	for _, ruleID := range ruleIDs {
		if mapped := ruleToIssueIDs[ruleID]; len(mapped) > 0 {
			ids = append(ids, mapped...)
		}
	}
	return dedupeStringsSorted(ids)
}

func buildRuleToIssueIDs(candidates []IssueCandidate) map[string][]string {
	out := make(map[string][]string)
	for _, candidate := range candidates {
		for _, ruleID := range dedupeStringsSorted(candidate.RuleIDs) {
			out[ruleID] = append(out[ruleID], candidate.ID)
		}
	}
	for ruleID := range out {
		out[ruleID] = dedupeStringsSorted(out[ruleID])
	}
	return out
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func filepathToSlash(path string) string {
	return strings.ReplaceAll(path, "\\", "/")
}

func compatSyntheticSeedEvidenceID(seed IssueSeed) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("seed:%s:%s:%s:%d:%d:%s", seed.RuleID, seed.Status, seed.File, seed.StartLine, seed.EndLine, seed.Symbol)))
	return "ev-" + hex.EncodeToString(sum[:8])
}

func compatSeedFactQuality(quality float64) string {
	switch {
	case quality >= 0.95:
		return "proof"
	case quality >= 0.65:
		return "structural"
	default:
		return "heuristic"
	}
}

func collectCounterEvidenceIDs(evidenceIDs []string, evidenceIndex map[string]EvidenceRecord) []string {
	if len(evidenceIDs) == 0 || len(evidenceIndex) == 0 {
		return nil
	}
	withinCluster := make(map[string]struct{}, len(evidenceIDs))
	for _, evidenceID := range evidenceIDs {
		withinCluster[evidenceID] = struct{}{}
	}
	var counter []string
	for _, evidenceID := range evidenceIDs {
		record, ok := evidenceIndex[evidenceID]
		if !ok {
			continue
		}
		for _, contradictID := range record.Contradicts {
			if _, sameCluster := withinCluster[contradictID]; sameCluster {
				continue
			}
			if _, exists := evidenceIndex[contradictID]; !exists {
				continue
			}
			counter = append(counter, contradictID)
		}
	}
	return dedupeStringsSorted(counter)
}

func normalizeVerificationSource(scan report.ScanReport, verification VerificationSource) VerificationSource {
	out := verification.Clone()
	if len(out.IssueSeeds) == 0 {
		return out
	}
	for i := range out.IssueSeeds {
		out.IssueSeeds[i] = normalizeIssueSeedDefaults(out.IssueSeeds[i])
	}
	_ = scan
	return out
}

func normalizeIssueSeedDefaults(seed IssueSeed) IssueSeed {
	normalized := seed
	if normalized.Title == "" {
		normalized.Title = normalized.RuleID
	}
	if normalized.File == "" {
		normalized.File = "unknown"
	}
	normalized.File = filepathToSlash(normalized.File)
	if normalized.StartLine <= 0 {
		normalized.StartLine = 1
	}
	if normalized.EndLine < normalized.StartLine {
		normalized.EndLine = normalized.StartLine
	}
	if normalized.Status == "" {
		normalized.Status = "open"
	}
	if normalized.Category == "" {
		normalized.Category = "bug"
	}
	if normalized.Severity == "" {
		normalized.Severity = "medium"
	}
	if normalized.Source == "" {
		normalized.Source = "rule"
	}
	if normalized.Confidence <= 0 {
		normalized.Confidence = 0.45
	}
	if normalized.Quality <= 0 {
		normalized.Quality = 0.4
	}
	if len(normalized.EvidenceIDs) == 0 {
		normalized.EvidenceIDs = []string{compatSyntheticSeedEvidenceID(normalized)}
	}
	normalized.EvidenceIDs = dedupeStringsSorted(normalized.EvidenceIDs)
	return normalized
}

func ensureIssueSeedEvidenceRecords(scan report.ScanReport, verification VerificationSource, seed IssueSeed, evidenceIndex map[string]EvidenceRecord) {
	for _, id := range seed.EvidenceIDs {
		if _, ok := evidenceIndex[id]; ok {
			continue
		}
		evidenceIndex[id] = buildIssueSeedEvidenceRecord(scan, verification, seed, id)
	}
}

func buildIssueSeedEvidenceRecord(scan report.ScanReport, verification VerificationSource, seed IssueSeed, evidenceID string) EvidenceRecord {
	return EvidenceRecord{
		ID:              evidenceID,
		Kind:            "rule_assertion",
		Source:          seed.Source,
		ProducerID:      "rule:" + seed.RuleID,
		ProducerVersion: verification.ReportSchemaVersion,
		Repo:            scan.RepoName,
		Commit:          scan.CommitSHA,
		BoundaryHash:    compatBoundaryHash(scan),
		FactQuality:     compatSeedFactQuality(seed.Quality),
		EntityIDs:       compactStrings([]string{seed.Symbol}),
		Locations: []LocationRef{{
			RepoRelPath: seed.File,
			StartLine:   seed.StartLine,
			EndLine:     seed.EndLine,
			SymbolID:    seed.Symbol,
		}},
		Claims:      compactStrings([]string{seed.RuleID}),
		Payload:     map[string]any{"title": seed.Title, "status": seed.Status, "synthetic": true},
		Supports:    nil,
		Contradicts: nil,
		DerivedFrom: compactStrings([]string{seed.RuleID}),
		CreatedAt:   scan.ScannedAt,
	}
}
