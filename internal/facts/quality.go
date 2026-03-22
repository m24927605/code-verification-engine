package facts

// FactQuality represents the provenance quality of an extracted fact.
// Higher quality means more reliable extraction (AST > structural > heuristic).
type FactQuality string

const (
	// QualityProof indicates the fact was extracted via AST/native parser (e.g., go/ast, tree-sitter).
	QualityProof FactQuality = "proof"
	// QualityStructural indicates the fact was extracted via structural parsing or filtered regex patterns.
	QualityStructural FactQuality = "structural"
	// QualityHeuristic indicates the fact was extracted via regex/raw pattern match or name/path heuristics.
	QualityHeuristic FactQuality = "heuristic"
)

// qualityRank maps quality levels to numeric ranks for comparison.
// Higher rank means higher quality.
var qualityRank = map[FactQuality]int{
	QualityHeuristic:  0,
	QualityStructural: 1,
	QualityProof:      2,
}

// MinQuality returns the lowest quality from a set of qualities.
// If no qualities are provided, it returns QualityHeuristic as the safest default.
func MinQuality(qualities ...FactQuality) FactQuality {
	if len(qualities) == 0 {
		return QualityHeuristic
	}
	min := qualities[0]
	minRank := qualityRank[min]
	for _, q := range qualities[1:] {
		r := qualityRank[q]
		if r < minRank {
			min = q
			minRank = r
		}
	}
	return min
}
