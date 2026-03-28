package claims

import "sort"

const (
	ClaimStatusAccepted   = "accepted"
	ClaimStatusDowngraded = "downgraded"
	ClaimStatusRejected   = "rejected"
	ClaimStatusUnknown    = "unknown"
)

func compactStrings(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s != "" {
			out = append(out, s)
		}
	}
	return dedupeStringsSorted(out)
}

func dedupeStringsSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		set[s] = struct{}{}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func clamp(v, low, high float64) float64 {
	if v < low {
		return low
	}
	if v > high {
		return high
	}
	return v
}
