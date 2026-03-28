package claims

import (
	"testing"
)

func TestCompactStrings(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"nil input", nil, nil},
		{"empty input", []string{}, nil},
		{"all empty strings", []string{"", "", ""}, nil},
		{"no empty", []string{"b", "a"}, []string{"a", "b"}},
		{"mixed", []string{"a", "", "b", "", "c"}, []string{"a", "b", "c"}},
		{"duplicates removed", []string{"a", "a", "b"}, []string{"a", "b"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := compactStrings(tt.in)
			if len(got) != len(tt.want) {
				t.Fatalf("compactStrings(%v) = %v, want %v", tt.in, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("compactStrings(%v)[%d] = %q, want %q", tt.in, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestDedupeStringsSorted(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"nil", nil, nil},
		{"empty", []string{}, nil},
		{"all empty strings", []string{"", "", ""}, nil},
		{"single", []string{"a"}, []string{"a"}},
		{"duplicates", []string{"b", "a", "b", "a"}, []string{"a", "b"}},
		{"sorted output", []string{"c", "a", "b"}, []string{"a", "b", "c"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dedupeStringsSorted(tt.in)
			if len(got) != len(tt.want) {
				t.Fatalf("dedupeStringsSorted(%v) = %v, want %v", tt.in, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("dedupeStringsSorted(%v)[%d] = %q, want %q", tt.in, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestFirstNonEmpty(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		values []string
		want   string
	}{
		{"no values", nil, ""},
		{"all empty", []string{"", ""}, ""},
		{"first non-empty", []string{"", "a", "b"}, "a"},
		{"first is non-empty", []string{"x", "y"}, "x"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := firstNonEmpty(tt.values...)
			if got != tt.want {
				t.Fatalf("firstNonEmpty(%v) = %q, want %q", tt.values, got, tt.want)
			}
		})
	}
}

func TestClamp(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		v, lo, hi  float64
		want       float64
	}{
		{"below low", -1, 0, 1, 0},
		{"above high", 2, 0, 1, 1},
		{"in range", 0.5, 0, 1, 0.5},
		{"at low", 0, 0, 1, 0},
		{"at high", 1, 0, 1, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := clamp(tt.v, tt.lo, tt.hi)
			if got != tt.want {
				t.Fatalf("clamp(%v, %v, %v) = %v, want %v", tt.v, tt.lo, tt.hi, got, tt.want)
			}
		})
	}
}
