package globalfilter

import (
	"strings"
	"testing"
)

// referenceMatchString is the lowering implementation matchString used before
// the ASCII fast path; the fast path must select exactly the same values.
func referenceMatchString(sf *StringFilter, value string) bool {
	if sf == nil {
		return true
	}
	pattern := strings.ToLower(strings.TrimSpace(sf.Pattern))
	if pattern == "" {
		return true
	}
	value = strings.ToLower(value)
	pattern, anchoredStart, anchoredEnd := trimAnchors(pattern)
	switch {
	case anchoredStart && anchoredEnd:
		return value == pattern
	case anchoredStart:
		return strings.HasPrefix(value, pattern)
	case anchoredEnd:
		return strings.HasSuffix(value, pattern)
	default:
		return strings.Contains(value, pattern)
	}
}

// TestMatchStringASCIIFoldAgreesWithLowering cross-checks matchString against
// the lowering reference over every anchor mode, mixed case, boundary lengths
// (empty, pattern longer than value) and non-ASCII input, which must take the
// strings.ToLower fallback (the Kelvin sign lowers to an ASCII 'k').
func TestMatchStringASCIIFoldAgreesWithLowering(t *testing.T) {
	values := []string{"", "FS", "fs", "Network", "/Var/Log/Access.LOG", "read", "x",
		"Ärger", "ärger", "Kelvin", "kelvin", "@[`{"}
	cores := []string{"", "f", "FS", "s", "net", "WORK", "network2", "/var", "LOG", "access.log",
		"ä", "Ä", "kel", "K", "@", "`", "[", "{"}
	for _, core := range cores {
		for _, pattern := range []string{core, "^" + core, core + "$", "^" + core + "$", " " + core + " "} {
			sf := &StringFilter{Pattern: pattern}
			for _, value := range values {
				got, want := matchString(sf, value), referenceMatchString(sf, value)
				if got != want {
					t.Errorf("matchString(%q, %q) = %v, reference = %v", pattern, value, got, want)
				}
			}
		}
	}
}

// TestMatchStringASCIIDoesNotAllocate pins the allocation-free ASCII path:
// upper-case values (every row under a family filter) and upper-case patterns
// used to cost one strings.ToLower allocation each per candidate.
func TestMatchStringASCIIDoesNotAllocate(t *testing.T) {
	var sink bool
	for _, pattern := range []string{"Network", "^fs$", "^/var", "LOG$"} {
		sf := &StringFilter{Pattern: pattern}
		allocs := testing.AllocsPerRun(100, func() {
			sink = matchString(sf, "Network") || matchString(sf, "/Var/Log/Access.LOG")
		})
		if allocs != 0 {
			t.Errorf("matchString(%q) allocated %.0f times, want 0", pattern, allocs)
		}
	}
	_ = sink
}
