// Package parser provides input parsing helpers for globalfilter values.
// It is intentionally kept free of domain types so it can be imported by
// both globalfilter and its callers without creating import cycles.
package parser

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ParseDurationNs parses a human-readable duration string and returns the
// equivalent number of nanoseconds. Plain integers are interpreted as
// nanoseconds directly. Standard Go duration suffixes (ns, us/µs/μs, ms, s…)
// are also accepted. Returns an error for empty or unparseable input.
func ParseDurationNs(input string) (int64, error) {
	s := strings.TrimSpace(strings.ToLower(input))
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	s = strings.ReplaceAll(s, "µs", "us")
	s = strings.ReplaceAll(s, "μs", "us")
	if onlyDigits(s) || strings.HasPrefix(s, "-") && onlyDigits(s[1:]) {
		v, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return 0, err
		}
		return v, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, err
	}
	return d.Nanoseconds(), nil
}

// onlyDigits reports whether s is a non-empty string of ASCII decimal digits.
func onlyDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}
