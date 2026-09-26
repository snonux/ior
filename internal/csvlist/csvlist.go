// Package csvlist splits the comma-separated list values accepted by ior's
// command-line flags (-tps, -tpsExclude, -trace-*, -no-trace-*, -fields and
// the -syscall-sampling-* name=rate lists).
//
// It is the single home for that tokenisation so every list flag treats
// stray commas and padding the same way. That matters most for the regex
// lists: an empty regex matches every name, so a blank entry left in by a
// trailing comma would silently select (or exclude) everything.
package csvlist

import "strings"

// Split splits raw on commas, trims surrounding whitespace from each entry and
// drops entries that are blank after trimming. It returns nil when no
// non-blank entry remains, so callers can treat a blank or comma-only value
// exactly like an unset flag by checking len(result) == 0.
//
// Entries cannot contain a comma: there is no quoting or escaping.
func Split(raw string) []string {
	parts := strings.Split(raw, ",")
	var values []string
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			values = append(values, part)
		}
	}
	return values
}
