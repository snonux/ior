// Package presenter formats globalfilter domain values for human-readable
// display. It imports globalfilter types but adds no domain logic, keeping
// presentation concerns out of the core filter package.
package presenter

import (
	"fmt"
	"strings"
	"time"

	"ior/internal/globalfilter"
)

// CompareOpSymbol returns the display symbol for a numeric comparison operator
// (e.g. OpEq → "=", OpNeq → "!=").
func CompareOpSymbol(op globalfilter.CompareOp) string {
	switch op {
	case globalfilter.OpEq:
		return "="
	case globalfilter.OpNeq:
		return "!="
	case globalfilter.OpGt:
		return ">"
	case globalfilter.OpGte:
		return ">="
	case globalfilter.OpLt:
		return "<"
	case globalfilter.OpLte:
		return "<="
	default:
		return "?"
	}
}

// AppendStringSummary appends a "name~pattern" token to parts when sf is
// non-nil and its pattern is non-empty, then returns the updated slice.
func AppendStringSummary(parts []string, name string, sf *globalfilter.StringFilter) []string {
	if sf == nil {
		return parts
	}
	pattern := strings.TrimSpace(sf.Pattern)
	if pattern == "" {
		return parts
	}
	return append(parts, fmt.Sprintf("%s~%s", name, pattern))
}

// AppendNumericSummary appends a "nameOPvalue" token to parts when nf is
// non-nil. When duration is true the value is formatted as a time.Duration
// string rather than a raw integer.
func AppendNumericSummary(parts []string, name string, nf *globalfilter.NumericFilter, duration bool) []string {
	if nf == nil {
		return parts
	}
	value := fmt.Sprintf("%d", nf.Value)
	if duration {
		value = time.Duration(nf.Value).String()
	}
	return append(parts, fmt.Sprintf("%s%s%s", name, CompareOpSymbol(nf.Op), value))
}

// FilterSummary returns a compact human-readable description of all active
// filter predicates, e.g. "syscall~read pid=1234". Returns "all" when no
// predicates are set. This is the canonical presentation of a Filter value
// for status bars and log messages.
func FilterSummary(f globalfilter.Filter) string {
	parts := make([]string, 0, 10)
	if f.ErrorsOnly {
		parts = append(parts, "errors")
	}
	parts = AppendStringSummary(parts, "syscall", f.Syscall)
	parts = AppendStringSummary(parts, "family", f.Family)
	parts = AppendStringSummary(parts, "comm", f.Comm)
	parts = AppendStringSummary(parts, "file", f.File)
	parts = AppendNumericSummary(parts, "pid", f.PID, false)
	parts = AppendNumericSummary(parts, "tid", f.TID, false)
	parts = AppendNumericSummary(parts, "fd", f.FD, false)
	parts = AppendNumericSummary(parts, "latency", f.LatencyNs, true)
	parts = AppendNumericSummary(parts, "gap", f.GapNs, true)
	parts = AppendNumericSummary(parts, "bytes", f.Bytes, false)
	parts = AppendNumericSummary(parts, "ret", f.RetVal, false)
	if len(parts) == 0 {
		return "all"
	}
	return strings.Join(parts, " ")
}
