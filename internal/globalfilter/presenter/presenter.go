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

// Dimension identifies one filter predicate of a globalfilter.Filter for
// labelling. The declaration order is the canonical display order used by
// FilterSummary and by change labels built from DimensionSummary.
type Dimension int

// The filter dimensions, in canonical display order.
const (
	DimSyscall Dimension = iota
	DimFamily
	DimComm
	DimFile
	DimPID
	DimTID
	DimFD
	DimLatency
	DimGap
	DimBytes
	DimRet
)

// Dimensions lists every Dimension in canonical display order. It returns a
// fresh slice so callers cannot reorder the shared sequence.
func Dimensions() []Dimension {
	return []Dimension{
		DimSyscall, DimFamily, DimComm, DimFile,
		DimPID, DimTID, DimFD, DimLatency, DimGap, DimBytes, DimRet,
	}
}

// Name returns the dimension's display name ("syscall", "pid", "latency",
// ...), or "?" for an unknown dimension.
func (d Dimension) Name() string {
	switch d {
	case DimSyscall:
		return "syscall"
	case DimFamily:
		return "family"
	case DimComm:
		return "comm"
	case DimFile:
		return "file"
	case DimPID:
		return "pid"
	case DimTID:
		return "tid"
	case DimFD:
		return "fd"
	case DimLatency:
		return "latency"
	case DimGap:
		return "gap"
	case DimBytes:
		return "bytes"
	case DimRet:
		return "ret"
	default:
		return "?"
	}
}

// DimensionSummary returns the canonical token for f's constraint on d, e.g.
// "comm~nginx", "pid=42" or "latency>=1.5ms". It returns "" when that
// dimension is unset (nil, or a blank string pattern) or d is unknown. This is
// the single source of the per-predicate wording shared by FilterSummary and
// by every UI filter action label.
func DimensionSummary(f globalfilter.Filter, d Dimension) string {
	var parts []string
	switch d {
	case DimSyscall:
		parts = AppendStringSummary(nil, d.Name(), f.Syscall)
	case DimFamily:
		parts = AppendStringSummary(nil, d.Name(), f.Family)
	case DimComm:
		parts = AppendStringSummary(nil, d.Name(), f.Comm)
	case DimFile:
		parts = AppendStringSummary(nil, d.Name(), f.File)
	case DimPID:
		parts = AppendNumericSummary(nil, d.Name(), f.PID, false)
	case DimTID:
		parts = AppendNumericSummary(nil, d.Name(), f.TID, false)
	case DimFD:
		parts = AppendNumericSummary(nil, d.Name(), f.FD, false)
	case DimLatency:
		parts = AppendNumericSummary(nil, d.Name(), f.LatencyNs, true)
	case DimGap:
		parts = AppendNumericSummary(nil, d.Name(), f.GapNs, true)
	case DimBytes:
		parts = AppendNumericSummary(nil, d.Name(), f.Bytes, false)
	case DimRet:
		parts = AppendNumericSummary(nil, d.Name(), f.RetVal, false)
	}
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

// FilterSummary returns a compact human-readable description of all active
// filter predicates, e.g. "syscall~read pid=1234". Returns "all" when no
// predicates are set. This is the canonical presentation of a Filter value
// for status bars and log messages.
func FilterSummary(f globalfilter.Filter) string {
	parts := make([]string, 0, 12)
	if f.ErrorsOnly {
		parts = append(parts, "errors")
	}
	for _, d := range Dimensions() {
		if token := DimensionSummary(f, d); token != "" {
			parts = append(parts, token)
		}
	}
	if len(parts) == 0 {
		return "all"
	}
	return strings.Join(parts, " ")
}
