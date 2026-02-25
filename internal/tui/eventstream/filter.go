package eventstream

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

type CompareOp int

const (
	OpEq CompareOp = iota
	OpNeq
	OpGt
	OpGte
	OpLt
	OpLte
)

type NumericFilter struct {
	Op    CompareOp
	Value int64
}

type StringFilter struct {
	Pattern string
}

type Filter struct {
	Syscall    *StringFilter
	Comm       *StringFilter
	File       *StringFilter
	PID        *NumericFilter
	TID        *NumericFilter
	LatencyNs  *NumericFilter
	GapNs      *NumericFilter
	Bytes      *NumericFilter
	RetVal     *NumericFilter
	ErrorsOnly bool
}

func (f Filter) Matches(ev *StreamEvent) bool {
	if ev == nil {
		return false
	}
	if f.ErrorsOnly && !ev.IsError {
		return false
	}
	if !matchString(f.Syscall, ev.Syscall) {
		return false
	}
	if !matchString(f.Comm, ev.Comm) {
		return false
	}
	if !matchString(f.File, ev.FileName) {
		return false
	}
	if !matchNumeric(f.PID, int64(ev.PID)) {
		return false
	}
	if !matchNumeric(f.TID, int64(ev.TID)) {
		return false
	}
	if !matchNumeric(f.LatencyNs, int64(ev.DurationNs)) {
		return false
	}
	if !matchNumeric(f.GapNs, int64(ev.GapNs)) {
		return false
	}
	if !matchNumeric(f.Bytes, int64(ev.Bytes)) {
		return false
	}
	if !matchNumeric(f.RetVal, ev.RetVal) {
		return false
	}
	return true
}

func (f Filter) IsActive() bool {
	if f.ErrorsOnly {
		return true
	}
	for _, sf := range []*StringFilter{f.Syscall, f.Comm, f.File} {
		if sf != nil && strings.TrimSpace(sf.Pattern) != "" {
			return true
		}
	}
	for _, nf := range []*NumericFilter{f.PID, f.TID, f.LatencyNs, f.GapNs, f.Bytes, f.RetVal} {
		if nf != nil {
			return true
		}
	}
	return false
}

func (f Filter) Summary() string {
	parts := make([]string, 0, 10)
	if f.ErrorsOnly {
		parts = append(parts, "errors")
	}
	parts = appendStringSummary(parts, "syscall", f.Syscall)
	parts = appendStringSummary(parts, "comm", f.Comm)
	parts = appendStringSummary(parts, "file", f.File)
	parts = appendNumericSummary(parts, "pid", f.PID, false)
	parts = appendNumericSummary(parts, "tid", f.TID, false)
	parts = appendNumericSummary(parts, "latency", f.LatencyNs, true)
	parts = appendNumericSummary(parts, "gap", f.GapNs, true)
	parts = appendNumericSummary(parts, "bytes", f.Bytes, false)
	parts = appendNumericSummary(parts, "ret", f.RetVal, false)
	if len(parts) == 0 {
		return "all"
	}
	return strings.Join(parts, " ")
}

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

func appendStringSummary(parts []string, name string, sf *StringFilter) []string {
	if sf == nil {
		return parts
	}
	pattern := strings.TrimSpace(sf.Pattern)
	if pattern == "" {
		return parts
	}
	return append(parts, fmt.Sprintf("%s~%s", name, pattern))
}

func appendNumericSummary(parts []string, name string, nf *NumericFilter, duration bool) []string {
	if nf == nil {
		return parts
	}
	value := strconv.FormatInt(nf.Value, 10)
	if duration {
		value = time.Duration(nf.Value).String()
	}
	return append(parts, fmt.Sprintf("%s%s%s", name, compareOpSymbol(nf.Op), value))
}

func matchString(sf *StringFilter, value string) bool {
	if sf == nil {
		return true
	}
	pattern := strings.ToLower(strings.TrimSpace(sf.Pattern))
	if pattern == "" {
		return true
	}
	return strings.Contains(strings.ToLower(value), pattern)
}

func matchNumeric(nf *NumericFilter, value int64) bool {
	if nf == nil {
		return true
	}
	switch nf.Op {
	case OpEq:
		return value == nf.Value
	case OpNeq:
		return value != nf.Value
	case OpGt:
		return value > nf.Value
	case OpGte:
		return value >= nf.Value
	case OpLt:
		return value < nf.Value
	case OpLte:
		return value <= nf.Value
	default:
		return false
	}
}

func compareOpSymbol(op CompareOp) string {
	switch op {
	case OpEq:
		return "="
	case OpNeq:
		return "!="
	case OpGt:
		return ">"
	case OpGte:
		return ">="
	case OpLt:
		return "<"
	case OpLte:
		return "<="
	default:
		return "?"
	}
}

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
