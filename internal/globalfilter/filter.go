package globalfilter

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

type Candidate interface {
	SyscallValue() string
	CommValue() string
	FileValue() string
	PIDValue() uint32
	TIDValue() uint32
	FDValue() int32
	LatencyValue() uint64
	GapValue() uint64
	BytesValue() uint64
	ReturnValue() int64
	ErrorValue() bool
}

type Filter struct {
	Syscall    *StringFilter
	Comm       *StringFilter
	File       *StringFilter
	PID        *NumericFilter
	TID        *NumericFilter
	FD         *NumericFilter
	LatencyNs  *NumericFilter
	GapNs      *NumericFilter
	Bytes      *NumericFilter
	RetVal     *NumericFilter
	ErrorsOnly bool
}

func (f Filter) Clone() Filter {
	out := f
	out.Syscall = cloneStringFilter(f.Syscall)
	out.Comm = cloneStringFilter(f.Comm)
	out.File = cloneStringFilter(f.File)
	out.PID = cloneNumericFilter(f.PID)
	out.TID = cloneNumericFilter(f.TID)
	out.FD = cloneNumericFilter(f.FD)
	out.LatencyNs = cloneNumericFilter(f.LatencyNs)
	out.GapNs = cloneNumericFilter(f.GapNs)
	out.Bytes = cloneNumericFilter(f.Bytes)
	out.RetVal = cloneNumericFilter(f.RetVal)
	return out
}

func (f Filter) Equal(other Filter) bool {
	return sameStringFilter(f.Syscall, other.Syscall) &&
		sameStringFilter(f.Comm, other.Comm) &&
		sameStringFilter(f.File, other.File) &&
		sameNumericFilter(f.PID, other.PID) &&
		sameNumericFilter(f.TID, other.TID) &&
		sameNumericFilter(f.FD, other.FD) &&
		sameNumericFilter(f.LatencyNs, other.LatencyNs) &&
		sameNumericFilter(f.GapNs, other.GapNs) &&
		sameNumericFilter(f.Bytes, other.Bytes) &&
		sameNumericFilter(f.RetVal, other.RetVal) &&
		f.ErrorsOnly == other.ErrorsOnly
}

func (f Filter) Matches(candidate Candidate) bool {
	if candidate == nil {
		return false
	}
	if f.ErrorsOnly && !candidate.ErrorValue() {
		return false
	}
	if !matchString(f.Syscall, candidate.SyscallValue()) {
		return false
	}
	if !matchString(f.Comm, candidate.CommValue()) {
		return false
	}
	if !matchString(f.File, candidate.FileValue()) {
		return false
	}
	if !matchNumeric(f.PID, int64(candidate.PIDValue())) {
		return false
	}
	if !matchNumeric(f.TID, int64(candidate.TIDValue())) {
		return false
	}
	if !matchNumeric(f.FD, int64(candidate.FDValue())) {
		return false
	}
	if !matchNumeric(f.LatencyNs, int64(candidate.LatencyValue())) {
		return false
	}
	if !matchNumeric(f.GapNs, int64(candidate.GapValue())) {
		return false
	}
	if !matchNumeric(f.Bytes, int64(candidate.BytesValue())) {
		return false
	}
	if !matchNumeric(f.RetVal, candidate.ReturnValue()) {
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
	for _, nf := range []*NumericFilter{f.PID, f.TID, f.FD, f.LatencyNs, f.GapNs, f.Bytes, f.RetVal} {
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
	parts = appendNumericSummary(parts, "fd", f.FD, false)
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
	return append(parts, fmt.Sprintf("%s%s%s", name, CompareOpSymbol(nf.Op), value))
}

func matchString(sf *StringFilter, value string) bool {
	if sf == nil {
		return true
	}
	pattern := strings.ToLower(strings.TrimSpace(sf.Pattern))
	if pattern == "" {
		return true
	}
	value = strings.ToLower(value)
	anchoredStart := strings.HasPrefix(pattern, "^")
	anchoredEnd := strings.HasSuffix(pattern, "$")
	if anchoredStart {
		pattern = pattern[1:]
	}
	if anchoredEnd && len(pattern) > 0 {
		pattern = pattern[:len(pattern)-1]
	}
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

// CompareOpSymbol returns the summary/render symbol for a numeric comparison operator.
func CompareOpSymbol(op CompareOp) string {
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

func cloneStringFilter(in *StringFilter) *StringFilter {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func cloneNumericFilter(in *NumericFilter) *NumericFilter {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func sameStringFilter(left, right *StringFilter) bool {
	switch {
	case left == nil && right == nil:
		return true
	case left == nil || right == nil:
		return false
	default:
		return left.Pattern == right.Pattern
	}
}

func sameNumericFilter(left, right *NumericFilter) bool {
	switch {
	case left == nil && right == nil:
		return true
	case left == nil || right == nil:
		return false
	default:
		return left.Op == right.Op && left.Value == right.Value
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
