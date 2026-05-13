package globalfilter

import (
	"strings"
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
	// Op is the comparison operator applied when matching a candidate value.
	Op CompareOp
	// Value is the reference operand compared against the candidate value.
	Value int64
}

// NewEqFilter creates an equality NumericFilter for a positive value.
// Returns nil if value is not positive.
func NewEqFilter(value int64) *NumericFilter {
	if value <= 0 {
		return nil
	}
	return &NumericFilter{Op: OpEq, Value: value}
}

// EqValue returns the filter's positive equality value if the filter
// represents an exact-match constraint (Op == OpEq and Value > 0).
// Returns (0, false) when the filter is nil, uses a different operator,
// or has a non-positive value.
func (f *NumericFilter) EqValue() (int, bool) {
	if f == nil || f.Op != OpEq || f.Value <= 0 {
		return 0, false
	}
	return int(f.Value), true
}

type StringFilter struct {
	// Pattern is the substring (or anchored prefix/suffix) matched against the
	// candidate string value; matching is case-insensitive.
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
	// Syscall filters events by syscall/tracepoint name substring.
	Syscall *StringFilter
	// Comm filters events by process command name substring.
	Comm *StringFilter
	// File filters events by the file path involved in the syscall.
	File *StringFilter
	// PID filters events by process ID using a numeric comparison.
	PID *NumericFilter
	// TID filters events by thread ID using a numeric comparison.
	TID *NumericFilter
	// FD filters events by file descriptor number using a numeric comparison.
	FD *NumericFilter
	// LatencyNs filters events by syscall latency in nanoseconds.
	LatencyNs *NumericFilter
	// GapNs filters events by inter-syscall gap duration in nanoseconds.
	GapNs *NumericFilter
	// Bytes filters events by the number of bytes transferred.
	Bytes *NumericFilter
	// RetVal filters events by the syscall return value.
	RetVal *NumericFilter
	// ErrorsOnly restricts the filter to events where the syscall returned an error.
	ErrorsOnly bool
}

func (f Filter) Clone() Filter {
	out := f
	out.Syscall = cloneFilter(f.Syscall)
	out.Comm = cloneFilter(f.Comm)
	out.File = cloneFilter(f.File)
	out.PID = cloneFilter(f.PID)
	out.TID = cloneFilter(f.TID)
	out.FD = cloneFilter(f.FD)
	out.LatencyNs = cloneFilter(f.LatencyNs)
	out.GapNs = cloneFilter(f.GapNs)
	out.Bytes = cloneFilter(f.Bytes)
	out.RetVal = cloneFilter(f.RetVal)
	return out
}

func (f Filter) Equal(other Filter) bool {
	return sameFilter(f.Syscall, other.Syscall) &&
		sameFilter(f.Comm, other.Comm) &&
		sameFilter(f.File, other.File) &&
		sameFilter(f.PID, other.PID) &&
		sameFilter(f.TID, other.TID) &&
		sameFilter(f.FD, other.FD) &&
		sameFilter(f.LatencyNs, other.LatencyNs) &&
		sameFilter(f.GapNs, other.GapNs) &&
		sameFilter(f.Bytes, other.Bytes) &&
		sameFilter(f.RetVal, other.RetVal) &&
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

func cloneFilter[T any](in *T) *T {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func sameFilter[T comparable](left, right *T) bool {
	switch {
	case left == nil && right == nil:
		return true
	case left == nil || right == nil:
		return false
	default:
		return *left == *right
	}
}

