package globalfilter

import (
	"strings"
)

// CompareOp is the comparison a NumericFilter applies between a candidate
// value and the filter's reference value.
type CompareOp int

const (
	// OpEq selects values equal to the reference.
	OpEq CompareOp = iota
	// OpNeq selects values different from the reference.
	OpNeq
	// OpGt selects values strictly greater than the reference.
	OpGt
	// OpGte selects values greater than or equal to the reference.
	OpGte
	// OpLt selects values strictly less than the reference.
	OpLt
	// OpLte selects values less than or equal to the reference.
	OpLte
)

// NumericFilter constrains one numeric dimension (pid, fd, latency, ...) to
// the comparison Op against Value.
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
// The return type is int64 to avoid silent truncation on 32-bit architectures
// where converting int64 to int would silently discard the high 32 bits for
// values that exceed math.MaxInt32.
func (f *NumericFilter) EqValue() (int64, bool) {
	if f == nil || f.Op != OpEq || f.Value <= 0 {
		return 0, false
	}
	return f.Value, true
}

// StringFilter constrains one string dimension (comm, path, syscall, ...) by
// substring, case-insensitively. The anchors ^ and $ switch the match to
// prefix/suffix/exact; a blank or nil filter matches everything. Blanks are
// trimmed only outside the anchors, and only one anchor is taken from each
// end, so "^x $" is exactly "x " and "^^x" is the prefix "^x". Filters built
// from a concrete value rather than typed use ExactPattern/DirPattern.
//
// One start-anchored form is special: "^dir/*" selects the files directly in
// dir and nothing below it (see dirchildren.go and DirPattern).
//
// Case: substring, prefix (^x) and suffix (x$) matching ignore case; the
// fully anchored exact form (^x$) and the directory-children form (^dir/*) do
// not. Both say "exactly this value" (or "exactly this directory"), and a
// value differing in case is a different file or comm (Linux paths and comms
// are case-sensitive), so /tmp/A must not satisfy ^/tmp/a$. The rule lives in
// the pattern text itself, not in a separate flag, so a pattern round-trips
// unchanged through the filter modal and a user typing ^foo$ gets the same
// semantics as a row filter.
type StringFilter struct {
	// Pattern is the substring (or anchored prefix/suffix/exact, or ^dir/*
	// directory-children) pattern matched against the candidate string
	// value; only the exact and directory-children forms are case-sensitive.
	Pattern string
}

// Candidate is the per-dimension view of a filterable item - a syscall pair,
// a stream row, or any other row-shaped value. Each Value method reports one
// dimension of the candidate, and Filter.Matches applies every configured
// filter dimension against them. The file dimension is special: OldFileValue
// carries the rename source path, which Matches accepts as the dimension's
// alternate value (see its comment).
type Candidate interface {
	SyscallValue() string
	FamilyValue() string
	CommValue() string
	FileValue() string
	// OldFileValue reports the alternate value of the file dimension: the
	// source (oldname) path of a rename-like event, whose reported name
	// (FileValue) is only the destination (newname) path. It is empty for
	// every single-name candidate, and the file dimension of Matches treats it
	// as a second legitimate value — this method is the ONE place that knows a
	// candidate can carry two names, so no filter stage can re-narrow or
	// re-widen the rule on its own (the raw kernel-side counterpart is
	// MatchNameEvent, which reads oldname/newname straight from the payload).
	OldFileValue() string
	PIDValue() uint32
	TIDValue() uint32
	FDValue() int32
	LatencyValue() uint64
	GapValue() uint64
	BytesValue() uint64
	ReturnValue() int64
	ErrorValue() bool
}

// Filter is the active global event filter: one optional constraint per
// dimension plus the ErrorsOnly switch. A zero Filter matches everything;
// any single failing dimension rejects the candidate.
type Filter struct {
	// Syscall filters events by syscall/tracepoint name substring.
	Syscall *StringFilter
	// Family filters events by high-level syscall family (FS/Network/...)
	// substring. Family is derived from the syscall classification at
	// pair/row construction, so it is matched user-side only.
	Family *StringFilter
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

// Clone returns a deep copy with every pointer field duplicated, so the
// clone can be mutated without affecting the original's sub-filters.
func (f Filter) Clone() Filter {
	out := f
	out.Syscall = cloneFilter(f.Syscall)
	out.Family = cloneFilter(f.Family)
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

// Equal reports whether both filters configure identical constraints,
// pointer fields compared by value.
func (f Filter) Equal(other Filter) bool {
	return sameFilter(f.Syscall, other.Syscall) &&
		sameFilter(f.Family, other.Family) &&
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

// Matches reports whether the candidate satisfies every configured
// dimension. A nil candidate matches nothing.
//
// Every dimension checks its own sub-filter for nil BEFORE asking the
// candidate for the value, so an unconfigured dimension costs one pointer
// comparison and no interface call. Matches runs per buffered row on every
// stream tick (and per pair on the event loop), where most dimensions are
// unset; callers that re-filter many rows against one filter can skip the
// loop entirely when IsActive reports false.
//
// Matches (like IsActive) has a pointer receiver although Filter is otherwise
// used by value: Filter is 12 words, and a value receiver copied it on every
// call, i.e. once per buffered row per stream tick. Callers hold their own
// copy of the filter (the stream model, the export, the ingest check), so the
// pointer never aliases a filter that is swapped concurrently. A nil *Filter
// behaves like the zero filter.
func (f *Filter) Matches(candidate Candidate) bool {
	if candidate == nil {
		return false
	}
	if f == nil {
		return true
	}
	if f.ErrorsOnly && !candidate.ErrorValue() {
		return false
	}
	return f.matchesStrings(candidate) && f.matchesNumerics(candidate)
}

// matchesStrings applies the string dimensions (syscall, family, comm, file).
func (f *Filter) matchesStrings(candidate Candidate) bool {
	if f.Syscall != nil && !matchString(f.Syscall, candidate.SyscallValue()) {
		return false
	}
	if f.Family != nil && !matchString(f.Family, candidate.FamilyValue()) {
		return false
	}
	if f.Comm != nil && !matchString(f.Comm, candidate.CommValue()) {
		return false
	}
	return f.File == nil || matchFile(f.File, candidate)
}

// matchFile applies the file dimension, the one dimension that can carry two
// legitimate values: a rename-like candidate reports its destination path as
// FileValue and its source path as OldFileValue, and `-path <oldname>` is as
// valid a selection as `-path <newname>` (the raw enter filter MatchNameEvent
// has always matched either). Evaluating both here means every stage that
// calls Matches — pair checkpoint, dashboard ingest, Stream tab, CSV export —
// applies the same rule by construction, and no stage can silently diverge
// from the others again. The empty-OldFileValue guard matters for one
// degenerate input: the anchored pattern `^$` (an empty path) matches the
// empty string, so without the guard every single-name candidate would
// satisfy it through the absent oldname.
func matchFile(sf *StringFilter, candidate Candidate) bool {
	if matchString(sf, candidate.FileValue()) {
		return true
	}
	oldFile := candidate.OldFileValue()
	return oldFile != "" && matchString(sf, oldFile)
}

// matchesNumerics applies the numeric dimensions (pid, tid, fd, latency, gap,
// bytes, return value).
func (f *Filter) matchesNumerics(candidate Candidate) bool {
	if f.PID != nil && !matchNumeric(f.PID, int64(candidate.PIDValue())) {
		return false
	}
	if f.TID != nil && !matchNumeric(f.TID, int64(candidate.TIDValue())) {
		return false
	}
	if f.FD != nil && !matchNumeric(f.FD, int64(candidate.FDValue())) {
		return false
	}
	if f.LatencyNs != nil && !matchNumeric(f.LatencyNs, int64(candidate.LatencyValue())) {
		return false
	}
	if f.GapNs != nil && !matchNumeric(f.GapNs, int64(candidate.GapValue())) {
		return false
	}
	if f.Bytes != nil && !matchNumeric(f.Bytes, int64(candidate.BytesValue())) {
		return false
	}
	return f.RetVal == nil || matchNumeric(f.RetVal, candidate.ReturnValue())
}

// MatchesSyscallRow reports whether a syscall-table row with the given syscall
// name and family satisfies ONLY the row-level string dimensions of the filter
// (Syscall and Family). Trace-scope dimensions (pid/tid/fd/numeric/comm/file)
// are intentionally ignored: in --testflames the synthetic processes are seeded
// unfiltered, so applying those here would hide rows that should stay visible.
// A nil/empty Syscall or Family filter matches everything for that dimension.
func (f Filter) MatchesSyscallRow(name, family string) bool {
	return matchString(f.Syscall, name) && matchString(f.Family, family)
}

// IsActive reports whether any dimension is configured; an inactive filter
// is a pass-through and lets hot paths skip evaluation. It has a pointer
// receiver for the same reason as Matches; a nil *Filter is inactive.
func (f *Filter) IsActive() bool {
	if f == nil {
		return false
	}
	if f.ErrorsOnly {
		return true
	}
	for _, sf := range []*StringFilter{f.Syscall, f.Family, f.Comm, f.File} {
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

// trimAnchors splits a string pattern into the text actually compared against
// the value and the two anchor flags. The anchors are syntax, not content:
// `^exact$` matches a value of exactly `exact`, so the `^` and `$` are never
// part of what has to fit in the field being matched.
//
// It exists so the matcher and the length validator cannot disagree about what
// the pattern is. They did: validateTraceStringFilter measured the raw pattern
// against the kernel field size, so `^` plus a 15-character comm plus `$` -
// the documented way to exact-match the longest possible comm, and the syntax
// the filter modal advertises - was rejected as 17 characters for a 16-byte
// field it would have matched.
func trimAnchors(pattern string) (trimmed string, anchoredStart, anchoredEnd bool) {
	anchoredStart = strings.HasPrefix(pattern, "^")
	if anchoredStart {
		pattern = pattern[1:]
	}
	anchoredEnd = strings.HasSuffix(pattern, "$")
	if anchoredEnd && len(pattern) > 0 {
		pattern = pattern[:len(pattern)-1]
	}
	return pattern, anchoredStart, anchoredEnd
}

// ExactPattern returns the StringFilter pattern that matches value exactly -
// byte for byte, case included - and nothing else. It is how filters built
// from a concrete value - a selected table row - say "this one", as opposed
// to a typed pattern, which is a substring search.
//
// Wrapping in ^...$ is enough for any value, because trimAnchors removes
// exactly one anchor from each end and matchString trims blanks only outside
// them:
//   - leading/trailing blanks survive ("^/tmp/a $" stays exact, where the
//     bare "/tmp/a " would be trimmed to the substring "/tmp/a" and match
//     "/tmp/ab" too);
//   - a literal edge ^ or $ in the value stays literal ("^x$$" is exactly
//     "x$", where the bare "x$" would mean "ends with x").
func ExactPattern(value string) string {
	return "^" + value + "$"
}

// matchString reports whether value satisfies the string filter: a
// case-insensitive substring match, a case-insensitive prefix/suffix under
// one of the ^ and $ anchors, a case-sensitive exact match under both, or a
// case-sensitive directory-children match for ^dir/* (see StringFilter). A
// nil or blank filter matches everything.
//
// It runs per candidate on every matching path (event loop, stream re-filter,
// raw kernel-event filter), so it never allocates for the exact and
// directory-children forms (plain string comparisons) nor for the common all-ASCII case, which matchFoldASCII
// compares in place instead of lowering both strings: strings.ToLower
// allocates whenever its input has an upper-case letter, which is every row
// under a family filter ("FS", "Network", ...) and any pattern typed with
// capitals. For ASCII, ASCII case folding is exactly what ToLower does, so
// both paths select the same values.
func matchString(sf *StringFilter, value string) bool {
	if sf == nil {
		return true
	}
	pattern := strings.TrimSpace(sf.Pattern)
	if pattern == "" {
		return true
	}
	pattern, anchoredStart, anchoredEnd := trimAnchors(pattern)
	if anchoredStart && anchoredEnd {
		return value == pattern
	}
	if anchoredStart {
		if dir, ok := dirChildrenDir(pattern); ok {
			return matchDirChildren(dir, value)
		}
	}
	if isASCII(pattern) && isASCII(value) {
		return matchFoldASCII(pattern, value, anchoredStart, anchoredEnd)
	}
	value = strings.ToLower(value)
	pattern = strings.ToLower(pattern)
	switch {
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
