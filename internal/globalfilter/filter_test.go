package globalfilter

import (
	"math"
	"testing"
)

type sampleCandidate struct {
	syscall string
	family  string
	comm    string
	file    string
	pid     uint32
	tid     uint32
	fd      int32
	latency uint64
	gap     uint64
	bytes   uint64
	ret     int64
	isError bool
}

func (s sampleCandidate) SyscallValue() string { return s.syscall }
func (s sampleCandidate) FamilyValue() string  { return s.family }
func (s sampleCandidate) CommValue() string    { return s.comm }
func (s sampleCandidate) FileValue() string    { return s.file }
func (s sampleCandidate) PIDValue() uint32     { return s.pid }
func (s sampleCandidate) TIDValue() uint32     { return s.tid }
func (s sampleCandidate) FDValue() int32       { return s.fd }
func (s sampleCandidate) LatencyValue() uint64 { return s.latency }
func (s sampleCandidate) GapValue() uint64     { return s.gap }
func (s sampleCandidate) BytesValue() uint64   { return s.bytes }
func (s sampleCandidate) ReturnValue() int64   { return s.ret }
func (s sampleCandidate) ErrorValue() bool     { return s.isError }

func testCandidate() sampleCandidate {
	return sampleCandidate{
		syscall: "read",
		family:  "FS",
		comm:    "nginx",
		file:    "/var/log/access.log",
		pid:     1234,
		tid:     1235,
		fd:      7,
		latency: 1_500_000,
		gap:     12_000,
		bytes:   4_096,
		ret:     -1,
		isError: true,
	}
}

func TestFilterZeroValueMatchesAll(t *testing.T) {
	candidate := testCandidate()
	filter := Filter{}
	if !filter.Matches(candidate) {
		t.Fatalf("zero-value filter should match all candidates")
	}
	if filter.IsActive() {
		t.Fatalf("zero-value filter should be inactive")
	}
}

func TestFilterStringAndNumericMatching(t *testing.T) {
	candidate := testCandidate()
	filter := Filter{
		Syscall:   &StringFilter{Pattern: "ea"},
		Comm:      &StringFilter{Pattern: "NGI"},
		File:      &StringFilter{Pattern: "access"},
		PID:       &NumericFilter{Op: OpEq, Value: 1234},
		TID:       &NumericFilter{Op: OpNeq, Value: 1},
		FD:        &NumericFilter{Op: OpEq, Value: 7},
		LatencyNs: &NumericFilter{Op: OpGt, Value: 1_000_000},
		GapNs:     &NumericFilter{Op: OpLte, Value: 12_000},
		Bytes:     &NumericFilter{Op: OpLt, Value: 8_192},
		RetVal:    &NumericFilter{Op: OpGte, Value: -1},
	}
	if !filter.Matches(candidate) {
		t.Fatalf("combined filter should match candidate")
	}
}

func TestFilterFamilyMatchesAndExcludes(t *testing.T) {
	candidate := testCandidate()
	candidate.family = "Polling"

	if !(Filter{Family: &StringFilter{Pattern: "Polling"}}).Matches(candidate) {
		t.Fatalf("family filter Polling should match Polling candidate")
	}
	if !(Filter{Family: &StringFilter{Pattern: "poll"}}).Matches(candidate) {
		t.Fatalf("family filter should match case-insensitive substring")
	}
	if (Filter{Family: &StringFilter{Pattern: "Network"}}).Matches(candidate) {
		t.Fatalf("family filter Network should exclude Polling candidate")
	}
	if !(Filter{Family: &StringFilter{Pattern: "Polling"}}).IsActive() {
		t.Fatalf("non-empty family filter should be active")
	}

	base := Filter{Family: &StringFilter{Pattern: "Polling"}}
	cloned := base.Clone()
	cloned.Family.Pattern = "Process"
	if base.Family.Pattern != "Polling" {
		t.Fatalf("Clone() should deep-copy the Family filter")
	}
	if base.Equal(cloned) {
		t.Fatalf("filters with different Family patterns should not be Equal")
	}
}

func TestMatchesSyscallRow(t *testing.T) {
	cases := []struct {
		name    string
		filter  Filter
		syscall string
		family  string
		want    bool
	}{
		{
			name:    "empty filter matches everything",
			filter:  Filter{},
			syscall: "epoll_wait",
			family:  "Polling",
			want:    true,
		},
		{
			name:    "matches on family",
			filter:  Filter{Family: &StringFilter{Pattern: "Polling"}},
			syscall: "epoll_wait",
			family:  "Polling",
			want:    true,
		},
		{
			name:    "excludes on non-matching family",
			filter:  Filter{Family: &StringFilter{Pattern: "FS"}},
			syscall: "epoll_wait",
			family:  "Polling",
			want:    false,
		},
		{
			name:    "matches on syscall name",
			filter:  Filter{Syscall: &StringFilter{Pattern: "write"}},
			syscall: "write",
			family:  "FS",
			want:    true,
		},
		{
			name:    "excludes on non-matching syscall name",
			filter:  Filter{Syscall: &StringFilter{Pattern: "write"}},
			syscall: "read",
			family:  "FS",
			want:    false,
		},
		{
			name:    "both dimensions must match",
			filter:  Filter{Syscall: &StringFilter{Pattern: "write"}, Family: &StringFilter{Pattern: "FS"}},
			syscall: "write",
			family:  "FS",
			want:    true,
		},
		{
			name:    "one dimension mismatch fails the AND",
			filter:  Filter{Syscall: &StringFilter{Pattern: "write"}, Family: &StringFilter{Pattern: "Polling"}},
			syscall: "write",
			family:  "FS",
			want:    false,
		},
		{
			name:    "trace-scope dimensions are ignored",
			filter:  Filter{PID: NewEqFilter(999), Comm: &StringFilter{Pattern: "nope"}},
			syscall: "write",
			family:  "FS",
			want:    true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.filter.MatchesSyscallRow(tc.syscall, tc.family); got != tc.want {
				t.Fatalf("MatchesSyscallRow(%q, %q) = %v, want %v", tc.syscall, tc.family, got, tc.want)
			}
		})
	}
}

func TestFilterStringAnchorsSupportExactPrefixAndSuffix(t *testing.T) {
	candidate := testCandidate()

	if !(Filter{Syscall: &StringFilter{Pattern: "^read$"}}).Matches(candidate) {
		t.Fatalf("expected ^read$ to exactly match read")
	}
	if !(Filter{Syscall: &StringFilter{Pattern: "^re"}}).Matches(candidate) {
		t.Fatalf("expected ^re to match read by prefix")
	}
	if !(Filter{File: &StringFilter{Pattern: ".log$"}}).Matches(candidate) {
		t.Fatalf("expected .log$ to match by suffix")
	}

	candidate.syscall = "readlink"
	if (Filter{Syscall: &StringFilter{Pattern: "^read$"}}).Matches(candidate) {
		t.Fatalf("expected ^read$ not to match readlink")
	}
	if !(Filter{Syscall: &StringFilter{Pattern: "^read"}}).Matches(candidate) {
		t.Fatalf("expected ^read to match readlink by prefix")
	}
	if !(Filter{Syscall: &StringFilter{Pattern: "link$"}}).Matches(candidate) {
		t.Fatalf("expected link$ to match readlink by suffix")
	}
}

func TestFilterErrorsOnlyAndClone(t *testing.T) {
	filter := Filter{
		ErrorsOnly: true,
		File:       &StringFilter{Pattern: "access"},
		FD:         &NumericFilter{Op: OpEq, Value: 7},
	}
	clone := filter.Clone()
	clone.File.Pattern = "different"
	clone.FD.Value = 3

	if filter.File.Pattern != "access" {
		t.Fatalf("Clone() should deep-copy string filters")
	}
	if filter.FD.Value != 7 {
		t.Fatalf("Clone() should deep-copy numeric filters")
	}
	if !filter.Matches(testCandidate()) {
		t.Fatalf("errors-only filter should match error candidate")
	}

	candidate := testCandidate()
	candidate.isError = false
	if filter.Matches(candidate) {
		t.Fatalf("errors-only filter should reject non-error candidate")
	}
}

func TestFilterEqual(t *testing.T) {
	base := Filter{
		Syscall:    &StringFilter{Pattern: "read"},
		Comm:       &StringFilter{Pattern: "nginx"},
		File:       &StringFilter{Pattern: "/var/log"},
		PID:        &NumericFilter{Op: OpEq, Value: 42},
		TID:        &NumericFilter{Op: OpNeq, Value: 99},
		FD:         &NumericFilter{Op: OpEq, Value: 7},
		LatencyNs:  &NumericFilter{Op: OpGt, Value: 1_000},
		GapNs:      &NumericFilter{Op: OpGte, Value: 500},
		Bytes:      &NumericFilter{Op: OpLt, Value: 4_096},
		RetVal:     &NumericFilter{Op: OpEq, Value: -1},
		ErrorsOnly: true,
	}
	if !base.Equal(base.Clone()) {
		t.Fatalf("expected cloned filter to compare equal")
	}

	mutated := base.Clone()
	mutated.File.Pattern = "/tmp"
	if mutated.Equal(base) {
		t.Fatalf("expected differing file pattern to compare unequal")
	}

	mutated = base.Clone()
	mutated.Bytes = nil
	if mutated.Equal(base) {
		t.Fatalf("expected missing numeric filter to compare unequal")
	}
}

// TestEqValueReturnsInt64PreservesLargeValues verifies that EqValue returns
// int64 so that values larger than math.MaxInt32 are not silently truncated on
// 32-bit architectures (where int is 32 bits wide).
func TestEqValueReturnsInt64PreservesLargeValues(t *testing.T) {
	// A value that would be truncated to a different number if cast to int32.
	large := int64(math.MaxInt32) + 1
	f := &NumericFilter{Op: OpEq, Value: large}
	got, ok := f.EqValue()
	if !ok {
		t.Fatalf("EqValue() returned ok=false for a valid positive value")
	}
	if got != large {
		t.Fatalf("EqValue() = %d, want %d (int64 value must not be truncated)", got, large)
	}

	// Nil filter must return (0, false).
	var nilFilter *NumericFilter
	if v, ok := nilFilter.EqValue(); ok || v != 0 {
		t.Fatalf("EqValue() on nil filter: got (%d, %v), want (0, false)", v, ok)
	}

	// Non-OpEq filter must return (0, false).
	neqFilter := &NumericFilter{Op: OpNeq, Value: 1}
	if v, ok := neqFilter.EqValue(); ok || v != 0 {
		t.Fatalf("EqValue() on OpNeq filter: got (%d, %v), want (0, false)", v, ok)
	}

	// Non-positive value must return (0, false).
	zeroFilter := &NumericFilter{Op: OpEq, Value: 0}
	if v, ok := zeroFilter.EqValue(); ok || v != 0 {
		t.Fatalf("EqValue() on zero value: got (%d, %v), want (0, false)", v, ok)
	}
}
