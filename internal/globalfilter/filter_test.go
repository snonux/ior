package globalfilter

import (
	"strings"
	"testing"
)

type sampleCandidate struct {
	syscall string
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
	if got := filter.Summary(); got != "all" {
		t.Fatalf("Summary() = %q, want all", got)
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

func TestFilterSummaryAndDurationParsing(t *testing.T) {
	filter := Filter{
		ErrorsOnly: true,
		Syscall:    &StringFilter{Pattern: "read"},
		PID:        &NumericFilter{Op: OpEq, Value: 1234},
		LatencyNs:  &NumericFilter{Op: OpGt, Value: 1_000_000},
	}
	got := filter.Summary()
	for _, want := range []string{"errors", "syscall~read", "pid=1234", "latency>1ms"} {
		if !strings.Contains(got, want) {
			t.Fatalf("Summary() = %q, missing %q", got, want)
		}
	}

	for _, tc := range []struct {
		in   string
		want int64
	}{
		{in: "1ms", want: 1_000_000},
		{in: "10us", want: 10_000},
		{in: "500ns", want: 500},
		{in: "42", want: 42},
	} {
		gotNs, err := ParseDurationNs(tc.in)
		if err != nil {
			t.Fatalf("ParseDurationNs(%q) err = %v", tc.in, err)
		}
		if gotNs != tc.want {
			t.Fatalf("ParseDurationNs(%q) = %d, want %d", tc.in, gotNs, tc.want)
		}
	}
	if _, err := ParseDurationNs("garbage"); err == nil {
		t.Fatalf("ParseDurationNs(garbage) expected error")
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
