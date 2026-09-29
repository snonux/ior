package globalfilter

import (
	"slices"
	"testing"
)

// recordingCandidate is a Candidate that records which accessors Matches
// asked for, so the tests can pin that unconfigured dimensions are never
// evaluated (task qo2: Matches runs per buffered row on every stream tick).
type recordingCandidate struct {
	sampleCandidate
	calls *[]string
}

func (r recordingCandidate) record(name string) { *r.calls = append(*r.calls, name) }

func (r recordingCandidate) SyscallValue() string {
	r.record("Syscall")
	return r.sampleCandidate.SyscallValue()
}

func (r recordingCandidate) FamilyValue() string {
	r.record("Family")
	return r.sampleCandidate.FamilyValue()
}

func (r recordingCandidate) CommValue() string {
	r.record("Comm")
	return r.sampleCandidate.CommValue()
}

func (r recordingCandidate) FileValue() string {
	r.record("File")
	return r.sampleCandidate.FileValue()
}

func (r recordingCandidate) OldFileValue() string {
	r.record("OldFile")
	return r.sampleCandidate.OldFileValue()
}

func (r recordingCandidate) PIDValue() uint32 {
	r.record("PID")
	return r.sampleCandidate.PIDValue()
}

func (r recordingCandidate) TIDValue() uint32 {
	r.record("TID")
	return r.sampleCandidate.TIDValue()
}

func (r recordingCandidate) FDValue() int32 {
	r.record("FD")
	return r.sampleCandidate.FDValue()
}

func (r recordingCandidate) LatencyValue() uint64 {
	r.record("Latency")
	return r.sampleCandidate.LatencyValue()
}

func (r recordingCandidate) GapValue() uint64 {
	r.record("Gap")
	return r.sampleCandidate.GapValue()
}

func (r recordingCandidate) BytesValue() uint64 {
	r.record("Bytes")
	return r.sampleCandidate.BytesValue()
}

func (r recordingCandidate) ReturnValue() int64 {
	r.record("Return")
	return r.sampleCandidate.ReturnValue()
}

func (r recordingCandidate) ErrorValue() bool {
	r.record("Error")
	return r.sampleCandidate.ErrorValue()
}

// TestMatchesEvaluatesOnlyConfiguredDimensions pins the lazy evaluation of
// Matches: an unset dimension must not call its accessor. Before task qo2
// every accessor ran for every candidate even under the zero filter, and for
// stream rows each call copied the whole row.
func TestMatchesEvaluatesOnlyConfiguredDimensions(t *testing.T) {
	cases := []struct {
		name      string
		filter    Filter
		want      bool
		wantCalls []string
	}{
		{name: "zero filter", filter: Filter{}, want: true, wantCalls: nil},
		{name: "family only", filter: Filter{Family: &StringFilter{Pattern: "fs"}}, want: true, wantCalls: []string{"Family"}},
		{name: "family only mismatch", filter: Filter{Family: &StringFilter{Pattern: "network"}}, want: false, wantCalls: []string{"Family"}},
		{name: "errors only", filter: Filter{ErrorsOnly: true}, want: true, wantCalls: []string{"Error"}},
		{name: "pid only", filter: Filter{PID: &NumericFilter{Op: OpEq, Value: 1234}}, want: true, wantCalls: []string{"PID"}},
		{name: "retval only", filter: Filter{RetVal: &NumericFilter{Op: OpGte, Value: 0}}, want: false, wantCalls: []string{"Return"}},
		// A file mismatch on a single-name candidate consults OldFileValue
		// (empty), the alternate value of the file dimension.
		{name: "file mismatch", filter: Filter{File: &StringFilter{Pattern: "/nope"}}, want: false, wantCalls: []string{"File", "OldFile"}},
		// A file hit short-circuits before OldFileValue.
		{name: "file match", filter: Filter{File: &StringFilter{Pattern: "access"}}, want: true, wantCalls: []string{"File"}},
		// The first failing dimension stops evaluation.
		{name: "short circuit", filter: Filter{Syscall: &StringFilter{Pattern: "write"}, PID: &NumericFilter{Op: OpEq, Value: 1}}, want: false, wantCalls: []string{"Syscall"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls []string
			candidate := recordingCandidate{sampleCandidate: testCandidate(), calls: &calls}
			if got := tc.filter.Matches(candidate); got != tc.want {
				t.Fatalf("Matches() = %v, want %v", got, tc.want)
			}
			if !slices.Equal(calls, tc.wantCalls) {
				t.Fatalf("accessors called = %v, want %v", calls, tc.wantCalls)
			}
		})
	}
}

// TestMatchesEmptyFilterMatchesEverything covers the empty-filter fast path
// from the outside: a zero filter, and one whose string patterns are blank,
// match every candidate (even the zero candidate) and report inactive, while
// a single configured dimension still filters.
func TestMatchesEmptyFilterMatchesEverything(t *testing.T) {
	blank := Filter{Syscall: &StringFilter{Pattern: "  "}, Family: &StringFilter{}}
	for _, f := range []Filter{{}, blank} {
		if f.IsActive() {
			t.Fatalf("filter %+v should be inactive", f)
		}
		for _, c := range []sampleCandidate{{}, testCandidate()} {
			if !f.Matches(c) {
				t.Fatalf("inactive filter %+v rejected candidate %+v", f, c)
			}
		}
	}
	if (&Filter{}).Matches(nil) {
		t.Fatal("zero filter matched a nil candidate")
	}
	// A nil *Filter behaves like the zero filter (pointer receivers).
	var nilFilter *Filter
	if nilFilter.IsActive() || !nilFilter.Matches(testCandidate()) || nilFilter.Matches(nil) {
		t.Fatal("nil *Filter should be inactive, match every candidate and reject nil")
	}

	familyOnly := Filter{Family: &StringFilter{Pattern: "Network"}}
	if !familyOnly.IsActive() {
		t.Fatal("family-only filter should be active")
	}
	if familyOnly.Matches(testCandidate()) {
		t.Fatal("family-only filter matched a candidate of another family")
	}
}
