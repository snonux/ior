package streamrow

import (
	"reflect"
	"testing"

	"ior/internal/globalfilter"
)

// TestRowCandidateAccessorsUsePointerReceivers pins that only *Row satisfies
// globalfilter.Candidate. With value receivers every accessor call made
// through a *Row copied the whole ~250-byte row, and Filter.Matches makes up
// to 14 such calls per row on every stream tick (task qo2). Reverting any
// accessor to a value receiver leaves *Row a Candidate, so this test checks
// each method on the value type's method set explicitly.
func TestRowCandidateAccessorsUsePointerReceivers(t *testing.T) {
	candidate := reflect.TypeFor[globalfilter.Candidate]()
	if !reflect.TypeFor[*Row]().Implements(candidate) {
		t.Fatal("*Row does not implement globalfilter.Candidate")
	}
	value := reflect.TypeFor[Row]()
	for i := range candidate.NumMethod() {
		name := candidate.Method(i).Name
		if _, ok := value.MethodByName(name); ok {
			t.Errorf("Row.%s has a value receiver; use a pointer receiver so matching does not copy the row", name)
		}
	}
}

// matchBenchRow is a representative stream row for the matching tests.
func matchBenchRow() Row {
	return Row{
		Syscall:    "read",
		Family:     "FS",
		Comm:       "nginx",
		PID:        1234,
		TID:        1235,
		FileName:   "/var/log/access.log",
		DurationNs: 1_500_000,
		GapNs:      12_000,
		Bytes:      4096,
		RetVal:     4096,
		FD:         7,
	}
}

// matchBenchFilter configures every dimension so Matches evaluates every
// accessor, all of them passing for matchBenchRow.
func matchBenchFilter() globalfilter.Filter {
	return globalfilter.Filter{
		Syscall:   &globalfilter.StringFilter{Pattern: "read"},
		Family:    &globalfilter.StringFilter{Pattern: "fs"},
		Comm:      &globalfilter.StringFilter{Pattern: "nginx"},
		File:      &globalfilter.StringFilter{Pattern: "access"},
		PID:       &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: 1234},
		TID:       &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: 1235},
		FD:        &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: 7},
		LatencyNs: &globalfilter.NumericFilter{Op: globalfilter.OpGt, Value: 0},
		GapNs:     &globalfilter.NumericFilter{Op: globalfilter.OpGt, Value: 0},
		Bytes:     &globalfilter.NumericFilter{Op: globalfilter.OpGte, Value: 1},
		RetVal:    &globalfilter.NumericFilter{Op: globalfilter.OpGte, Value: 0},
	}
}

// TestMatchesRowPointerDoesNotAllocate guards the stream re-filter hot path:
// matching a *Row against a fully configured filter must not heap-allocate
// (no boxing of row copies into the Candidate interface).
func TestMatchesRowPointerDoesNotAllocate(t *testing.T) {
	row := matchBenchRow()
	filter := matchBenchFilter()
	if !filter.Matches(&row) {
		t.Fatal("benchmark filter does not match the benchmark row")
	}
	allocs := testing.AllocsPerRun(100, func() {
		matchSink = filter.Matches(&row)
	})
	if allocs != 0 {
		t.Fatalf("Filter.Matches(&row) allocated %.0f times, want 0", allocs)
	}
}

var matchSink bool

// BenchmarkMatchesRow measures one fully configured Filter.Matches over a
// *Row, the per-row cost of an active stream-tab filter.
func BenchmarkMatchesRow(b *testing.B) {
	row := matchBenchRow()
	filter := matchBenchFilter()
	b.ReportAllocs()
	for b.Loop() {
		matchSink = filter.Matches(&row)
	}
}

// BenchmarkMatchesRowEmptyFilter measures Matches under the zero filter,
// where no dimension is configured and no accessor should run.
func BenchmarkMatchesRowEmptyFilter(b *testing.B) {
	row := matchBenchRow()
	var filter globalfilter.Filter
	b.ReportAllocs()
	for b.Loop() {
		matchSink = filter.Matches(&row)
	}
}
