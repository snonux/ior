package streamrow

import (
	"reflect"
	"testing"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/globalfilter"
	"ior/internal/types"
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

// filelessClosePair is a live close pair that carries no file, so its stream
// row renders the event.NoFileName placeholder.
func filelessClosePair() *event.Pair {
	enter := &types.FdEvent{TraceId: types.SYS_ENTER_CLOSE, Time: 10, Pid: 5, Tid: 5, Fd: 3}
	pair := event.NewPair(enter)
	pair.ExitEv = &types.RetEvent{TraceId: types.SYS_EXIT_CLOSE, Time: 20, Pid: 5, Tid: 5}
	return pair
}

// TestFilelessRowAndLivePairAgreeOnFileFilter is the task op2 regression: a
// fileless pair's buffered row used to report its "N:file" display
// placeholder as FileValue while the live pair checkpoint reported "", so a
// file filter matching the placeholder kept the buffered rows yet dropped
// every new live pair. Every pattern must now give both the same verdict,
// while the row still displays the placeholder.
func TestFilelessRowAndLivePairAgreeOnFileFilter(t *testing.T) {
	pair := filelessClosePair()
	row := New(1, pair)
	if row.FileName != event.NoFileName {
		t.Fatalf("display FileName = %q, want %q", row.FileName, event.NoFileName)
	}
	if got := row.FileValue(); got != "" {
		t.Fatalf("FileValue = %q, want empty for a fileless row", got)
	}

	cases := []struct {
		pattern string
		want    bool
	}{
		{pattern: "file", want: false},
		{pattern: "N:file", want: false},
		{pattern: globalfilter.ExactPattern(event.NoFileName), want: false},
		{pattern: "^$", want: true},
		{pattern: "", want: true},
		{pattern: "   ", want: true},
	}
	for _, tc := range cases {
		filter := globalfilter.Filter{File: &globalfilter.StringFilter{Pattern: tc.pattern}}
		live := filter.MatchPair(pair)
		buffered := filter.Matches(&row)
		if live != buffered {
			t.Errorf("pattern %q: live pair=%v, buffered row=%v; they must agree", tc.pattern, live, buffered)
		}
		if buffered != tc.want {
			t.Errorf("pattern %q: buffered row matched=%v, want %v", tc.pattern, buffered, tc.want)
		}
	}
}

// TestRowWithFileAndLivePairAgreeOnFileFilter is the negative side of op2:
// a pair that does carry a file keeps reporting its real path, so filters on
// that path still select both the live pair and its row, and the empty-path
// pattern selects neither.
func TestRowWithFileAndLivePairAgreeOnFileFilter(t *testing.T) {
	pair := filelessClosePair()
	pair.File = file.NewFd(3, "/tmp/profile", 0)
	row := New(1, pair)
	if got := row.FileValue(); got != "/tmp/profile" {
		t.Fatalf("FileValue = %q, want /tmp/profile", got)
	}
	for pattern, want := range map[string]bool{"file": true, "^/tmp/profile$": true, "^$": false, "N:file": false} {
		filter := globalfilter.Filter{File: &globalfilter.StringFilter{Pattern: pattern}}
		live, buffered := filter.MatchPair(pair), filter.Matches(&row)
		if live != want || buffered != want {
			t.Errorf("pattern %q: live=%v buffered=%v, want both %v", pattern, live, buffered, want)
		}
	}
}

// TestFilelessRenameRowStillMatchesOldName pins that blanking the placeholder
// does not disturb the rename rule: a rename-like row without a destination
// file still matches `-path <oldname>` through OldFileValue, as the live pair
// does.
func TestFilelessRenameRowStillMatchesOldName(t *testing.T) {
	pair := filelessClosePair()
	pair.Oldname = "/tmp/source"
	row := New(1, pair)
	for pattern, want := range map[string]bool{"source": true, "^/tmp/source$": true, "N:file": false} {
		filter := globalfilter.Filter{File: &globalfilter.StringFilter{Pattern: pattern}}
		live, buffered := filter.MatchPair(pair), filter.Matches(&row)
		if live != want || buffered != want {
			t.Errorf("pattern %q: live=%v buffered=%v, want both %v", pattern, live, buffered, want)
		}
	}
}
