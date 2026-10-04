package eventstream

import (
	"slices"
	"strings"
	"testing"

	"ior/internal/globalfilter"
)

// filterRowsFixture returns rows of two families, some of them errors.
func filterRowsFixture() []StreamEvent {
	return []StreamEvent{
		{Seq: 1, Syscall: "read", Family: "FS", IsError: false, FD: UnknownFD},
		{Seq: 2, Syscall: "sendto", Family: "Network", IsError: true, FD: UnknownFD},
		{Seq: 3, Syscall: "write", Family: "FS", IsError: true, FD: UnknownFD},
		{Seq: 4, Syscall: "recvfrom", Family: "Network", IsError: false, FD: UnknownFD},
	}
}

// filteredSeqs returns the sequence numbers of rows, for compact assertions.
func filteredSeqs(rows []StreamEvent) []uint64 {
	seqs := make([]uint64, 0, len(rows))
	for _, row := range rows {
		seqs = append(seqs, row.Seq)
	}
	return seqs
}

// TestFilterRowsSelectsMatchingRowsInOrder covers the row selection shared by
// Model.applyFilter and the CSV export: inactive filters (zero, or only blank
// patterns) keep every row in order, a filter with a single configured
// dimension (family only, errors only) still filters, and the result is
// appended to dst. It checks the result, not which path produced it; the
// cost of the inactive-filter bulk copy is measured by BenchmarkFilterRows.
func TestFilterRowsSelectsMatchingRowsInOrder(t *testing.T) {
	src := filterRowsFixture()
	cases := []struct {
		name   string
		filter Filter
		want   []uint64
	}{
		{name: "zero filter", filter: Filter{}, want: []uint64{1, 2, 3, 4}},
		{name: "blank patterns", filter: Filter{Syscall: &StringFilter{Pattern: " "}, Family: &StringFilter{}}, want: []uint64{1, 2, 3, 4}},
		{name: "family only", filter: Filter{Family: &StringFilter{Pattern: "network"}}, want: []uint64{2, 4}},
		{name: "errors only", filter: Filter{ErrorsOnly: true}, want: []uint64{2, 3}},
		{name: "nothing matches", filter: Filter{Syscall: &StringFilter{Pattern: "^open$"}}, want: []uint64{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A non-empty dst proves filterRows appends rather than overwrites.
			dst := []StreamEvent{{Seq: 99}}
			got := filterRows(dst, src, tc.filter)
			if want := append([]uint64{99}, tc.want...); !slices.Equal(filteredSeqs(got), want) {
				t.Fatalf("filterRows seqs = %v, want %v", filteredSeqs(got), want)
			}
		})
	}
	if got := filterRows(nil, nil, Filter{}); len(got) != 0 {
		t.Fatalf("filterRows over no rows = %v, want empty", got)
	}
}

// BenchmarkFilterRows measures filterRows over a full ring buffer's worth of
// rows. The "inactive" case is the bulk-copy fast path taken on every stream
// tick when no filter is set; compare it with "family" (one configured
// dimension, Matches per row) to see what the shortcut saves.
func BenchmarkFilterRows(b *testing.B) {
	fixture := filterRowsFixture()
	src := make([]StreamEvent, ringBufferCapacity)
	for i := range src {
		src[i] = fixture[i%len(fixture)]
	}
	dst := make([]StreamEvent, 0, len(src))
	for _, bc := range []struct {
		name   string
		filter Filter
	}{
		{name: "inactive", filter: Filter{}},
		{name: "family", filter: Filter{Family: &StringFilter{Pattern: "fs"}}},
	} {
		b.Run(bc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				dst = filterRows(dst[:0], src, bc.filter)
			}
		})
	}
}

// TestFilterRowsKeepsWarningRowsWhateverTheFilterSays pins that synthetic
// warning rows bypass the user filter while real rows stay filtered. The
// startup warning "-tid T: not a thread of -pid P ... the trace will stay
// empty" (task wr2) is raised exactly in the scopes whose active pid/tid
// predicates used to hide it, leaving an empty view with no explanation
// (task ur2). The negative half proves the bypass is not "filter nothing":
// the real rows the same filter rejects are still dropped.
//
// There is deliberately no "errors only" case: NewWarning builds its rows with
// IsError set (RetVal -1), so a warning satisfies that predicate through plain
// Filter.Matches and the case would pass with the bypass removed - it could
// not tell the bypass from ordinary matching. Every filtering case below is one a
// warning row does not satisfy on its own (it is Syscall "warning", Family
// Misc, PID 0), so each of those fails if the IsWarning bypass is taken out.
// The "inactive filter" case is only a control: an inactive filter takes the
// bulk-copy path that never reaches the bypass, so it passes either way and
// just pins that real rows and the warning all come through unfiltered.
func TestFilterRowsKeepsWarningRowsWhateverTheFilterSays(t *testing.T) {
	warn := NewWarningEvent(5, "ior: -tid 1: not a thread of -pid 7: the trace will stay empty")
	src := append(filterRowsFixture(), warn)
	cases := []struct {
		name   string
		filter Filter
		want   []uint64
	}{
		{name: "pid+tid that match no row", filter: Filter{PID: globalfilter.NewEqFilter(7), TID: globalfilter.NewEqFilter(1)}, want: []uint64{5}},
		{name: "syscall pattern", filter: Filter{Syscall: &StringFilter{Pattern: "^open$"}}, want: []uint64{5}},
		{name: "family filter keeps matching real rows too", filter: Filter{Family: &StringFilter{Pattern: "network"}}, want: []uint64{2, 4, 5}},
		{name: "inactive filter", filter: Filter{}, want: []uint64{1, 2, 3, 4, 5}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := filteredSeqs(filterRows(nil, src, tc.filter))
			if !slices.Equal(got, tc.want) {
				t.Fatalf("filterRows seqs = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestModelShowsStartupWarningBehindAnActivePidTidFilter is the model-level
// reproduction of task ur2's finding: `-pid P -tid 1` left the stream tab at
// "total:1 filtered:0" because the pid/tid filter hid the lone warning row.
// The warning must be counted and rendered, and real rows the filter rejects
// must still be hidden. It also pins the documented counter trade-off: the
// status line's "filtered" count includes the bypassed warning row (here
// total:2 filtered:1, although no real row matches), because visibility of the
// warning wins over counter purity.
func TestModelShowsStartupWarningBehindAnActivePidTidFilter(t *testing.T) {
	rb := NewRingBuffer()
	m := NewModel(rb)
	rb.Push(NewWarningEvent(1, "ior: -tid 1: not a thread of -pid 7: the trace will stay empty"))
	rb.Push(StreamEvent{Seq: 2, Syscall: "read", Family: "FS", PID: 99, TID: 99, FD: UnknownFD})
	m.SetFilter(Filter{PID: globalfilter.NewEqFilter(7), TID: globalfilter.NewEqFilter(1)})
	m.Refresh()

	if len(m.allEvents) != 2 || len(m.filtered) != 1 || !m.filtered[0].IsWarning {
		t.Fatalf("allEvents=%d filtered=%+v, want 2 rows with only the warning visible", len(m.allEvents), m.filtered)
	}
	got := m.View(200, 24)
	if !strings.Contains(got, "not a thread of -pid 7") {
		t.Fatalf("stream view hides the startup warning:\n%s", got)
	}
	if !strings.Contains(got, "total:2 filtered:1") {
		t.Fatalf("status line should count the bypassed warning in filtered (total:2 filtered:1):\n%s", got)
	}
}
