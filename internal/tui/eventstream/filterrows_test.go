package eventstream

import (
	"slices"
	"testing"
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
