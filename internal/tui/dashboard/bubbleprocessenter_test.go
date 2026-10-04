package dashboard

import (
	"testing"

	"ior/internal/globalfilter"
	"ior/internal/statsengine"
)

// These tests pin that Enter on the Processes bubble chart acts on the bubble
// that is highlighted (task up2). The chart orders its bubbles itself and
// breaks metric ties by the display label ("20#1:x"); Enter used to rebuild
// that order with a second sort keyed on a different string ("20:x"), so
// whenever a recycled PID tied with another process on the metric - common
// with the default count metric - the index picked a different row than the
// one on screen. Enter now resolves the highlighted bubble's ID (processKey)
// against the rows, so no second ordering can disagree with the chart.

// bubbleEnterCase is one tie scenario: rows tie on the syscall count, and
// each bubble, when highlighted, must yield the filter wantFilter[node ID].
type bubbleEnterCase struct {
	name       string
	col        int
	rows       []statsengine.ProcessSnapshot
	wantFilter map[string]func(globalfilter.Filter) bool
}

func pidFilterIs(pid int64) func(globalfilter.Filter) bool {
	return func(f globalfilter.Filter) bool {
		return f.PID != nil && f.PID.Op == globalfilter.OpEq && f.PID.Value == pid
	}
}

func commFilterIs(comm string) func(globalfilter.Filter) bool {
	return func(f globalfilter.Filter) bool { return f.Comm != nil && f.Comm.Pattern == comm }
}

func TestProcessBubbleEnterFollowsHighlightedBubbleOnTies(t *testing.T) {
	tests := []bubbleEnterCase{
		{
			// '#' sorts before ':' and '0', so the chart puts "20#1:x" ahead of
			// "200:y" while a "PID:comm" tie-break puts "200:y" first.
			name: "recycled PID next to a longer PID (pid column)",
			col:  0,
			rows: []statsengine.ProcessSnapshot{
				{PID: 20, Lifetime: 1, Comm: "x", Syscalls: 5},
				{PID: 200, Comm: "y", Syscalls: 5},
			},
			wantFilter: map[string]func(globalfilter.Filter) bool{
				"20#1": pidFilterIs(20),
				"200":  pidFilterIs(200),
			},
		},
		{
			// Two lifetimes of one PID with different comms: on the Comm column
			// the filter must carry the highlighted lifetime's comm.
			name: "two lifetimes of one PID (comm column)",
			col:  processCommColumn,
			rows: []statsengine.ProcessSnapshot{
				{PID: 2000, Lifetime: 0, Comm: "a", Syscalls: 5},
				{PID: 2000, Lifetime: 1, Comm: "b", Syscalls: 5},
			},
			wantFilter: map[string]func(globalfilter.Filter) bool{
				"2000":   commFilterIs("a"),
				"2000#1": commFilterIs("b"),
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertEveryBubbleEntersItsOwnRow(t, tc)
		})
	}
}

// assertEveryBubbleEntersItsOwnRow highlights each bubble in turn (as the
// user would with j) and checks that both selectedProcessSnapshot and the
// filter Enter emits belong to that bubble's own row.
func assertEveryBubbleEntersItsOwnRow(t *testing.T, tc bubbleEnterCase) {
	t.Helper()
	m := newVizModel(t, TabProcesses, tabVizModeBubbles, processesSnapshot(tc.rows...))
	m.processesTab.col = tc.col
	chart := &m.processesTab.bubble
	if len(chart.nodes) != len(tc.rows) {
		t.Fatalf("chart has %d bubbles, want %d", len(chart.nodes), len(tc.rows))
	}
	for i := range chart.nodes {
		id := chart.nodes[chart.selected].ID
		row, ok := m.selectedProcessSnapshot()
		if !ok || processRowKey(row) != id {
			t.Fatalf("bubble %d (%q): selectedProcessSnapshot = %+v ok=%v", i, id, row, ok)
		}
		want, known := tc.wantFilter[id]
		if !known {
			t.Fatalf("bubble %q is not in the case's expectations", id)
		}
		req, ok := enterFilterRequest(t, m)
		if !ok {
			t.Fatalf("bubble %q: Enter emitted no filter request", id)
		}
		if !want(req.Filter) {
			t.Fatalf("bubble %q: Enter pushed %q (filter %+v), which is another process", id, req.Action, req.Filter)
		}
		m = pressJ(t, m, 1)
		chart = &m.processesTab.bubble
	}
}

// TestProcessBubbleEnterTargetsNothingWithoutBubbles checks the negative
// case: with no highlighted bubble (an empty chart) Enter has no row to act
// on and must not fall back to some other one.
func TestProcessBubbleEnterTargetsNothingWithoutBubbles(t *testing.T) {
	m := newVizModel(t, TabProcesses, tabVizModeBubbles, processesSnapshot())
	if row, ok := m.selectedProcessSnapshot(); ok {
		t.Fatalf("selected %+v with an empty chart", row)
	}
	if _, ok := enterFilterRequest(t, m); ok {
		t.Fatal("Enter emitted a filter request with no bubbles")
	}
}
