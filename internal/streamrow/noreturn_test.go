package streamrow

import (
	"testing"

	"ior/internal/event"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

// TestNewCarriesNoReturn (task pr2): a noreturn row (exit, exit_group,
// rt_sigreturn) keeps its marker in the shared row, so the Stream tab can show
// "-" for its placeholder latency and return value, while the data outputs
// keep RetVal 0, DurationNs 0 and IsError false.
func TestNewCarriesNoReturn(t *testing.T) {
	enter := &types.NullEvent{EventType: types.ENTER_NULL_EVENT, TraceId: types.SYS_ENTER_EXIT_GROUP, Time: 5, Pid: 1, Tid: 1}
	pair := event.NewPair(enter)
	pair.ExitEv = &types.NullEvent{EventType: types.EXIT_NULL_EVENT, TraceId: types.SYS_ENTER_EXIT_GROUP - 1, Time: 5, Pid: 1, Tid: 1}
	pair.NoReturn = true

	got := New(1, pair)
	if !got.NoReturn || got.Syscall != "exit_group" || got.RetVal != 0 || got.IsError || got.DurationNs != 0 {
		t.Fatalf("row = %+v, want NoReturn exit_group with RetVal 0, no error, no latency", got)
	}

	pair.NoReturn = false
	if New(2, pair).NoReturn {
		t.Fatal("a row built from an ordinary pair is marked NoReturn")
	}
}

// TestNoReturnRowFailsOutcomeFilters (task pr2): a buffered noreturn row and
// the live pair it was built from must get the same verdict from the global
// filter, or a ret/latency filter would admit the live pair and then hide (or
// keep) the buffered row on the next refresh and in the CSV export. Both
// reject every latency/return-value predicate; the ordinary row built from the
// same pair keeps matching ret == 0.
func TestNoReturnRowFailsOutcomeFilters(t *testing.T) {
	enter := &types.NullEvent{EventType: types.ENTER_NULL_EVENT, TraceId: types.SYS_ENTER_RT_SIGRETURN, Time: 5, Pid: 1, Tid: 1}
	pair := event.NewPair(enter)
	pair.ExitEv = &types.NullEvent{EventType: types.EXIT_NULL_EVENT, TraceId: types.SYS_ENTER_RT_SIGRETURN - 1, Time: 5, Pid: 1, Tid: 1}
	pair.NoReturn = true

	for name, filter := range map[string]globalfilter.Filter{
		"ret == 0":     {RetVal: &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: 0}},
		"latency >= 0": {LatencyNs: &globalfilter.NumericFilter{Op: globalfilter.OpGte, Value: 0}},
	} {
		row := New(1, pair)
		if filter.Matches(&row) || filter.MatchPair(pair) {
			t.Errorf("%s: row %v / pair %v, want both rejected", name, filter.Matches(&row), filter.MatchPair(pair))
		}
		pair.NoReturn = false
		row = New(2, pair)
		if !filter.Matches(&row) || !filter.MatchPair(pair) {
			t.Errorf("%s on an ordinary row: row %v / pair %v, want both kept", name, filter.Matches(&row), filter.MatchPair(pair))
		}
		pair.NoReturn = true
	}
}
