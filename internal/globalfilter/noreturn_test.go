package globalfilter

import (
	"testing"

	"ior/internal/event"
	"ior/internal/types"
)

// noReturnPair builds a noreturn row the way the event loop emits it
// (eventLoop.completeNoReturnEnter): the enter plus a synthetic NullEvent exit
// carrying no ret, Duration 0, NoReturn set.
func noReturnPair() *event.Pair {
	return &event.Pair{
		EnterEv:        &types.NullEvent{EventType: types.ENTER_NULL_EVENT, TraceId: types.SYS_ENTER_EXIT_GROUP, Pid: 77, Tid: 77},
		ExitEv:         &types.NullEvent{EventType: types.EXIT_NULL_EVENT, TraceId: types.SYS_ENTER_EXIT_GROUP - 1, Pid: 77, Tid: 77},
		Comm:           "sh",
		DurationToPrev: 9_000,
		NoReturn:       true,
	}
}

// fastSuccessPair is the negative control: a real syscall that returned 0 in
// 500ns, i.e. exactly what the placeholders of a noreturn row look like
// (ret 0, a small latency) but with a genuine outcome.
func fastSuccessPair() *event.Pair {
	return &event.Pair{
		EnterEv:        &types.RetEvent{TraceId: types.SYS_ENTER_CLOSE, Pid: 77, Tid: 77},
		ExitEv:         &types.RetEvent{TraceId: types.SYS_EXIT_CLOSE, Pid: 77, Tid: 77, Ret: 0},
		Comm:           "sh",
		Duration:       500,
		DurationToPrev: 9_000,
	}
}

// TestOutcomeFiltersRejectNoReturnPairs (task pr2): exit, exit_group and
// rt_sigreturn rows have no return value and no latency (their 0s are
// placeholders), so every latency or return-value predicate rejects them,
// whatever its operator, and errors-only does too. The control pair - a real
// call that returned 0 quickly - must keep matching exactly the predicates it
// satisfies, so the rule is keyed on Pair.NoReturn and not on the values.
func TestOutcomeFiltersRejectNoReturnPairs(t *testing.T) {
	tests := []struct {
		name        string
		filter      Filter
		wantControl bool
	}{
		{"ret == 0", Filter{RetVal: &NumericFilter{Op: OpEq, Value: 0}}, true},
		{"ret != 0", Filter{RetVal: &NumericFilter{Op: OpNeq, Value: 0}}, false},
		{"ret >= 0", Filter{RetVal: &NumericFilter{Op: OpGte, Value: 0}}, true},
		{"ret < 0", Filter{RetVal: &NumericFilter{Op: OpLt, Value: 0}}, false},
		{"latency < 1ms", Filter{LatencyNs: &NumericFilter{Op: OpLt, Value: 1_000_000}}, true},
		{"latency <= 0", Filter{LatencyNs: &NumericFilter{Op: OpLte, Value: 0}}, false},
		{"latency > 100ns", Filter{LatencyNs: &NumericFilter{Op: OpGt, Value: 100}}, true},
		{"latency >= 0", Filter{LatencyNs: &NumericFilter{Op: OpGte, Value: 0}}, true},
		{"latency == 0", Filter{LatencyNs: &NumericFilter{Op: OpEq, Value: 0}}, false},
		{"errors only", Filter{ErrorsOnly: true}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.filter.MatchPair(noReturnPair()) {
				t.Errorf("%s matched a noreturn exit_group pair, which has no outcome", tt.name)
			}
			if got := tt.filter.MatchPair(fastSuccessPair()); got != tt.wantControl {
				t.Errorf("%s on the control pair = %v, want %v", tt.name, got, tt.wantControl)
			}
		})
	}
}

// TestNonOutcomeFiltersStillSelectNoReturnPairs: the rule only concerns the
// outcome dimensions. A noreturn row has a real syscall, comm, pid, tid and
// gap, so filters on those keep it, alone and combined.
func TestNonOutcomeFiltersStillSelectNoReturnPairs(t *testing.T) {
	for name, filter := range map[string]Filter{
		"zero filter": {},
		"syscall":     {Syscall: &StringFilter{Pattern: ExactPattern("exit_group")}},
		"comm":        {Comm: &StringFilter{Pattern: "sh"}},
		"pid":         {PID: &NumericFilter{Op: OpEq, Value: 77}},
		"tid":         {TID: &NumericFilter{Op: OpEq, Value: 77}},
		"gap":         {GapNs: &NumericFilter{Op: OpGte, Value: 9_000}},
		"combined":    {Syscall: &StringFilter{Pattern: "exit"}, PID: &NumericFilter{Op: OpEq, Value: 77}, GapNs: &NumericFilter{Op: OpGt, Value: 1}},
	} {
		if !filter.MatchPair(noReturnPair()) {
			t.Errorf("%s filter rejected the noreturn pair", name)
		}
	}
	// Combined with an outcome predicate the pair is rejected even when every
	// other dimension selects it.
	withRet := Filter{Syscall: &StringFilter{Pattern: "exit"}, RetVal: &NumericFilter{Op: OpEq, Value: 0}}
	if withRet.MatchPair(noReturnPair()) {
		t.Error("syscall=exit plus ret==0 matched the noreturn pair")
	}
}

// TestCandidateNoReturnValueRejectsOutcomes pins the rule at the Candidate
// level, independent of the pair adapter (the Stream tab and CSV export
// filter rows, not pairs).
func TestCandidateNoReturnValueRejectsOutcomes(t *testing.T) {
	row := testCandidate()
	row.ret, row.latency, row.isError, row.noReturn = 0, 0, false, true
	for name, filter := range map[string]Filter{
		"ret == 0":     {RetVal: &NumericFilter{Op: OpEq, Value: 0}},
		"latency >= 0": {LatencyNs: &NumericFilter{Op: OpGte, Value: 0}},
		"latency < 1":  {LatencyNs: &NumericFilter{Op: OpLt, Value: 1}},
	} {
		if filter.Matches(row) {
			t.Errorf("%s matched a NoReturnValue candidate", name)
		}
		row.noReturn = false
		if !filter.Matches(row) {
			t.Errorf("%s rejected the same candidate without NoReturnValue", name)
		}
		row.noReturn = true
	}
}
