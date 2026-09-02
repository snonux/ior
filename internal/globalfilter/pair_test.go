package globalfilter

import (
	"testing"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/types"
)

func samplePair() *event.Pair {
	return &event.Pair{
		EnterEv:        &types.RetEvent{TraceId: types.SYS_ENTER_READ, Pid: 1234, Tid: 1235},
		ExitEv:         &types.RetEvent{TraceId: types.SYS_EXIT_READ, Pid: 1234, Tid: 1235, Ret: -1},
		Comm:           "nginx",
		File:           file.NewFd(7, "/var/log/access.log", 0),
		Duration:       1_500_000,
		DurationToPrev: 12_000,
		Bytes:          4_096,
	}
}

func TestMatchPairMatchesAllSupportedFields(t *testing.T) {
	filter := Filter{
		Syscall:    &StringFilter{Pattern: "rea"},
		Comm:       &StringFilter{Pattern: "NGI"},
		File:       &StringFilter{Pattern: "access"},
		PID:        &NumericFilter{Op: OpEq, Value: 1234},
		TID:        &NumericFilter{Op: OpEq, Value: 1235},
		FD:         &NumericFilter{Op: OpEq, Value: 7},
		LatencyNs:  &NumericFilter{Op: OpGt, Value: 1_000_000},
		GapNs:      &NumericFilter{Op: OpLte, Value: 12_000},
		Bytes:      &NumericFilter{Op: OpLt, Value: 8_192},
		RetVal:     &NumericFilter{Op: OpEq, Value: -1},
		ErrorsOnly: true,
	}
	if !MatchPair(filter, samplePair()) {
		t.Fatalf("expected full filter to match pair")
	}
}

func TestMatchPairRejectsMismatchesAndMissingFD(t *testing.T) {
	pair := samplePair()
	if MatchPair(Filter{Syscall: &StringFilter{Pattern: "write"}}, pair) {
		t.Fatalf("expected syscall mismatch to reject pair")
	}
	if MatchPair(Filter{FD: &NumericFilter{Op: OpEq, Value: 99}}, pair) {
		t.Fatalf("expected fd mismatch to reject pair")
	}

	pair.File = nil
	if MatchPair(Filter{FD: &NumericFilter{Op: OpEq, Value: 7}}, pair) {
		t.Fatalf("expected missing fd to reject pair")
	}
}

// TestMatchPairSeesRetOnKindSpecificExits guards the ret-carrier fix at the
// filter layer: accept/pipe/socketpair/eventfd exits decode into their own
// event structs rather than *types.RetEvent, so `ret`/errors-only filters used
// to see ret=0 and silently drop every failing call of those syscalls.
func TestMatchPairSeesRetOnKindSpecificExits(t *testing.T) {
	tests := []struct {
		name  string
		enter event.Event
		exit  event.Event
		ret   int64
	}{
		{
			name:  "accept",
			enter: &types.AcceptEvent{TraceId: types.SYS_ENTER_ACCEPT, Pid: 1234, Tid: 1235},
			exit:  &types.AcceptEvent{TraceId: types.SYS_EXIT_ACCEPT, Pid: 1234, Tid: 1235, Ret: -11},
			ret:   -11,
		},
		{
			name:  "pipe",
			enter: &types.PipeEvent{TraceId: types.SYS_ENTER_PIPE, Pid: 1234, Tid: 1235},
			exit:  &types.PipeEvent{TraceId: types.SYS_EXIT_PIPE, Pid: 1234, Tid: 1235, Ret: -24},
			ret:   -24,
		},
		{
			name:  "socketpair",
			enter: &types.SocketpairEvent{TraceId: types.SYS_ENTER_SOCKETPAIR, Pid: 1234, Tid: 1235},
			exit:  &types.SocketpairEvent{TraceId: types.SYS_EXIT_SOCKETPAIR, Pid: 1234, Tid: 1235, Ret: -93},
			ret:   -93,
		},
		{
			name:  "eventfd2",
			enter: &types.EventfdEvent{TraceId: types.SYS_ENTER_EVENTFD2, Pid: 1234, Tid: 1235},
			exit:  &types.EventfdEvent{TraceId: types.SYS_EXIT_EVENTFD2, Pid: 1234, Tid: 1235, Ret: -24},
			ret:   -24,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pair := &event.Pair{EnterEv: tt.enter, ExitEv: tt.exit, Comm: "srv"}
			if !MatchPair(Filter{ErrorsOnly: true}, pair) {
				t.Fatalf("errors-only filter did not match failing %s pair", tt.name)
			}
			if !MatchPair(Filter{RetVal: &NumericFilter{Op: OpEq, Value: tt.ret}}, pair) {
				t.Fatalf("ret == %d filter did not match %s pair", tt.ret, tt.name)
			}
		})
	}
}
