package internal

import (
	"testing"

	"ior/internal/event"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

func TestHandlePerfOpenExitTracksReturnedFd(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})

	enter := &types.PerfOpenEvent{
		EventType: types.ENTER_PERF_OPEN_EVENT,
		TraceId:   types.SYS_ENTER_PERF_EVENT_OPEN,
		Time:      100,
		Pid:       200,
		Tid:       201,
		AttrType:  1,
		AttrSize:  64,
		Config:    2,
		TargetPid: 0,
		Cpu:       -1,
		GroupFd:   -1,
		Flags:     0,
	}
	exit := &types.RetEvent{
		EventType: types.EXIT_RET_EVENT,
		TraceId:   types.SYS_EXIT_PERF_EVENT_OPEN,
		Time:      200,
		Ret:       77,
		Pid:       200,
		Tid:       201,
	}
	ep := &event.Pair{EnterEv: enter, ExitEv: exit}

	if ok := el.handlePerfOpenExit(ep, enter); !ok {
		t.Fatal("handlePerfOpenExit returned false")
	}
	if ep.File == nil || ep.File.FD() != 77 {
		t.Fatalf("expected resolved perf fd 77, got file=%v", ep.File)
	}
}

func TestHandlePerfOpenExitAppliesPairFilter(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{
		filter: globalfilter.Filter{
			Syscall: &globalfilter.StringFilter{Pattern: "openat"},
		},
	})

	enter := &types.PerfOpenEvent{
		EventType: types.ENTER_PERF_OPEN_EVENT,
		TraceId:   types.SYS_ENTER_PERF_EVENT_OPEN,
		Time:      100,
		Pid:       202,
		Tid:       203,
	}
	exit := &types.RetEvent{
		EventType: types.EXIT_RET_EVENT,
		TraceId:   types.SYS_EXIT_PERF_EVENT_OPEN,
		Time:      200,
		Ret:       1,
		Pid:       202,
		Tid:       203,
	}
	ep := &event.Pair{EnterEv: enter, ExitEv: exit}

	if ok := el.handlePerfOpenExit(ep, enter); ok {
		t.Fatal("handlePerfOpenExit should reject pair due to filter mismatch")
	}
}

func TestInitRawHandlersRegistersSecurityEvents(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	if _, ok := el.rawHandlers[types.ENTER_KEYCTL_EVENT]; !ok {
		t.Fatal("ENTER_KEYCTL_EVENT handler is not registered")
	}
	if _, ok := el.rawHandlers[types.ENTER_PTRACE_EVENT]; !ok {
		t.Fatal("ENTER_PTRACE_EVENT handler is not registered")
	}
	if _, ok := el.rawHandlers[types.ENTER_PERF_OPEN_EVENT]; !ok {
		t.Fatal("ENTER_PERF_OPEN_EVENT handler is not registered")
	}
}
