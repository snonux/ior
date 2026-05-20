package internal

import (
	"testing"

	"ior/internal/event"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

func TestHandleExecExitSetsPathAndComm(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	enter := &types.ExecEvent{
		EventType: types.ENTER_EXEC_EVENT,
		TraceId:   types.SYS_ENTER_EXECVEAT,
		Time:      100,
		Pid:       200,
		Tid:       201,
		Dirfd:     -100,
		Flags:     0,
	}
	copy(enter.Filename[:], "/definitely-missing-execveat")
	copy(enter.Comm[:], "ioworkload")
	exit := &types.RetEvent{
		EventType: types.EXIT_RET_EVENT,
		TraceId:   types.SYS_EXIT_EXECVEAT,
		Time:      200,
		Ret:       -2,
		Pid:       200,
		Tid:       201,
	}
	ep := &event.Pair{EnterEv: enter, ExitEv: exit}

	if ok := el.handleExecExit(ep, enter); !ok {
		t.Fatal("handleExecExit returned false")
	}
	if got := ep.File.Name(); got != "/definitely-missing-execveat" {
		t.Fatalf("exec path = %q, want %q", got, "/definitely-missing-execveat")
	}
	if got := ep.Comm; got != "ioworkload" {
		t.Fatalf("comm = %q, want %q", got, "ioworkload")
	}
}

func TestHandleExecExitAppliesPairFilter(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{
		filter: globalfilter.Filter{
			Syscall: &globalfilter.StringFilter{Pattern: "openat"},
		},
	})
	enter := &types.ExecEvent{
		EventType: types.ENTER_EXEC_EVENT,
		TraceId:   types.SYS_ENTER_EXECVE,
		Time:      100,
		Pid:       210,
		Tid:       211,
	}
	copy(enter.Filename[:], "/definitely-missing-execve")
	copy(enter.Comm[:], "ioworkload")
	exit := &types.RetEvent{
		EventType: types.EXIT_RET_EVENT,
		TraceId:   types.SYS_EXIT_EXECVE,
		Time:      200,
		Ret:       -2,
		Pid:       210,
		Tid:       211,
	}
	ep := &event.Pair{EnterEv: enter, ExitEv: exit}

	if ok := el.handleExecExit(ep, enter); ok {
		t.Fatal("handleExecExit should reject pair due to filter mismatch")
	}
}

func TestInitRawHandlersRegistersExecEvent(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	if _, ok := el.rawHandlers[types.ENTER_EXEC_EVENT]; !ok {
		t.Fatal("ENTER_EXEC_EVENT handler is not registered")
	}
}
