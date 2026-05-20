package internal

import (
	"testing"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

func TestHandleTwoFdExitUsesFirstDescriptor(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	el.fdState().set(81, file.NewFd(81, "/proc/self/fd/81", -1))

	enter := &types.TwoFdEvent{
		EventType: types.ENTER_TWO_FD_EVENT,
		TraceId:   types.SYS_ENTER_MOVE_MOUNT,
		Time:      100,
		Pid:       70,
		Tid:       71,
		FdA:       81,
		FdB:       82,
		Extra:     0x2,
	}
	exit := &types.RetEvent{
		EventType: types.EXIT_RET_EVENT,
		TraceId:   types.SYS_EXIT_MOVE_MOUNT,
		Time:      200,
		Ret:       0,
		Pid:       70,
		Tid:       71,
	}
	ep := &event.Pair{EnterEv: enter, ExitEv: exit}

	if ok := el.handleTwoFdExit(ep, enter); !ok {
		t.Fatal("handleTwoFdExit returned false")
	}
	if ep.File == nil || ep.File.FD() != 81 {
		t.Fatalf("expected resolved descriptor 81, got file=%v", ep.File)
	}
}

func TestHandleTwoFdExitAppliesPairFilter(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{
		filter: globalfilter.Filter{
			Syscall: &globalfilter.StringFilter{Pattern: "openat"},
		},
	})

	enter := &types.TwoFdEvent{
		EventType: types.ENTER_TWO_FD_EVENT,
		TraceId:   types.SYS_ENTER_MOVE_MOUNT,
		Time:      100,
		Pid:       72,
		Tid:       73,
		FdA:       91,
		FdB:       92,
		Extra:     0,
	}
	exit := &types.RetEvent{
		EventType: types.EXIT_RET_EVENT,
		TraceId:   types.SYS_EXIT_MOVE_MOUNT,
		Time:      200,
		Ret:       0,
		Pid:       72,
		Tid:       73,
	}
	ep := &event.Pair{EnterEv: enter, ExitEv: exit}

	if ok := el.handleTwoFdExit(ep, enter); ok {
		t.Fatal("handleTwoFdExit should reject pair due to filter mismatch")
	}
}

func TestInitRawHandlersRegistersTwoFdEvent(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	if _, ok := el.rawHandlers[types.ENTER_TWO_FD_EVENT]; !ok {
		t.Fatal("ENTER_TWO_FD_EVENT handler is not registered")
	}
}
