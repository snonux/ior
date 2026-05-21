package internal

import (
	"testing"

	"ior/internal/event"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

func TestHandlePipeExitTracksReturnedFds(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})

	enter := &types.PipeEvent{
		EventType: types.ENTER_PIPE_EVENT,
		TraceId:   types.SYS_ENTER_PIPE2,
		Time:      100,
		Pid:       70,
		Tid:       71,
		Flags:     0x80000,
		Fd0:       -1,
		Fd1:       -1,
		Ret:       0,
	}
	exit := &types.PipeEvent{
		EventType: types.EXIT_PIPE_EVENT,
		TraceId:   types.SYS_EXIT_PIPE2,
		Time:      200,
		Pid:       70,
		Tid:       71,
		Flags:     0x80000,
		Fd0:       52,
		Fd1:       53,
		Ret:       0,
	}
	ep := &event.Pair{EnterEv: enter, ExitEv: exit}

	if ok := el.handlePipeExit(ep, enter); !ok {
		t.Fatal("handlePipeExit returned false")
	}
	verifyFileDescriptor(t, el, 52, "pipe:524288:52:53")
	verifyFileDescriptor(t, el, 53, "pipe:524288:52:53")
}

func TestHandleEventfdExitTracksReturnedFd(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})

	enter := &types.EventfdEvent{
		EventType: types.ENTER_EVENTFD_EVENT,
		TraceId:   types.SYS_ENTER_EVENTFD2,
		Time:      100,
		Pid:       80,
		Tid:       81,
		Flags:     0x800,
		Ret:       -1,
	}
	exit := &types.EventfdEvent{
		EventType: types.EXIT_EVENTFD_EVENT,
		TraceId:   types.SYS_EXIT_EVENTFD2,
		Time:      200,
		Pid:       80,
		Tid:       81,
		Flags:     0x800,
		Ret:       61,
	}
	ep := &event.Pair{EnterEv: enter, ExitEv: exit}

	if ok := el.handleEventfdExit(ep, enter); !ok {
		t.Fatal("handleEventfdExit returned false")
	}
	verifyFileDescriptor(t, el, 61, "eventfd:2048")
}

func TestHandleEventfdExitAppliesPairFilter(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{
		filter: globalfilter.Filter{
			Syscall: &globalfilter.StringFilter{Pattern: "openat"},
		},
	})

	enter := &types.EventfdEvent{
		EventType: types.ENTER_EVENTFD_EVENT,
		TraceId:   types.SYS_ENTER_EVENTFD,
		Time:      100,
		Pid:       82,
		Tid:       83,
		Flags:     0,
		Ret:       -1,
	}
	exit := &types.EventfdEvent{
		EventType: types.EXIT_EVENTFD_EVENT,
		TraceId:   types.SYS_EXIT_EVENTFD,
		Time:      200,
		Pid:       82,
		Tid:       83,
		Flags:     0,
		Ret:       44,
	}
	ep := &event.Pair{EnterEv: enter, ExitEv: exit}

	if ok := el.handleEventfdExit(ep, enter); ok {
		t.Fatal("handleEventfdExit should reject pair due to filter mismatch")
	}
}

func TestEventfdDescriptorNameByTraceID(t *testing.T) {
	tests := []struct {
		name    string
		traceID types.TraceId
		flags   int32
		want    string
	}{
		{name: "eventfd", traceID: types.SYS_ENTER_EVENTFD2, flags: 1, want: "eventfd:1"},
		{name: "memfd_create", traceID: types.SYS_ENTER_MEMFD_CREATE, flags: 2, want: "memfd:2"},
		{name: "memfd_secret", traceID: types.SYS_ENTER_MEMFD_SECRET, flags: 3, want: "memfd-secret:3"},
		{name: "userfaultfd", traceID: types.SYS_ENTER_USERFAULTFD, flags: 4, want: "userfaultfd:4"},
		{name: "signalfd", traceID: types.SYS_ENTER_SIGNALFD4, flags: 5, want: "signalfd:5"},
		{name: "timerfd_create", traceID: types.SYS_ENTER_TIMERFD_CREATE, flags: 6, want: "timerfd:6"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := eventfdDescriptorName(tt.traceID, tt.flags)
			if got != tt.want {
				t.Fatalf("eventfdDescriptorName(%s, %d) = %q, want %q", tt.traceID.String(), tt.flags, got, tt.want)
			}
		})
	}
}

func TestInitRawHandlersRegistersIPCEvents(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	if _, ok := el.rawHandlers[types.ENTER_PIPE_EVENT]; !ok {
		t.Fatal("ENTER_PIPE_EVENT handler is not registered")
	}
	if _, ok := el.rawHandlers[types.EXIT_PIPE_EVENT]; !ok {
		t.Fatal("EXIT_PIPE_EVENT handler is not registered")
	}
	if _, ok := el.rawHandlers[types.ENTER_EVENTFD_EVENT]; !ok {
		t.Fatal("ENTER_EVENTFD_EVENT handler is not registered")
	}
	if _, ok := el.rawHandlers[types.EXIT_EVENTFD_EVENT]; !ok {
		t.Fatal("EXIT_EVENTFD_EVENT handler is not registered")
	}
}
