package internal

import (
	"testing"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

func TestHandleSocketExitTracksReturnedFd(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})

	enter := &types.SocketEvent{
		EventType: types.ENTER_SOCKET_EVENT,
		TraceId:   types.SYS_ENTER_SOCKET,
		Time:      100,
		Pid:       42,
		Tid:       43,
		Family:    1,
		Type:      2,
		Protocol:  0,
	}
	exit := &types.RetEvent{
		EventType: types.EXIT_SOCKET_EVENT,
		TraceId:   types.SYS_EXIT_SOCKET,
		Time:      200,
		Ret:       55,
		Pid:       42,
		Tid:       43,
	}
	ep := &event.Pair{EnterEv: enter, ExitEv: exit}

	if ok := el.handleSocketExit(ep, enter); !ok {
		t.Fatal("handleSocketExit returned false")
	}
	verifyFileDescriptor(t, el, 55, "socket:1:2:0")
}

func TestHandleSocketExitAppliesPairFilter(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{
		filter: globalfilter.Filter{
			Syscall: &globalfilter.StringFilter{Pattern: "openat"},
		},
	})

	enter := &types.SocketEvent{
		EventType: types.ENTER_SOCKET_EVENT,
		TraceId:   types.SYS_ENTER_SOCKET,
		Time:      100,
		Pid:       42,
		Tid:       43,
		Family:    1,
		Type:      2,
		Protocol:  0,
	}
	exit := &types.RetEvent{
		EventType: types.EXIT_SOCKET_EVENT,
		TraceId:   types.SYS_EXIT_SOCKET,
		Time:      200,
		Ret:       55,
		Pid:       42,
		Tid:       43,
	}
	ep := &event.Pair{EnterEv: enter, ExitEv: exit}

	if ok := el.handleSocketExit(ep, enter); ok {
		t.Fatal("handleSocketExit should reject pair due to filter mismatch")
	}
}

func TestHandleSocketpairExitTracksReturnedFdsFromExitEvent(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})

	enter := &types.SocketpairEvent{
		EventType: types.ENTER_SOCKETPAIR_EVENT,
		TraceId:   types.SYS_ENTER_SOCKETPAIR,
		Time:      100,
		Pid:       77,
		Tid:       78,
		Family:    1,
		Type:      1,
		Protocol:  0,
		Sv0:       -1,
		Sv1:       -1,
		Ret:       0,
	}
	exit := &types.SocketpairEvent{
		EventType: types.EXIT_SOCKETPAIR_EVENT,
		TraceId:   types.SYS_EXIT_SOCKETPAIR,
		Time:      200,
		Pid:       77,
		Tid:       78,
		Family:    1,
		Type:      1,
		Protocol:  0,
		Sv0:       61,
		Sv1:       62,
		Ret:       0,
	}
	ep := &event.Pair{EnterEv: enter, ExitEv: exit}

	if ok := el.handleSocketpairExit(ep, enter); !ok {
		t.Fatal("handleSocketpairExit returned false")
	}
	verifyFileDescriptor(t, el, 61, "socket:1:1:0")
	verifyFileDescriptor(t, el, 62, "socket:1:1:0")
}

func TestHandleAcceptExitTracksAcceptedFd(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})

	el.fdState().set(11, file.NewFd(11, "socket:1:1:0", -1))

	enter := &types.AcceptEvent{
		EventType: types.ENTER_ACCEPT_EVENT,
		TraceId:   types.SYS_ENTER_ACCEPT4,
		Time:      100,
		Pid:       91,
		Tid:       92,
		Fd:        11,
		Ret:       -1,
	}
	exit := &types.AcceptEvent{
		EventType: types.EXIT_ACCEPT_EVENT,
		TraceId:   types.SYS_EXIT_ACCEPT4,
		Time:      200,
		Pid:       91,
		Tid:       92,
		Fd:        -1,
		Ret:       77,
	}
	ep := &event.Pair{EnterEv: enter, ExitEv: exit}

	if ok := el.handleAcceptExit(ep, enter); !ok {
		t.Fatal("handleAcceptExit returned false")
	}
	verifyFileDescriptor(t, el, 77, "socket:1:1:0")
}

func TestInitRawHandlersRegistersSocketEvents(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	if _, ok := el.rawHandlers[types.ENTER_SOCKET_EVENT]; !ok {
		t.Fatal("ENTER_SOCKET_EVENT handler is not registered")
	}
	if _, ok := el.rawHandlers[types.ENTER_SOCKETPAIR_EVENT]; !ok {
		t.Fatal("ENTER_SOCKETPAIR_EVENT handler is not registered")
	}
	if _, ok := el.rawHandlers[types.EXIT_SOCKETPAIR_EVENT]; !ok {
		t.Fatal("EXIT_SOCKETPAIR_EVENT handler is not registered")
	}
	if _, ok := el.rawHandlers[types.ENTER_ACCEPT_EVENT]; !ok {
		t.Fatal("ENTER_ACCEPT_EVENT handler is not registered")
	}
	if _, ok := el.rawHandlers[types.EXIT_ACCEPT_EVENT]; !ok {
		t.Fatal("EXIT_ACCEPT_EVENT handler is not registered")
	}
}
