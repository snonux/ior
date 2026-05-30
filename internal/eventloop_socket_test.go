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

// TestHandleSocketpairExitDoesNotTrackDomainAsFd is a regression lock-in for the
// socketpair(2) audit (task c00). socketpair's first argument (args[0]) is the
// address-family/domain constant (e.g. AF_UNIX, AF_INET6), NOT a file
// descriptor: the two created fds are written by the kernel into the OUTPUT
// array sv[2] (args[3]) and are only valid AFTER the call returns. KindSocketpair
// captures sv0/sv1 from that output buffer at exit; it must never register the
// domain integer as an fd. This test pins that invariant by using a Family value
// (AF_INET6 == 10) that is numerically distinct from the returned fds and
// asserting fd 10 is never tracked.
func TestHandleSocketpairExitDoesNotTrackDomainAsFd(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})

	const afInet6 = 10
	enter := &types.SocketpairEvent{
		EventType: types.ENTER_SOCKETPAIR_EVENT,
		TraceId:   types.SYS_ENTER_SOCKETPAIR,
		Time:      100,
		Pid:       77,
		Tid:       78,
		Family:    afInet6,
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
		Family:    afInet6,
		Type:      1,
		Protocol:  0,
		Sv0:       3,
		Sv1:       4,
		Ret:       0,
	}
	ep := &event.Pair{EnterEv: enter, ExitEv: exit}

	if ok := el.handleSocketpairExit(ep, enter); !ok {
		t.Fatal("handleSocketpairExit returned false")
	}
	// Only the output fds sv[2] are tracked.
	verifyFileDescriptor(t, el, 3, "socket:10:1:0")
	verifyFileDescriptor(t, el, 4, "socket:10:1:0")
	// The domain constant (AF_INET6 == 10) must NOT have been captured as an fd.
	verifyFdNotTracked(t, el, afInet6)
}

// TestHandleSocketpairExitDropsFdsOnError pins that a failed socketpair(2)
// (ret != 0) tracks no descriptors: the sv[2] output buffer is undefined on
// error, so the BPF exit handler leaves sv0/sv1 at the -1 sentinel and the
// userspace handler must not register anything.
func TestHandleSocketpairExitDropsFdsOnError(t *testing.T) {
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
		Sv0:       -1,
		Sv1:       -1,
		Ret:       -24, // -EMFILE
	}
	ep := &event.Pair{EnterEv: enter, ExitEv: exit}

	if ok := el.handleSocketpairExit(ep, enter); !ok {
		t.Fatal("handleSocketpairExit returned false")
	}
	verifyFdNotTracked(t, el, 1)
	verifyFdNotTracked(t, el, -1)
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

func TestHandleAcceptExitAppliesPairFilter(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{
		filter: globalfilter.Filter{
			Syscall: &globalfilter.StringFilter{Pattern: "openat"},
		},
	})

	el.fdState().set(11, file.NewFd(11, "socket:1:1:0", -1))

	enter := &types.AcceptEvent{
		EventType: types.ENTER_ACCEPT_EVENT,
		TraceId:   types.SYS_ENTER_ACCEPT,
		Time:      100,
		Pid:       91,
		Tid:       92,
		Fd:        11,
		Ret:       -1,
	}
	exit := &types.AcceptEvent{
		EventType: types.EXIT_ACCEPT_EVENT,
		TraceId:   types.SYS_EXIT_ACCEPT,
		Time:      200,
		Pid:       91,
		Tid:       92,
		Fd:        -1,
		Ret:       77,
	}
	ep := &event.Pair{EnterEv: enter, ExitEv: exit}

	if ok := el.handleAcceptExit(ep, enter); ok {
		t.Fatal("handleAcceptExit should reject pair due to filter mismatch")
	}
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
