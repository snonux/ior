package internal

import (
	"syscall"
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
	verifyFileDescriptor(t, el, 42, 55, "socket:1:2:0")
}

func TestHandleSocketExitMasksTypeAndTracksCreationFlags(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	rawType := int32(syscall.SOCK_STREAM | syscall.SOCK_NONBLOCK | syscall.SOCK_CLOEXEC)
	enter := &types.SocketEvent{
		EventType: types.ENTER_SOCKET_EVENT,
		TraceId:   types.SYS_ENTER_SOCKET,
		Pid:       42,
		Tid:       43,
		Family:    syscall.AF_INET,
		Type:      rawType,
	}
	exit := &types.RetEvent{TraceId: types.SYS_EXIT_SOCKET, Ret: 55, Pid: 42, Tid: 43}
	ep := &event.Pair{EnterEv: enter, ExitEv: exit}

	if ok := el.handleSocketExit(ep, enter); !ok {
		t.Fatal("handleSocketExit returned false")
	}
	verifyFileDescriptor(t, el, 42, 55, "socket:2:1:0")
	verifySocketDescriptorFlags(t, el, 42, 55, syscall.O_RDWR|syscall.O_NONBLOCK|syscall.O_CLOEXEC)
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
	verifyFileDescriptor(t, el, 77, 61, "socket:1:1:0")
	verifyFileDescriptor(t, el, 77, 62, "socket:1:1:0")
}

func TestHandleSocketpairExitMasksTypeAndTracksCreationFlags(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	rawType := int32(syscall.SOCK_STREAM | syscall.SOCK_NONBLOCK | syscall.SOCK_CLOEXEC)
	enter := &types.SocketpairEvent{
		EventType: types.ENTER_SOCKETPAIR_EVENT,
		TraceId:   types.SYS_ENTER_SOCKETPAIR,
		Pid:       77,
		Tid:       78,
		Family:    syscall.AF_UNIX,
		Type:      rawType,
		Sv0:       -1,
		Sv1:       -1,
	}
	exit := &types.SocketpairEvent{
		EventType: types.EXIT_SOCKETPAIR_EVENT,
		TraceId:   types.SYS_EXIT_SOCKETPAIR,
		Pid:       77,
		Tid:       78,
		Family:    syscall.AF_UNIX,
		Type:      rawType,
		Sv0:       61,
		Sv1:       62,
	}
	ep := &event.Pair{EnterEv: enter, ExitEv: exit}

	if ok := el.handleSocketpairExit(ep, enter); !ok {
		t.Fatal("handleSocketpairExit returned false")
	}
	for _, fd := range []int32{61, 62} {
		verifyFileDescriptor(t, el, 77, fd, "socket:1:1:0")
		verifySocketDescriptorFlags(t, el, 77, fd, syscall.O_RDWR|syscall.O_NONBLOCK|syscall.O_CLOEXEC)
	}
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
	verifyFileDescriptor(t, el, 77, 3, "socket:10:1:0")
	verifyFileDescriptor(t, el, 77, 4, "socket:10:1:0")
	// The domain constant (AF_INET6 == 10) must NOT have been captured as an fd.
	verifyFdNotTracked(t, el, 77, afInet6)
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
	verifyFdNotTracked(t, el, 77, 1)
	verifyFdNotTracked(t, el, 77, -1)
}

func TestHandleAcceptExitTracksAcceptedFd(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})

	el.fdState().set(11, 91, file.NewFd(11, "socket:1:1:0", -1))

	enter := &types.AcceptEvent{
		EventType: types.ENTER_ACCEPT_EVENT,
		TraceId:   types.SYS_ENTER_ACCEPT4,
		Time:      100,
		Pid:       91,
		Tid:       92,
		Fd:        11,
		Ret:       -1,
		Flags:     syscall.SOCK_NONBLOCK | syscall.SOCK_CLOEXEC,
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
	verifyFileDescriptor(t, el, 91, 77, "socket:1:1:0")
	verifySocketDescriptorFlags(t, el, 91, 77, syscall.O_RDWR|syscall.O_NONBLOCK|syscall.O_CLOEXEC)
}

// A listener named by procfs ("socket:[inode]") must not lend that identity
// to the connections it accepts: each connection is a different socket, and
// the copied inode made all their traffic look like the listener's.
func TestHandleAcceptExitDoesNotCopyListenerProcfsIdentity(t *testing.T) {
	for name, listenerName := range map[string]string{
		"procfs inode":    "socket:[75019555]",
		"empty name":      "",
		"non socket name": "/tmp/not-a-socket",
		"bare prefix":     "socket:",
	} {
		t.Run(name, func(t *testing.T) {
			el := mustNewEventLoop(t, eventLoopConfig{})
			el.fdState().set(11, 91, file.NewFd(11, listenerName, -1))
			enter := &types.AcceptEvent{
				EventType: types.ENTER_ACCEPT_EVENT, TraceId: types.SYS_ENTER_ACCEPT,
				Pid: 91, Tid: 92, Fd: 11,
			}
			exit := &types.AcceptEvent{EventType: types.EXIT_ACCEPT_EVENT, TraceId: types.SYS_EXIT_ACCEPT, Ret: 77}
			ep := &event.Pair{EnterEv: enter, ExitEv: exit}

			if ok := el.handleAcceptExit(ep, enter); !ok {
				t.Fatal("handleAcceptExit returned false")
			}
			verifyFileDescriptor(t, el, 91, 77, "socket:accepted")
			if got := ep.File.Name(); got != "socket:accepted" {
				t.Fatalf("accept row file = %q, want socket:accepted", got)
			}
		})
	}
}

// Two connections accepted from one procfs-named listener stay unnamed after
// it, and the listener keeps its own identity.
func TestHandleAcceptExitKeepsListenerIdentityApart(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	el.fdState().set(11, 91, file.NewFd(11, "socket:[75019555]", -1))
	for _, conn := range []int64{77, 78} {
		enter := &types.AcceptEvent{EventType: types.ENTER_ACCEPT_EVENT, TraceId: types.SYS_ENTER_ACCEPT, Pid: 91, Tid: 92, Fd: 11}
		exit := &types.AcceptEvent{EventType: types.EXIT_ACCEPT_EVENT, TraceId: types.SYS_EXIT_ACCEPT, Ret: conn}
		if ok := el.handleAcceptExit(&event.Pair{EnterEv: enter, ExitEv: exit}, enter); !ok {
			t.Fatal("handleAcceptExit returned false")
		}
		verifyFileDescriptor(t, el, 91, int32(conn), "socket:accepted")
	}
	verifyFileDescriptor(t, el, 91, 11, "socket:[75019555]")
}

func TestIsSyntheticSocketName(t *testing.T) {
	for name, want := range map[string]bool{
		"socket:1:1:0":      true,
		"socket:10:2:17":    true,
		"socket:accepted":   true,
		"socket:[75019555]": false,
		"socket:[":          false,
		"socket:":           false,
		"":                  false,
		"pipe:[5]":          false,
		"/etc/passwd":       false,
	} {
		if got := isSyntheticSocketName(name); got != want {
			t.Errorf("isSyntheticSocketName(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestHandleAcceptExitDoesNotInheritListeningFlags(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	el.fdState().set(11, 91, file.NewFd(11, "socket:1:1:0", syscall.O_NONBLOCK|syscall.O_CLOEXEC))
	enter := &types.AcceptEvent{
		EventType: types.ENTER_ACCEPT_EVENT,
		TraceId:   types.SYS_ENTER_ACCEPT,
		Pid:       91,
		Tid:       92,
		Fd:        11,
	}
	exit := &types.AcceptEvent{EventType: types.EXIT_ACCEPT_EVENT, TraceId: types.SYS_EXIT_ACCEPT, Ret: 77}
	ep := &event.Pair{EnterEv: enter, ExitEv: exit}

	if ok := el.handleAcceptExit(ep, enter); !ok {
		t.Fatal("handleAcceptExit returned false")
	}
	verifySocketDescriptorFlags(t, el, 91, 77, syscall.O_RDWR)
}

func TestHandleLegacyAccept4ExitKeepsFlagsUnknown(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	el.fdState().set(11, 91, file.NewFd(11, "socket:1:1:0", syscall.O_NONBLOCK))
	enter := &types.AcceptEvent{
		EventType: types.ENTER_ACCEPT_EVENT,
		TraceId:   types.SYS_ENTER_ACCEPT4,
		Pid:       91,
		Tid:       92,
		Fd:        11,
		Flags:     -1,
	}
	exit := &types.AcceptEvent{EventType: types.EXIT_ACCEPT_EVENT, TraceId: types.SYS_EXIT_ACCEPT4, Ret: 77}
	ep := &event.Pair{EnterEv: enter, ExitEv: exit}

	if ok := el.handleAcceptExit(ep, enter); !ok {
		t.Fatal("handleAcceptExit returned false")
	}
	verifySocketDescriptorFlags(t, el, 91, 77, -1)
}

func TestHandleAcceptExitAppliesPairFilter(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{
		filter: globalfilter.Filter{
			Syscall: &globalfilter.StringFilter{Pattern: "openat"},
		},
	})

	el.fdState().set(11, 91, file.NewFd(11, "socket:1:1:0", -1))

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

func verifySocketDescriptorFlags(t *testing.T, el *eventLoop, pid uint32, fd int32, want int32) {
	t.Helper()
	tracked, ok := el.fdState().get(fd, pid)
	if !ok {
		t.Fatalf("pid %d fd %d was not tracked", pid, fd)
	}
	if got := int32(tracked.Flags()); got != want {
		t.Fatalf("pid %d fd %d flags = %#x, want %#x", pid, fd, got, want)
	}
}
