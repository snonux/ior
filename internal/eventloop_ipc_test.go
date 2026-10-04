package internal

import (
	"syscall"
	"testing"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

type pipeExitTestCase struct {
	name       string
	enterTrace types.TraceId
	exitTrace  types.TraceId
	flags      int32
	wantName   string
	wantRead   string
	wantWrite  string
}

func TestHandlePipeExitTracksReturnedFds(t *testing.T) {
	tests := []pipeExitTestCase{
		{
			name:       "pipe",
			enterTrace: types.SYS_ENTER_PIPE,
			exitTrace:  types.SYS_EXIT_PIPE,
			wantName:   "pipe:0:52:53",
			wantRead:   "O_RDONLY",
			wantWrite:  "O_WRONLY",
		},
		{
			name:       "pipe2",
			enterTrace: types.SYS_ENTER_PIPE2,
			exitTrace:  types.SYS_EXIT_PIPE2,
			flags:      syscall.O_CLOEXEC | syscall.O_NONBLOCK,
			wantName:   "pipe:526336:52:53",
			wantRead:   "O_RDONLY|O_CLOEXEC|O_NONBLOCK",
			wantWrite:  "O_WRONLY|O_CLOEXEC|O_NONBLOCK",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testPipeExitTracking(t, tt)
		})
	}
}

func testPipeExitTracking(t *testing.T, tt pipeExitTestCase) {
	t.Helper()
	el := mustNewEventLoop(t, eventLoopConfig{})
	enter := &types.PipeEvent{
		EventType: types.ENTER_PIPE_EVENT,
		TraceId:   tt.enterTrace,
		Time:      100,
		Pid:       70,
		Tid:       71,
		Flags:     tt.flags,
		Fd0:       -1,
		Fd1:       -1,
	}
	exit := &types.PipeEvent{
		EventType: types.EXIT_PIPE_EVENT,
		TraceId:   tt.exitTrace,
		Time:      200,
		Pid:       70,
		Tid:       71,
		Flags:     tt.flags,
		Fd0:       52,
		Fd1:       53,
	}
	ep := &event.Pair{EnterEv: enter, ExitEv: exit}

	if ok := el.handlePipeExit(ep, enter); !ok {
		t.Fatal("handlePipeExit returned false")
	}
	verifyFileDescriptor(t, el, 70, 52, tt.wantName)
	verifyFileDescriptor(t, el, 70, 53, tt.wantName)
	verifyFileDescriptorFlags(t, el, 70, 52, tt.wantRead)
	verifyFileDescriptorFlags(t, el, 70, 53, tt.wantWrite)
}

func verifyFileDescriptorFlags(t *testing.T, el *eventLoop, pid uint32, fd int32, want string) {
	t.Helper()
	tracked, ok := el.fdState().files[fdKey(pid, fd)]
	if !ok {
		t.Fatalf("pid %d fd %d was not tracked", pid, fd)
	}
	if got := tracked.Flags().String(); got != want {
		t.Errorf("pid %d fd %d flags = %q, want %q", pid, fd, got, want)
	}
}

// TestHandlePipeExitFailureTracksNoFds locks in the pipe(2) failure path:
// when the syscall returns -1 the kernel writes nothing into the output buffer,
// so the BPF exit handler leaves fd0/fd1 at -1 and the runtime must not register
// any descriptor. Tracking a bogus fd here would attribute later reads/writes to
// a pipe that was never created.
func TestHandlePipeExitFailureTracksNoFds(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})

	enter := &types.PipeEvent{
		EventType: types.ENTER_PIPE_EVENT,
		TraceId:   types.SYS_ENTER_PIPE,
		Time:      100,
		Pid:       72,
		Tid:       73,
		Flags:     0,
		Fd0:       -1,
		Fd1:       -1,
		Ret:       0,
	}
	exit := &types.PipeEvent{
		EventType: types.EXIT_PIPE_EVENT,
		TraceId:   types.SYS_EXIT_PIPE,
		Time:      200,
		Pid:       72,
		Tid:       73,
		Flags:     0,
		Fd0:       -1,
		Fd1:       -1,
		Ret:       -1,
	}
	ep := &event.Pair{EnterEv: enter, ExitEv: exit}

	if ok := el.handlePipeExit(ep, enter); !ok {
		t.Fatal("handlePipeExit returned false")
	}
	verifyFdNotTracked(t, el, 72, -1)
	if ep.File != nil {
		t.Errorf("expected no file attached to failed pipe pair, got %q", ep.File.Name())
	}
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
	verifyFileDescriptor(t, el, 80, 61, "eventfd:2048")
}

func TestHandleEventfdExitTranslatesSyscallFlags(t *testing.T) {
	tests := []struct {
		name    string
		traceID types.TraceId
		raw     int32
		want    int32
	}{
		{name: "epoll_create", traceID: types.SYS_ENTER_EPOLL_CREATE, raw: 1, want: syscall.O_RDWR},
		{name: "epoll_create1", traceID: types.SYS_ENTER_EPOLL_CREATE1, raw: syscall.O_CLOEXEC, want: syscall.O_RDWR | syscall.O_CLOEXEC},
		{name: "inotify_init", traceID: types.SYS_ENTER_INOTIFY_INIT, raw: 2, want: syscall.O_RDONLY},
		{name: "inotify_init1", traceID: types.SYS_ENTER_INOTIFY_INIT1, raw: syscall.O_CLOEXEC | syscall.O_NONBLOCK, want: syscall.O_RDONLY | syscall.O_CLOEXEC | syscall.O_NONBLOCK},
		{name: "fanotify_init", traceID: types.SYS_ENTER_FANOTIFY_INIT, raw: 1 | 2, want: -1},
		{name: "landlock_create_ruleset", traceID: types.SYS_ENTER_LANDLOCK_CREATE_RULESET, raw: 0, want: -1},
		{name: "eventfd", traceID: types.SYS_ENTER_EVENTFD, raw: 1, want: syscall.O_RDWR},
		{name: "eventfd2", traceID: types.SYS_ENTER_EVENTFD2, raw: 1 | syscall.O_CLOEXEC | syscall.O_NONBLOCK, want: syscall.O_RDWR | syscall.O_CLOEXEC | syscall.O_NONBLOCK},
		{name: "memfd_create", traceID: types.SYS_ENTER_MEMFD_CREATE, raw: 1 | 2 | 4, want: syscall.O_RDWR | syscall.O_CLOEXEC},
		{name: "memfd_secret", traceID: types.SYS_ENTER_MEMFD_SECRET, raw: syscall.O_CLOEXEC, want: syscall.O_RDWR | syscall.O_CLOEXEC},
		{name: "userfaultfd", traceID: types.SYS_ENTER_USERFAULTFD, raw: 1 | syscall.O_CLOEXEC | syscall.O_NONBLOCK, want: syscall.O_RDWR | syscall.O_CLOEXEC | syscall.O_NONBLOCK},
		{name: "signalfd", traceID: types.SYS_ENTER_SIGNALFD, raw: 1, want: syscall.O_RDWR},
		{name: "signalfd4", traceID: types.SYS_ENTER_SIGNALFD4, raw: syscall.O_CLOEXEC | syscall.O_NONBLOCK, want: syscall.O_RDWR | syscall.O_CLOEXEC | syscall.O_NONBLOCK},
		{name: "timerfd_create", traceID: types.SYS_ENTER_TIMERFD_CREATE, raw: syscall.O_CLOEXEC | syscall.O_NONBLOCK, want: syscall.O_RDWR | syscall.O_CLOEXEC | syscall.O_NONBLOCK},
		{name: "pidfd_open", traceID: types.SYS_ENTER_PIDFD_OPEN, raw: syscall.O_NONBLOCK, want: syscall.O_RDWR | syscall.O_CLOEXEC | syscall.O_NONBLOCK},
		{name: "fsmount", traceID: types.SYS_ENTER_FSMOUNT, raw: 1, want: -1},
		{name: "fsopen", traceID: types.SYS_ENTER_FSOPEN, raw: 1, want: -1},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			el := mustNewEventLoop(t, eventLoopConfig{})
			fd := int32(100 + i)
			pid := uint32(200 + i)
			enter := &types.EventfdEvent{
				EventType: types.ENTER_EVENTFD_EVENT,
				TraceId:   tt.traceID,
				Pid:       pid,
				Tid:       pid,
				Flags:     tt.raw,
				Fd:        -1,
				Ret:       -1,
			}
			exit := &types.EventfdEvent{
				EventType: types.EXIT_EVENTFD_EVENT,
				Pid:       pid,
				Tid:       pid,
				Flags:     tt.raw,
				Fd:        -1,
				Ret:       int64(fd),
			}
			ep := &event.Pair{EnterEv: enter, ExitEv: exit}

			if ok := el.handleEventfdExit(ep, enter); !ok {
				t.Fatal("handleEventfdExit returned false")
			}
			tracked, ok := el.fdState().files[fdKey(pid, fd)]
			if !ok {
				t.Fatalf("pid %d fd %d was not tracked", pid, fd)
			}
			if got := int32(tracked.Flags()); got != tt.want {
				t.Fatalf("tracked flags = %#x, want %#x (raw %#x)", got, tt.want, tt.raw)
			}
		})
	}
}

func TestHandleSignalfdUpdateKeepsExistingDescriptorMetadata(t *testing.T) {
	tests := []struct {
		name  string
		enter types.TraceId
		exit  types.TraceId
		flags int32
	}{
		{name: "signalfd", enter: types.SYS_ENTER_SIGNALFD, exit: types.SYS_EXIT_SIGNALFD},
		{name: "signalfd4", enter: types.SYS_ENTER_SIGNALFD4, exit: types.SYS_EXIT_SIGNALFD4, flags: syscall.O_NONBLOCK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			el := mustNewEventLoop(t, eventLoopConfig{})
			const (
				pid = uint32(90)
				fd  = int32(62)
			)
			existing := file.NewFd(fd, "signalfd:existing", syscall.O_RDWR|syscall.O_CLOEXEC)
			el.fdState().set(fd, pid, existing)
			enter := &types.EventfdEvent{
				EventType: types.ENTER_EVENTFD_EVENT,
				TraceId:   tt.enter,
				Pid:       pid,
				Tid:       91,
				Flags:     tt.flags,
				Fd:        fd,
				Ret:       -1,
			}
			exit := &types.EventfdEvent{
				EventType: types.EXIT_EVENTFD_EVENT,
				TraceId:   tt.exit,
				Pid:       pid,
				Tid:       91,
				Flags:     tt.flags,
				Fd:        -1,
				Ret:       int64(fd),
			}
			ep := &event.Pair{EnterEv: enter, ExitEv: exit}

			if ok := el.handleEventfdExit(ep, enter); !ok {
				t.Fatal("handleEventfdExit returned false")
			}
			tracked := el.fdState().files[fdKey(pid, fd)]
			if tracked != existing {
				t.Fatal("signalfd update replaced the existing tracked descriptor")
			}
			if got := tracked.Flags().String(); got != "O_RDWR|O_CLOEXEC" {
				t.Fatalf("tracked flags = %q, want unchanged O_RDWR|O_CLOEXEC", got)
			}
		})
	}
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
		name          string
		traceID       types.TraceId
		flags         int32
		identity      string
		identityKnown bool
		want          string
	}{
		{name: "eventfd", traceID: types.SYS_ENTER_EVENTFD2, flags: 1, want: "eventfd:1"},
		{name: "epoll_create1", traceID: types.SYS_ENTER_EPOLL_CREATE1, flags: 11, want: "epollfd:11"},
		{name: "inotify_init1", traceID: types.SYS_ENTER_INOTIFY_INIT1, flags: 12, want: "inotifyfd:12"},
		{name: "fanotify_init", traceID: types.SYS_ENTER_FANOTIFY_INIT, flags: 13, want: "fanotifyfd:13"},
		{name: "landlock_create_ruleset", traceID: types.SYS_ENTER_LANDLOCK_CREATE_RULESET, flags: 14, want: "landlockfd:14"},
		{name: "fsopen", traceID: types.SYS_ENTER_FSOPEN, flags: 15, identity: "tmpfs", identityKnown: true, want: "fsopen:tmpfs"},
		{name: "memfd_create", traceID: types.SYS_ENTER_MEMFD_CREATE, flags: 2, identity: "ior-memfd", identityKnown: true, want: "memfd:ior-memfd"},
		{name: "empty fsopen name", traceID: types.SYS_ENTER_FSOPEN, flags: 15, identityKnown: true, want: "fsopen:"},
		{name: "empty memfd name", traceID: types.SYS_ENTER_MEMFD_CREATE, flags: 2, identityKnown: true, want: "memfd:"},
		{name: "legacy fsopen", traceID: types.SYS_ENTER_FSOPEN, flags: 15, want: "fsopenfd:15"},
		{name: "fsmount", traceID: types.SYS_ENTER_FSMOUNT, flags: 1, want: "fsmountfd:1"},
		{name: "legacy memfd_create", traceID: types.SYS_ENTER_MEMFD_CREATE, flags: 2, want: "memfd:2"},
		{name: "memfd_secret", traceID: types.SYS_ENTER_MEMFD_SECRET, flags: 3, want: "memfd-secret:3"},
		{name: "userfaultfd", traceID: types.SYS_ENTER_USERFAULTFD, flags: 4, want: "userfaultfd:4"},
		{name: "signalfd", traceID: types.SYS_ENTER_SIGNALFD4, flags: 5, want: "signalfd:5"},
		{name: "timerfd_create", traceID: types.SYS_ENTER_TIMERFD_CREATE, flags: 6, want: "timerfd:6"},
		{name: "pidfd_open", traceID: types.SYS_ENTER_PIDFD_OPEN, flags: 7, want: "pidfd:7"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := eventfdDescriptorName(tt.traceID, tt.flags, tt.identity, tt.identityKnown)
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
