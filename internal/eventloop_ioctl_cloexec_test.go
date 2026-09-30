package internal

import (
	"syscall"
	"testing"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

// These tests pin task xo2: ioctl(fd, FIOCLEX) and ioctl(fd, FIONCLEX) change
// close-on-exec exactly like fcntl F_SETFD, so the fd tracker must learn the
// new state or fdTracker.dropOnExec keeps (or drops) the entry wrongly.

const (
	ioctlCloexecFd       = int32(83)
	ioctlCloexecFilename = "/tmp/ioctl-cloexec.txt"
)

func TestIoctlCloseOnExecRequestsDecideExecSurvival(t *testing.T) {
	tests := []struct {
		name          string
		cmd           uint32
		originalFlags int32
		wantFlags     int32
		keptAfterExec bool
	}{
		{
			name:          "FIOCLEX then exec drops the fd",
			cmd:           ioctlFioclex,
			originalFlags: syscall.O_RDWR | syscall.O_APPEND,
			wantFlags:     syscall.O_RDWR | syscall.O_APPEND | syscall.O_CLOEXEC,
		},
		{
			name:          "FIONCLEX then exec keeps the fd",
			cmd:           ioctlFionclex,
			originalFlags: syscall.O_RDONLY | syscall.O_CLOEXEC,
			wantFlags:     syscall.O_RDONLY,
			keptAfterExec: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			el := newFilteredEventLoop(t, globalfilter.Filter{})
			el.fdState().set(ioctlCloexecFd, execCommPid,
				file.NewFd(ioctlCloexecFd, ioctlCloexecFilename, tc.originalFlags))

			ep := feedIoctlPair(t, el, ioctlCloexecFd, tc.cmd, 0, 0)
			if ep == nil {
				t.Fatal("an unfiltered successful ioctl must be emitted")
			}
			assertPairFdFlags(t, ep, ioctlCloexecFd, tc.wantFlags)
			ep.Recycle()
			assertTrackedFdFlags(t, el, ioctlCloexecFd, tc.wantFlags)

			execPid(t, el)
			if tc.keptAfterExec {
				verifyFileDescriptor(t, el, execCommPid, ioctlCloexecFd, ioctlCloexecFilename)
			} else {
				verifyFdNotTracked(t, el, execCommPid, ioctlCloexecFd)
			}
		})
	}
}

// TestFailedIoctlCloseOnExecRequestChangesNothing: a failed FIOCLEX/FIONCLEX
// (and a positive return neither request can produce) must leave the tracked
// state, and therefore exec survival, exactly as it was.
func TestFailedIoctlCloseOnExecRequestChangesNothing(t *testing.T) {
	tests := []struct {
		name          string
		cmd           uint32
		ret           int64
		originalFlags int32
		keptAfterExec bool
	}{
		{"FIOCLEX EBADF", ioctlFioclex, -int64(syscall.EBADF), syscall.O_RDWR, true},
		{"FIONCLEX EBADF", ioctlFionclex, -int64(syscall.EBADF), syscall.O_RDWR | syscall.O_CLOEXEC, false},
		{"FIOCLEX positive return", ioctlFioclex, 1, syscall.O_RDWR, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			el := newFilteredEventLoop(t, globalfilter.Filter{})
			el.fdState().set(ioctlCloexecFd, execCommPid,
				file.NewFd(ioctlCloexecFd, ioctlCloexecFilename, tc.originalFlags))

			ep := feedIoctlPair(t, el, ioctlCloexecFd, tc.cmd, 0, tc.ret)
			if ep == nil {
				t.Fatal("an unfiltered failed ioctl must remain observable")
			}
			ep.Recycle()
			assertTrackedFdFlags(t, el, ioctlCloexecFd, tc.originalFlags)

			execPid(t, el)
			if tc.keptAfterExec {
				verifyFileDescriptor(t, el, execCommPid, ioctlCloexecFd, ioctlCloexecFilename)
			} else {
				verifyFdNotTracked(t, el, execCommPid, ioctlCloexecFd)
			}
		})
	}
}

// TestUnrelatedIoctlIsNotReadAsFcntl guards the trace-ID routing: ioctl pairs
// share the fcntl_event layout, but a request number that happens to equal an
// fcntl command must not be applied as that command.
func TestUnrelatedIoctlIsNotReadAsFcntl(t *testing.T) {
	const dupTarget = int32(84)
	tests := []struct {
		name string
		cmd  uint32
		arg  uint64
		ret  int64
	}{
		{"request equal to F_SETFD", syscall.F_SETFD, syscall.FD_CLOEXEC, 0},
		{"request equal to F_DUPFD", syscall.F_DUPFD, 0, int64(dupTarget)},
		{"request equal to F_SETFL", syscall.F_SETFL, syscall.O_NONBLOCK, 0},
		{"TCGETS", syscall.TCGETS, 0, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			const originalFlags = syscall.O_RDWR
			el := newFilteredEventLoop(t, globalfilter.Filter{})
			el.fdState().set(ioctlCloexecFd, execCommPid,
				file.NewFd(ioctlCloexecFd, ioctlCloexecFilename, originalFlags))

			ep := feedIoctlPair(t, el, ioctlCloexecFd, tc.cmd, tc.arg, tc.ret)
			if ep == nil {
				t.Fatal("an unfiltered ioctl must be emitted")
			}
			defer ep.Recycle()
			if got := ep.File.Name(); got != ioctlCloexecFilename {
				t.Fatalf("ioctl row reports %q, want %q", got, ioctlCloexecFilename)
			}
			assertTrackedFdFlags(t, el, ioctlCloexecFd, originalFlags)
			verifyFdNotTracked(t, el, execCommPid, dupTarget)
		})
	}
}

// TestIoctlCloseOnExecOnUnknownFdPromotesIt: like F_SETFD, a successful
// FIOCLEX on a descriptor the tracker never saw opened promotes the
// procfs-resolved entry with known close-on-exec, so the exec drops it.
func TestIoctlCloseOnExecOnUnknownFdPromotesIt(t *testing.T) {
	el := newFilteredEventLoop(t, globalfilter.Filter{})
	ep := feedIoctlPair(t, el, ioctlCloexecFd, ioctlFioclex, 0, 0)
	if ep == nil {
		t.Fatal("an unfiltered successful ioctl must be emitted")
	}
	ep.Recycle()

	entry, ok := el.fdState().get(ioctlCloexecFd, execCommPid)
	if !ok {
		t.Fatal("FIOCLEX on an unknown fd did not promote it into the fd table")
	}
	tracked, ok := entry.(*file.FdFile)
	if !ok {
		t.Fatalf("promoted entry is %T, want *file.FdFile", entry)
	}
	if set, known := tracked.CloseOnExec(); !set || !known {
		t.Fatalf("CloseOnExec() = (%v, %v), want (true, true)", set, known)
	}
	execPid(t, el)
	verifyFdNotTracked(t, el, execCommPid, ioctlCloexecFd)
}

// TestDroppedIoctlRowStillUpdatesCloseOnExec: the fd-state effect runs before
// the pair filter, so a row a -latency filter drops still records FIOCLEX.
func TestDroppedIoctlRowStillUpdatesCloseOnExec(t *testing.T) {
	el := newFilteredEventLoop(t, dropsEveryPairOfLatency())
	el.fdState().set(ioctlCloexecFd, execCommPid,
		file.NewFd(ioctlCloexecFd, ioctlCloexecFilename, syscall.O_RDWR))

	if ep := feedIoctlPair(t, el, ioctlCloexecFd, ioctlFioclex, 0, 0); ep != nil {
		defer ep.Recycle()
		t.Fatalf("ioctl row survived a -latency filter it cannot satisfy: %v", ep)
	}
	assertTrackedFdFlags(t, el, ioctlCloexecFd, syscall.O_RDWR|syscall.O_CLOEXEC)
}

// feedIoctlPair feeds one ioctl enter/exit pair in the fcntl_event layout the
// generated BPF handler emits for sys_enter_ioctl.
func feedIoctlPair(t *testing.T, el *eventLoop, fd int32, cmd uint32, arg uint64, ret int64) *event.Pair {
	t.Helper()
	enter := types.FcntlEvent{
		EventType: types.ENTER_FCNTL_EVENT,
		TraceId:   types.SYS_ENTER_IOCTL,
		Time:      dupPairStart,
		Pid:       execCommPid,
		Tid:       execCommTid,
		Fd:        uint32(fd),
		Cmd:       cmd,
		Arg:       arg,
	}
	enterRaw, err := enter.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	_, exitRaw := makeExitRetEvent(t, dupPairStart+openPairLatency, execCommPid, execCommTid,
		types.SYS_EXIT_IOCTL, ret)
	return feedRawPair(t, el, enterRaw, exitRaw)
}

// execPid delivers a sched_process_exec record for execCommPid, which runs the
// exec-time close-on-exec eviction.
func execPid(t *testing.T, el *eventLoop) {
	t.Helper()
	el.processRawEvent(makeProcessExecEvent(t, writePairStart, execCommPid, execCommTid, "newprog"),
		make(chan *event.Pair, 1))
}
