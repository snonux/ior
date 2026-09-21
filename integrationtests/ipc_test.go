package integrationtests

import (
	"strings"
	"syscall"
	"testing"
)

const mqPayloadLen = uint64(14)

var ipcDescriptorTraceArgs = []string{"-trace-syscalls", "pipe,pipe2,eventfd,eventfd2,write,close"}

var inotifyTraceArgs = []string{"-trace-syscalls", "inotify_init1,inotify_add_watch,inotify_rm_watch,close"}

func TestPipeBasic(t *testing.T) {
	result, _ := runScenarioResultWithIorArgs(t, "pipe-basic", []ExpectedEvent{
		{
			Tracepoint: "enter_pipe",
			MinCount:   1,
			Flags:      &ExpectedFlags{AccessMode: ptrTo(syscall.O_RDONLY)},
		},
		{
			PathContains: "pipe:",
			Tracepoint:   "enter_write",
			MinCount:     1,
			Flags:        &ExpectedFlags{AccessMode: ptrTo(syscall.O_WRONLY)},
		},
		{Tracepoint: "enter_close", MinCount: 2},
	}, ipcDescriptorTraceArgs)

	assertTracepointPathPrefix(t, result, "enter_pipe", "pipe:")
	if got := totalTracepointPathCount(result, "enter_close", "pipe:"); got < 2 {
		t.Fatalf("enter_close records with tracked pipe descriptor prefix = %d, want >= 2", got)
	}
}

func TestPipe2Basic(t *testing.T) {
	result, _ := runScenarioResultWithIorArgs(t, "pipe2-basic", []ExpectedEvent{
		{
			Tracepoint: "enter_pipe2",
			MinCount:   1,
			Flags: &ExpectedFlags{
				AccessMode: ptrTo(syscall.O_RDONLY),
				Set:        syscall.O_CLOEXEC | syscall.O_NONBLOCK,
			},
		},
		{
			PathContains: "pipe:",
			Tracepoint:   "enter_write",
			MinCount:     1,
			Flags: &ExpectedFlags{
				AccessMode: ptrTo(syscall.O_WRONLY),
				Set:        syscall.O_CLOEXEC | syscall.O_NONBLOCK,
			},
		},
		{Tracepoint: "enter_close", MinCount: 2},
	}, ipcDescriptorTraceArgs)

	assertTracepointPathPrefix(t, result, "enter_pipe2", "pipe:")
	if got := totalTracepointPathCount(result, "enter_close", "pipe:"); got < 2 {
		t.Fatalf("enter_close records with tracked pipe2 descriptor prefix = %d, want >= 2", got)
	}
}

func TestEventfdBasic(t *testing.T) {
	result, _ := runScenarioResultWithIorArgs(t, "eventfd-basic", []ExpectedEvent{
		{Tracepoint: "enter_eventfd", MinCount: 1},
		{Tracepoint: "enter_close", MinCount: 1},
	}, ipcDescriptorTraceArgs)

	assertTracepointPathPrefix(t, result, "enter_eventfd", "eventfd:")
	assertTracepointPathPrefix(t, result, "enter_close", "eventfd:")
}

func TestEventfd2Basic(t *testing.T) {
	result, _ := runScenarioResultWithIorArgs(t, "eventfd2-basic", []ExpectedEvent{
		{
			Tracepoint: "enter_eventfd2",
			MinCount:   1,
			Flags: &ExpectedFlags{
				AccessMode: ptrTo(syscall.O_RDWR),
				Set:        syscall.O_CLOEXEC | syscall.O_NONBLOCK,
			},
		},
		{Tracepoint: "enter_close", MinCount: 1},
	}, ipcDescriptorTraceArgs)

	assertTracepointPathPrefix(t, result, "enter_eventfd2", "eventfd:")
	assertTracepointPathPrefix(t, result, "enter_close", "eventfd:")
}

func TestFdFromAirEventfdUsers(t *testing.T) {
	enableParallelIfRequested(t)
	h := newTestHarness(t)
	result, pid, err := h.RunWithIorArgs("fd-from-air-eventfd-users", defaultDuration, []string{
		"-trace-families", "IPC", "-trace-syscalls", "close",
	})
	if err != nil {
		t.Fatalf("run scenario fd-from-air-eventfd-users: %v", err)
	}
	AssertNoUnexpectedPID(t, result, pid)
	AssertNoUnexpectedComm(t, result, "ioworkload")
	AssertEventsPresent(t, result, []ExpectedEvent{
		{
			Tracepoint: "enter_memfd_create",
			MinCount:   1,
			Flags: &ExpectedFlags{
				AccessMode: ptrTo(syscall.O_RDWR),
				Set:        syscall.O_CLOEXEC,
			},
		},
		{Tracepoint: "enter_memfd_secret", MinCount: 1},
		{Tracepoint: "enter_userfaultfd", MinCount: 1},
		{Tracepoint: "enter_signalfd", MinCount: 1},
		{Tracepoint: "enter_signalfd4", MinCount: 1},
		{Tracepoint: "enter_timerfd_create", MinCount: 1},
		// The timerfd is armed and read back while still open, so
		// timerfd_settime/gettime fire against the existing descriptor.
		{Tracepoint: "enter_timerfd_settime", MinCount: 1},
		{Tracepoint: "enter_timerfd_gettime", MinCount: 1},
		{
			Tracepoint:   "enter_signalfd4",
			PathContains: "signalfd:",
			MinCount:     2,
			Flags: &ExpectedFlags{
				AccessMode: ptrTo(syscall.O_RDWR),
				Set:        syscall.O_CLOEXEC,
				Clear:      syscall.O_NONBLOCK,
			},
		},
		{
			Tracepoint:   "enter_close",
			PathContains: "signalfd:",
			MinCount:     1,
			Flags: &ExpectedFlags{
				AccessMode: ptrTo(syscall.O_RDWR),
				Set:        syscall.O_CLOEXEC,
				Clear:      syscall.O_NONBLOCK,
			},
		},
	})

	assertTracepointExactPath(t, result, "enter_memfd_create", "memfd:ior-memfd")
	assertTracepointPathPrefix(t, result, "enter_timerfd_create", "timerfd:")

	// timerfd_settime/gettime take the timerfd as arg0 (kind=fd@arg0). The
	// "timerfd:" path prefix proves the enter handlers captured that fd via
	// fd_event rather than emitting a null event, locking in the 6ac9fa4 fix.
	assertTracepointPathPrefix(t, result, "enter_timerfd_settime", "timerfd:")
	assertTracepointPathPrefix(t, result, "enter_timerfd_gettime", "timerfd:")
}

func assertTracepointExactPath(t *testing.T, result TestResult, tracepoint, wantPath string) {
	t.Helper()
	for _, rec := range result.Records {
		if strings.Contains(rec.TraceID.String(), tracepoint) && rec.Path == wantPath {
			return
		}
	}
	t.Fatalf("expected at least one %s record with exact path %q", tracepoint, wantPath)
}

func TestFanotifyFlags(t *testing.T) {
	result, _ := runScenarioResultWithIorArgs(t, "fanotify-flags", []ExpectedEvent{
		{Tracepoint: "enter_fanotify_init", MinCount: 1},
	}, []string{"-trace-syscalls", "fanotify_init,close"})

	// This isolated workload closes a descriptor only when fanotify_init
	// succeeds. Use that syscall outcome, not the label under test, to decide
	// whether an unprivileged EPERM skip is expected.
	if totalTracepointPathCount(result, "enter_close", "") == 0 {
		return
	}
	// fanotify_init's event_f_flags argument is not captured, so its access
	// mode is deliberately unknown; assert identity without inventing flags.
	AssertEventsPresent(t, result, []ExpectedEvent{
		{
			Tracepoint:   "enter_fanotify_init",
			PathContains: "fanotifyfd:",
			MinCount:     1,
		},
		{
			Tracepoint:   "enter_close",
			PathContains: "fanotifyfd:",
			MinCount:     1,
		},
	})
}

// TestInotifyBasic pins the watched path and notification group fd in the same
// row, including errors. Later group operations must retain their group label.
func TestInotifyBasic(t *testing.T) {
	rows, _ := runParquetScenarioRows(t, "inotify-basic", defaultDuration, inotifyTraceArgs, nil)
	groupFD := notificationGroupFD(t, rows, "inotify_init1")
	AssertRowsPresent(t, rows, []ExpectedRow{
		{Syscall: "inotify_add_watch", FileContains: "/watched", FD: &groupFD, RetValAtLeast: ptrTo(int64(1)), IsError: ptrTo(false), Bytes: ptrTo(uint64(0))},
		{Syscall: "inotify_add_watch", FileContains: "/missing", FD: &groupFD, RetVal: ptrTo(-int64(syscall.ENOENT)), IsError: ptrTo(true)},
		{Syscall: "inotify_rm_watch", FileContains: "inotifyfd:", FD: &groupFD, RetVal: ptrTo(int64(0)), IsError: ptrTo(false)},
		{Syscall: "close", FileContains: "inotifyfd:", FD: &groupFD, RetVal: ptrTo(int64(0)), IsError: ptrTo(false)},
	})
}

func TestPosixMqBasic(t *testing.T) {
	enableParallelIfRequested(t)
	h := newTestHarness(t)
	result, pid, err := h.Run("mq-posix-basic", defaultDuration)
	if err != nil {
		errText := err.Error()
		if strings.Contains(errText, "mq_open: permission denied") ||
			strings.Contains(errText, "mq_open: operation not permitted") ||
			strings.Contains(errText, "mq_open: function not implemented") {
			t.Skipf("mq syscalls unavailable in this environment: %v", err)
		}
		t.Fatalf("run scenario mq-posix-basic: %v", err)
	}

	AssertNoUnexpectedPID(t, result, pid)
	AssertNoUnexpectedComm(t, result, "ioworkload")
	AssertEventsPresent(t, result, []ExpectedEvent{
		{Tracepoint: "enter_mq_open", MinCount: 1},
		{Tracepoint: "enter_mq_unlink", MinCount: 1},
		{Tracepoint: "enter_mq_timedsend", MinCount: 1},
		{Tracepoint: "enter_mq_timedreceive", MinCount: 1},
		{Tracepoint: "enter_mq_notify", MinCount: 1},
		{Tracepoint: "enter_mq_getsetattr", MinCount: 1},
		{Tracepoint: "enter_close", MinCount: 1},
	})

	assertTracepointPathPrefix(t, result, "enter_mq_open", "/ior-mq-")
	assertTracepointPathPrefix(t, result, "enter_mq_unlink", "/ior-mq-")
	assertTracepointPathPrefix(t, result, "enter_mq_timedsend", "/ior-mq-")
	assertTracepointPathPrefix(t, result, "enter_mq_timedreceive", "/ior-mq-")
	assertTracepointPathPrefix(t, result, "enter_mq_notify", "/ior-mq-")
	assertTracepointPathPrefix(t, result, "enter_mq_getsetattr", "/ior-mq-")
	assertTracepointPathPrefix(t, result, "enter_close", "/ior-mq-")

	sendExp := ExpectedEvent{Tracepoint: "enter_mq_timedsend", Comm: "ioworkload", PathContains: "/ior-mq-"}
	recvExp := ExpectedEvent{Tracepoint: "enter_mq_timedreceive", Comm: "ioworkload", PathContains: "/ior-mq-"}
	// mq_timedsend returns 0 on success (a status, not a byte count), so it is
	// UNCLASSIFIED and must NOT be attributed any write bytes. Only
	// mq_timedreceive returns a real received byte count (ReadClassified).
	assertEventBytesEqual(t, result, sendExp, 0)
	assertEventBytesAtLeast(t, result, recvExp, mqPayloadLen)
	assertEventDurationPositive(t, result, sendExp)
	assertEventDurationPositive(t, result, recvExp)
}
