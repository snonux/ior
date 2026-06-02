package integrationtests

import (
	"strings"
	"testing"
)

const mqPayloadLen = uint64(14)

var ipcDescriptorTraceArgs = []string{"-trace-syscalls", "pipe,pipe2,eventfd,eventfd2,close"}

var inotifyTraceArgs = []string{"-trace-syscalls", "inotify_init1,inotify_add_watch,inotify_rm_watch,close"}

func TestPipeBasic(t *testing.T) {
	result, _ := runScenarioResultWithIorArgs(t, "pipe-basic", []ExpectedEvent{
		{Tracepoint: "enter_pipe", MinCount: 1},
		{Tracepoint: "enter_close", MinCount: 2},
	}, ipcDescriptorTraceArgs)

	assertTracepointPathPrefix(t, result, "enter_pipe", "pipe:")
	if got := totalTracepointPathCount(result, "enter_close", "pipe:"); got < 2 {
		t.Fatalf("enter_close records with tracked pipe descriptor prefix = %d, want >= 2", got)
	}
}

func TestPipe2Basic(t *testing.T) {
	result, _ := runScenarioResultWithIorArgs(t, "pipe2-basic", []ExpectedEvent{
		{Tracepoint: "enter_pipe2", MinCount: 1},
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
		{Tracepoint: "enter_eventfd2", MinCount: 1},
		{Tracepoint: "enter_close", MinCount: 1},
	}, ipcDescriptorTraceArgs)

	assertTracepointPathPrefix(t, result, "enter_eventfd2", "eventfd:")
	assertTracepointPathPrefix(t, result, "enter_close", "eventfd:")
}

func TestFdFromAirEventfdUsers(t *testing.T) {
	enableParallelIfRequested(t)
	h := newTestHarness(t)
	result, pid, err := h.RunWithIorArgs("fd-from-air-eventfd-users", defaultDuration, []string{
		"-trace-families", "IPC",
	})
	if err != nil {
		t.Fatalf("run scenario fd-from-air-eventfd-users: %v", err)
	}
	AssertNoUnexpectedPID(t, result, pid)
	AssertNoUnexpectedComm(t, result, "ioworkload")
	AssertEventsPresent(t, result, []ExpectedEvent{
		{Tracepoint: "enter_memfd_create", MinCount: 1},
		{Tracepoint: "enter_memfd_secret", MinCount: 1},
		{Tracepoint: "enter_userfaultfd", MinCount: 1},
		{Tracepoint: "enter_signalfd", MinCount: 1},
		{Tracepoint: "enter_signalfd4", MinCount: 1},
		{Tracepoint: "enter_timerfd_create", MinCount: 1},
	})

	assertTracepointPathPrefix(t, result, "enter_memfd_create", "memfd:")
	assertTracepointPathPrefix(t, result, "enter_timerfd_create", "timerfd:")
}

// TestInotifyBasic asserts end-to-end tracing of the inotify IPC family.
// The inotify-basic scenario issues inotify_init1(IN_CLOEXEC) ->
// inotify_add_watch(fd, file, IN_CREATE|IN_DELETE|IN_MODIFY) ->
// inotify_rm_watch(fd, wd) -> close(fd). We assert all three inotify enter
// tracepoints fire at least once, with positive durations and the hermetic
// PID/comm guards already applied by runScenarioResultWithIorArgs. The
// inotify_init1 instance fd resolves to the "inotifyfd:" path label, and the
// close on that same fd carries the same label.
func TestInotifyBasic(t *testing.T) {
	result, _ := runScenarioResultWithIorArgs(t, "inotify-basic", []ExpectedEvent{
		{Tracepoint: "enter_inotify_init1", MinCount: 1},
		{Tracepoint: "enter_inotify_add_watch", MinCount: 1},
		{Tracepoint: "enter_inotify_rm_watch", MinCount: 1},
		{Tracepoint: "enter_close", MinCount: 1},
	}, inotifyTraceArgs)

	// inotify_init1 returns a registered fd labelled inotifyfd:, and the
	// subsequent close of that fd resolves to the same tracked label.
	assertTracepointPathPrefix(t, result, "enter_inotify_init1", "inotifyfd:")
	assertTracepointPathPrefix(t, result, "enter_close", "inotifyfd:")

	// inotify_add_watch / inotify_rm_watch capture the inotify instance fd
	// (kind=fd@arg0), so they too resolve to the tracked inotifyfd: label.
	assertTracepointPathPrefix(t, result, "enter_inotify_add_watch", "inotifyfd:")
	assertTracepointPathPrefix(t, result, "enter_inotify_rm_watch", "inotifyfd:")

	assertEventDurationPositive(t, result, ExpectedEvent{Tracepoint: "enter_inotify_init1", Comm: "ioworkload"})
	assertEventDurationPositive(t, result, ExpectedEvent{Tracepoint: "enter_inotify_add_watch", Comm: "ioworkload"})
	assertEventDurationPositive(t, result, ExpectedEvent{Tracepoint: "enter_inotify_rm_watch", Comm: "ioworkload"})
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
