package integrationtests

import (
	"strings"
	"testing"
)

const mqPayloadLen = uint64(14)

func TestPipeBasic(t *testing.T) {
	result, _ := runScenarioResult(t, "pipe-basic", []ExpectedEvent{
		{Tracepoint: "enter_pipe", MinCount: 1},
		{Tracepoint: "enter_close", MinCount: 2},
	})

	assertTracepointPathPrefix(t, result, "enter_pipe", "pipe:")
	if got := totalTracepointPathCount(result, "enter_close", "pipe:"); got < 2 {
		t.Fatalf("enter_close records with tracked pipe descriptor prefix = %d, want >= 2", got)
	}
}

func TestPipe2Basic(t *testing.T) {
	result, _ := runScenarioResult(t, "pipe2-basic", []ExpectedEvent{
		{Tracepoint: "enter_pipe2", MinCount: 1},
		{Tracepoint: "enter_close", MinCount: 2},
	})

	assertTracepointPathPrefix(t, result, "enter_pipe2", "pipe:")
	if got := totalTracepointPathCount(result, "enter_close", "pipe:"); got < 2 {
		t.Fatalf("enter_close records with tracked pipe2 descriptor prefix = %d, want >= 2", got)
	}
}

func TestEventfdBasic(t *testing.T) {
	result, _ := runScenarioResult(t, "eventfd-basic", []ExpectedEvent{
		{Tracepoint: "enter_eventfd", MinCount: 1},
		{Tracepoint: "enter_close", MinCount: 1},
	})

	assertTracepointPathPrefix(t, result, "enter_eventfd", "eventfd:")
	assertTracepointPathPrefix(t, result, "enter_close", "eventfd:")
}

func TestEventfd2Basic(t *testing.T) {
	result, _ := runScenarioResult(t, "eventfd2-basic", []ExpectedEvent{
		{Tracepoint: "enter_eventfd2", MinCount: 1},
		{Tracepoint: "enter_close", MinCount: 1},
	})

	assertTracepointPathPrefix(t, result, "enter_eventfd2", "eventfd:")
	assertTracepointPathPrefix(t, result, "enter_close", "eventfd:")
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
	assertEventBytesAtLeast(t, result, sendExp, mqPayloadLen)
	assertEventBytesAtLeast(t, result, recvExp, mqPayloadLen)
	assertEventDurationPositive(t, result, sendExp)
	assertEventDurationPositive(t, result, recvExp)
}
