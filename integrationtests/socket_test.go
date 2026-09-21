package integrationtests

import (
	"strings"
	"syscall"
	"testing"
)

var socketTraceArgs = []string{
	"-trace-syscalls",
	"socket,socketpair,bind,listen,accept4,accept,connect,shutdown,getsockname,getpeername,setsockopt,getsockopt,close",
}

func TestSocketBasic(t *testing.T) {
	result, _ := runScenarioResultWithIorArgs(t, "socket-basic", []ExpectedEvent{
		{
			Tracepoint: "enter_socket",
			MinCount:   1,
			Flags:      &ExpectedFlags{AccessMode: ptrTo(syscall.O_RDWR)},
		},
		{
			Tracepoint: "enter_close",
			MinCount:   1,
		},
	}, socketTraceArgs)

	assertTracepointPathPrefix(t, result, "enter_socket", "socket:1:")
	assertTracepointPathPrefix(t, result, "enter_close", "socket:1:")
}

func TestSocketpairBasic(t *testing.T) {
	rows, _ := runParquetScenarioRows(t, "socketpair-basic", defaultDuration, socketTraceArgs, nil)
	AssertRowsPresent(t, rows, []ExpectedRow{
		{
			FileContains: "socket:1:",
			Syscall:      "socketpair",
			Comm:         "ioworkload",
			FDAtLeast:    ptrTo(int32(1)),
			RetVal:       ptrTo(int64(0)),
			IsError:      ptrTo(false),
		},
		{
			FileContains: "socket:1:",
			Syscall:      "close",
			Comm:         "ioworkload",
			MinCount:     2,
			FDAtLeast:    ptrTo(int32(1)),
			RetVal:       ptrTo(int64(0)),
			IsError:      ptrTo(false),
		},
	})
}

func TestSocketAcceptLifecycle(t *testing.T) {
	result, _ := runScenarioResultWithIorArgs(t, "socket-accept-lifecycle", []ExpectedEvent{
		{Tracepoint: "enter_bind", MinCount: 1},
		{Tracepoint: "enter_connect", MinCount: 1},
		{Tracepoint: "enter_listen", MinCount: 1},
		{
			Tracepoint: "enter_accept4",
			MinCount:   1,
			Flags: &ExpectedFlags{
				AccessMode: ptrTo(syscall.O_RDWR),
				Set:        syscall.O_NONBLOCK | syscall.O_CLOEXEC,
			},
		},
		{Tracepoint: "enter_shutdown", MinCount: 1},
	}, socketTraceArgs)

	assertTracepointPathPrefix(t, result, "enter_bind", "socket:1:")
	assertTracepointPathPrefix(t, result, "enter_connect", "socket:1:")
	assertTracepointPathPrefix(t, result, "enter_listen", "socket:1:")
	assertTracepointPathPrefix(t, result, "enter_accept4", "socket:1:1:0")
	assertTracepointPathPrefix(t, result, "enter_shutdown", "socket:1:")
}

func TestSocketAcceptLifecyclePlain(t *testing.T) {
	result, _ := runScenarioResultWithIorArgs(t, "socket-accept-lifecycle-plain", []ExpectedEvent{
		{Tracepoint: "enter_bind", MinCount: 1},
		{Tracepoint: "enter_connect", MinCount: 1},
		{Tracepoint: "enter_listen", MinCount: 1},
		{
			Tracepoint: "enter_accept",
			MinCount:   1,
			Flags: &ExpectedFlags{
				AccessMode: ptrTo(syscall.O_RDWR),
				Clear:      syscall.O_NONBLOCK | syscall.O_CLOEXEC,
			},
		},
		{Tracepoint: "enter_shutdown", MinCount: 1},
	}, socketTraceArgs)

	assertTracepointPathPrefix(t, result, "enter_bind", "socket:1:")
	assertTracepointPathPrefix(t, result, "enter_connect", "socket:1:")
	assertTracepointPathPrefix(t, result, "enter_listen", "socket:1:")
	assertTracepointPathPrefix(t, result, "enter_accept", "socket:1:1:0")
	assertTracepointPathPrefix(t, result, "enter_shutdown", "socket:1:")

	AssertEventsAbsent(t, result, []ExpectedEvent{
		{Tracepoint: "enter_accept4"},
	})
}

func TestSocketIntrospection(t *testing.T) {
	result, _ := runScenarioResultWithIorArgs(t, "socket-introspection", []ExpectedEvent{
		{Tracepoint: "enter_getsockname", MinCount: 1},
		{Tracepoint: "enter_getpeername", MinCount: 1},
		{Tracepoint: "enter_setsockopt", MinCount: 1},
		{Tracepoint: "enter_getsockopt", MinCount: 1},
	}, socketTraceArgs)

	assertTracepointPathPrefix(t, result, "enter_getsockname", "socket:1:")
	assertTracepointPathPrefix(t, result, "enter_getpeername", "socket:1:")
	assertTracepointPathPrefix(t, result, "enter_setsockopt", "socket:1:")
	assertTracepointPathPrefix(t, result, "enter_getsockopt", "socket:1:")
}

func assertTracepointPathPrefix(t *testing.T, result TestResult, tracepoint, wantPrefix string) {
	t.Helper()
	if got := countTracepointPathPrefix(result, tracepoint, wantPrefix); got == 0 {
		t.Fatalf("expected at least one %s record with path prefix %q", tracepoint, wantPrefix)
	}
}

func countTracepointPathPrefix(result TestResult, tracepoint, wantPrefix string) int {
	var count int
	for _, rec := range result.Records {
		if !strings.Contains(rec.TraceID.String(), tracepoint) {
			continue
		}
		if strings.HasPrefix(rec.Path, wantPrefix) {
			count++
		}
	}
	return count
}

func totalTracepointPathCount(result TestResult, tracepoint, wantPrefix string) uint64 {
	var total uint64
	for _, rec := range result.Records {
		if !strings.Contains(rec.TraceID.String(), tracepoint) {
			continue
		}
		if strings.HasPrefix(rec.Path, wantPrefix) {
			total += rec.Cnt.Count
		}
	}
	return total
}
