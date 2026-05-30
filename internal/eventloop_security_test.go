package internal

import (
	"testing"

	"ior/internal/event"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

func TestHandlePerfOpenExitTracksReturnedFd(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})

	enter := &types.PerfOpenEvent{
		EventType: types.ENTER_PERF_OPEN_EVENT,
		TraceId:   types.SYS_ENTER_PERF_EVENT_OPEN,
		Time:      100,
		Pid:       200,
		Tid:       201,
		AttrType:  1,
		AttrSize:  64,
		Config:    2,
		TargetPid: 0,
		Cpu:       -1,
		GroupFd:   -1,
		Flags:     0,
	}
	exit := &types.RetEvent{
		EventType: types.EXIT_RET_EVENT,
		TraceId:   types.SYS_EXIT_PERF_EVENT_OPEN,
		Time:      200,
		Ret:       77,
		Pid:       200,
		Tid:       201,
	}
	ep := &event.Pair{EnterEv: enter, ExitEv: exit}

	if ok := el.handlePerfOpenExit(ep, enter); !ok {
		t.Fatal("handlePerfOpenExit returned false")
	}
	if ep.File == nil || ep.File.FD() != 77 {
		t.Fatalf("expected resolved perf fd 77, got file=%v", ep.File)
	}
}

// TestHandlePerfOpenExitFailedReturnNoFd locks in the audit finding that
// perf_event_open(2) returns a new fd on success or -1 on error. A negative
// return (e.g. EPERM, which is common for perf_event_open under a restrictive
// perf_event_paranoid setting) must not be recorded as an fd, since it is not
// a real descriptor. The return is an fd number, never a byte count.
func TestHandlePerfOpenExitFailedReturnNoFd(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})

	enter := &types.PerfOpenEvent{
		EventType: types.ENTER_PERF_OPEN_EVENT,
		TraceId:   types.SYS_ENTER_PERF_EVENT_OPEN,
		Time:      100,
		Pid:       300,
		Tid:       301,
		AttrType:  1,
		AttrSize:  64,
		Config:    2,
		TargetPid: -1,
		Cpu:       0,
		GroupFd:   -1,
		Flags:     0,
	}
	exit := &types.RetEvent{
		EventType: types.EXIT_RET_EVENT,
		TraceId:   types.SYS_EXIT_PERF_EVENT_OPEN,
		Time:      200,
		Ret:       -1, // -EPERM mapped to -1 return
		Pid:       300,
		Tid:       301,
	}
	ep := &event.Pair{EnterEv: enter, ExitEv: exit}

	if ok := el.handlePerfOpenExit(ep, enter); !ok {
		t.Fatal("handlePerfOpenExit returned false")
	}
	if ep.File != nil {
		t.Fatalf("expected no fd recorded for failed perf_event_open, got file=%v", ep.File)
	}
	if _, ok := el.fdState().get(-1); ok {
		t.Fatal("failed perf_event_open must not register an fd in fdState")
	}
}

// TestPerfDescriptorNameFormat pins the descriptor format produced for a
// successful perf_event_open. The audit confirmed args[0] (attr pointer) is
// captured as the attr struct's type/config, not as an fd, and args[1] is the
// monitored pid. The descriptor encodes attr_type, config, target pid, cpu,
// and group_fd under the "perf:" prefix (matched by the integration test).
func TestPerfDescriptorNameFormat(t *testing.T) {
	ev := &types.PerfOpenEvent{
		AttrType:  4,
		Config:    7,
		TargetPid: 0,
		Cpu:       -1,
		GroupFd:   -1,
	}
	got := perfDescriptorName(ev)
	const want = "perf:4:7:0:-1:-1"
	if got != want {
		t.Fatalf("perfDescriptorName = %q, want %q", got, want)
	}
}

func TestHandlePerfOpenExitAppliesPairFilter(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{
		filter: globalfilter.Filter{
			Syscall: &globalfilter.StringFilter{Pattern: "openat"},
		},
	})

	enter := &types.PerfOpenEvent{
		EventType: types.ENTER_PERF_OPEN_EVENT,
		TraceId:   types.SYS_ENTER_PERF_EVENT_OPEN,
		Time:      100,
		Pid:       202,
		Tid:       203,
	}
	exit := &types.RetEvent{
		EventType: types.EXIT_RET_EVENT,
		TraceId:   types.SYS_EXIT_PERF_EVENT_OPEN,
		Time:      200,
		Ret:       1,
		Pid:       202,
		Tid:       203,
	}
	ep := &event.Pair{EnterEv: enter, ExitEv: exit}

	if ok := el.handlePerfOpenExit(ep, enter); ok {
		t.Fatal("handlePerfOpenExit should reject pair due to filter mismatch")
	}
}

func TestInitRawHandlersRegistersSecurityEvents(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	if _, ok := el.rawHandlers[types.ENTER_KEYCTL_EVENT]; !ok {
		t.Fatal("ENTER_KEYCTL_EVENT handler is not registered")
	}
	if _, ok := el.rawHandlers[types.ENTER_PTRACE_EVENT]; !ok {
		t.Fatal("ENTER_PTRACE_EVENT handler is not registered")
	}
	if _, ok := el.rawHandlers[types.ENTER_PERF_OPEN_EVENT]; !ok {
		t.Fatal("ENTER_PERF_OPEN_EVENT handler is not registered")
	}
}
