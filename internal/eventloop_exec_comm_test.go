package internal

import (
	"testing"

	"ior/internal/event"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

// execCommTid models a task that forked from a shell and then exec'd: the tid
// survives the execve, which is exactly why a comm cached before the exec
// stays attached to the post-exec program.
const (
	execCommPid = 4242
	execCommTid = 4242
)

func makeProcessExecEvent(t *testing.T, time uint64, pid, tid uint32, comm string) []byte {
	t.Helper()
	ev := types.ProcessExecEvent{
		EventType: types.PROCESS_EXEC_EVENT,
		Time:      time,
		Pid:       pid,
		Tid:       tid,
	}
	copy(ev.Comm[:], comm)
	raw, err := ev.Bytes()
	if err != nil {
		t.Fatalf("ProcessExecEvent.Bytes() error = %v", err)
	}
	if len(raw) != processExecEventWireSize {
		t.Fatalf("ProcessExecEvent wire size = %d, want %d", len(raw), processExecEventWireSize)
	}
	return raw
}

// processExecEventWireSize pins the kernel payload size of struct
// process_exec_event (internal/c/types.h): 4+4+8+4+4+16 with no trailing
// padding. NewProcessExecEventFast takes its fast path only at this exact
// length, so a drift here would silently move every decode onto the slow
// binary.Read path.
const processExecEventWireSize = 40

// feedFirstPostExecSyscall pushes the enter/exit pair of the dynamic loader's
// very first post-exec syscall - access("/etc/ld.so.preload") - through the raw
// event path and returns the emitted pair, or nil when the pair was filtered.
func feedFirstPostExecSyscall(t *testing.T, el *eventLoop) *event.Pair {
	t.Helper()
	out := make(chan *event.Pair, 1)
	_, enterRaw := makeEnterPathEvent(t, defaulTime, execCommPid, execCommTid,
		"/etc/ld.so.preload", types.SYS_ENTER_ACCESS)
	_, exitRaw := makeExitRetEvent(t, defaulTime+100, execCommPid, execCommTid,
		types.SYS_EXIT_ACCESS, -2)

	el.processRawEvent(enterRaw, out)
	el.processRawEvent(exitRaw, out)

	select {
	case ep := <-out:
		return ep
	default:
		return nil
	}
}

// TestFirstPostExecSyscallCarriesPostExecComm is the regression test for the
// comm column contradicting the -comm filter. It models the exact race: a
// forked child whose /proc/<tid>/comm was read before it exec'd, so the async
// resolver cached the shell's name for that tid, and the new program's very
// first syscall then arrives. The kernel's sched:sched_process_exec record must
// have corrected the cache before that syscall is turned into a row.
func TestFirstPostExecSyscallCarriesPostExecComm(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})

	// The pre-exec lookup won the race and cached the forking shell's name.
	el.setCachedComm(execCommTid, "bash")

	el.processRawEvent(makeProcessExecEvent(t, defaulTime-1, execCommPid, execCommTid, "cat"),
		make(chan *event.Pair, 1))

	if got, ok := el.cachedComm(execCommTid); !ok || got != "cat" {
		t.Fatalf("cached comm after exec record = %q (present=%v), want \"cat\"", got, ok)
	}

	ep := feedFirstPostExecSyscall(t, el)
	if ep == nil {
		t.Fatal("expected the first post-exec syscall to be emitted")
	}
	defer ep.Recycle()
	if ep.Comm != "cat" {
		t.Fatalf("first post-exec syscall comm = %q, want \"cat\"", ep.Comm)
	}
}

// TestFirstPostExecSyscallWithoutExecRecordKeepsStaleComm pins the mechanism
// the fix removes: with no sched:sched_process_exec record, the stale pre-exec
// comm is what reaches the row. It guards the fixture above - if this ever
// stops reproducing the stale label, the positive test proves nothing.
func TestFirstPostExecSyscallWithoutExecRecordKeepsStaleComm(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	el.setCachedComm(execCommTid, "bash")

	ep := feedFirstPostExecSyscall(t, el)
	if ep == nil {
		t.Fatal("expected the first post-exec syscall to be emitted")
	}
	defer ep.Recycle()
	if ep.Comm != "bash" {
		t.Fatalf("comm without an exec record = %q, want the stale \"bash\"", ep.Comm)
	}
}

// TestCommFilterAgreesWithReportedCommAcrossExec is the end-to-end invariant
// the bug violated: under -comm <name>, every emitted row must report that
// comm. The post-exec syscall of a task the filter targets has to survive, and
// the same syscall from a task that merely kept a matching cache entry from
// before its exec must not.
func TestCommFilterAgreesWithReportedCommAcrossExec(t *testing.T) {
	for _, tc := range []struct {
		name       string
		execComm   string
		wantEmit   bool
		wantReport string
	}{
		{name: "post-exec comm matches the filter", execComm: "cat", wantEmit: true, wantReport: "cat"},
		{name: "post-exec comm does not match the filter", execComm: "grep", wantEmit: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			el := mustNewEventLoop(t, eventLoopConfig{
				filter: globalfilter.Filter{
					Comm: &globalfilter.StringFilter{Pattern: "cat"},
				},
			})
			// Pre-exec the tid looked like the filtered command, which is how
			// non-matching tasks used to slip past the comm gate.
			el.setCachedComm(execCommTid, "cat")
			el.processRawEvent(makeProcessExecEvent(t, defaulTime-1, execCommPid, execCommTid, tc.execComm),
				make(chan *event.Pair, 1))

			ep := feedFirstPostExecSyscall(t, el)
			if !tc.wantEmit {
				if ep != nil {
					t.Fatalf("row with comm %q survived the -comm cat filter", ep.Comm)
				}
				return
			}
			if ep == nil {
				t.Fatal("expected the matching post-exec syscall to be emitted")
			}
			defer ep.Recycle()
			if ep.Comm != tc.wantReport {
				t.Fatalf("emitted comm = %q, want %q", ep.Comm, tc.wantReport)
			}
		})
	}
}

// TestExecExitDoesNotCacheThePreExecComm guards the second half of the fix:
// the sys_enter_execve payload carries the *calling* program's name, so writing
// it into the comm cache would re-poison the tid right after the kernel's exec
// record corrected it.
func TestExecExitDoesNotCacheThePreExecComm(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	el.processRawEvent(makeProcessExecEvent(t, defaulTime-1, execCommPid, execCommTid, "cat"),
		make(chan *event.Pair, 1))

	enter := &types.ExecEvent{
		EventType: types.ENTER_EXEC_EVENT,
		TraceId:   types.SYS_ENTER_EXECVE,
		Time:      defaulTime,
		Pid:       execCommPid,
		Tid:       execCommTid,
	}
	copy(enter.Comm[:], "bash")
	copy(enter.Filename[:], "/usr/bin/cat")
	exit := &types.RetEvent{
		EventType: types.EXIT_RET_EVENT,
		TraceId:   types.SYS_EXIT_EXECVE,
		Time:      defaulTime + 10,
		Pid:       execCommPid,
		Tid:       execCommTid,
	}

	el.tracepointEntered(enter)
	out := make(chan *event.Pair, 1)
	el.tracepointExited(exit, out)

	select {
	case ep := <-out:
		// The execve row itself belongs to the caller, so it reports "bash".
		if ep.Comm != "bash" {
			t.Fatalf("execve row comm = %q, want \"bash\"", ep.Comm)
		}
		ep.Recycle()
	default:
		t.Fatal("expected the execve pair to be emitted")
	}

	if got, ok := el.cachedComm(execCommTid); !ok || got != "cat" {
		t.Fatalf("cached comm after execve exit = %q (present=%v), want \"cat\"", got, ok)
	}
}
