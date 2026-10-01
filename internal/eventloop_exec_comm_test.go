package internal

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

// execCommTid models a task that forked from a shell and then exec'd: the tid
// survives the execve, which is exactly why a comm cached before the exec
// stays attached to the post-exec program. Both lie above every possible pid
// (absentPidBase, task zs2) so the procfs fallback of an untraced descriptor
// finds no process, whatever runs on the host (testdata/payloadsplit.golden
// prints this pid).
const (
	execCommPid = absentPidBase + 4242
	execCommTid = absentPidBase + 4242
)

// execSurvivalCase is one fd-table entry of
// TestProcessExecEventKeepsOnlyDescriptorsKnownToSurvive: entry builds the
// tracked file and keep says whether it must survive the exec.
type execSurvivalCase struct {
	name  string
	fd    int32
	entry func() file.File
	keep  bool
}

// makeProcessExecEvent builds the exec record of a task that kept its tid
// across the exec (old_tid == tid), which is every exec except one by a
// non-leader thread (see makeProcessExecEventFrom).
func makeProcessExecEvent(t *testing.T, time uint64, pid, tid uint32, comm string) []byte {
	t.Helper()
	return makeProcessExecEventFrom(t, time, pid, tid, tid, comm)
}

// makeProcessExecEventFrom builds an exec record whose task ran as oldTid
// before the exec and as tid after it.
func makeProcessExecEventFrom(t *testing.T, time uint64, pid, tid, oldTid uint32, comm string) []byte {
	t.Helper()
	ev := types.ProcessExecEvent{
		EventType: types.PROCESS_EXEC_EVENT,
		Time:      time,
		Pid:       pid,
		Tid:       tid,
		OldTid:    oldTid,
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
// process_exec_event (internal/c/types.h): 4+4+8+4+4+16+4(old_tid)+
// 4(exit_untraced) with no trailing padding. NewProcessExecEventFast decodes
// only this length and the legacy 40-byte one, so a drift here would turn
// every exec record into a dropped malformed event.
const processExecEventWireSize = 48

// newEventLoopWithStaleComm builds an event loop whose comm cache reached the
// stale state the way production does: the asynchronous resolver read
// /proc/<tid>/comm while the tid was still the forking shell, and that value
// landed in the cache before the exec. Setting the entry with setCachedComm
// would pin the same symptom, but not the mechanism - this drives
// commResolver.resolveFn, the LRU write path and the pending bookkeeping.
func newEventLoopWithStaleComm(t *testing.T, cfg eventLoopConfig, comm string) *eventLoop {
	t.Helper()
	resolver := newCommResolver(nil)
	resolver.resolveFn = func(_ context.Context, tid uint32) (string, error) {
		if tid == execCommTid {
			return comm, nil
		}
		// Other tids (the tracer's own pid, seeded at construction) must not
		// depend on what happens to run on the host.
		return "", nil
	}
	cfg.commResolver = resolver
	el := mustNewEventLoop(t, cfg)
	t.Cleanup(resolver.shutdown)

	el.queueCommLookup(execCommTid)
	waitForCondition(t, 2*time.Second, "timed out waiting for the pre-exec comm lookup to land",
		func() bool {
			got, ok := resolver.cached(execCommTid)
			return ok && got == comm
		})
	return el
}

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
	// The pre-exec lookup won the race and cached the forking shell's name.
	el := newEventLoopWithStaleComm(t, eventLoopConfig{}, "bash")

	el.processRawEvent(makeProcessExecEvent(t, defaulTime-1, execCommPid, execCommTid, "cat"),
		make(chan *event.Pair, 1))

	if got, ok := el.commState().cached(execCommTid); !ok || got != "cat" {
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

// TestLegacyProcessExecRecordRefreshesComm pins IOR_BPF_OBJECT compatibility
// for the exec record: an object built before old_tid emits a 40-byte record,
// which must still refresh the post-exec comm instead of being dropped as a
// malformed event with a warning per exec.
func TestLegacyProcessExecRecordRefreshesComm(t *testing.T) {
	el := newEventLoopWithStaleComm(t, eventLoopConfig{}, "bash")
	var warnings []string
	el.warningCb = func(message string) { warnings = append(warnings, message) }

	// The legacy layout is the current one minus old_tid and exit_untraced.
	raw := makeProcessExecEvent(t, defaulTime-1, execCommPid, execCommTid, "cat")
	el.processRawEvent(raw[:40], make(chan *event.Pair, 1))

	if len(warnings) != 0 {
		t.Fatalf("legacy exec record raised warnings %q, want none", warnings)
	}
	if got, ok := el.commState().cached(execCommTid); !ok || got != "cat" {
		t.Fatalf("cached comm after legacy exec record = %q (present=%v), want \"cat\"", got, ok)
	}
}

// TestFirstPostExecSyscallWithoutExecRecordKeepsStaleComm pins the mechanism
// the fix removes: with no sched:sched_process_exec record, the stale pre-exec
// comm is what reaches the row. It guards the fixture above - if this ever
// stops reproducing the stale label, the positive test proves nothing.
func TestFirstPostExecSyscallWithoutExecRecordKeepsStaleComm(t *testing.T) {
	el := newEventLoopWithStaleComm(t, eventLoopConfig{}, "bash")

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
			// Pre-exec the tid looked like the filtered command, which is how
			// non-matching tasks used to slip past the comm filter.
			el := newEventLoopWithStaleComm(t, eventLoopConfig{
				filter: globalfilter.Filter{
					Comm: &globalfilter.StringFilter{Pattern: "cat"},
				},
			}, "cat")
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
// it into the comm cache at the exit would re-poison the tid right after the
// kernel's exec record corrected it. (The enter's own seed precedes that record
// in ring order and is covered by TestSuccessfulExecRecordReplacesTheCallerComm.)
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

	if got, ok := el.commState().cached(execCommTid); !ok || got != "cat" {
		t.Fatalf("cached comm after execve exit = %q (present=%v), want \"cat\"", got, ok)
	}
}

// TestExecExitNeverWritesTheCommCache pins that the execve exit handler leaves
// the comm cache alone whatever the return value. The caller's name is applied
// when the ENTER record is consumed (seedCommFromEnterPayload; see
// TestFailedExecCommSeedsTheCacheWithoutARename), in ring order with the
// task_rename and exec records that follow. A write at exit - the old
// failed-execve path - restored the pre-rename name over a rename that landed
// between enter and exit (TestFailedExecCommDoesNotUndoARenameBetweenEnterAndExit).
// The enter goes through tracepointEntered here, which does not seed, so any
// cache entry afterwards came from the exit handler.
func TestExecExitNeverWritesTheCommCache(t *testing.T) {
	for _, tc := range []struct {
		name string
		ret  int64
	}{
		{name: "failed execve", ret: -2},
		{name: "negative raw word is not an errno", ret: -4096},
		{name: "successful execve", ret: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			el := mustNewEventLoop(t, eventLoopConfig{commResolver: newHermeticCommResolver()})
			t.Cleanup(el.commResolver.shutdown)

			enter := &types.ExecEvent{
				EventType: types.ENTER_EXEC_EVENT,
				TraceId:   types.SYS_ENTER_EXECVE,
				Time:      defaulTime,
				Pid:       execCommPid,
				Tid:       execCommTid,
			}
			copy(enter.Comm[:], "bash")
			copy(enter.Filename[:], "/usr/bin/does-not-exist")
			exit := &types.RetEvent{
				EventType: types.EXIT_RET_EVENT,
				TraceId:   types.SYS_EXIT_EXECVE,
				Time:      defaulTime + 10,
				Pid:       execCommPid,
				Tid:       execCommTid,
				Ret:       tc.ret,
			}

			el.tracepointEntered(enter)
			out := make(chan *event.Pair, 1)
			el.tracepointExited(exit, out)
			select {
			case ep := <-out:
				ep.Recycle()
			default:
				t.Fatal("expected the execve pair to be emitted")
			}

			if got, ok := el.commState().cached(execCommTid); ok {
				t.Fatalf("the execve exit wrote %q into the comm cache", got)
			}
		})
	}
}

// TestProcessExecEventWithEmptyCommKeepsCachedName covers the early return in
// handleProcessExecEvent. bpf_get_current_comm() should never hand us an empty
// name, but a truncated or zeroed record must not turn a good label into no
// label at all.
func TestProcessExecEventWithEmptyCommKeepsCachedName(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{commResolver: newHermeticCommResolver()})
	t.Cleanup(el.commResolver.shutdown)
	el.setCachedComm(execCommTid, "cat")

	el.processRawEvent(makeProcessExecEvent(t, defaulTime-1, execCommPid, execCommTid, ""),
		make(chan *event.Pair, 1))

	if got, ok := el.commState().cached(execCommTid); !ok || got != "cat" {
		t.Fatalf("cached comm after an all-zero control record = %q (present=%v), want \"cat\"", got, ok)
	}
}

// TestProcessExecEventLeavesPairingStateUntouched pins that a control record is
// exactly that: it must not consume the tid's pending enter event, must not
// count as a syscall, and must never produce a row.
func TestProcessExecEventLeavesPairingStateUntouched(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{commResolver: newHermeticCommResolver()})
	t.Cleanup(el.commResolver.shutdown)

	out := make(chan *event.Pair, 1)
	_, enterRaw := makeEnterPathEvent(t, defaulTime, execCommPid, execCommTid,
		"/etc/ld.so.preload", types.SYS_ENTER_ACCESS)
	el.processRawEvent(enterRaw, out)
	verifyEnterEventPending(t, el, execCommTid)
	pendingBefore := el.pairs.enters[execCommTid]
	syscallsBefore := el.numSyscalls
	afterFilterBefore := el.numSyscallsAfterFilter

	el.processRawEvent(makeProcessExecEvent(t, defaulTime+1, execCommPid, execCommTid, "cat"), out)

	verifyEnterEventPending(t, el, execCommTid)
	if el.pairs.enters[execCommTid] != pendingBefore {
		t.Fatal("control record replaced the pending enter event for the tid")
	}
	if el.numSyscalls != syscallsBefore {
		t.Fatalf("numSyscalls = %d, want %d (control records are not syscalls)", el.numSyscalls, syscallsBefore)
	}
	if el.numSyscallsAfterFilter != afterFilterBefore {
		t.Fatalf("numSyscallsAfterFilter = %d, want %d", el.numSyscallsAfterFilter, afterFilterBefore)
	}
	select {
	case ep := <-out:
		t.Fatalf("control record produced a row: %v", ep)
	default:
	}

	// The pair still completes normally afterwards, now with the new label.
	_, exitRaw := makeExitRetEvent(t, defaulTime+100, execCommPid, execCommTid, types.SYS_EXIT_ACCESS, -2)
	el.processRawEvent(exitRaw, out)
	select {
	case ep := <-out:
		if ep.Comm != "cat" {
			t.Fatalf("row comm = %q, want \"cat\"", ep.Comm)
		}
		ep.Recycle()
	default:
		t.Fatal("expected the pending pair to complete after the control record")
	}
}

// TestTypedRuntimeControlDropsMalformedEvent covers the type-assertion failure
// branch: the event must be reported and returned to its pool, not leaked.
func TestTypedRuntimeControlDropsMalformedEvent(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	warnings := make(chan string, 1)
	el.warningCb = func(message string) {
		select {
		case warnings <- message:
		default:
		}
	}

	var recycles int32
	control := typedRuntimePairControl((*eventLoop).handleProcessExecEvent)
	control(el, &recycleCountingEvent{tid: execCommTid, recycleCount: &recycles}, nil)

	if got := atomic.LoadInt32(&recycles); got != 1 {
		t.Fatalf("malformed control event recycled %d times, want 1", got)
	}
	select {
	case message := <-warnings:
		if !strings.Contains(message, "malformed control event") {
			t.Fatalf("warning = %q, want it to mention a malformed control event", message)
		}
	default:
		t.Fatal("expected a warning for the malformed control event")
	}
}

// TestUnresolvedCommRowsSurviveWithoutACommFilter guards against turning the
// comm checkpoint into a blanket drop for unlabelled rows: with no -comm
// filter, a path or rename row whose comm has not resolved yet (short-lived
// process, procfs read still in flight) must still be emitted, just with an
// empty comm column.
func TestUnresolvedCommRowsSurviveWithoutACommFilter(t *testing.T) {
	const unresolvedTid = execCommTid + 1

	for _, tc := range []struct {
		name  string
		enter func(t *testing.T) []byte
		exit  func(t *testing.T) []byte
	}{
		{
			name: "path kind",
			enter: func(t *testing.T) []byte {
				_, raw := makeEnterPathEvent(t, defaulTime, execCommPid, unresolvedTid,
					"/etc/ld.so.preload", types.SYS_ENTER_ACCESS)
				return raw
			},
			exit: func(t *testing.T) []byte {
				_, raw := makeExitRetEvent(t, defaulTime+100, execCommPid, unresolvedTid,
					types.SYS_EXIT_ACCESS, -2)
				return raw
			},
		},
		{
			name: "name kind",
			enter: func(t *testing.T) []byte {
				_, raw := makeEnterNameEvent(t, defaulTime, execCommPid, unresolvedTid,
					"/tmp/old.txt", "/tmp/new.txt", types.SYS_ENTER_RENAME)
				return raw
			},
			exit: func(t *testing.T) []byte {
				_, raw := makeExitRetEvent(t, defaulTime+100, execCommPid, unresolvedTid,
					types.SYS_EXIT_RENAME, 0)
				return raw
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			el := mustNewEventLoop(t, eventLoopConfig{commResolver: newHermeticCommResolver()})
			t.Cleanup(el.commResolver.shutdown)

			out := make(chan *event.Pair, 1)
			el.processRawEvent(tc.enter(t), out)
			el.processRawEvent(tc.exit(t), out)

			select {
			case ep := <-out:
				if ep.Comm != "" {
					t.Fatalf("comm = %q, want the unresolved empty string", ep.Comm)
				}
				ep.Recycle()
			default:
				t.Fatal("an unlabelled row must still be emitted when no comm filter is active")
			}
		})
	}
}

// TestExecRecordAfterTheSyscallPairCannotRelabelIt states the ordering the fix
// depends on. The correction is applied when the control record is consumed, so
// a pair completed BEFORE it still carries the stale label; only later pairs
// are correct. That is exactly why the BPF probe emits into the same ring
// buffer (reservation order) and is attached before the syscall tracepoints -
// if the record could arrive late, the fix would not hold.
func TestExecRecordAfterTheSyscallPairCannotRelabelIt(t *testing.T) {
	el := newEventLoopWithStaleComm(t, eventLoopConfig{}, "bash")

	early := feedFirstPostExecSyscall(t, el)
	if early == nil {
		t.Fatal("expected the pre-record syscall to be emitted")
	}
	defer early.Recycle()
	if early.Comm != "bash" {
		t.Fatalf("pair fed before the exec record reported %q, want the stale \"bash\"", early.Comm)
	}

	el.processRawEvent(makeProcessExecEvent(t, defaulTime+200, execCommPid, execCommTid, "cat"),
		make(chan *event.Pair, 1))

	late := feedFirstPostExecSyscall(t, el)
	if late == nil {
		t.Fatal("expected the post-record syscall to be emitted")
	}
	defer late.Recycle()
	if late.Comm != "cat" {
		t.Fatalf("pair fed after the exec record reported %q, want \"cat\"", late.Comm)
	}
}

// TestExecRecordWinsOverAnInFlightProcfsLookup drives the logical race the
// per-tid exec epoch closes: a resolver worker reads the pre-exec name, is
// descheduled, and only reaches the cache after the kernel's exec record has
// installed the post-exec name. Both writes take the mutex, so the race
// detector cannot see this; only the ordering makes it visible.
func TestExecRecordWinsOverAnInFlightProcfsLookup(t *testing.T) {
	readStarted := make(chan struct{})
	release := make(chan struct{})
	resolver := newCommResolver(nil)
	resolver.lookupWorkers = 1
	resolver.resolveFn = func(_ context.Context, tid uint32) (string, error) {
		if tid != execCommTid {
			return "", nil
		}
		// The worker has read the pre-exec name and is now descheduled.
		close(readStarted)
		<-release
		return "bash", nil
	}
	el := mustNewEventLoop(t, eventLoopConfig{commResolver: resolver})
	t.Cleanup(resolver.shutdown)

	el.queueCommLookup(execCommTid)
	select {
	case <-readStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the procfs lookup to start")
	}

	// The exec record lands while that worker is parked.
	el.processRawEvent(makeProcessExecEvent(t, defaulTime-1, execCommPid, execCommTid, "cat"),
		make(chan *event.Pair, 1))
	if got, ok := el.commState().cached(execCommTid); !ok || got != "cat" {
		t.Fatalf("cached comm right after the exec record = %q (present=%v), want \"cat\"", got, ok)
	}

	close(release)
	waitForCondition(t, 2*time.Second, "timed out waiting for the stale lookup to complete",
		func() bool { return pendingCount(resolver) == 0 })

	if got, ok := el.commState().cached(execCommTid); !ok || got != "cat" {
		t.Fatalf("cached comm after the stale lookup landed = %q (present=%v), want \"cat\"", got, ok)
	}
	ep := feedFirstPostExecSyscall(t, el)
	if ep == nil {
		t.Fatal("expected the post-exec syscall to be emitted")
	}
	defer ep.Recycle()
	if ep.Comm != "cat" {
		t.Fatalf("row comm = %q, want \"cat\"", ep.Comm)
	}
}

// TestRingbufDropsHealAStaleCommCache covers the one loss the ordered control
// record cannot cover: the record itself was dropped because
// bpf_ringbuf_reserve() failed. An open or exec of the tid would heal it (the
// enter payload is applied before the raw -comm gate, seedCommFromEnterPayload,
// so even a filtered-out open does), but a tid that only reads and writes has
// no such record and nothing else corrects it, so the drop counter has to
// trigger re-resolution (markAllStale). This test's tid issues only access(2).
// Until the re-read lands the old label is still served, which is deliberate:
// blanking it would drop the tid's rows at the exit-side comm check.
func TestRingbufDropsHealAStaleCommCache(t *testing.T) {
	var procComm atomic.Value
	procComm.Store("bash")

	resolver := newCommResolver(nil)
	resolver.resolveFn = func(_ context.Context, tid uint32) (string, error) {
		if tid != execCommTid {
			return "", nil
		}
		return procComm.Load().(string), nil
	}
	el := mustNewEventLoop(t, eventLoopConfig{commResolver: resolver})
	t.Cleanup(resolver.shutdown)

	el.queueCommLookup(execCommTid)
	waitForCondition(t, 2*time.Second, "timed out waiting for the pre-exec comm lookup", func() bool {
		got, ok := resolver.cached(execCommTid)
		return ok && got == "bash"
	})

	// The task exec'd into "cat", but its control record never made it out of
	// the kernel. procfs already reports the new name.
	procComm.Store("cat")

	stale := feedFirstPostExecSyscall(t, el)
	if stale == nil {
		t.Fatal("expected the post-exec syscall to be emitted")
	}
	if stale.Comm != "bash" {
		t.Fatalf("comm before the drop is observed = %q, want the stale \"bash\"", stale.Comm)
	}
	stale.Recycle()

	// The drop monitor observes the loss on its next tick.
	el.handleRingbufDropResult(ringbufDropResult{total: 7, delta: 7})
	if got := el.numRingbufDrops.Load(); got != 7 {
		t.Fatalf("numRingbufDrops = %d, want 7", got)
	}

	// The request is consumed on the event-loop goroutine, and the re-read it
	// triggers is asynchronous, so the healing shows up on a later row.
	waitForCondition(t, 2*time.Second, "timed out waiting for the comm cache to heal", func() bool {
		ep := feedFirstPostExecSyscall(t, el)
		if ep == nil {
			return false
		}
		defer ep.Recycle()
		return ep.Comm == "cat"
	})
}

// TestMarkAllStaleKeepsServingTheCurrentValue pins the deliberate choice of
// stale-marking over eviction: a flagged entry still answers with its current
// value, so rows keep a (possibly outdated) label instead of losing it and
// being dropped at the exit-side comm check.
func TestMarkAllStaleKeepsServingTheCurrentValue(t *testing.T) {
	resolved := make(chan struct{})
	resolver := newCommResolver(nil)
	resolver.resolveFn = func(_ context.Context, _ uint32) (string, error) {
		select {
		case <-resolved:
		default:
			close(resolved)
		}
		return "cat", nil
	}
	defer resolver.shutdown()

	resolver.setCached(execCommTid, "bash")
	if marked := resolver.markAllStale(); marked != 1 {
		t.Fatalf("markAllStale marked %d entries, want 1", marked)
	}
	// Marking again must not re-count an already flagged entry.
	if marked := resolver.markAllStale(); marked != 0 {
		t.Fatalf("second markAllStale marked %d entries, want 0", marked)
	}

	if got, ok := resolver.cached(execCommTid); !ok || got != "bash" {
		t.Fatalf("stale entry served %q (present=%v), want the retained \"bash\"", got, ok)
	}
	select {
	case <-resolved:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the stale entry to be re-resolved")
	}
	waitForCondition(t, 2*time.Second, "timed out waiting for the refreshed comm", func() bool {
		got, ok := resolver.cached(execCommTid)
		return ok && got == "cat"
	})
}

// TestPathKindsApplyTheFullPairFilter pins the asymmetry between the two
// comm-less kinds. For a path row `ep.File` is the very pathname the raw enter
// filter already matched, so the full pair filter is safe and is applied. For a
// rename row it is not: the raw filter matches oldname OR newname while
// `File.Name()` reports only the newname, so applying MatchPair there would
// drop rows a `-path <oldname>` filter legitimately selected - which is why
// that kind keeps the comm-only checkpoint.
func TestPathKindsApplyTheFullPairFilter(t *testing.T) {
	t.Run("path row is dropped by a non-comm filter dimension", func(t *testing.T) {
		el := mustNewEventLoop(t, eventLoopConfig{
			filter: globalfilter.Filter{
				Syscall: &globalfilter.StringFilter{Pattern: "openat"},
			},
			commResolver: newHermeticCommResolver(),
		})
		t.Cleanup(el.commResolver.shutdown)

		out := make(chan *event.Pair, 1)
		_, enterRaw := makeEnterPathEvent(t, defaulTime, execCommPid, execCommTid,
			"/etc/ld.so.preload", types.SYS_ENTER_ACCESS)
		_, exitRaw := makeExitRetEvent(t, defaulTime+100, execCommPid, execCommTid,
			types.SYS_EXIT_ACCESS, -2)
		el.processRawEvent(enterRaw, out)
		el.processRawEvent(exitRaw, out)

		select {
		case ep := <-out:
			t.Fatalf("access row survived a -syscall openat filter: %v", ep)
		default:
		}
	})

	t.Run("path row matching the path filter survives", func(t *testing.T) {
		// The risk direction of routing handlePathExit through the full pair
		// filter: a row the -path filter legitimately selects must still be
		// emitted, and must still carry its file and comm.
		el := mustNewEventLoop(t, eventLoopConfig{
			filter: globalfilter.Filter{
				File: &globalfilter.StringFilter{Pattern: "/etc/ld.so.preload"},
			},
			commResolver: newHermeticCommResolver(),
		})
		t.Cleanup(el.commResolver.shutdown)
		el.setCachedComm(execCommTid, "cat")

		out := make(chan *event.Pair, 1)
		_, enterRaw := makeEnterPathEvent(t, defaulTime, execCommPid, execCommTid,
			"/etc/ld.so.preload", types.SYS_ENTER_ACCESS)
		_, exitRaw := makeExitRetEvent(t, defaulTime+100, execCommPid, execCommTid,
			types.SYS_EXIT_ACCESS, -2)
		el.processRawEvent(enterRaw, out)
		el.processRawEvent(exitRaw, out)

		select {
		case ep := <-out:
			if ep.File == nil || ep.File.Name() != "/etc/ld.so.preload" {
				t.Fatalf("unexpected file on the path row: %v", ep.File)
			}
			if ep.Comm != "cat" {
				t.Fatalf("path row comm = %q, want \"cat\"", ep.Comm)
			}
			ep.Recycle()
		default:
			t.Fatal("a path row matching the -path filter must still be emitted")
		}
	})

	t.Run("rename row matched on oldname survives", func(t *testing.T) {
		el := mustNewEventLoop(t, eventLoopConfig{
			filter: globalfilter.Filter{
				File: &globalfilter.StringFilter{Pattern: "/tmp/old.txt"},
			},
			commResolver: newHermeticCommResolver(),
		})
		t.Cleanup(el.commResolver.shutdown)

		out := make(chan *event.Pair, 1)
		_, enterRaw := makeEnterNameEvent(t, defaulTime, execCommPid, execCommTid,
			"/tmp/old.txt", "/tmp/new.txt", types.SYS_ENTER_RENAME)
		_, exitRaw := makeExitRetEvent(t, defaulTime+100, execCommPid, execCommTid,
			types.SYS_EXIT_RENAME, 0)
		el.processRawEvent(enterRaw, out)
		el.processRawEvent(exitRaw, out)

		select {
		case ep := <-out:
			if ep.File == nil || ep.File.Name() != "/tmp/new.txt" {
				t.Fatalf("unexpected file on the rename row: %v", ep.File)
			}
			ep.Recycle()
		default:
			t.Fatal("a rename matched on its oldname must still be emitted")
		}
	})
}

// feedOpenByHandleAtPair drives a full name_to_handle_at + open_by_handle_at
// sequence through the raw event path and returns the emitted open_by_handle_at
// pair, or nil when it was filtered. name_to_handle_at itself never produces a
// row: handlePathExit only parks its pathname for the correlation.
func feedOpenByHandleAtPair(t *testing.T, el *eventLoop, pathname string, fd int32) *event.Pair {
	t.Helper()
	out := make(chan *event.Pair, 2)

	_, enterNameRaw := makeEnterPathEvent(t, defaulTime, execCommPid, execCommTid,
		pathname, types.SYS_ENTER_NAME_TO_HANDLE_AT)
	_, exitNameRaw := makeExitRetEvent(t, defaulTime+100, execCommPid, execCommTid,
		types.SYS_EXIT_NAME_TO_HANDLE_AT, 0)
	el.processRawEvent(enterNameRaw, out)
	el.processRawEvent(exitNameRaw, out)

	_, enterOpenRaw := makeEnterOpenByHandleAtEvent(t, defaulTime+200, execCommPid, execCommTid,
		syscall.O_RDONLY)
	_, exitOpenRaw := makeExitRetEvent(t, defaulTime+300, execCommPid, execCommTid,
		types.SYS_EXIT_OPEN_BY_HANDLE_AT, int64(fd))
	el.processRawEvent(enterOpenRaw, out)
	el.processRawEvent(exitOpenRaw, out)

	select {
	case ep := <-out:
		return ep
	default:
		return nil
	}
}

// TestOpenByHandleAtRowsCannotContradictTheCommFilter closes the last kind that
// escaped every filter dimension. open_by_handle_at has no raw enter filter at
// all (rawRuntimeEvents registers it with a nil filter) and its exit handler
// used to attach the resolved comm and return true, so under `-comm cat` a row
// labelled "bash" was emitted - the exact contradiction this whole fix exists
// to remove. Nothing before the exit checkpoint helps: tracepointEntered no
// longer looks at the comm at all, and a raw filter cannot answer it because the
// kind's payload carries none.
func TestOpenByHandleAtRowsCannotContradictTheCommFilter(t *testing.T) {
	const pathname = "/tmp/handle.txt"

	t.Run("row whose comm contradicts the filter is dropped", func(t *testing.T) {
		el := newEventLoopWithStaleComm(t, eventLoopConfig{
			filter: globalfilter.Filter{
				Comm: &globalfilter.StringFilter{Pattern: "cat"},
			},
		}, "bash")

		if ep := feedOpenByHandleAtPair(t, el, pathname, 70); ep != nil {
			defer ep.Recycle()
			t.Fatalf("open_by_handle_at row survived -comm cat with comm=%q file=%v", ep.Comm, ep.File)
		}
	})

	t.Run("row whose comm matches the filter survives", func(t *testing.T) {
		el := newEventLoopWithStaleComm(t, eventLoopConfig{
			filter: globalfilter.Filter{
				Comm: &globalfilter.StringFilter{Pattern: "cat"},
			},
		}, "cat")

		ep := feedOpenByHandleAtPair(t, el, pathname, 71)
		if ep == nil {
			t.Fatal("open_by_handle_at row matching -comm cat must still be emitted")
		}
		defer ep.Recycle()
		if ep.Comm != "cat" {
			t.Fatalf("row comm = %q, want \"cat\"", ep.Comm)
		}
		if ep.File == nil || ep.File.Name() != pathname {
			t.Fatalf("row file = %v, want %q", ep.File, pathname)
		}
	})

	t.Run("row is filtered on the pathname it reports", func(t *testing.T) {
		// The full pair filter is deliberate here, not just the comm
		// dimension: ep.File is in both branches exactly the name the row
		// displays, so -path can never select a row that then shows a
		// different file.
		el := newEventLoopWithStaleComm(t, eventLoopConfig{
			filter: globalfilter.Filter{
				File: &globalfilter.StringFilter{Pattern: "/tmp/other.txt"},
			},
		}, "cat")

		if ep := feedOpenByHandleAtPair(t, el, pathname, 72); ep != nil {
			defer ep.Recycle()
			t.Fatalf("open_by_handle_at row survived a non-matching -path filter: file=%v", ep.File)
		}
	})
}

// TestKernelCommWinsOverAnInFlightProcfsLookup is the non-exec half of the
// epoch guard. The open event's payload comm is task->comm as BPF read it when
// the syscall started, and it is cached when the enter record is consumed; a
// resolver worker descheduled with an older name must not land on top of it.
// Before every kernel-sourced write bumped the rename generation this was
// reachable without any execve at all - prctl(PR_SET_NAME) is enough - and
// after a dropped exec record too.
func TestKernelCommWinsOverAnInFlightProcfsLookup(t *testing.T) {
	readStarted := make(chan struct{})
	release := make(chan struct{})
	resolver := newCommResolver(nil)
	resolver.lookupWorkers = 1
	resolver.resolveFn = func(_ context.Context, tid uint32) (string, error) {
		if tid != execCommTid {
			return "", nil
		}
		// The worker read the old name and is now descheduled.
		close(readStarted)
		<-release
		return "bash", nil
	}
	el := mustNewEventLoop(t, eventLoopConfig{commResolver: resolver})
	t.Cleanup(resolver.shutdown)
	// Registered after the shutdown cleanup so it runs before it (LIFO): an
	// early t.Fatal must not leave the worker parked, or shutdown deadlocks on
	// workersWG instead of reporting the failure.
	unpark := unparkOnce(release)
	t.Cleanup(unpark)

	el.queueCommLookup(execCommTid)
	select {
	case <-readStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the procfs lookup to start")
	}

	// An open event carrying the current kernel name arrives while that worker
	// is parked.
	out := make(chan *event.Pair, 1)
	openEv, _ := makeEnterOpenEvent(t, defaulTime, execCommPid, execCommTid)
	// Overwrite, do not overlay: makeEnterOpenEvent seeds "testcomm", and a
	// plain copy would leave a "cattcomm" tail behind.
	openEv.Comm = [types.MAX_PROGNAME_LENGTH]byte{}
	copy(openEv.Comm[:], "cat")
	enterRaw, err := openEv.Bytes()
	if err != nil {
		t.Fatalf("OpenEvent.Bytes() error = %v", err)
	}
	_, exitRaw := makeExitRetEvent(t, defaulTime+100, execCommPid, execCommTid,
		types.SYS_EXIT_OPENAT, 5)
	el.processRawEvent(enterRaw, out)
	el.processRawEvent(exitRaw, out)
	select {
	case ep := <-out:
		ep.Recycle()
	default:
		t.Fatal("expected the open pair to be emitted")
	}
	if got, ok := el.commState().cached(execCommTid); !ok || got != "cat" {
		t.Fatalf("cached comm right after the open event = %q (present=%v), want \"cat\"", got, ok)
	}

	unpark()
	waitForCondition(t, 2*time.Second, "timed out waiting for the stale lookup to complete",
		func() bool { return pendingCount(resolver) == 0 })

	if got, ok := el.commState().cached(execCommTid); !ok || got != "cat" {
		t.Fatalf("cached comm after the stale lookup landed = %q (present=%v), want \"cat\"", got, ok)
	}
}

// unparkOnce returns an idempotent closer for the channel a parked resolver
// worker is blocked on. Registering it with t.Cleanup keeps a t.Fatal before
// the unpark from leaving that worker parked forever, which would deadlock
// commResolver.shutdown on workersWG and hide the real failure behind a test
// timeout. It closes over the channel value rather than the variable, so the
// worker's receive never races the test goroutine.
func unparkOnce(ch chan struct{}) func() {
	var once sync.Once
	return func() { once.Do(func() { close(ch) }) }
}

// commEntryStale reports the stale flag of a cache entry under the resolver's
// own mutex, so tests can observe it without racing the lookup workers.
func commEntryStale(r *commResolver, tid uint32) (stale, present bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	entry, ok := r.comms[tid]
	return entry.stale, ok
}

// TestLookupInFlightAcrossAStalenessSweepLandsStale closes the hole markAllStale
// alone leaves open. The sweep can only flag entries that exist when it runs; a
// lookup already in flight creates its entry afterwards, with a value read
// before the exec record the drop lost, and setCommLocked clears the stale flag
// on the way in. Without the sweep-generation check that tid would keep a
// pre-exec label forever whenever the drop burst was a one-off.
func TestLookupInFlightAcrossAStalenessSweepLandsStale(t *testing.T) {
	readStarted := make(chan struct{})
	release := make(chan struct{})
	var reads atomic.Int32

	resolver := newCommResolver(nil)
	resolver.lookupWorkers = 1
	resolver.resolveFn = func(_ context.Context, tid uint32) (string, error) {
		if tid != execCommTid {
			return "", nil
		}
		if reads.Add(1) == 1 {
			// Read before the exec, and parked until the sweep has run.
			close(readStarted)
			<-release
			return "bash", nil
		}
		return "cat", nil
	}
	t.Cleanup(resolver.shutdown)
	unpark := unparkOnce(release)
	t.Cleanup(unpark)

	resolver.queueLookup(execCommTid)
	select {
	case <-readStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the procfs lookup to start")
	}

	// The drop monitor sweeps while the lookup is in flight. There is nothing
	// cached for this tid yet, so the sweep itself cannot reach it.
	if marked := resolver.markAllStale(); marked != 0 {
		t.Fatalf("markAllStale marked %d entries, want 0 (the cache is still empty)", marked)
	}

	unpark()
	waitForCondition(t, 2*time.Second, "timed out waiting for the lookup to land",
		func() bool { return pendingCount(resolver) == 0 })

	stale, present := commEntryStale(resolver, execCommTid)
	if !present {
		t.Fatal("the late lookup did not create a cache entry")
	}
	if !stale {
		t.Fatal("a lookup that predates the staleness sweep must land stale")
	}

	// The retained value is still served, and the flag drives one re-read that
	// heals the label.
	if got, ok := resolver.cached(execCommTid); !ok || got != "bash" {
		t.Fatalf("stale entry served %q (present=%v), want the retained \"bash\"", got, ok)
	}
	waitForCondition(t, 2*time.Second, "timed out waiting for the comm cache to heal", func() bool {
		got, ok := resolver.cached(execCommTid)
		return ok && got == "cat"
	})
	// The healed value must not be flagged again: the sweep generation it was
	// read under is the current one.
	if stale, _ := commEntryStale(resolver, execCommTid); stale {
		t.Fatal("the healing re-read must land clean, otherwise re-resolution never terminates")
	}
}

// TestProcessExecEventDropsCloseOnExecDescriptors is the regression test for
// the stale-descriptor bug: a process opens /etc/app.conf O_CLOEXEC as fd 7
// and execs; the kernel closes fd 7, and the new program gets fd 7 back from a
// syscall ior does not trace. Without the eviction on the sched_process_exec
// record, every later row on fd 7 reported /etc/app.conf with the old
// program's O_RDONLY|O_CLOEXEC flags.
func TestProcessExecEventDropsCloseOnExecDescriptors(t *testing.T) {
	const staleName = "/etc/app.conf"
	const staleFd = 7
	el := newFilteredEventLoop(t, globalfilter.Filter{})
	if ep := feedOpenPairWithFlags(t, el, staleName, execCommPid, execCommTid, staleFd,
		syscall.O_RDONLY|syscall.O_CLOEXEC); ep != nil {
		ep.Recycle()
	}
	verifyFileDescriptor(t, el, execCommPid, staleFd, staleName)

	el.processRawEvent(makeProcessExecEvent(t, defaulTime+1, execCommPid, execCommTid, "newprog"),
		make(chan *event.Pair, 1))

	verifyFdNotTracked(t, el, execCommPid, staleFd)
	ep := feedReadPairForPid(t, el, execCommPid, execCommTid, staleFd)
	if ep == nil {
		t.Fatal("expected the post-exec read to produce a row")
	}
	defer ep.Recycle()
	if got := ep.File.Name(); got == staleName {
		t.Fatalf("post-exec row on fd %d still reports the pre-exec file %q", staleFd, got)
	}
}

// TestProcessExecEventKeepsOnlyDescriptorsKnownToSurvive pins which entries
// the exec record evicts: exactly those not known to survive execve(2). The
// close-on-exec state is exercised through every way the tracker learns it
// (open flags, F_SETFD-style MergeFlags in both directions, close_range's
// CLOSE_RANGE_CLOEXEC via addFlagsRange), plus the unknown cases that must be
// dropped conservatively, and another pid that must stay untouched.
func TestProcessExecEventKeepsOnlyDescriptorsKnownToSurvive(t *testing.T) {
	const otherPid = execCommPid + 1
	cases := execSurvivalCases()
	el := newFilteredEventLoop(t, globalfilter.Filter{})
	fds := el.fdState()
	seedExecSurvivalState(fds, cases, otherPid)

	// An empty comm makes the record useless as a label, but the exec still
	// happened, so the eviction must not hide behind the comm early return.
	el.processRawEvent(makeProcessExecEvent(t, defaulTime, execCommPid, execCommTid, ""),
		make(chan *event.Pair, 1))

	for _, tc := range cases {
		_, tracked := fds.files[fdKey(execCommPid, tc.fd)]
		if tracked != tc.keep {
			t.Errorf("%s: fd %d tracked after exec = %v, want %v", tc.name, tc.fd, tracked, tc.keep)
		}
	}
	verifyFdNotTracked(t, el, execCommPid, 17)
	if _, ok := fds.fileAges[fdKey(execCommPid, 10)]; ok {
		t.Error("evicted fd 10 left its LRU age behind")
	}
	assertExecProcFdCache(t, fds, otherPid)
	verifyFileDescriptor(t, el, otherPid, 10, "/other")
	// A surviving descriptor must keep its pid registered so a later exit
	// still evicts it (the per-pid index must never miss).
	assertFdIndexConsistent(t, fds)
	fds.deletePid(execCommPid)
	verifyFdNotTracked(t, el, execCommPid, 11)
	if _, ok := fds.procFdCache[fdKey(execCommPid, 22)]; ok {
		t.Error("surviving procfs cache entry was not evicted by the later exit")
	}
	assertFdIndexConsistent(t, fds)
}

// execSurvivalCases covers every way the tracker learns the close-on-exec
// state of an entry (open flags, F_SETFD-style MergeFlags in both
// directions) plus the unknown cases that must be dropped conservatively.
func execSurvivalCases() []execSurvivalCase {
	return []execSurvivalCase{
		{"opened O_CLOEXEC", 10, func() file.File { return file.NewFd(10, "/a", syscall.O_RDONLY|syscall.O_CLOEXEC) }, false},
		{"opened without O_CLOEXEC", 11, func() file.File { return file.NewFd(11, "/b", syscall.O_RDWR) }, true},
		{"F_SETFD set FD_CLOEXEC later", 12, func() file.File {
			f := file.NewFd(12, "/c", syscall.O_RDONLY)
			f.MergeFlags(syscall.O_CLOEXEC, syscall.O_CLOEXEC)
			return f
		}, false},
		{"F_SETFD cleared FD_CLOEXEC later", 13, func() file.File {
			f := file.NewFd(13, "/d", syscall.O_RDONLY|syscall.O_CLOEXEC)
			f.MergeFlags(syscall.O_CLOEXEC, 0)
			return f
		}, true},
		{"known clear, status flags unknown", 14, func() file.File {
			f := file.NewFd(14, "/e", -1)
			f.MergeFlags(syscall.O_CLOEXEC, 0)
			return f
		}, true},
		{"flags entirely unknown", 15, func() file.File { return file.NewFd(15, "/f", -1) }, false},
		{"not an FdFile", 16, func() file.File { return file.NewPathname([]byte("/g")) }, false},
	}
}

// seedExecSurvivalState registers cases for execCommPid, a close_range'd
// descriptor (fd 17), another pid's entries, and procfs cache entries.
func seedExecSurvivalState(fds *fdTracker, cases []execSurvivalCase, otherPid uint32) {
	for _, tc := range cases {
		fds.set(tc.fd, execCommPid, tc.entry())
	}
	// close_range(17, 17, CLOSE_RANGE_CLOEXEC) on a known-clear descriptor.
	fds.set(17, execCommPid, file.NewFd(17, "/h", syscall.O_RDONLY))
	fds.addFlagsRange(17, 17, execCommPid, syscall.O_CLOEXEC)
	fds.set(10, otherPid, file.NewFd(10, "/other", syscall.O_RDONLY|syscall.O_CLOEXEC))
	// Procfs cache entries follow the same rule as the fd table: known-set
	// and unknown (unresolvable) state are dropped, known-clear survives.
	fds.setProcFdCache(20, execCommPid, file.NewFd(20, "/cached-cloexec", syscall.O_RDONLY|syscall.O_CLOEXEC))
	fds.setProcFdCache(21, execCommPid, file.NewFd(21, "", -1))
	fds.setProcFdCache(22, execCommPid, file.NewFd(22, "/cached-kept", syscall.O_RDONLY))
	fds.setProcFdCache(20, otherPid, file.NewFd(20, "/cached-other", syscall.O_RDONLY|syscall.O_CLOEXEC))
}

// assertExecProcFdCache checks the procfs cache after execCommPid's exec: the
// known-set (20) and unknown (21) entries are gone, the known-clear one (22)
// and otherPid's entry survive.
func assertExecProcFdCache(t *testing.T, fds *fdTracker, otherPid uint32) {
	t.Helper()
	for _, fd := range []int32{20, 21} {
		if _, ok := fds.procFdCache[fdKey(execCommPid, fd)]; ok {
			t.Errorf("exec'ing pid's procfs cache entry for fd %d survived the exec", fd)
		}
	}
	if cached, ok := fds.procFdCache[fdKey(execCommPid, 22)]; !ok || cached.Name() != "/cached-kept" {
		t.Error("known-clear procfs cache entry was dropped by the exec")
	}
	if _, ok := fds.procFdCache[fdKey(otherPid, 20)]; !ok {
		t.Error("another pid's procfs cache entry was dropped by this pid's exec")
	}
}

// TestProcessExecEventKeepsDup2dStdoutName drives the common shell pattern
// end to end through the real handlers: open a log file O_CLOEXEC, dup2 it
// onto fd 1 (registerDup clears FD_CLOEXEC on the duplicate, as the kernel
// does), exec, then write(1). The duplicate survives the exec in the kernel,
// so it must keep its name; the O_CLOEXEC original must be gone.
func TestProcessExecEventKeepsDup2dStdoutName(t *testing.T) {
	const logName = "/var/log/job.log"
	const openedFd = 5
	const stdout = 1
	el := newFilteredEventLoop(t, globalfilter.Filter{})
	if ep := feedOpenPairWithFlags(t, el, logName, execCommPid, execCommTid, openedFd,
		syscall.O_WRONLY|syscall.O_CLOEXEC); ep != nil {
		ep.Recycle()
	}
	if ep := feedFdPair(t, el, types.SYS_ENTER_DUP2, types.SYS_EXIT_DUP2,
		openedFd, stdout, dupPairStart, dupPairStart+openPairLatency); ep != nil {
		ep.Recycle()
	}

	el.processRawEvent(makeProcessExecEvent(t, dupPairStart+openPairLatency+1, execCommPid, execCommTid, "job"),
		make(chan *event.Pair, 1))

	verifyFdNotTracked(t, el, execCommPid, openedFd)
	ep := feedFdPair(t, el, types.SYS_ENTER_WRITE, types.SYS_EXIT_WRITE,
		stdout, 64, writePairStart, writePairStart+openPairLatency)
	if ep == nil {
		t.Fatal("expected the post-exec write(1) to produce a row")
	}
	defer ep.Recycle()
	if got := ep.File.Name(); got != logName {
		t.Fatalf("post-exec write(1) reports %q, want the dup2'd %q", got, logName)
	}
}

// TestDropOnExecIgnoresUnregisteredPids covers the fast paths: a zero-value
// tracker must not panic, and an exec of a pid that never registered a
// descriptor must leave every other pid alone.
func TestDropOnExecIgnoresUnregisteredPids(t *testing.T) {
	(&fdTracker{}).dropOnExec(execCommPid)

	fds := newFDTracker(nil)
	fds.dropOnExec(execCommPid)
	fds.set(3, execCommPid, file.NewFd(3, "/x", syscall.O_RDONLY|syscall.O_CLOEXEC))
	fds.dropOnExec(execCommPid + 1)
	if _, ok := fds.get(3, execCommPid); !ok {
		t.Fatal("exec of an unregistered pid evicted another pid's descriptor")
	}
}
