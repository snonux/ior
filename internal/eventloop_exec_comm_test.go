package internal

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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
			// non-matching tasks used to slip past the comm gate.
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

// TestFailedExecCachesTheCallerComm covers the one execve where the
// sys_enter_execve comm IS the task's name going forward: a failed one. No
// sched_process_exec record fires for it, so refusing to cache here would throw
// away a name the kernel handed us for free.
func TestFailedExecCachesTheCallerComm(t *testing.T) {
	for _, tc := range []struct {
		name      string
		ret       int64
		wantComm  string
		wantCache bool
	}{
		{name: "failed execve caches the caller name", ret: -2, wantComm: "bash", wantCache: true},
		{name: "successful execve caches nothing", ret: 0, wantCache: false},
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

			got, ok := el.cachedComm(execCommTid)
			if ok != tc.wantCache {
				t.Fatalf("cached comm present = %v, want %v (got %q)", ok, tc.wantCache, got)
			}
			if tc.wantCache && got != tc.wantComm {
				t.Fatalf("cached comm = %q, want %q", got, tc.wantComm)
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

	if got, ok := el.cachedComm(execCommTid); !ok || got != "cat" {
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
	control := typedRuntimeControl((*eventLoop).handleProcessExecEvent)
	control(el, &recycleCountingEvent{tid: execCommTid, recycleCount: &recycles})

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
	if got, ok := el.cachedComm(execCommTid); !ok || got != "cat" {
		t.Fatalf("cached comm right after the exec record = %q (present=%v), want \"cat\"", got, ok)
	}

	close(release)
	waitForCondition(t, 2*time.Second, "timed out waiting for the stale lookup to complete",
		func() bool { return pendingCount(resolver) == 0 })

	if got, ok := el.cachedComm(execCommTid); !ok || got != "cat" {
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
// bpf_ringbuf_reserve() failed. Nothing else corrects that tid - with a -comm
// filter active, handleOpenExit never sees the non-matching program's opens -
// so the drop counter has to trigger re-resolution. Until the re-read lands the
// old label is still served, which is deliberate: blanking it would drop the
// tid's events at the enter-side comm gate.
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
// being dropped at the comm gate.
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
