package internal

import (
	"testing"

	"ior/internal/event"
	"ior/internal/types"
)

// The pair tracker is keyed by tid, and the kernel hands tid numbers out again
// as soon as the task that held one is reaped. These tests model exactly that:
// execCommTid is first owned by a task that dies inside access(), and the same
// number is then handed to a new task.
const (
	// deadTaskPath is the filename the dying task passed to access(). It is
	// the fingerprint of a fabricated row: no live task ever asks for it, so
	// seeing it on a row emitted after the exit record means the row was built
	// from the dead task's parked enter.
	deadTaskPath = "/dead/process/path"
	// recycledTaskPath is what the task holding the recycled tid number really
	// asks for.
	recycledTaskPath = "/etc/hosts"
	// siblingTaskPath is what a sibling thread of the dying task asks for.
	siblingTaskPath = "/etc/services"
	// oneHourNs is the wall time between the dead task's syscall and the
	// recycled task's - the latency and the gap that a surviving entry
	// fabricates.
	oneHourNs = uint64(3600) * 1000 * 1000 * 1000
)

// newPairEvictionEventLoop builds an unfiltered event loop with a hermetic
// comm resolver, so nothing but the pair tracker decides whether a row is
// emitted.
func newPairEvictionEventLoop(t *testing.T) *eventLoop {
	t.Helper()
	el := mustNewEventLoop(t, eventLoopConfig{commResolver: newHermeticCommResolver()})
	t.Cleanup(el.commResolver.shutdown)
	return el
}

// feedAccessEnter pushes one access() sys_enter for tid and leaves it parked:
// the matching exit is fed separately, so a test can kill the task in between.
func feedAccessEnter(t *testing.T, el *eventLoop, out chan *event.Pair,
	at uint64, tid uint32, pathname string) {
	t.Helper()
	_, raw := makeEnterPathEvent(t, at, execCommPid, tid, pathname, types.SYS_ENTER_ACCESS)
	el.processRawEvent(raw, out)
}

// feedAccessExit pushes one access() sys_exit for tid and returns the row it
// produced, or nil when no row was emitted.
func feedAccessExit(t *testing.T, el *eventLoop, out chan *event.Pair,
	at uint64, tid uint32) *event.Pair {
	t.Helper()
	_, raw := makeExitRetEvent(t, at, execCommPid, tid, types.SYS_EXIT_ACCESS, 0)
	el.processRawEvent(raw, out)
	return nextRow(out)
}

// feedTaskExit delivers the sched:sched_process_exit control record for tid as
// the exit of a whole single-threaded process (group_dead set), the shape of
// a task whose tid the kernel can hand to a new owner.
func feedTaskExit(t *testing.T, el *eventLoop, out chan *event.Pair, at uint64, tid uint32) {
	t.Helper()
	el.processRawEvent(makeProcessExitEvent(t, at, execCommPid, tid), out)
}

// rowFile renders a row's filename for a failure message without assuming the
// row carries a file at all.
func rowFile(ep *event.Pair) string {
	if ep == nil || ep.File == nil {
		return "<none>"
	}
	return ep.File.Name()
}

// TestRecycledTidDoesNotPairWithTheDeadTasksEnter is the regression test for
// pairTracker.enters surviving sched_process_exit.
//
// A task killed inside a syscall never gets its sys_exit, so its enter stays
// parked under its tid forever. When the kernel hands that tid number to a new
// task, an exit arriving for the new task consumes the dead one's enter and the
// row is emitted with the dead task's filename and an enter timestamp from
// before it died - a syscall that never happened, with a latency as long as the
// gap between the two tasks. Nothing catches it downstream: the recycled task
// runs the same syscall, so the enter/exit trace-ID guard in tracepointExited
// sees perfectly matching IDs.
//
// The new task's own enter is missing here on purpose, which is what makes the
// dead enter reachable: it is dropped by ring-buffer backpressure (before
// task dr2 the enter-side comm gate in tracepointEntered dropped it under -comm
// as well, for every brand-new tid; that gate is gone, so loss is now the only
// route to a missing enter). Evicting the comm on exit (the sibling fix)
// guarantees a recycled tid starts uncached.
func TestRecycledTidDoesNotPairWithTheDeadTasksEnter(t *testing.T) {
	el := newPairEvictionEventLoop(t)
	out := make(chan *event.Pair, 2)

	feedAccessEnter(t, el, out, defaulTime, execCommTid, deadTaskPath)
	feedTaskExit(t, el, out, defaulTime+100, execCommTid)

	if ep := feedAccessExit(t, el, out, defaulTime+oneHourNs, execCommTid); ep != nil {
		file, latency := rowFile(ep), ep.Duration
		ep.Recycle()
		t.Fatalf("recycled tid emitted a row built from the dead task's enter: file=%s latency=%dns",
			file, latency)
	}

	// The other direction: the eviction must not cost the recycled task its
	// own rows. Its next complete pair is emitted, and carries its own path.
	start := defaulTime + oneHourNs + 200
	feedAccessEnter(t, el, out, start, execCommTid, recycledTaskPath)
	ep := feedAccessExit(t, el, out, start+100, execCommTid)
	if ep == nil {
		t.Fatal("the recycled task's own access() pair was not emitted")
	}
	defer ep.Recycle()
	if got := rowFile(ep); got != recycledTaskPath {
		t.Fatalf("recycled task's row file = %s, want %s", got, recycledTaskPath)
	}
	if ep.Duration != 100 {
		t.Fatalf("recycled task's row latency = %dns, want 100ns", ep.Duration)
	}
}

// TestRecycledTidDoesNotInheritTheDeadTasksGap covers the milder half of the
// same defect: pairTracker.prevTimes is keyed by tid as well, so the recycled
// task's first pair got a DurationToPrev measured from the dead task's last
// syscall. That is the value -gap filters on and the one the latency+gaps tab
// aggregates, so an hour of another process's lifetime showed up as this one's
// idle time.
func TestRecycledTidDoesNotInheritTheDeadTasksGap(t *testing.T) {
	el := newPairEvictionEventLoop(t)
	out := make(chan *event.Pair, 2)

	// The dying task completes one access() pair first, which is what records
	// its exit timestamp as the tid's gap baseline.
	feedAccessEnter(t, el, out, defaulTime, execCommTid, deadTaskPath)
	first := feedAccessExit(t, el, out, defaulTime+100, execCommTid)
	if first == nil {
		t.Fatal("the dying task's own access() pair was not emitted")
	}
	first.Recycle()

	feedTaskExit(t, el, out, defaulTime+200, execCommTid)

	// An hour later the tid is recycled and its new owner runs its first
	// syscall. A first pair on a tid has no gap, so this one must report zero.
	start := defaulTime + oneHourNs
	feedAccessEnter(t, el, out, start, execCommTid, recycledTaskPath)
	ep := feedAccessExit(t, el, out, start+100, execCommTid)
	if ep == nil {
		t.Fatal("the recycled task's access() pair was not emitted")
	}
	defer ep.Recycle()
	if ep.DurationToPrev != 0 {
		t.Fatalf("recycled task's first row gap = %dns, want 0 (measured from the dead task's last syscall)",
			ep.DurationToPrev)
	}
}

// TestProcessExitEvictsOnlyTheExitedTasksPairState pins the granularity claim
// in handleProcessExitEvent for the pair tracker: sched_process_exit fires per
// task and both maps are keyed per task, so a thread exit must drop that
// thread's parked enter and gap baseline and nothing else. Evicting by tgid
// instead would delete the still-in-flight syscalls of every sibling thread of
// a living multithreaded process - turning this fix into a row-losing bug of
// its own.
func TestProcessExitEvictsOnlyTheExitedTasksPairState(t *testing.T) {
	const siblingTid = execCommTid + 1
	el := newPairEvictionEventLoop(t)
	out := make(chan *event.Pair, 2)

	// The sibling thread completes a pair (setting its gap baseline) and then
	// enters a second syscall that is still in flight when its peer dies.
	feedAccessEnter(t, el, out, defaulTime, siblingTid, siblingTaskPath)
	if ep := feedAccessExit(t, el, out, defaulTime+100, siblingTid); ep != nil {
		ep.Recycle()
	} else {
		t.Fatal("the sibling thread's first access() pair was not emitted")
	}
	feedAccessEnter(t, el, out, defaulTime+300, siblingTid, siblingTaskPath)

	// A thread exit (group_dead clear), as it is while the sibling lives.
	el.processRawEvent(makeThreadExitEvent(t, defaulTime+400, execCommPid, execCommTid), out)

	ep := feedAccessExit(t, el, out, defaulTime+500, siblingTid)
	if ep == nil {
		t.Fatal("a sibling thread's in-flight syscall was dropped by another task's exit")
	}
	defer ep.Recycle()
	if got := rowFile(ep); got != siblingTaskPath {
		t.Fatalf("sibling thread's row file = %s, want %s", got, siblingTaskPath)
	}
	if ep.DurationToPrev != 200 {
		t.Fatalf("sibling thread's gap = %dns, want 200ns (enter at +300 after its own exit at +100)",
			ep.DurationToPrev)
	}
}

// TestTaskExitDropsTheParkedHandleAndKeepsTheHandleNames covers the fourth
// piece of tid-keyed state the exit record has to clear, and the piece of
// handle state it must NOT clear.
//
// A handle a name_to_handle_at returned is parked under the tid from its
// control record until the call's exit record; a task whose exit record was
// lost leaves it parked, and the task's own death drops it. The names, in
// contrast, are filed under the handle itself: handing a handle to another
// process is what the API is for, so a name outlives the task that took the
// handle and still names the open another process makes. That is an absolute
// name; one scoped to the taker's process ends with the PROCESS, on its
// group-dead record (eventloop_handle_exit_test.go). (While the stash was
// keyed by tid it had to be dropped here, or the recycled tid's next
// open_by_handle_at was named after the dead task's path.)
func TestTaskExitDropsTheParkedHandleAndKeepsTheHandleNames(t *testing.T) {
	el := newPairEvictionEventLoop(t)
	out := make(chan *event.Pair, 4)

	// The dead task takes handle A of its own path, then starts a second
	// name_to_handle_at whose handle record arrives but whose exit is lost.
	for _, raw := range makeNameToHandleAtRecords(t, defaulTime, execCommPid, execCommTid,
		deadTaskPath, testHandleA) {
		el.processRawEvent(raw, out)
	}
	lost := makeNameToHandleAtRecords(t, defaulTime+150, execCommPid, execCommTid, siblingTaskPath, testHandleB)
	el.processRawEvent(lost[0], out)
	el.processRawEvent(lost[1], out)
	drainRows(out)
	if _, ok := el.handleState().taken[execCommTid]; !ok {
		t.Fatal("fixture: the second call's handle is not parked")
	}

	feedTaskExit(t, el, out, defaulTime+400, execCommTid)
	if _, ok := el.handleState().taken[execCommTid]; ok {
		t.Fatal("the dead task's parked handle survived its exit record")
	}

	assertRecycledTidOpensByHandle(t, el, out, testHandleA, deadTaskPath)
	assertRecycledTidOpensByHandle(t, el, out, testHandleB, "")
}

// assertRecycledTidOpensByHandle has the task that now owns execCommTid open
// handle h and checks the name of the row and of the fd table entry.
//
// get, not resolve: resolve falls back to /proc/<pid>/fd and returns a File
// built around the fd it was handed either way, so its FD() is the argument
// and asserting on it proves nothing.
func assertRecycledTidOpensByHandle(t *testing.T, el *eventLoop, out chan *event.Pair, h testHandle, want string) {
	t.Helper()
	const recycledFd = 77
	_, enterOpen := makeEnterOpenByHandleEvent(t, defaulTime+500, execCommPid, execCommTid, 0, h)
	el.processRawEvent(enterOpen, out)
	_, exitOpen := makeExitRetEvent(t, defaulTime+600, execCommPid, execCommTid,
		types.SYS_EXIT_OPEN_BY_HANDLE_AT, recycledFd)
	el.processRawEvent(exitOpen, out)

	ep := nextRow(out)
	if ep == nil {
		t.Fatal("the open_by_handle_at pair was not emitted")
	}
	defer ep.Recycle()
	if got := ep.File.Name(); got != want {
		t.Fatalf("open_by_handle_at row named %q, want %q", got, want)
	}
	fdFile, ok := el.fdState().get(recycledFd, execCommPid)
	if !ok {
		t.Fatalf("fd %d was never registered in the fd table for pid %d", recycledFd, execCommPid)
	}
	if got := fdFile.Name(); got != want {
		t.Fatalf("fd table entry for (pid=%d, fd=%d) = %q, want %q", execCommPid, recycledFd, got, want)
	}
}

// drainRows empties whatever rows the setup emitted, so a test asserts only on
// the row it actually cares about.
func drainRows(out chan *event.Pair) {
	for {
		select {
		case ep := <-out:
			ep.Recycle()
		default:
			return
		}
	}
}

// nextRow returns the next row, or nil when none was emitted.
func nextRow(out chan *event.Pair) *event.Pair {
	select {
	case ep := <-out:
		return ep
	default:
		return nil
	}
}
