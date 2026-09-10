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
	select {
	case ep := <-out:
		return ep
	default:
		return nil
	}
}

// feedTaskExit delivers the sched:sched_process_exit control record for tid.
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
// dead enter reachable: it is dropped either by ring-buffer backpressure or -
// far more routinely - by the enter-side comm gate in tracepointEntered, which
// under -comm drops a non-open/exec enter for a tid whose comm is not cached
// yet. A brand-new tid is exactly that case, and evicting the comm on exit (the
// sibling fix) guarantees a recycled tid starts uncached.
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

	feedTaskExit(t, el, out, defaulTime+400, execCommTid)

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
