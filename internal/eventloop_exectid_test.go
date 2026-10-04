package internal

import (
	"math"
	"syscall"
	"testing"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/types"
)

// A non-leader exec: process nleExecPid (the leader's tid) runs a second
// thread nleExecCaller, which calls execve. de_thread() hands the caller the
// leader's tid, so the execve enters under nleExecCaller and returns under
// nleExecPid. The records arrive in kernel order: the execve enter, the dead
// leader's sched_process_exit, the sched_process_exec record carrying the old
// tid, then the execve exit.
const (
	nleExecPid    = 5000
	nleExecCaller = 5003
)

// makeNonLeaderExecEnter builds the sys_enter_execve record of the caller.
func makeNonLeaderExecEnter(t *testing.T, time uint64, tid uint32) []byte {
	t.Helper()
	return makeNonLeaderExecEnterFor(t, types.SYS_ENTER_EXECVE, time, tid)
}

// makeNonLeaderExecEnterFor builds an exec-family enter record (execve or
// execveat, by traceID) of the caller.
func makeNonLeaderExecEnterFor(t *testing.T, traceID types.TraceId, time uint64, tid uint32) []byte {
	t.Helper()
	enter := &types.ExecEvent{
		EventType: types.ENTER_EXEC_EVENT, TraceId: traceID, Time: time,
		Pid: nleExecPid, Tid: tid, Dirfd: -1, SchemaVersion: types.EXEC_EVENT_SCHEMA_VERSION,
	}
	copy(enter.Filename[:], "/usr/bin/newprog")
	copy(enter.Comm[:], "caller")
	return mustRaw(t, enter)
}

// feedNonLeaderExec drives the leader's exit, the exec record and the execve
// exit (return value 0) through the raw event path and returns the row the
// exit completed, or nil.
func feedNonLeaderExec(t *testing.T, el *eventLoop, exitTime uint64) *event.Pair {
	t.Helper()
	out := make(chan *event.Pair, 1)
	el.processRawEvent(makeThreadExitEvent(t, exitTime-3, nleExecPid, nleExecPid), out)
	el.processRawEvent(makeProcessExecEventFrom(t, exitTime-2, nleExecPid, nleExecPid, nleExecCaller, "newprog"), out)
	_, exitRaw := makeExitRetEvent(t, exitTime, nleExecPid, nleExecPid, types.SYS_EXIT_EXECVE, 0)
	el.processRawEvent(exitRaw, out)
	select {
	case ep := <-out:
		return ep
	default:
		return nil
	}
}

// completeCallerAccess runs one access(2) pair on the caller so it has a gap
// baseline (prevTimes) ending at exitTime.
func completeCallerAccess(t *testing.T, el *eventLoop, enterTime, exitTime uint64) {
	t.Helper()
	_, enterRaw := makeEnterPathEvent(t, enterTime, nleExecPid, nleExecCaller, "/etc/hosts", types.SYS_ENTER_ACCESS)
	_, exitRaw := makeExitRetEvent(t, exitTime, nleExecPid, nleExecCaller, types.SYS_EXIT_ACCESS, 0)
	if ep := feedRawPair(t, el, enterRaw, exitRaw); ep != nil {
		ep.Recycle()
	} else {
		t.Fatal("expected the caller's access pair to be emitted")
	}
}

func newNonLeaderExecLoop(t *testing.T) *eventLoop {
	t.Helper()
	el := mustNewEventLoop(t, eventLoopConfig{commResolver: newHermeticCommResolver()})
	t.Cleanup(el.commResolver.shutdown)
	el.setCachedCommFromKernel(nleExecCaller, "caller", math.MaxUint64)
	return el
}

// TestNonLeaderExecPairsUnderLeaderTid is the regression test for task 0p2:
// the execve enter parked under the caller's tid must pair with the exit that
// arrives under the leader's tid, the row must report the calling thread, and
// nothing may be left behind under the vanished pre-exec tid.
func TestNonLeaderExecPairsUnderLeaderTid(t *testing.T) {
	el := newNonLeaderExecLoop(t)
	completeCallerAccess(t, el, 1000, 1100)
	el.handleState().park(nleExecCaller, testHandleA.key(), 1400)
	el.handleState().park(nleExecPid, testHandleB.key(), 1400)
	el.processRawEvent(makeNonLeaderExecEnter(t, 1500, nleExecCaller), make(chan *event.Pair, 1))
	mismatches := el.numTracepointMismatches

	ep := feedNonLeaderExec(t, el, 2000)
	if ep == nil {
		t.Fatal("non-leader execve produced no row: its enter was not re-keyed to the leader tid")
	}
	defer ep.Recycle()
	if got := ep.EnterEv.GetTid(); got != nleExecCaller {
		t.Errorf("row tid = %d, want the calling thread %d", got, nleExecCaller)
	}
	if got := ep.EnterEv.GetPid(); got != nleExecPid {
		t.Errorf("row pid = %d, want %d", got, nleExecPid)
	}
	if ep.Comm != "caller" || ep.FileName() != "/usr/bin/newprog" {
		t.Errorf("row comm/file = %q/%q, want caller//usr/bin/newprog", ep.Comm, ep.FileName())
	}
	if ep.Duration != 500 || ep.DurationToPrev != 400 {
		t.Errorf("row duration/gap = %d/%d, want 500/400 (gap from the caller's previous syscall)",
			ep.Duration, ep.DurationToPrev)
	}
	if el.numTracepointMismatches != mismatches {
		t.Errorf("numTracepointMismatches rose to %d", el.numTracepointMismatches)
	}
	assertNoCallerState(t, el)
	if got := el.pairs.prevTime(nleExecPid); got != 2000 {
		t.Errorf("leader tid gap baseline = %d, want the execve exit time 2000", got)
	}
	if got, ok := el.commState().cached(nleExecPid); !ok || got != "newprog" {
		t.Errorf("leader tid comm = %q (present=%v), want newprog", got, ok)
	}
}

// assertNoCallerState checks that nothing is keyed by the pre-exec tid any
// more, that no enter or name_to_handle_at handle stays parked for either
// tid, and that the exec caller index holds no hint.
func assertNoCallerState(t *testing.T, el *eventLoop) {
	t.Helper()
	for _, tid := range []uint32{nleExecCaller, nleExecPid} {
		if _, ok := el.pairs.enters[tid]; ok {
			t.Errorf("enter still parked under tid %d", tid)
		}
	}
	if _, ok := el.pairs.prevTimes[nleExecCaller]; ok {
		t.Error("gap baseline left under the pre-exec tid")
	}
	if _, ok := el.commState().cached(nleExecCaller); ok {
		t.Error("comm left cached under the pre-exec tid")
	}
	for _, tid := range []uint32{nleExecCaller, nleExecPid} {
		if _, ok := el.handleState().taken[tid]; ok {
			t.Errorf("parked handle left under tid %d", tid)
		}
	}
	if len(el.pairs.execCallers) != 0 {
		t.Errorf("exec caller index not empty: %v", el.pairs.execCallers)
	}
}

// TestNonLeaderExecDropsStaleEnters covers the lost-record cases: a non-exec
// enter parked under the caller's tid (its exit record was lost) must not be
// moved onto the leader tid, and a leader enter or parked handle whose exit
// record was lost must not be kept after the exec. Neither may produce a
// row or a mismatch.
func TestNonLeaderExecDropsStaleEnters(t *testing.T) {
	el := newNonLeaderExecLoop(t)
	el.setCachedCommFromKernel(nleExecPid, "caller", math.MaxUint64)
	// The dead leader's parked name_to_handle_at handle: with its exit
	// record lost, only the exec record drops it before the tid's next
	// name_to_handle_at exit (which would discard it by its time).
	el.handleState().park(nleExecPid, testHandleB.key(), 800)
	out := make(chan *event.Pair, 1)
	_, staleCaller := makeEnterPathEvent(t, 900, nleExecPid, nleExecCaller, "/etc/hosts", types.SYS_ENTER_ACCESS)
	el.processRawEvent(staleCaller, out)
	verifyEnterEventPending(t, el, nleExecCaller)
	_, staleLeader := makeEnterPathEvent(t, 950, nleExecPid, nleExecPid, "/etc/passwd", types.SYS_ENTER_ACCESS)
	el.processRawEvent(staleLeader, out)
	verifyEnterEventPending(t, el, nleExecPid)

	// No leader exit record (lost) and no execve enter (lost): only the exec
	// record and the exit arrive.
	el.processRawEvent(makeProcessExecEventFrom(t, 1998, nleExecPid, nleExecPid, nleExecCaller, "newprog"), out)
	_, exitRaw := makeExitRetEvent(t, 2000, nleExecPid, nleExecPid, types.SYS_EXIT_EXECVE, 0)
	el.processRawEvent(exitRaw, out)

	select {
	case ep := <-out:
		t.Fatalf("stale enter produced a row: %v", ep)
	default:
	}
	if el.numTracepointMismatches != 0 {
		t.Errorf("numTracepointMismatches = %d, want 0", el.numTracepointMismatches)
	}
	assertNoCallerState(t, el)
}

// TestProcessExecEventWithKeptTidMovesNothing is the negative case: an exec
// record whose old tid equals its tid (a leader exec, or a record without
// the field) must leave every pending enter where it is.
func TestProcessExecEventWithKeptTidMovesNothing(t *testing.T) {
	for _, oldTid := range []uint32{nleExecPid, 0} {
		el := newNonLeaderExecLoop(t)
		out := make(chan *event.Pair, 1)
		el.processRawEvent(makeNonLeaderExecEnter(t, 1500, nleExecCaller), out)
		el.processRawEvent(makeProcessExecEventFrom(t, 1600, nleExecPid, nleExecPid, oldTid, "newprog"), out)

		verifyEnterEventPending(t, el, nleExecCaller)
		if _, ok := el.pairs.enters[nleExecPid]; ok {
			t.Errorf("old tid %d: enter appeared under the leader tid", oldTid)
		}
		if _, ok := el.commState().cached(nleExecCaller); !ok {
			t.Errorf("old tid %d: caller comm evicted", oldTid)
		}
	}
}

// TestPairTrackerMoveExecCallerWithoutState pins that a move with nothing
// under the old tid still clears the dead leader's leftovers and creates no
// entries.
func TestPairTrackerMoveExecCallerWithoutState(t *testing.T) {
	p := newPairTracker()
	p.setPrevTime(nleExecPid, 77)
	p.moveExecCaller(nleExecCaller, nleExecPid)
	if len(p.enters) != 0 || len(p.prevTimes) != 0 || len(p.prevTimeAges) != 0 {
		t.Fatalf("tracker not empty after move: enters=%v prevTimes=%v", p.enters, p.prevTimes)
	}
}

// feedExecveExit drives one execve exit with ret under tid and returns the
// completed row, or nil.
func feedExecveExit(t *testing.T, el *eventLoop, time uint64, tid uint32, ret int64) *event.Pair {
	t.Helper()
	out := make(chan *event.Pair, 1)
	_, exitRaw := makeExitRetEvent(t, time, nleExecPid, tid, types.SYS_EXIT_EXECVE, ret)
	el.processRawEvent(exitRaw, out)
	select {
	case ep := <-out:
		return ep
	default:
		return nil
	}
}

// TestNonLeaderExecWithLostExecRecordStillPairs covers the lost
// sched_process_exec record: BPF already moved its enter state, so the exit
// arrives under the leader tid, but userspace never re-keyed the caller's
// enter. The successful execve exit under tid == pid must adopt it.
func TestNonLeaderExecWithLostExecRecordStillPairs(t *testing.T) {
	el := newNonLeaderExecLoop(t)
	completeCallerAccess(t, el, 1000, 1100)
	out := make(chan *event.Pair, 1)
	el.processRawEvent(makeNonLeaderExecEnter(t, 1500, nleExecCaller), out)
	el.processRawEvent(makeThreadExitEvent(t, 1997, nleExecPid, nleExecPid), out)

	ep := feedExecveExit(t, el, 2000, nleExecPid, 0)
	if ep == nil {
		t.Fatal("lost exec record: the execve exit did not adopt the caller's enter")
	}
	defer ep.Recycle()
	if got := ep.EnterEv.GetTid(); got != nleExecCaller {
		t.Errorf("row tid = %d, want %d", got, nleExecCaller)
	}
	if ep.Duration != 500 || ep.DurationToPrev != 400 {
		t.Errorf("row duration/gap = %d/%d, want 500/400", ep.Duration, ep.DurationToPrev)
	}
	assertNoCallerState(t, el)
}

// lostExecCase drives one unrelated exit past a parked non-leader exec enter.
type lostExecCase struct {
	name  string
	drive func(t *testing.T, el *eventLoop) *event.Pair
}

// lostExecUnrelatedExitCases lists the exits that must not adopt the parked
// enter of the caller's exec.
func lostExecUnrelatedExitCases() []lostExecCase {
	return []lostExecCase{
		{"failed execve exit", func(t *testing.T, el *eventLoop) *event.Pair {
			return feedExecveExit(t, el, 2000, nleExecPid, -2)
		}},
		{"exit under another non-leader tid", func(t *testing.T, el *eventLoop) *event.Pair {
			return feedExecveExit(t, el, 2000, nleExecCaller+1, 0)
		}},
		{"non-exec exit under the leader", func(t *testing.T, el *eventLoop) *event.Pair {
			out := make(chan *event.Pair, 1)
			_, exitRaw := makeExitRetEvent(t, 2000, nleExecPid, nleExecPid, types.SYS_EXIT_ACCESS, 0)
			el.processRawEvent(exitRaw, out)
			select {
			case ep := <-out:
				return ep
			default:
				return nil
			}
		}},
	}
}

// TestLostExecRecordFallbackIsNarrow pins what the fallback must not adopt:
// a failed execve exit (a failed exec keeps its tid), an exit under a
// non-leader tid, a non-exec exit, and a hint whose enter was already
// consumed by the caller's own exit.
func TestLostExecRecordFallbackIsNarrow(t *testing.T) {
	for _, tc := range lostExecUnrelatedExitCases() {
		t.Run(tc.name, func(t *testing.T) {
			el := newNonLeaderExecLoop(t)
			el.processRawEvent(makeNonLeaderExecEnter(t, 1500, nleExecCaller), make(chan *event.Pair, 1))
			if ep := tc.drive(t, el); ep != nil {
				ep.Recycle()
				t.Fatal("unrelated exit adopted the caller's exec enter")
			}
			verifyEnterEventPending(t, el, nleExecCaller)
		})
	}

	t.Run("stale hint", func(t *testing.T) {
		el := newNonLeaderExecLoop(t)
		el.processRawEvent(makeNonLeaderExecEnter(t, 1500, nleExecCaller), make(chan *event.Pair, 1))
		// The caller's own failed execve consumes its enter.
		if ep := feedExecveExit(t, el, 1600, nleExecCaller, -2); ep != nil {
			ep.Recycle()
		} else {
			t.Fatal("caller's failed execve produced no row")
		}
		// A later enter under the caller's tid that is not an exec must
		// not be taken for a parked exec enter.
		_, accessRaw := makeEnterPathEvent(t, 1700, nleExecPid, nleExecCaller, "/etc/hosts", types.SYS_ENTER_ACCESS)
		el.processRawEvent(accessRaw, make(chan *event.Pair, 1))
		if ep := feedExecveExit(t, el, 2000, nleExecPid, 0); ep != nil {
			ep.Recycle()
			t.Fatal("exit adopted an enter through a stale hint")
		}
		verifyEnterEventPending(t, el, nleExecCaller)
	})
}

// TestExecCallerIndexStaysBounded pins that hints of enters trimmed from the
// pending-enter LRU do not accumulate: the index is pruned back to the live
// exec enters once it outgrows the limit.
func TestExecCallerIndexStaysBounded(t *testing.T) {
	p := newPairTracker()
	p.maxSize = 4
	for pid := uint32(1); pid <= 64; pid++ {
		enter := &types.ExecEvent{EventType: types.ENTER_EXEC_EVENT, TraceId: types.SYS_ENTER_EXECVE,
			Pid: pid * 10, Tid: pid*10 + 1}
		p.set(enter)
	}
	// indexExecCaller prunes dead hints while enters still holds the new
	// enter on top of the limit (limit+1 pairs, so at most limit+1 live
	// hints survive); only afterwards does prune() trim the OLDEST enters,
	// which can leave the hints of those just-trimmed pairs stale until the
	// next pruning pass. Hence the bound is limit+1, not limit.
	if got := p.execCallerHints; got > p.limit()+1 {
		t.Fatalf("exec caller index holds %d hints, want at most %d", got, p.limit()+1)
	}
	total := 0
	for _, tids := range p.execCallers {
		total += len(tids)
	}
	if total != p.execCallerHints {
		t.Fatalf("execCallerHints = %d, but the index holds %d tids", p.execCallerHints, total)
	}
}

// TestLostExecRecordAdoptsSurvivingConcurrentCaller pins the per-pid set:
// two threads of one process park execve enters, the later one is killed by
// de_thread (its exit record evicts it), and the winner's exec record is
// lost. The winner's enter must still be adopted by the exit under the pid.
func TestLostExecRecordAdoptsSurvivingConcurrentCaller(t *testing.T) {
	const loser = nleExecCaller + 1
	el := newNonLeaderExecLoop(t)
	out := make(chan *event.Pair, 1)
	el.processRawEvent(makeNonLeaderExecEnter(t, 1500, nleExecCaller), out)
	el.processRawEvent(makeNonLeaderExecEnter(t, 1510, loser), out)
	el.processRawEvent(makeThreadExitEvent(t, 1990, nleExecPid, loser), out)
	el.processRawEvent(makeThreadExitEvent(t, 1995, nleExecPid, nleExecPid), out)

	ep := feedExecveExit(t, el, 2000, nleExecPid, 0)
	if ep == nil {
		t.Fatal("the loser's eviction hid the winner's parked exec enter")
	}
	defer ep.Recycle()
	if got := ep.EnterEv.GetTid(); got != nleExecCaller {
		t.Errorf("row tid = %d, want the surviving caller %d", got, nleExecCaller)
	}
	assertNoCallerState(t, el)
}

// TestLeaderExecPairsBeforeFallback pins that the fallback only runs when the
// exit has no enter of its own: with a non-leader exec enter parked and the
// leader's own execve enter parked too, the exit under the pid pairs with the
// leader's enter, and the non-leader's enter stays pending.
func TestLeaderExecPairsBeforeFallback(t *testing.T) {
	el := newNonLeaderExecLoop(t)
	out := make(chan *event.Pair, 1)
	el.processRawEvent(makeNonLeaderExecEnter(t, 1500, nleExecCaller), out)
	el.processRawEvent(makeNonLeaderExecEnter(t, 1600, nleExecPid), out)

	ep := feedExecveExit(t, el, 2000, nleExecPid, 0)
	if ep == nil {
		t.Fatal("the leader's own execve did not pair")
	}
	defer ep.Recycle()
	if got := ep.EnterEv.GetTid(); got != nleExecPid {
		t.Errorf("row tid = %d, want the leader %d", got, nleExecPid)
	}
	verifyEnterEventPending(t, el, nleExecCaller)
}

// makeUntracedExecRecord builds the exec record BPF emits under -tid
// <nleExecCaller>: the caller exec'd onto the filtered leader tid, so the
// record is flagged ExitUntraced.
func makeUntracedExecRecord(t *testing.T, time uint64) []byte {
	t.Helper()
	ev := types.ProcessExecEvent{
		EventType: types.PROCESS_EXEC_EVENT, Time: time, Pid: nleExecPid, Tid: nleExecPid,
		OldTid: nleExecCaller, ExitUntraced: 1,
	}
	copy(ev.Comm[:], "newprog")
	return mustRaw(t, &ev)
}

// feedUntracedExecRecord processes the flagged exec record and returns the
// row it completed, or nil.
func feedUntracedExecRecord(t *testing.T, el *eventLoop, time uint64) *event.Pair {
	t.Helper()
	out := make(chan *event.Pair, 1)
	el.processRawEvent(makeUntracedExecRecord(t, time), out)
	select {
	case ep := <-out:
		return ep
	default:
		return nil
	}
}

// TestUntracedNonLeaderExecCompletesFromExecRecord is the regression test for
// task dp2: under -tid <non-leader> the traced thread's execve returns under
// the filtered leader tid, so its exit never arrives. The flagged exec record
// must still evict the process's FD_CLOEXEC descriptors and complete the
// parked enter as a successful row that ends at the exec record, reported
// under the calling thread, with nothing left behind for either tid.
func TestUntracedNonLeaderExecCompletesFromExecRecord(t *testing.T) {
	cases := []struct {
		name       string
		enterID    types.TraceId
		wantExitID types.TraceId
	}{
		{"execve", types.SYS_ENTER_EXECVE, types.SYS_EXIT_EXECVE},
		{"execveat", types.SYS_ENTER_EXECVEAT, types.SYS_EXIT_EXECVEAT},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			el := newNonLeaderExecLoop(t)
			completeCallerAccess(t, el, 1000, 1100)
			el.fdState().set(7, nleExecPid, file.NewFd(7, "/cloexec", syscall.O_RDONLY|syscall.O_CLOEXEC))
			el.processRawEvent(makeNonLeaderExecEnterFor(t, tc.enterID, 1500, nleExecCaller),
				make(chan *event.Pair, 1))

			ep := feedUntracedExecRecord(t, el, 1800)
			if ep == nil {
				t.Fatal("untraced-exit exec record completed no row: the parked execve enter was left behind")
			}
			defer ep.Recycle()
			assertUntracedExecRow(t, ep, tc.wantExitID)
			verifyFdNotTracked(t, el, nleExecPid, 7)
			assertNoCallerState(t, el)
			if got, ok := el.commState().cached(nleExecPid); !ok || got != "newprog" {
				t.Errorf("leader tid comm = %q (present=%v), want newprog", got, ok)
			}
		})
	}
}

// assertUntracedExecRow checks the row completed from a flagged exec record.
func assertUntracedExecRow(t *testing.T, ep *event.Pair, wantExitID types.TraceId) {
	t.Helper()
	if got := ep.EnterEv.GetTid(); got != nleExecCaller {
		t.Errorf("row tid = %d, want the calling thread %d", got, nleExecCaller)
	}
	if got := ep.ExitEv.GetTraceId(); got != wantExitID {
		t.Errorf("exit trace id = %v, want %v", got, wantExitID)
	}
	ret, ok := ep.ExitEv.(*types.RetEvent)
	if !ok || ret.Ret != 0 || ret.Pid != nleExecPid {
		t.Errorf("exit = %#v, want a successful RetEvent of pid %d", ep.ExitEv, nleExecPid)
	}
	if ep.FileName() != "/usr/bin/newprog" {
		t.Errorf("row file = %q, want /usr/bin/newprog", ep.FileName())
	}
	if ep.Duration != 300 || ep.DurationToPrev != 400 {
		t.Errorf("row duration/gap = %d/%d, want 300/400 (enter to exec record, gap from the caller's access)",
			ep.Duration, ep.DurationToPrev)
	}
}

// TestUntracedExecRecordWithoutExecEnterEmitsNothing pins the negative
// paths: a flagged exec record with no parked enter (execve not traced), or
// with only a stale non-exec enter under the caller (its exit was lost), must
// not fabricate a row, and must still evict FD_CLOEXEC descriptors. The
// stale enter never reaches completeUntracedExec: rekeyExecCaller's
// moveExecCaller moves only exec enters and recycles anything else, so the
// completion finds no pending enter under the leader tid. execExitTraceID's
// own non-exec guard is covered by TestExecExitTraceID.
func TestUntracedExecRecordWithoutExecEnterEmitsNothing(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, el *eventLoop)
	}{
		{"no parked enter", func(*testing.T, *eventLoop) {}},
		{"stale non-exec enter", func(t *testing.T, el *eventLoop) {
			_, raw := makeEnterPathEvent(t, 900, nleExecPid, nleExecCaller, "/etc/hosts", types.SYS_ENTER_ACCESS)
			el.processRawEvent(raw, make(chan *event.Pair, 1))
			verifyEnterEventPending(t, el, nleExecCaller)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			el := newNonLeaderExecLoop(t)
			el.fdState().set(7, nleExecPid, file.NewFd(7, "/cloexec", syscall.O_RDONLY|syscall.O_CLOEXEC))
			tc.setup(t, el)
			if ep := feedUntracedExecRecord(t, el, 1800); ep != nil {
				ep.Recycle()
				t.Fatal("flagged exec record fabricated a row without a parked execve enter")
			}
			if el.numTracepointMismatches != 0 {
				t.Errorf("numTracepointMismatches = %d, want 0", el.numTracepointMismatches)
			}
			verifyFdNotTracked(t, el, nleExecPid, 7)
			assertNoCallerState(t, el)
		})
	}
}

// TestUnflaggedNonLeaderExecRecordWaitsForExit is the counterpart: without
// ExitUntraced the execve's exit is still coming, so the record must only
// re-key the enter, not complete it.
func TestUnflaggedNonLeaderExecRecordWaitsForExit(t *testing.T) {
	el := newNonLeaderExecLoop(t)
	out := make(chan *event.Pair, 1)
	el.processRawEvent(makeNonLeaderExecEnter(t, 1500, nleExecCaller), out)
	el.processRawEvent(makeProcessExecEventFrom(t, 1800, nleExecPid, nleExecPid, nleExecCaller, "newprog"), out)
	select {
	case ep := <-out:
		ep.Recycle()
		t.Fatal("unflagged exec record completed the execve before its exit arrived")
	default:
	}
	verifyEnterEventPending(t, el, nleExecPid)
}

// TestExecExitTraceID pins the exit trace id a flagged exec record completes
// with, and that no other syscall's enter is completed at all.
func TestExecExitTraceID(t *testing.T) {
	cases := []struct {
		name   string
		enter  types.TraceId
		want   types.TraceId
		wantOK bool
	}{
		{"execve", types.SYS_ENTER_EXECVE, types.SYS_EXIT_EXECVE, true},
		{"execveat", types.SYS_ENTER_EXECVEAT, types.SYS_EXIT_EXECVEAT, true},
		{"access", types.SYS_ENTER_ACCESS, 0, false},
		{"exit id of execve", types.SYS_EXIT_EXECVE, 0, false},
		{"zero", 0, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := execExitTraceID(tc.enter)
			if got != tc.want || ok != tc.wantOK {
				t.Fatalf("execExitTraceID(%v) = %v, %v; want %v, %v", tc.enter, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}
