package internal

import (
	"maps"
	"slices"
	"testing"

	"ior/internal/event"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

// Task v13, review follow-up: what an exec exit without an enter may adopt,
// what the adopted pair proves, and what a proven exec costs a process that
// holds no row. The proofs themselves are tested in
// eventloop_restart_reexec_test.go.

// execCallersInFlight are the two places the exec enter of a non-leader
// thread (restartTid, entered at restartBase+800) waits for its exit: parked
// under the thread's tid, or kept with the row of the execve's interrupted
// first run. Both are candidates for an exec exit under the leader tid that
// has no enter of its own (adoptLostExecCaller).
func execCallersInFlight() map[string]func(f *restartFixture) {
	return map[string]func(f *restartFixture){
		"parked": func(f *restartFixture) {
			f.feedNone(f.execEnter(restartBase+800, restartTid), "the thread's execve enter")
		},
		"kept with its held row": func(f *restartFixture) { f.interruptExecve(restartTid) },
	}
}

// holdOtherThreadsRead leaves a read of restartOtherTid held with its
// re-executed enter kept, and returns the interrupted row.
func (f *restartFixture) holdOtherThreadsRead() restartRow {
	f.t.Helper()
	f.interruptRead(restartBase-300, restartOtherTid, restartSys)
	f.feedNone(f.resumeRecord(restartBase+900, restartOtherTid), "RESUME record")
	f.feedNone(f.readEnter(restartBase+900, restartOtherTid), "re-executed read enter")
	return restartRow{name: "read", tid: restartOtherTid, ret: restartSys, enterTime: restartBase - 300, duration: 500}
}

// requireExecCallerInFlight fails unless restartTid's exec enter is where
// execCallersInFlight left it: parked with its hint in the index of exec
// callers, or kept with the held row.
func (f *restartFixture) requireExecCallerInFlight() {
	f.t.Helper()
	if _, parked := f.el.pairs.pending(restartTid); parked {
		if f.el.pairs.execCallerHints != 1 {
			f.t.Fatalf("exec caller hints = %v, want the parked caller's kept", f.el.pairs.execCallers)
		}
		return
	}
	f.requireExecveStillContinuing(restartTid)
}

// TestFilterAnsweredLeaderExecveCostsNoLiveThreadItsRow: a seccomp filter
// answers the leader's execve with 0 - an exit under the leader tid, no
// enter, no exec record - while a non-leader thread is inside a real execve
// and a third thread, alive, holds a read with its re-executed enter kept.
// The exit used to adopt the non-leader's enter (a wrong execve row, and the
// thread's real execve then without its enter), and since the adopted pair
// counted as a proof of an exec, the live thread's row was released, its
// kept enter recycled and its tid retired: the read's real exit made no row
// and was not counted. With exec records trusted and no record dropped since
// the candidate's enter - none at all, or one the monitor saw before it -
// the exit adopts nothing: the read folds, and the thread's real execve
// pairs when its exec record and exit arrive.
func TestFilterAnsweredLeaderExecveCostsNoLiveThreadItsRow(t *testing.T) {
	for name, enterExecve := range execCallersInFlight() {
		for drops, dropBefore := range map[string]bool{"nothing dropped": false, "a drop seen before the enter": true} {
			t.Run(name+", "+drops, func(t *testing.T) {
				f := newReexecFixture(t, globalfilter.Filter{})
				if dropBefore {
					f.loseRecords(1)
					f.monitorPoll(restartBase - 1000)
				}
				f.holdOtherThreadsRead()
				enterExecve(f)
				counted := f.el.numSyscalls
				f.clockAt(restartBase + 2950)
				f.feedNone(f.execExit(restartBase+2900, restartPid, 0), "the filter-answered execve exit")
				f.requireExecCallerInFlight()
				if f.el.numSyscalls != counted || f.el.numTracepointMismatches != 0 {
					t.Fatalf("numSyscalls=%d mismatches=%d, want %d and 0: the exit pairs with nothing",
						f.el.numSyscalls, f.el.numTracepointMismatches, counted)
				}
				f.requireLiveThreadsReadFolds()
				f.requireExecCallerInFlight()
				f.requireRealExecvePairs()
			})
		}
	}
}

// TestRefusedParkedExecCallerEndsTheSearch: the filter answers the leader's
// execve while two non-leader threads are inside real execves. One has its
// enter parked, with nothing dropped since. The other's was interrupted and
// re-executed, its second enter kept with the held row - an enter older than
// a drop the monitor saw before the parked caller entered. The parked
// caller is asked first and refused, and that is the answer for the process:
// the thread is alive, so nobody has exec'd since its enter. The exit used
// to go on to the held thread, whose enter the drop does cover, adopt it and
// take the pair for a proof: the thread's -513 row and a wrong successful
// execve came out, and the row of a third, live thread was released. Now
// nothing is adopted and nothing released; all three stay where they were.
func TestRefusedParkedExecCallerEndsTheSearch(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	f.holdOtherThreadsRead()
	f.interruptExecve(restartTid)
	f.loseRecords(1)
	f.monitorPoll(restartBase + 1000)
	const parkedAt = restartBase + 1500
	f.feedNone(f.execEnter(parkedAt, restartThirdTid), "the parked caller's execve enter")
	counted := f.el.numSyscalls
	f.clockAt(restartBase + 2950)
	f.feedNone(f.execExit(restartBase+2900, restartPid, 0), "the filter-answered execve exit")
	if f.el.numSyscalls != counted || f.el.numTracepointMismatches != 0 {
		t.Fatalf("numSyscalls=%d mismatches=%d, want %d and 0: the exit pairs with nothing",
			f.el.numSyscalls, f.el.numTracepointMismatches, counted)
	}
	f.requireHeldUnder(restartOtherTid, restartTid)
	f.requireExecveStillContinuing(restartTid)
	if held, _ := f.el.restarts.lookup(restartOtherTid); held.continuation == nil {
		t.Fatal("the live thread's kept read enter is gone")
	}
	parked, ok := f.el.pairs.pending(restartThirdTid)
	if !ok || parked.EnterEv.GetTime() != parkedAt || f.el.pairs.execCallerHints != 1 {
		t.Fatalf("the parked caller: %+v (parked=%t, %d hints), want its enter parked and its hint kept",
			parked, ok, f.el.pairs.execCallerHints)
	}
}

// TestHeldExecCallerIsJudgedByItsReexecutedEnter pins the time a held
// candidate is asked about: that of its kept, re-executed enter
// (restartBase+800), not of the row's -513 exit (restartBase+500). The exec
// record is reserved after the enter the exec ran from, so a drop first seen
// between the two is one seen before the candidate's enter and no evidence;
// judged by the exit's time it adopted. A drop first seen at the enter's own
// time is evidence, as at every "at or after" of the watch.
//
// The clock is scripted for this: a live loop that saw a drop between the
// two refuses the fold at RESUME and holds no such row. Stamps that lie in
// the records' past (an unknown boottime offset) get a run there.
func TestHeldExecCallerIsJudgedByItsReexecutedEnter(t *testing.T) {
	for _, tc := range []struct {
		name   string
		seenAt uint64
		rows   int
	}{
		{"a drop seen between the -513 exit and the enter", restartBase + 650, 0},
		{"a drop seen at the enter's time", restartBase + 800, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newReexecFixture(t, globalfilter.Filter{})
			f.interruptExecve(restartTid)
			f.loseRecords(1)
			f.monitorPoll(tc.seenAt)
			f.clockAt(restartBase + 2950)
			rows := f.feed(f.execExit(restartBase+2900, restartPid, 0))
			if len(rows) != tc.rows {
				t.Fatalf("rows = %+v, want %d", rows, tc.rows)
			}
			if tc.rows == 0 {
				f.requireHeldUnder(restartTid)
				f.requireExecveStillContinuing(restartTid)
				return
			}
			f.requireNothingHeld()
		})
	}
}

// requireLiveThreadsReadFolds feeds the exit of the read holdOtherThreadsRead
// left re-executing and fails unless it folds into the held row: one row,
// from the first enter to this exit, counted once with its first exit.
func (f *restartFixture) requireLiveThreadsReadFolds() {
	f.t.Helper()
	counted := f.el.numSyscalls
	f.clockAt(restartBase + 3550)
	rows := f.feed(f.readExit(restartBase+3500, restartOtherTid, 7))
	want := restartRow{name: "read", tid: restartOtherTid, ret: 7, enterTime: restartBase - 300, duration: 3800}
	if len(rows) != 1 || rows[0] != want || f.el.numSyscalls != counted {
		f.t.Fatalf("the live thread's read gave %+v (numSyscalls %d -> %d), want the folded row %+v",
			rows, counted, f.el.numSyscalls, want)
	}
}

// requireRealExecvePairs feeds the exec record and the exit of restartTid's
// execve and fails unless the exit pairs with the enter the thread made the
// call with: the last row is its successful execve.
func (f *restartFixture) requireRealExecvePairs() {
	f.t.Helper()
	rows := f.feed(f.execRecord(restartBase+4000, restartPid, restartTid, false))
	rows = append(rows, f.feed(f.execExit(restartBase+4500, restartPid, 0))...)
	if len(rows) == 0 {
		f.t.Fatal("the thread's real execve has no row")
	}
	last := rows[len(rows)-1]
	if last.name != "execve" || last.tid != restartTid || last.ret != 0 || last.enterTime != restartBase+800 {
		f.t.Fatalf("rows = %+v, want the thread's execve from its enter at %d last", rows, restartBase+800)
	}
	f.requireNothingHeld()
	f.requireNoEnterPending(restartTid, restartPid)
}

// TestLostExecRecordAdoptionReleasesTheDeadThreadsRows is the same stream
// with the evidence the adoption asks for: a record was dropped after the
// thread entered its execve, so its exec record may be the lost one. The
// exit adopts the enter, the pair proves the exec, and the row another
// thread still holds - a thread that exec killed, its exit record lost too -
// is released behind it, the kept enter recycled and the tid retired.
func TestLostExecRecordAdoptionReleasesTheDeadThreadsRows(t *testing.T) {
	execve := map[string][]restartRow{
		"parked":                 {{name: "execve", tid: restartTid, enterTime: restartBase + 800, duration: 2100}},
		"kept with its held row": {interruptedExecveRow, {name: "execve", tid: restartTid, enterTime: restartBase + 800, duration: 2100, gap: 300}},
	}
	for name, enterExecve := range execCallersInFlight() {
		t.Run(name, func(t *testing.T) {
			f := newReexecFixture(t, globalfilter.Filter{})
			dead := f.holdOtherThreadsRead()
			enterExecve(f)
			f.loseExecRecord(restartBase + 2950)
			want := append(slices.Clone(execve[name]), dead)
			if rows := f.feed(f.execExit(restartBase+2900, restartPid, 0)); !slices.Equal(rows, want) {
				t.Fatalf("rows = %+v, want %+v", rows, want)
			}
			f.requireNothingHeld()
			f.requireTidsRetired(restartTid, restartOtherTid)
		})
	}
}

// TestUntrustedExecRecordsAdoptButProveNothing: in a run whose exec records
// nothing vouches for - the exec probe not attached, or no drop counter - a
// missing exec record is no evidence either way. The exit adopts the
// candidate's enter as it did before task v13, since such a run has no other
// way to the row of a non-leader exec, but the pair is not taken for a proof:
// the row another thread holds stays held, with its kept enter.
func TestUntrustedExecRecordsAdoptButProveNothing(t *testing.T) {
	for name, enterExecve := range execCallersInFlight() {
		t.Run(name, func(t *testing.T) {
			f := newReexecFixture(t, globalfilter.Filter{})
			f.el.trustExecRecords(false)
			f.holdOtherThreadsRead()
			enterExecve(f)
			rows := f.feed(f.execExit(restartBase+2900, restartPid, 0))
			if len(rows) == 0 || rows[len(rows)-1].name != "execve" || rows[len(rows)-1].tid != restartTid {
				t.Fatalf("rows = %+v, want the adopted execve of tid %d last", rows, restartTid)
			}
			f.requireHeldUnder(restartOtherTid)
			if held, _ := f.el.restarts.lookup(restartOtherTid); held.continuation == nil {
				t.Fatal("the other thread's kept enter is gone")
			}
			f.requireLiveThreadsReadFolds()
		})
	}
}

// TestTrustExecRecordsNeedsTheProbeAndTheCounter: exec records are trusted
// only when the loop was told that the sched_process_exec probe attached and
// has a drop counter; by default, and with either missing, they are not, and
// an exec exit without an enter adopts unchecked.
func TestTrustExecRecordsNeedsTheProbeAndTheCounter(t *testing.T) {
	counted := newDropCountedFixture(t, globalfilter.Filter{}).el
	uncounted := newRestartFixture(t, globalfilter.Filter{}).el
	if counted.execRecordsTrusted || uncounted.execRecordsTrusted {
		t.Fatal("exec records are trusted by a loop nobody told")
	}
	for _, tc := range []struct {
		name     string
		el       *eventLoop
		attached bool
		want     bool
	}{
		{"probe and counter", counted, true, true},
		{"no probe", counted, false, false},
		{"no counter", uncounted, true, false},
	} {
		tc.el.trustExecRecords(tc.attached)
		if tc.el.execRecordsTrusted != tc.want {
			t.Fatalf("%s: execRecordsTrusted = %t, want %t", tc.name, tc.el.execRecordsTrusted, tc.want)
		}
	}
}

// TestLostExecRecordExitWithAParkedCallerStaysWithTheLeadersExecve pins the
// other form of the stream nothing decides (adoptLostExecCaller): the leader
// holds an execve re-executed with its enter kept, and a non-leader thread
// has an execve enter parked. The exit under the leader tid is the next step
// of the leader's fold and is taken as that - one row, or the -513 row and
// the execve's own when the fold is refused - and the parked caller is not
// asked. Its enter stays parked: enters of threads an exec ended are not
// released behind the exec, only held rows are.
func TestLostExecRecordExitWithAParkedCallerStaysWithTheLeadersExecve(t *testing.T) {
	leaders := map[string][]restartRow{
		"folded": {{name: "execve", tid: restartPid, enterTime: restartBase, duration: 3000}},
		"refused": {{name: "execve", tid: restartPid, ret: restartNoIntr, enterTime: restartBase, duration: 500},
			{name: "execve", tid: restartPid, enterTime: restartBase + 800, duration: 2200, gap: 300}},
	}
	for name, want := range leaders {
		t.Run(name, func(t *testing.T) {
			f := newReexecFixture(t, globalfilter.Filter{})
			f.el.setCachedComm(restartPid, "leader")
			f.interruptExecve(restartPid)
			f.feedNone(f.execEnter(restartBase+900, restartTid), "the other thread's execve enter")
			if name == "refused" {
				f.loseRecords(3)
				f.clockAt(restartBase + 9000)
			}
			if rows := f.feed(f.execExit(restartBase+3000, restartPid, 0)); !slices.Equal(rows, want) {
				t.Fatalf("rows = %+v, want %+v", rows, want)
			}
			f.requireNothingHeld()
			f.requireNoEnterPending(restartPid)
			if parked, ok := f.el.pairs.pending(restartTid); !ok || parked.EnterEv.GetTime() != restartBase+900 {
				t.Fatalf("the other thread's enter: %+v (parked=%t), want it left parked", parked, ok)
			}
		})
	}
}

// heldReadOf is a held row built by hand: an interrupted read of thread tid
// of process pid, its exit stamped exitAt.
func heldReadOf(pid, tid uint32, exitAt uint64) *heldRestart {
	return &heldRestart{pair: &event.Pair{
		EnterEv: &types.FdEvent{TraceId: types.SYS_ENTER_READ, Pid: pid, Tid: tid},
		ExitEv:  &types.RetEvent{TraceId: types.SYS_EXIT_READ, Time: exitAt, Pid: pid, Tid: tid, Ret: restartSys},
	}}
}

// requireHeldCounted fails unless the tracker's per-process count (heldOf)
// is exactly what its held rows add up to, with no entry for a process that
// holds none. A count too low would hide a process's rows from the release
// behind its exec (takeProcess); one too high only costs the scan back.
func requireHeldCounted(t *testing.T, r *restartTracker) {
	t.Helper()
	want := make(map[uint32]int)
	for _, held := range r.held {
		want[held.pair.ExitEv.GetPid()]++
	}
	if !maps.Equal(r.heldOf, want) {
		t.Fatalf("rows counted per process = %v, held rows add up to %v", r.heldOf, want)
	}
}

// TestHeldRowsAreCountedPerProcess follows the count through every way a row
// enters and leaves the tracker: hold, a second hold under the same tid,
// take, takeProcess, takeInterruptedBy and takeAll.
func TestHeldRowsAreCountedPerProcess(t *testing.T) {
	const a, b = uint32(absentPidBase + 7), uint32(absentPidBase + 60)
	tracker := restartTracker{restartBlock: true, reexec: true}
	steps := []struct {
		name string
		do   func()
		held int
	}{
		{"three rows of a, two of b", func() {
			for _, row := range []*heldRestart{heldReadOf(a, a, 100), heldReadOf(a, a+1, 200), heldReadOf(a, a+2, 300),
				heldReadOf(b, b, 100), heldReadOf(b, b+1, 400)} {
				tracker.hold(row)
			}
		}, 5},
		{"a tid's row replaced by another process's", func() { tracker.hold(heldReadOf(b, a+2, 350)) }, 5},
		{"take", func() { tracker.take(a) }, 4},
		{"take of a tid without a row", func() { tracker.take(a + 9) }, 4},
		{"takeProcess", func() { tracker.takeProcess(a) }, 3},
		{"takeProcess of a process without rows", func() { tracker.takeProcess(a) }, 3},
		{"takeInterruptedBy", func() { tracker.takeInterruptedBy(100) }, 2},
		{"takeAll", func() { tracker.takeAll() }, 0},
	}
	for _, step := range steps {
		step.do()
		if len(tracker.held) != step.held {
			t.Fatalf("after %s: %d rows held, want %d", step.name, len(tracker.held), step.held)
		}
		requireHeldCounted(t, &tracker)
	}
}

// holdStrangersRows fills the fixture's tracker with n rows, one process
// each, none of them the fixture's.
func (f *restartFixture) holdStrangersRows(n uint32) {
	f.t.Helper()
	for i := range n {
		pid := restartStrangerPid + 100 + i
		if !f.el.restarts.hold(heldReadOf(pid, pid, restartBase+uint64(i))) {
			f.t.Fatalf("row %d was not held", i)
		}
	}
}

// TestProvenExecOfAProcessWithoutHeldRowsAllocatesNothing: nearly every exec
// a host-wide trace sees is of a process that holds no row, and each is
// proven twice (exec record, then the paired exit). While other processes
// hold rows, the release behind such a record used to allocate a slice for
// every held row and scan them all. It allocates nothing now - the process
// is answered from the per-process count - and neither does a takeWhere
// that matches nothing.
func TestProvenExecOfAProcessWithoutHeldRowsAllocatesNothing(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	f.holdStrangersRows(512)
	behindExec := testing.AllocsPerRun(100, func() {
		f.el.restarts.noteExec(restartPid)
		f.el.releaseRestartsBehindExec(f.out)
	})
	noMatch := testing.AllocsPerRun(100, func() { f.el.restarts.takeInterruptedBy(restartBase - 1) })
	if behindExec != 0 || noMatch != 0 {
		t.Fatalf("allocations: %v behind the exec, %v for a takeWhere without a match, want none", behindExec, noMatch)
	}
	if len(f.el.restarts.held) != 512 || f.el.restarts.execed.noted {
		t.Fatalf("%d rows held, proof still noted=%t, want the 512 rows left and the proof spent",
			len(f.el.restarts.held), f.el.restarts.execed.noted)
	}
}

// BenchmarkProvenExecOfAProcessWithoutHeldRows is the cost of that step with
// the tracker at its bound (maxHeldRestarts rows of other processes).
func BenchmarkProvenExecOfAProcessWithoutHeldRows(b *testing.B) {
	el := &eventLoop{}
	el.restarts.restartBlock, el.restarts.reexec = true, true
	for i := range uint32(maxHeldRestarts) {
		pid := restartStrangerPid + 100 + i
		el.restarts.hold(heldReadOf(pid, pid, restartBase+uint64(i)))
	}
	pairs := make(chan *event.Pair, pairChannelSlots)
	b.ReportAllocs()
	for b.Loop() {
		el.restarts.noteExec(restartPid)
		el.releaseRestartsBehindExec(pairs)
	}
}
