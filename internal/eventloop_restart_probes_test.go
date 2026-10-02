package internal

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ior/internal/event"
	"ior/internal/globalfilter"
	"ior/internal/textsafe"
)

// Tests for the restart folds' guard against runtime probe changes (task o03,
// "Runtime probe changes" in eventloop_restart.go). A syscall whose probes are
// switched off in the TUI while a call of it is interrupted is re-executed
// unseen, BPF's pending entry outlives that re-execution, and once the probes
// are on again the task's next call of that syscall is announced as the
// continuation. The loop is told of every probe change (probesChanged, on the
// probe manager's goroutine) and from then on folds nothing into a row
// interrupted before it.

// changeProbes reports a runtime probe change that the probe manager made at
// boot-clock time at: the hook the manager calls, on this goroutine.
func (f *restartFixture) changeProbes(at uint64) {
	f.t.Helper()
	f.clockAt(at)
	f.el.probesChanged()
}

// noticeProbeChange is the loop's select case for a probe change: it takes the
// wake token, which must be there, and returns the rows the woken loop emits.
func (f *restartFixture) noticeProbeChange() []restartRow {
	f.t.Helper()
	select {
	case <-f.el.restarts.probes.wake:
	default:
		f.t.Fatal("the probe change did not wake the loop")
	}
	var rows []restartRow
	f.el.SetPrintCallback(func(ep *event.Pair) {
		rows = append(rows, rowOf(ep))
		ep.Recycle()
	})
	f.el.releaseRestartsBehindProbeChange(f.out)
	return rows
}

// heldPhase is one way a row can stand in the tracker when the probes change:
// hold drives the fixture there, interrupted is the row as it was at its first
// exit, and continuation, when hold took the continuation's enter for the
// fold, is that continuation's exit and the row it must become on its own.
type heldPhase struct {
	hold         func(f *restartFixture)
	interrupted  restartRow
	continuation func(f *restartFixture) []byte
	ownRow       restartRow
}

func heldPhases() map[string]heldPhase {
	read := restartRow{name: "read", tid: restartTid, ret: restartSys, enterTime: restartBase, duration: 500}
	sleep := restartRow{name: "clock_nanosleep", tid: restartTid, ret: -516, enterTime: restartBase, duration: 500,
		sleepNs: restartSleepNs}
	return map[string]heldPhase{
		"-512 waiting": {interrupted: read, hold: func(f *restartFixture) {
			f.interruptRead(restartBase, restartTid, restartSys)
		}},
		"-512 in its handler": {interrupted: read, hold: func(f *restartFixture) {
			f.interruptRead(restartBase, restartTid, restartSys)
			f.feedNone(f.handlerRecord(restartBase+510, restartTid, true), "HANDLER record")
		}},
		"-512 announced": {interrupted: read, hold: func(f *restartFixture) {
			f.interruptRead(restartBase, restartTid, restartSys)
			f.feedNone(f.resumeRecord(restartBase+800, restartTid), "RESUME record")
		}},
		"-512 with its enter taken": {interrupted: read, hold: (*restartFixture).holdReexecutedRead,
			continuation: func(f *restartFixture) []byte { return f.readExit(restartBase+3000, restartTid, 1) },
			ownRow: restartRow{name: "read", tid: restartTid, ret: 1, enterTime: restartBase + 800,
				duration: 2200, gap: 300}},
		"-516 waiting": {interrupted: sleep, hold: func(f *restartFixture) { f.interrupt(restartBase, restartTid) }},
		"-516 with its enter taken": {interrupted: sleep, hold: func(f *restartFixture) {
			f.interrupt(restartBase, restartTid)
			f.resume(restartBase+800, restartTid)
			f.feedNone(f.restartEnter(restartBase+800, restartTid), "restart_syscall enter")
		},
			continuation: func(f *restartFixture) []byte { return f.restartExit(restartBase+3000, restartTid, 0) },
			ownRow: restartRow{name: "restart_syscall", tid: restartTid, ret: 0, enterTime: restartBase + 800,
				duration: 2200, gap: 300}},
	}
}

// TestProbeChangeReleasesHeldRowsInEveryPhase: whatever a held row waits for,
// a runtime probe change ends the wait. The woken loop emits the row as it was
// at its interrupted exit and holds nothing; a continuation whose enter the
// fold had already taken gets that enter back and becomes a row of its own
// when its exit arrives - the two rows ior showed before it folded anything.
func TestProbeChangeReleasesHeldRowsInEveryPhase(t *testing.T) {
	for name, phase := range heldPhases() {
		t.Run(name, func(t *testing.T) {
			f := newReexecFixture(t, globalfilter.Filter{})
			phase.hold(f)
			f.changeProbes(restartBase + 1000)

			rows := f.noticeProbeChange()
			if len(rows) != 1 || rows[0] != phase.interrupted {
				t.Fatalf("released rows = %+v, want the unchanged interrupted row %+v", rows, phase.interrupted)
			}
			f.requireNothingHeld()
			if phase.continuation == nil {
				f.requireNoEnterPending(restartTid)
				return
			}
			if row := f.feedOne(phase.continuation(f), "continuation's exit"); row != phase.ownRow {
				t.Fatalf("continuation's row = %+v, want %+v", row, phase.ownRow)
			}
			if f.el.numSyscalls != 2 {
				t.Fatalf("numSyscalls = %d, want 2: the interrupted call and its continuation", f.el.numSyscalls)
			}
		})
	}
}

// TestCallAfterAProbeChangeIsNotFoldedIntoTheHeldRow is the task's case, with
// a loop that never gets to its wake-up: a read exits -512 and is held, read's
// probes are switched off (the re-execution runs unseen) and on again, and the
// program's next read - announced by BPF from the entry that outlived the
// re-execution, enter and exit in order, nothing lost - arrives. It is a call
// of its own: RESUME releases the held row, and the read pairs as its own row.
func TestCallAfterAProbeChangeIsNotFoldedIntoTheHeldRow(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	f.interruptRead(restartBase, restartTid, restartSys)
	f.changeProbes(restartBase + 10_000) // detached
	f.changeProbes(restartBase + 20_000) // attached again

	f.clockAt(restartBase + 30_050)
	requireInterruptedRow(t, f.feedOne(f.resumeRecord(restartBase+30_000, restartTid), "stale RESUME record"), restartSys)
	f.requireNothingHeld()
	f.feedNone(f.readEnter(restartBase+30_000, restartTid), "the program's own read enter")
	row := f.feedOne(f.readExit(restartBase+31_000, restartTid, 7), "the program's own read exit")
	want := restartRow{name: "read", tid: restartTid, ret: 7, enterTime: restartBase + 30_000, duration: 1000, gap: 29_500}
	if row != want || f.el.numSyscalls != 2 {
		t.Fatalf("row = %+v numSyscalls=%d, want the read as its own row %+v and 2 calls", row, f.el.numSyscalls, want)
	}
}

// TestRestartSyscallAfterAProbeChangeIsNotFoldedIntoTheHeldSleep is the same
// for a stopped sleep: restart_syscall's probes were off when the kernel
// resumed the sleep, and the restart_syscall announced after they came back
// resumes a later stopped call of the thread.
func TestRestartSyscallAfterAProbeChangeIsNotFoldedIntoTheHeldSleep(t *testing.T) {
	eachRestartFixture(t, func(t *testing.T, newFixture restartFixtureMaker) {
		f := newFixture(t, globalfilter.Filter{})
		now := uint64(0)
		f.el.dropStampClock = func() uint64 { return now }
		f.interrupt(restartBase, restartTid)
		now = restartBase + 10_000
		f.el.probesChanged()

		now = restartBase + 30_050
		sleep := f.feedOne(f.resumeRecord(restartBase+30_000, restartTid), "stale RESUME record")
		if sleep.name != "clock_nanosleep" || sleep.ret != -516 || sleep.duration != 500 {
			t.Fatalf("released row = %+v, want the unchanged -516 sleep", sleep)
		}
		f.feedNone(f.restartEnter(restartBase+30_000, restartTid), "a later call's restart_syscall enter")
		row := f.feedOne(f.restartExit(restartBase+31_000, restartTid, 0), "a later call's restart_syscall exit")
		if row.name != "restart_syscall" || row.enterTime != restartBase+30_000 || f.el.numSyscalls != 2 {
			t.Fatalf("row = %+v numSyscalls=%d, want restart_syscall as its own row and 2 calls", row, f.el.numSyscalls)
		}
	})
}

// TestProbeChangeAfterTheEnterWasTakenRefusesTheFold: the announced enter was
// taken while everything was attached, then the probes change, and an exit of
// the syscall arrives. The continuation's own exit may have gone unseen while
// the exit probe was off, and this one may belong to a call that was in flight
// when it came back. The loop, not woken here, refuses at the exit: the
// interrupted row, and the enter paired with that exit as a row of its own.
func TestProbeChangeAfterTheEnterWasTakenRefusesTheFold(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	f.holdReexecutedRead()
	f.changeProbes(restartBase + 900)

	f.clockAt(restartBase + 3050)
	requireTwoRows(t, f.feed(f.readExit(restartBase+3000, restartTid, 1)), restartBase, restartBase+3000, 1)
	f.requireNothingHeld()
}

// TestRowInterruptedBeforeAProbeChangeIsNotHeld: a loop that lags behind the
// ring buffer learns of the change before it reads the interrupted exit. A
// rule that released "the rows held when the change was noticed" would hold
// this row afterwards and fold the stale announcement into it; the row is
// judged by the time of its exit instead, is emitted at once, and the call
// announced later is a row of its own.
func TestRowInterruptedBeforeAProbeChangeIsNotHeld(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	f.changeProbes(restartBase + 10_000)
	if rows := f.noticeProbeChange(); len(rows) != 0 {
		t.Fatalf("woken loop emitted %+v with nothing held", rows)
	}

	f.feedNone(f.readEnter(restartBase, restartTid), "read enter")
	requireInterruptedRow(t, f.feedOne(f.readExit(restartBase+500, restartTid, restartSys), "interrupted read exit"), restartSys)
	f.requireNothingHeld()
	f.feedNone(f.resumeRecord(restartBase+30_000, restartTid), "stale RESUME record")
	f.feedNone(f.readEnter(restartBase+30_000, restartTid), "the program's own read enter")
	row := f.feedOne(f.readExit(restartBase+31_000, restartTid, 7), "the program's own read exit")
	if row.ret != 7 || row.enterTime != restartBase+30_000 || f.el.numSyscalls != 2 {
		t.Fatalf("row = %+v numSyscalls=%d, want the read as its own row and 2 calls", row, f.el.numSyscalls)
	}
}

// TestProbeChangeBeforeTheInterruptionDoesNotBlockTheFold is the negative: a
// change says nothing about a call interrupted after it. Its row is held, the
// woken loop leaves it alone, and its re-execution folds as in a run whose
// probes never change - for a stopped sleep as well.
func TestProbeChangeBeforeTheInterruptionDoesNotBlockTheFold(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	f.changeProbes(restartBase - 100)
	f.interruptRead(restartBase, restartTid, restartSys)
	if rows := f.noticeProbeChange(); len(rows) != 0 || len(f.el.restarts.held) != 1 {
		t.Fatalf("woken loop emitted %+v and left %d rows held, want the row interrupted after the change still held",
			rows, len(f.el.restarts.held))
	}
	f.clockAt(restartBase + 850)
	f.feedNone(f.resumeRecord(restartBase+800, restartTid), "RESUME record")
	f.feedNone(f.readEnter(restartBase+800, restartTid), "re-executed read enter")
	f.clockAt(restartBase + 3050)
	requireFolded(t, f.feed(f.readExit(restartBase+3000, restartTid, 1)), restartBase, "the probes changed before the interruption")

	f = newReexecFixture(t, globalfilter.Filter{})
	f.changeProbes(restartBase - 100)
	requireFoldedSleep(t, f.foldSleep(restartBase), restartBase, "the probes changed before the interruption")
}

// TestProbeChangeInsideTheInterruptedCallDoesNotBlockTheFold: a row is judged
// by when its call was interrupted, not by when the call began. A read that
// was already blocked when some probe changed and is interrupted afterwards
// has its whole continuation after the change, seen like any other: the row is
// held, the woken loop leaves it alone, and the re-execution folds.
func TestProbeChangeInsideTheInterruptedCallDoesNotBlockTheFold(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	f.feedNone(f.readEnter(restartBase, restartTid), "read enter")
	f.changeProbes(restartBase + 200)
	f.feedNone(f.readExit(restartBase+500, restartTid, restartSys), "read exit interrupted after the probe change")
	if rows := f.noticeProbeChange(); len(rows) != 0 || len(f.el.restarts.held) != 1 {
		t.Fatalf("woken loop emitted %+v and left %d rows held, want the row interrupted after the change still held",
			rows, len(f.el.restarts.held))
	}
	f.clockAt(restartBase + 850)
	f.feedNone(f.resumeRecord(restartBase+800, restartTid), "RESUME record")
	f.feedNone(f.readEnter(restartBase+800, restartTid), "re-executed read enter")
	f.clockAt(restartBase + 3050)
	requireFolded(t, f.feed(f.readExit(restartBase+3000, restartTid, 1)), restartBase,
		"the probes changed while the call was blocked, before it was interrupted")
}

// TestWokenLoopReleasesTheRowsInterruptedUpToTheStamp: the woken loop releases
// what the time rule refuses, no more and no less. A row interrupted in the
// very nanosecond of the stamp is refused (changedSince), so it is released -
// left held, it could only wait for a fold that will not happen. A row
// interrupted one nanosecond later is as sound as any and stays.
func TestWokenLoopReleasesTheRowsInterruptedUpToTheStamp(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	f.interruptRead(restartBase, restartTid, restartSys)        // interrupted at restartBase+500
	f.interruptRead(restartBase+1, restartOtherTid, restartSys) // and one nanosecond later
	f.changeProbes(restartBase + 500)

	rows := f.noticeProbeChange()
	if len(rows) != 1 {
		t.Fatalf("woken loop released %+v, want only the row interrupted at the stamp", rows)
	}
	requireInterruptedRow(t, rows[0], restartSys)
	if _, held := f.el.restarts.lookup(restartOtherTid); !held || len(f.el.restarts.held) != 1 {
		t.Fatalf("%d rows held after the wake, want only the one interrupted after the stamp", len(f.el.restarts.held))
	}
}

// TestWithoutAProbeChangeNothingIsRefused: the watch's zero value is "no
// change", not "a change at time 0" - a record stamped 0 must not be refused
// by it - and its stamp only moves forward, so of two changes reported from
// two goroutines the later one stands whichever is stored last.
func TestWithoutAProbeChangeNothingIsRefused(t *testing.T) {
	var watch restartProbeWatch
	if watch.changedSince(0) || watch.changedSince(restartBase) {
		t.Fatal("a watch nobody reported a change to refuses rows")
	}
	watch.note(500)
	watch.note(300)
	if !watch.changedSince(400) || !watch.changedSince(500) {
		t.Fatal("an earlier stamp stored late moved the watch back: a row interrupted between the two changes folds again")
	}
	if watch.changedSince(501) {
		t.Fatal("a row interrupted after the latest change is refused")
	}
}

// scriptedPendingClearer is the kernel's restart_pending_map as the loop sees
// it: it counts the clears and notes the boot clock at each.
type scriptedPendingClearer struct {
	err       error
	clears    atomic.Int64
	clock     func() uint64
	clearedAt []uint64
}

func (c *scriptedPendingClearer) Clear() error {
	c.clears.Add(1)
	if c.clock != nil {
		c.clearedAt = append(c.clearedAt, c.clock())
	}
	return c.err
}

// TestProbeChangeClearsTheKernelsPendingRestarts: each reported change clears
// restart_pending_map, and the stamp is a clock reading taken AFTER the clear -
// an entry the clear removed must belong to a call the stamp refuses too. Here
// the clear itself takes time: it starts at 100 and the clock stands at 500
// when it is done. A first stamp already stands while the clear runs: after an
// attach the fresh probes record from the moment they are attached, and the
// loop must not fold those records for as long as a clear takes.
func TestProbeChangeClearsTheKernelsPendingRestarts(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	f.clockAt(100)
	pending := &scriptedPendingClearer{}
	var stampedBeforeClear uint64
	pending.clock = func() uint64 {
		defer f.clockAt(500)
		stampedBeforeClear = f.el.restarts.probes.changedAt.Load()
		return f.drops.now
	}
	f.el.restartPending = pending

	f.el.probesChanged()
	if got := pending.clears.Load(); got != 1 || pending.clearedAt[0] != 100 {
		t.Fatalf("clears = %d at %v, want one clear, begun at 100", got, pending.clearedAt)
	}
	if stampedBeforeClear != 100 {
		t.Fatalf("change stamp = %d while the clear ran, want 100: a first stamp before the clear", stampedBeforeClear)
	}
	if got := f.el.restarts.probes.changedAt.Load(); got != 500 {
		t.Fatalf("change stamp = %d, want 500, the reading taken after the clear", got)
	}
	f.el.probesChanged()
	if got := pending.clears.Load(); got != 2 {
		t.Fatalf("clears = %d after a second change, want 2", got)
	}
}

// TestFailedClearStillRefusesTheFold: a clear the kernel refuses is reported
// once, however many probes a family toggle changes, and takes nothing from
// the guard - the stale announcement the map then still makes is refused by
// time.
func TestFailedClearStillRefusesTheFold(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	var warnings []string
	f.el.SetWarningCallback(func(message string) { warnings = append(warnings, message) })
	f.el.restartPending = &scriptedPendingClearer{err: errors.New("bad file descriptor")}
	f.interruptRead(restartBase, restartTid, restartSys)

	f.changeProbes(restartBase + 10_000)
	f.changeProbes(restartBase + 20_000)
	if len(warnings) != 1 || !strings.Contains(warnings[0], "bad file descriptor") {
		t.Fatalf("warnings = %q, want the failed clear reported once", warnings)
	}
	f.clockAt(restartBase + 30_050)
	requireInterruptedRow(t, f.feedOne(f.resumeRecord(restartBase+30_000, restartTid), "stale RESUME record"), restartSys)
}

// TestWatchProbeChangesHooksTheManagerAndReportsOnce: trace setup hands the
// loop the probe manager's SetChangeHook. The loop registers probesChanged
// there and reports one change itself, for one the TUI made before anybody
// listened: the kernel's pending restarts are cleared, the loop is woken, and
// a call interrupted before that stamp is not held.
func TestWatchProbeChangesHooksTheManagerAndReportsOnce(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	pending := &scriptedPendingClearer{}
	f.el.restartPending = pending
	f.clockAt(restartBase + 600)
	var hook func()
	f.el.watchProbeChanges(func(registered func()) { hook = registered })
	if hook == nil {
		t.Fatal("watchProbeChanges registered no hook")
	}
	if got := pending.clears.Load(); got != 1 {
		t.Fatalf("clears = %d after installing the hook, want 1: a toggle made before it left entries behind", got)
	}
	if rows := f.noticeProbeChange(); len(rows) != 0 {
		t.Fatalf("woken loop emitted %+v with nothing held", rows)
	}
	f.feedNone(f.readEnter(restartBase, restartTid), "read enter")
	requireInterruptedRow(t, f.feedOne(f.readExit(restartBase+500, restartTid, restartSys), "interrupted read exit"), restartSys)

	f.clockAt(restartBase + 5000)
	hook()
	if got := f.el.restarts.probes.changedAt.Load(); got != restartBase+5000 {
		t.Fatalf("change stamp = %d after the registered hook ran, want %d", got, restartBase+5000)
	}
}

// probeChangeRun is a running loop for the two tests below: an atomic boot
// clock (the test moves it while the loop runs), an unbuffered raw channel, so
// a send returns only once the loop has taken the record, and the emitted
// rows on a channel with room for every row a test produces (the loop must
// never block on it while the test blocks on the raw channel).
type probeChangeRun struct {
	f     *restartFixture
	now   atomic.Uint64
	rawCh chan []byte
	rows  chan restartRow
	stop  func()
}

func startProbeChangeRun(t *testing.T) *probeChangeRun {
	t.Helper()
	return startProbeChangeRunWith(t, nil)
}

// startProbeChangeRunWith is startProbeChangeRun with the loop's output
// replaced by output, when that is not nil, before the loop starts.
func startProbeChangeRunWith(t *testing.T, output func(el *eventLoop)) *probeChangeRun {
	t.Helper()
	r := &probeChangeRun{f: newRestartFixture(t, globalfilter.Filter{}), rawCh: make(chan []byte),
		rows: make(chan restartRow, 1024)}
	r.f.el.dropStampClock = r.now.Load
	r.f.el.SetPrintCallback(func(ep *event.Pair) {
		r.rows <- rowOf(ep)
		ep.Recycle()
	})
	if output != nil {
		output(r.f.el)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.f.el.run(ctx, r.rawCh)
	}()
	r.stop = func() {
		cancel()
		<-done
	}
	t.Cleanup(r.stop)
	return r
}

// TestRunningLoopReleasesAHeldRowWhenProbesChange: the loop is idle - a
// stopped sleep is held and its thread produces nothing - when another
// goroutine reports a probe change. The loop wakes without a record and emits
// the row.
func TestRunningLoopReleasesAHeldRowWhenProbesChange(t *testing.T) {
	r := startProbeChangeRun(t)
	r.holdStoppedSleep()
	select {
	case row := <-r.rows:
		t.Fatalf("row %+v emitted before the probes changed, want the -516 row held", row)
	default:
	}

	r.now.Store(restartBase + 1000)
	r.f.el.probesChanged()
	select {
	case row := <-r.rows:
		if row.name != "clock_nanosleep" || row.tid != restartTid || row.ret != -516 {
			t.Fatalf("released row = %+v, want the held -516 sleep", row)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the idle loop did not release the held row after a probe change")
	}
}

// holdStoppedSleep feeds the running loop a sleep of restartTid that is stopped
// (-516) and held. The third record is only a marker: the loop takes it after
// it has finished the -516 exit, so the row is held when this returns.
func (r *probeChangeRun) holdStoppedSleep() {
	r.rawCh <- r.f.sleepEnter(restartBase, restartTid)
	r.rawCh <- r.f.sleepExit(restartBase+500, restartTid, -516)
	r.rawCh <- r.f.sleepEnter(restartBase+600, restartOtherTid)
}

// TestRowReleasedByAProbeChangeIsFlushedInAPlainRun: in a -plain run a row
// goes into the sink's buffer and leaves it when the flush timer fires, and
// the timer is armed by whoever buffered a row. The woken loop buffers the
// rows it releases without a record having arrived, so it has to arm the
// timer itself: the held thread is stopped and nothing else may come for a
// long time, and the row would sit in the buffer until then.
func TestRowReleasedByAProbeChangeIsFlushedInAPlainRun(t *testing.T) {
	old := plainFlushInterval
	plainFlushInterval = 20 * time.Millisecond
	t.Cleanup(func() { plainFlushInterval = old })

	w := &recordingWriter{}
	r := startProbeChangeRunWith(t, func(el *eventLoop) {
		sink := newPlainSink(w, textsafe.EscapeNever)
		el.printCb, el.flusher = sink.Print, sink
	})
	r.holdStoppedSleep()
	r.now.Store(restartBase + 1000)
	r.f.el.probesChanged()

	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, out := w.snapshot(); strings.Contains(out, ",clock_nanosleep,") {
			return
		}
		if time.Now().After(deadline) {
			_, out := w.snapshot()
			t.Fatalf("output = %q after the probe change, want the released -516 row written by the flush timer", out)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// changeProbesUntil reports probe changes from two goroutines, each at a new
// clock reading, until the returned function is called; that function waits
// for both to finish.
func (r *probeChangeRun) changeProbesUntil() func() {
	var changers sync.WaitGroup
	stopChanging := make(chan struct{})
	for range 2 {
		changers.Add(1)
		go func() {
			defer changers.Done()
			for {
				select {
				case <-stopChanging:
					return
				default:
					r.now.Add(1)
					r.f.el.probesChanged()
				}
			}
		}()
	}
	return func() {
		close(stopChanging)
		changers.Wait()
	}
}

// TestProbeChangesRaceWithTheRunningLoop: probe changes are reported from the
// goroutines that make them while the loop holds, folds and releases rows.
// Run with -race, this is what notices the loop's tracker being touched from
// the hook. Every stopped sleep ends as one folded row or as two rows, never
// lost and never three, whatever the interleaving.
func TestProbeChangesRaceWithTheRunningLoop(t *testing.T) {
	const sleeps = 300
	r := startProbeChangeRun(t)
	pending := &scriptedPendingClearer{}
	r.f.el.restartPending = pending

	stopChanging := r.changeProbesUntil()
	for range sleeps {
		base := r.now.Add(10_000)
		r.rawCh <- r.f.sleepEnter(base, restartTid)
		r.rawCh <- r.f.sleepExit(base+500, restartTid, -516)
		r.rawCh <- r.f.resumeRecord(base+800, restartTid)
		r.rawCh <- r.f.restartEnter(base+800, restartTid)
		r.rawCh <- r.f.restartExit(base+3000, restartTid, 0)
	}
	stopChanging()
	r.stop()

	if pending.clears.Load() == 0 {
		t.Fatal("no probe change was reported while the loop ran")
	}
	rows := len(r.rows)
	if rows < sleeps || rows > 2*sleeps || uint(rows) != r.f.el.numSyscalls {
		t.Fatalf("%d rows for %d stopped sleeps (numSyscalls %d), want one or two rows per sleep, each counted once",
			rows, sleeps, r.f.el.numSyscalls)
	}
	r.f.requireNothingHeld()
}
