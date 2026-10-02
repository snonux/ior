package internal

import (
	"context"
	"testing"
	"time"

	"ior/internal/event"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

// Tests for folding restart_syscall into the -516 row it resumes (task fs2,
// eventloop_restart.go). Both fixtures leave BPF's re-execution proof off, as
// a run without the signal_deliver probe has it. Every test that drives an
// event loop runs on each of them (eachRestartFixture): without a drop
// counter, as a run on an older BPF object, where the fold goes by the syscall
// stream alone, and with a counter that never moves, which is the run ior
// normally makes and sends each fold through the drop check
// (restartProofLost). What the check does when the counter moves (task p03) is
// tested in eventloop_restart_drops_test.go, and the re-execution fold of
// -512/-513/-514 (task 103) in eventloop_restart_reexec_test.go.

const (
	restartPid      = uint32(4100)
	restartTid      = uint32(4101)
	restartOtherTid = uint32(4102)
	restartSleepNs  = int64(2_000_000_000)
	restartBase     = uint64(1_000_000)
)

// restartRow is what a test needs from an emitted row, copied out so the pair
// can be recycled at once.
type restartRow struct {
	name      string
	tid       uint32
	ret       int64
	enterTime uint64
	duration  uint64
	gap       uint64
	sleepNs   int64
}

func rowOf(ep *event.Pair) restartRow {
	row := restartRow{
		name:      ep.EnterEv.GetTraceId().Name(),
		tid:       ep.EnterEv.GetTid(),
		enterTime: ep.EnterEv.GetTime(),
		duration:  ep.Duration,
		gap:       ep.DurationToPrev,
		sleepNs:   ep.RequestedSleepNs,
	}
	if retEv, ok := ep.ExitEv.(event.RetCarrier); ok {
		row.ret = retEv.GetRet()
	}
	return row
}

// restartFixture drives raw records through one event loop and collects the
// rows each record emits.
type restartFixture struct {
	t   *testing.T
	el  *eventLoop
	out chan *event.Pair
	// drops is the scripted drop counter of a fixture that has one
	// (newDropCountedFixture, newReexecFixture); nil for the plain
	// restart_syscall fixture.
	drops *reexecDrops
}

func newRestartFixture(t *testing.T, filter globalfilter.Filter) *restartFixture {
	t.Helper()
	el := mustNewEventLoop(t, eventLoopConfig{commResolver: newHermeticCommResolver(), filter: filter})
	t.Cleanup(el.commResolver.shutdown)
	el.setCachedComm(restartTid, "sleeper")
	el.setCachedComm(restartOtherTid, "other")
	// As many slots as processRawEvents has: a record may release held rows
	// before its own pair.
	return &restartFixture{t: t, el: el, out: make(chan *event.Pair, pairChannelSlots)}
}

// restartFixtureMaker builds the fixture of one kind of run.
type restartFixtureMaker func(*testing.T, globalfilter.Filter) *restartFixture

// eachRestartFixture runs test once per kind of run the restart_syscall fold
// must behave the same in: without a drop counter (newRestartFixture), where
// the fold is unchecked, and with a counter on which nothing is ever lost
// (newDropCountedFixture), where every fold step asks the drop watch first and
// is told that nothing was lost. The counter and the fixture's boot clock both
// stay at 0, which is enough for that answer: the watch has stood at "0, first
// seen at time 0" since before any record, and an unchanged total is never
// stamped again.
func eachRestartFixture(t *testing.T, test func(t *testing.T, newFixture restartFixtureMaker)) {
	t.Helper()
	runs := []struct {
		name string
		make restartFixtureMaker
	}{
		{"no drop counter", newRestartFixture},
		{"drop counter that never moves", newDropCountedFixture},
	}
	for _, run := range runs {
		t.Run(run.name, func(t *testing.T) { test(t, run.make) })
	}
}

// feed processes one raw record and returns the rows it emitted, in order.
func (f *restartFixture) feed(raw []byte) []restartRow {
	f.t.Helper()
	f.el.processRawEvent(raw, f.out)
	var rows []restartRow
	for {
		select {
		case ep := <-f.out:
			rows = append(rows, rowOf(ep))
			ep.Recycle()
		default:
			return rows
		}
	}
}

// feedNone feeds raw and fails when it emitted a row.
func (f *restartFixture) feedNone(raw []byte, what string) {
	f.t.Helper()
	if rows := f.feed(raw); len(rows) != 0 {
		f.t.Fatalf("%s emitted %+v, want no row yet", what, rows)
	}
}

// feedOne feeds raw and returns the single row it must emit.
func (f *restartFixture) feedOne(raw []byte, what string) restartRow {
	f.t.Helper()
	rows := f.feed(raw)
	if len(rows) != 1 {
		f.t.Fatalf("%s emitted %d rows (%+v), want 1", what, len(rows), rows)
	}
	return rows[0]
}

func (f *restartFixture) sleepEnter(at uint64, tid uint32) []byte {
	f.t.Helper()
	ev := types.SleepEvent{EventType: types.ENTER_SLEEP_EVENT, TraceId: types.SYS_ENTER_CLOCK_NANOSLEEP,
		Time: at, Pid: restartPid, Tid: tid, RequestedNs: restartSleepNs}
	raw, err := ev.Bytes()
	if err != nil {
		f.t.Fatalf("SleepEvent.Bytes() error = %v", err)
	}
	return raw
}

func (f *restartFixture) sleepExit(at uint64, tid uint32, ret int64) []byte {
	f.t.Helper()
	_, raw := makeExitRetEvent(f.t, at, restartPid, tid, types.SYS_EXIT_CLOCK_NANOSLEEP, ret)
	return raw
}

func (f *restartFixture) restartEnter(at uint64, tid uint32) []byte {
	f.t.Helper()
	_, raw := makeEnterNullEvent(f.t, at, restartPid, tid, types.SYS_ENTER_RESTART_SYSCALL)
	return raw
}

func (f *restartFixture) restartExit(at uint64, tid uint32, ret int64) []byte {
	f.t.Helper()
	_, raw := makeExitRetEvent(f.t, at, restartPid, tid, types.SYS_EXIT_RESTART_SYSCALL, ret)
	return raw
}

// interrupt feeds a clock_nanosleep enter at `at` and its -516 exit 500ns
// later, which must both stay silent: the row is held.
func (f *restartFixture) interrupt(at uint64, tid uint32) {
	f.t.Helper()
	f.feedNone(f.sleepEnter(at, tid), "clock_nanosleep enter")
	f.feedNone(f.sleepExit(at+500, tid, -516), "clock_nanosleep -516 exit")
}

func (f *restartFixture) requireNothingHeld() {
	f.t.Helper()
	if n := len(f.el.restarts.held); n != 0 {
		f.t.Fatalf("%d rows still held, want none", n)
	}
}

// TestRestartSyscallFoldsIntoTheInterruptedCall is the positive case: a
// clock_nanosleep stopped by SIGSTOP exits -516, the kernel resumes it via
// restart_syscall after SIGCONT, and ior emits ONE row - the original call
// with its requested sleep, the final return value and the whole span from
// the first enter to the final exit (stopped time included) as latency.
func TestRestartSyscallFoldsIntoTheInterruptedCall(t *testing.T) {
	eachRestartFixture(t, func(t *testing.T, newFixture restartFixtureMaker) {
		f := newFixture(t, globalfilter.Filter{})
		f.interrupt(restartBase, restartTid)
		f.feedNone(f.restartEnter(restartBase+1500, restartTid), "restart_syscall enter")
		row := f.feedOne(f.restartExit(restartBase+3000, restartTid, 0), "restart_syscall exit")

		want := restartRow{name: "clock_nanosleep", tid: restartTid, ret: 0, enterTime: restartBase,
			duration: 3000, sleepNs: restartSleepNs}
		if row != want {
			t.Fatalf("folded row = %+v, want %+v", row, want)
		}
		if f.el.numSyscalls != 1 {
			t.Fatalf("numSyscalls = %d, want 1 (one call)", f.el.numSyscalls)
		}
		f.requireNothingHeld()
	})
}

// TestRestartSyscallFoldsRepeatedStops: a resumed call stopped again exits
// restart_syscall with -516 and is resumed by another restart_syscall; every
// piece folds into the one original row.
func TestRestartSyscallFoldsRepeatedStops(t *testing.T) {
	eachRestartFixture(t, func(t *testing.T, newFixture restartFixtureMaker) {
		f := newFixture(t, globalfilter.Filter{})
		f.interrupt(restartBase, restartTid)
		f.feedNone(f.restartEnter(restartBase+1000, restartTid), "first restart_syscall enter")
		f.feedNone(f.restartExit(restartBase+1500, restartTid, -516), "first restart_syscall -516 exit")
		f.feedNone(f.restartEnter(restartBase+2000, restartTid), "second restart_syscall enter")
		row := f.feedOne(f.restartExit(restartBase+4000, restartTid, 0), "second restart_syscall exit")

		if row.name != "clock_nanosleep" || row.ret != 0 || row.duration != 4000 || row.sleepNs != restartSleepNs {
			t.Fatalf("folded row = %+v, want clock_nanosleep ret=0 duration=4000 sleep=%d", row, restartSleepNs)
		}
		if f.el.numSyscalls != 1 {
			t.Fatalf("numSyscalls = %d, want 1", f.el.numSyscalls)
		}
		f.requireNothingHeld()
	})
}

// TestRestartRowReleasedByAnotherSyscall: a handled signal turns -516 into
// EINTR, so the tid's next record is some other syscall (the handler's, or
// the program's next). The held row is emitted unchanged, before that
// syscall's own row, and the gap chain stays intact.
func TestRestartRowReleasedByAnotherSyscall(t *testing.T) {
	eachRestartFixture(t, func(t *testing.T, newFixture restartFixtureMaker) {
		f := newFixture(t, globalfilter.Filter{})
		f.interrupt(restartBase, restartTid)
		_, syncEnter := makeEnterNullEvent(t, restartBase+800, restartPid, restartTid, types.SYS_ENTER_SYNC)
		released := f.feedOne(syncEnter, "sync enter")
		if released.name != "clock_nanosleep" || released.ret != -516 || released.duration != 500 {
			t.Fatalf("released row = %+v, want clock_nanosleep ret=-516 duration=500", released)
		}
		f.requireNothingHeld()

		_, syncExit := makeExitNullEvent(t, restartBase+900, restartPid, restartTid, types.SYS_EXIT_SYNC)
		sync := f.feedOne(syncExit, "sync exit")
		if sync.name != "sync" || sync.gap != 300 {
			t.Fatalf("sync row = %+v, want name sync and gap 300 from the released row's exit", sync)
		}
		if f.el.numSyscalls != 2 {
			t.Fatalf("numSyscalls = %d, want 2", f.el.numSyscalls)
		}
	})
}

// TestRestartRowReleasedBeforeANoReturnRow: the typical handled-signal case,
// the handler returning at once through rt_sigreturn. One record then
// completes two rows, the released -516 row first.
func TestRestartRowReleasedBeforeANoReturnRow(t *testing.T) {
	eachRestartFixture(t, func(t *testing.T, newFixture restartFixtureMaker) {
		f := newFixture(t, globalfilter.Filter{})
		f.interrupt(restartBase, restartTid)
		_, sigreturn := makeEnterNullEvent(t, restartBase+700, restartPid, restartTid, types.SYS_ENTER_RT_SIGRETURN)
		rows := f.feed(sigreturn)
		if len(rows) != 2 || rows[0].name != "clock_nanosleep" || rows[0].ret != -516 || rows[1].name != "rt_sigreturn" {
			t.Fatalf("rows = %+v, want the released clock_nanosleep -516 row, then rt_sigreturn", rows)
		}
		f.requireNothingHeld()
	})
}

// TestRestartSyscallOfAnotherTidDoesNotFold: restart_syscall resumes the
// call of its own thread only. Another tid's restart_syscall is an ordinary
// row, and the held row stays held.
func TestRestartSyscallOfAnotherTidDoesNotFold(t *testing.T) {
	eachRestartFixture(t, func(t *testing.T, newFixture restartFixtureMaker) {
		f := newFixture(t, globalfilter.Filter{})
		f.interrupt(restartBase, restartTid)
		f.feedNone(f.restartEnter(restartBase+1000, restartOtherTid), "other tid's restart_syscall enter")
		row := f.feedOne(f.restartExit(restartBase+1200, restartOtherTid, 0), "other tid's restart_syscall exit")
		if row.name != "restart_syscall" || row.tid != restartOtherTid || row.duration != 200 {
			t.Fatalf("row = %+v, want the other tid's own restart_syscall row", row)
		}
		if _, held := f.el.restarts.lookup(restartTid); !held {
			t.Fatal("the -516 row of the first tid is no longer held")
		}
	})
}

// TestRestartSyscallWithoutAHeldRowIsARow: a restart_syscall whose -516
// predates the trace (or was released) is reported as itself.
func TestRestartSyscallWithoutAHeldRowIsARow(t *testing.T) {
	eachRestartFixture(t, func(t *testing.T, newFixture restartFixtureMaker) {
		f := newFixture(t, globalfilter.Filter{})
		f.feedNone(f.restartEnter(restartBase, restartTid), "restart_syscall enter")
		row := f.feedOne(f.restartExit(restartBase+400, restartTid, 0), "restart_syscall exit")
		if row.name != "restart_syscall" || row.ret != 0 || row.duration != 400 {
			t.Fatalf("row = %+v, want restart_syscall ret=0 duration=400", row)
		}
		f.requireNothingHeld()
	})
}

// TestRestartSyscallAfterAnotherSyscallDoesNotFold: the continuation must be
// the tid's very next record. A syscall in between released the row, so a
// later restart_syscall is a row of its own.
func TestRestartSyscallAfterAnotherSyscallDoesNotFold(t *testing.T) {
	eachRestartFixture(t, func(t *testing.T, newFixture restartFixtureMaker) {
		f := newFixture(t, globalfilter.Filter{})
		f.interrupt(restartBase, restartTid)
		_, syncEnter := makeEnterNullEvent(t, restartBase+600, restartPid, restartTid, types.SYS_ENTER_SYNC)
		f.feedOne(syncEnter, "sync enter")
		_, syncExit := makeExitNullEvent(t, restartBase+700, restartPid, restartTid, types.SYS_EXIT_SYNC)
		f.feedOne(syncExit, "sync exit")
		f.feedNone(f.restartEnter(restartBase+800, restartTid), "restart_syscall enter")
		row := f.feedOne(f.restartExit(restartBase+900, restartTid, 0), "restart_syscall exit")
		if row.name != "restart_syscall" {
			t.Fatalf("row = %+v, want an unfolded restart_syscall row", row)
		}
	})
}

// TestRestartRowReleasedWhenTheContinuationIsCutShort: the restart_syscall
// enter arrived but its exit did not (lost record); the tid's next enter
// releases the row unchanged instead of folding a stranger into it.
func TestRestartRowReleasedWhenTheContinuationIsCutShort(t *testing.T) {
	eachRestartFixture(t, func(t *testing.T, newFixture restartFixtureMaker) {
		f := newFixture(t, globalfilter.Filter{})
		f.interrupt(restartBase, restartTid)
		f.feedNone(f.restartEnter(restartBase+1000, restartTid), "restart_syscall enter")
		row := f.feedOne(f.sleepEnter(restartBase+2000, restartTid), "next clock_nanosleep enter")
		if row.name != "clock_nanosleep" || row.ret != -516 || row.duration != 500 {
			t.Fatalf("released row = %+v, want the unchanged -516 row", row)
		}
		f.requireNothingHeld()
	})
}

// TestRestartRowReleasedAtThreadExit: a task killed while stopped (SIGKILL
// after SIGSTOP) never resumes; its exit record emits the held row before the
// tid's state is retired, so no row is lost.
func TestRestartRowReleasedAtThreadExit(t *testing.T) {
	eachRestartFixture(t, func(t *testing.T, newFixture restartFixtureMaker) {
		f := newFixture(t, globalfilter.Filter{})
		f.interrupt(restartBase, restartTid)
		row := f.feedOne(makeThreadExitEvent(t, restartBase+5000, restartPid, restartTid), "thread exit record")
		if row.name != "clock_nanosleep" || row.ret != -516 || row.tid != restartTid {
			t.Fatalf("released row = %+v, want the unchanged -516 row", row)
		}
		f.requireNothingHeld()
		if _, ok := f.el.pairs.prevTimes[restartTid]; ok {
			t.Fatal("the exit record did not retire the gap baseline after the released row set it")
		}
	})
}

// TestRestartFoldIsFilteredAsOneRow: filters judge the folded row, not its
// pieces. A latency floor the -516 piece alone misses passes the whole call;
// ret filters see the final return value, not the restart code; a syscall
// filter on restart_syscall no longer selects the continuation; and a syscall
// filter on the original keeps the whole call.
func TestRestartFoldIsFilteredAsOneRow(t *testing.T) {
	eachRestartFixture(t, func(t *testing.T, newFixture restartFixtureMaker) {
		tests := []struct {
			name   string
			filter globalfilter.Filter
			want   int
		}{
			{"latency floor above the interrupted piece", globalfilter.Filter{
				LatencyNs: &globalfilter.NumericFilter{Op: globalfilter.OpGte, Value: 2000}}, 1},
			{"latency ceiling below the whole call", globalfilter.Filter{
				LatencyNs: &globalfilter.NumericFilter{Op: globalfilter.OpLt, Value: 1000}}, 0},
			{"ret is the final return", globalfilter.Filter{
				RetVal: &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: 0}}, 1},
			{"the restart code is gone", globalfilter.Filter{
				RetVal: &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: -516}}, 0},
			{"syscall restart_syscall", globalfilter.Filter{
				Syscall: &globalfilter.StringFilter{Pattern: "restart_syscall"}}, 0},
			{"syscall clock_nanosleep", globalfilter.Filter{
				Syscall: &globalfilter.StringFilter{Pattern: "clock_nanosleep"}}, 1},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				f := newFixture(t, tc.filter)
				f.interrupt(restartBase, restartTid)
				f.feedNone(f.restartEnter(restartBase+1500, restartTid), "restart_syscall enter")
				rows := f.feed(f.restartExit(restartBase+3000, restartTid, 0))
				if len(rows) != tc.want {
					t.Fatalf("rows = %+v, want %d", rows, tc.want)
				}
				if f.el.numSyscalls != 1 {
					t.Fatalf("numSyscalls = %d, want 1", f.el.numSyscalls)
				}
				f.requireNothingHeld()
			})
		}
	})
}

// TestRestartRowsReleasedWhenTheLoopStops: a call still held when the trace
// ends - the task is still stopped, or the run is cut off - is emitted
// unchanged on both stop paths, oldest exit first.
func TestRestartRowsReleasedWhenTheLoopStops(t *testing.T) {
	eachRestartFixture(t, func(t *testing.T, newFixture restartFixtureMaker) {
		for _, stopByCancel := range []bool{false, true} {
			name := map[bool]string{false: "raw channel closed", true: "context cancelled"}[stopByCancel]
			t.Run(name, func(t *testing.T) {
				f := newFixture(t, globalfilter.Filter{})
				var rows []restartRow
				f.el.SetPrintCallback(func(ep *event.Pair) {
					rows = append(rows, rowOf(ep))
					ep.Recycle()
				})
				stream := [][]byte{
					f.sleepEnter(restartBase+100, restartOtherTid), f.sleepEnter(restartBase, restartTid),
					f.sleepExit(restartBase+600, restartOtherTid, -516), f.sleepExit(restartBase+500, restartTid, -516),
				}
				rawCh := filledRawChannel(stream)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if stopByCancel {
					go func() {
						for len(rawCh) > 0 {
							time.Sleep(time.Millisecond)
						}
						cancel()
					}()
				} else {
					close(rawCh)
				}
				f.el.run(ctx, rawCh)

				if len(rows) != 2 || rows[0].tid != restartTid || rows[1].tid != restartOtherTid ||
					rows[0].ret != -516 || rows[1].ret != -516 {
					t.Fatalf("rows = %+v, want both -516 rows, oldest exit first", rows)
				}
				if f.el.numSyscalls != 2 || f.el.numSyscallsAfterFilter != 2 {
					t.Fatalf("numSyscalls=%d afterFilter=%d, want 2 and 2", f.el.numSyscalls, f.el.numSyscallsAfterFilter)
				}
				f.requireNothingHeld()
			})
		}
	})
}

// TestRestartRowBeyondTheBoundIsNotFolded is the bound seen from the loop: with
// maxHeldRestarts rows already held (stopped threads whose releasing records
// never arrived), a further -516 row is completed at once, and its
// restart_syscall is then a row of its own.
func TestRestartRowBeyondTheBoundIsNotFolded(t *testing.T) {
	eachRestartFixture(t, func(t *testing.T, newFixture restartFixtureMaker) {
		f := newFixture(t, globalfilter.Filter{})
		const firstOtherTid = uint32(900_000)
		for tid := firstOtherTid; tid < firstOtherTid+maxHeldRestarts; tid++ {
			f.el.restarts.hold(&heldRestart{pair: &event.Pair{
				EnterEv: &types.NullEvent{TraceId: types.SYS_ENTER_NANOSLEEP, Tid: tid},
				ExitEv:  &types.RetEvent{TraceId: types.SYS_EXIT_NANOSLEEP, Tid: tid, Ret: -516},
			}})
		}
		f.feedNone(f.sleepEnter(restartBase, restartTid), "clock_nanosleep enter")
		sleep := f.feedOne(f.sleepExit(restartBase+500, restartTid, -516), "clock_nanosleep -516 exit at the bound")
		if sleep.name != "clock_nanosleep" || sleep.ret != -516 || sleep.duration != 500 {
			t.Fatalf("row = %+v, want the -516 row, completed unfolded", sleep)
		}
		f.feedNone(f.restartEnter(restartBase+1500, restartTid), "restart_syscall enter")
		restart := f.feedOne(f.restartExit(restartBase+3000, restartTid, 0), "restart_syscall exit")
		if restart.name != "restart_syscall" || restart.ret != 0 || restart.duration != 1500 {
			t.Fatalf("row = %+v, want restart_syscall as a row of its own", restart)
		}
		if n := len(f.el.restarts.held); n != maxHeldRestarts {
			t.Fatalf("%d rows held, want the %d that were held before", n, maxHeldRestarts)
		}
	})
}

// TestRestartHoldIsBounded: rows beyond maxHeldRestarts are not held (they
// are completed at once, unfolded), so lost release records cannot grow the
// map without bound. Without BPF's re-execution proof only -516 RetEvent
// exits are held at all; with it (foldReexecutedRestarts) -512/-513/-514 are
// held too, never an ordinary errno or a success, and under the same bound.
func TestRestartHoldIsBounded(t *testing.T) {
	var tracker restartTracker
	heldFor := func(tid uint32, ret int64) *heldRestart {
		return &heldRestart{pair: &event.Pair{
			EnterEv: &types.NullEvent{TraceId: types.SYS_ENTER_NANOSLEEP, Tid: tid},
			ExitEv:  &types.RetEvent{TraceId: types.SYS_EXIT_NANOSLEEP, Tid: tid, Ret: ret},
		}}
	}
	for _, ret := range []int64{-512, -513, -514, -4, 0} {
		if tracker.hold(heldFor(1, ret)) {
			t.Fatalf("a ret=%d row was held; only -516 has a restart_syscall continuation", ret)
		}
	}
	for tid := uint32(1); tid <= maxHeldRestarts; tid++ {
		if !tracker.hold(heldFor(tid, -516)) {
			t.Fatalf("row %d was not held below the bound", tid)
		}
	}
	if tracker.hold(heldFor(maxHeldRestarts+1, -516)) {
		t.Fatal("a row beyond maxHeldRestarts was held")
	}

	proven := restartTracker{reexec: true}
	for _, ret := range []int64{-4, 0, -515} {
		if proven.hold(heldFor(1, ret)) {
			t.Fatalf("a ret=%d row was held; it is not a restart code", ret)
		}
	}
	for i, ret := range []int64{-512, -513, -514, -516} {
		if !proven.hold(heldFor(uint32(i+1), ret)) {
			t.Fatalf("a ret=%d row was not held although re-executions are proven", ret)
		}
	}
	for tid := uint32(5); tid <= maxHeldRestarts; tid++ {
		proven.hold(heldFor(tid, -512))
	}
	if proven.hold(heldFor(maxHeldRestarts+1, -512)) {
		t.Fatal("a -512 row beyond maxHeldRestarts was held")
	}
}
