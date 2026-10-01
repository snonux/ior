package internal

import (
	"context"
	"errors"
	"testing"

	"ior/internal/event"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

// Tests for folding a re-executed call into the -512/-513/-514 row it
// continues (task 103, eventloop_restart.go). The fold is licensed by BPF's
// RESUME control record alone; the tests below drive the record stream the
// probes in internal/c/restart.c produce and, above all, the streams in which
// that record is missing, late, or addressed to someone else.

const (
	restartSys    = int64(-512)
	restartNoIntr = int64(-513)
	restartNoHand = int64(-514)
	restartReadFd = int32(3)
)

// reexecDrops scripts the kernel drop counter and the boot clock of a
// re-execution fixture: total is what the counter reads, err makes the read
// fail, and now is the time a change of the total is noticed at.
type reexecDrops struct {
	total uint64
	err   error
	now   uint64
}

// newReexecFixture is newRestartFixture with BPF's re-execution proof on, as
// trace setup turns it on when the signal_deliver and sched_process_exit
// probes attached and the drop counter can be read. The counter starts at 0
// and stays there unless the test moves it through the returned fixture's
// drops.
func newReexecFixture(t *testing.T, filter globalfilter.Filter) *restartFixture {
	t.Helper()
	f := newRestartFixture(t, filter)
	f.drops = &reexecDrops{}
	f.el.dropSrc = ringbufDropSourceFunc(func() (uint64, error) { return f.drops.total, f.drops.err })
	f.el.dropStampClock = func() uint64 { return f.drops.now }
	f.el.foldReexecutedRestarts(true, true)
	return f
}

// loseRecords moves the kernel drop counter by n, as n records refused by a
// full ring buffer do; the loop notices it at boot-clock time now.
func (f *restartFixture) loseRecords(n, now uint64) {
	f.drops.total += n
	f.drops.now = now
}

func (f *restartFixture) readEnter(at uint64, tid uint32) []byte {
	f.t.Helper()
	_, raw := makeEnterFdEvent(f.t, at, restartPid, tid, restartReadFd, types.SYS_ENTER_READ)
	return raw
}

func (f *restartFixture) readExit(at uint64, tid uint32, ret int64) []byte {
	f.t.Helper()
	_, raw := makeExitRetEvent(f.t, at, restartPid, tid, types.SYS_EXIT_READ, ret)
	return raw
}

// restartRecord builds the control record of the restart-fold probes.
func (f *restartFixture) restartRecord(at uint64, tid, phase, saRestart uint32) []byte {
	f.t.Helper()
	ev := types.SyscallRestartEvent{EventType: types.SYSCALL_RESTART_EVENT, Time: at, Pid: restartPid, Tid: tid,
		Phase: phase, SaRestart: saRestart}
	raw, err := ev.Bytes()
	if err != nil {
		f.t.Fatalf("SyscallRestartEvent.Bytes() error = %v", err)
	}
	return raw
}

func (f *restartFixture) handlerRecord(at uint64, tid uint32, saRestart bool) []byte {
	f.t.Helper()
	flag := uint32(0)
	if saRestart {
		flag = 1
	}
	return f.restartRecord(at, tid, types.RESTART_PHASE_HANDLER, flag)
}

func (f *restartFixture) resumeRecord(at uint64, tid uint32) []byte {
	f.t.Helper()
	return f.restartRecord(at, tid, types.RESTART_PHASE_RESUME, 0)
}

// interruptRead feeds a read enter at `at` and its exit with the restart code
// ret 500ns later, which must both stay silent: the row is held.
func (f *restartFixture) interruptRead(at uint64, tid uint32, ret int64) {
	f.t.Helper()
	f.feedNone(f.readEnter(at, tid), "read enter")
	f.feedNone(f.readExit(at+500, tid, ret), "interrupted read exit")
}

// syncCall feeds a sync enter and exit of tid (a syscall of the signal
// handler) and returns the row the exit emits.
func (f *restartFixture) syncCall(at uint64, tid uint32) restartRow {
	f.t.Helper()
	_, enter := makeEnterNullEvent(f.t, at, restartPid, tid, types.SYS_ENTER_SYNC)
	f.feedNone(enter, "sync enter")
	_, exit := makeExitNullEvent(f.t, at+50, restartPid, tid, types.SYS_EXIT_SYNC)
	return f.feedOne(exit, "sync exit")
}

// sigreturn feeds the handler's rt_sigreturn, a row at its enter.
func (f *restartFixture) sigreturn(at uint64, tid uint32) restartRow {
	f.t.Helper()
	_, raw := makeEnterNullEvent(f.t, at, restartPid, tid, types.SYS_ENTER_RT_SIGRETURN)
	return f.feedOne(raw, "rt_sigreturn enter")
}

// requireInterruptedRow fails unless row is the interrupted read exactly as
// it was at its first exit.
func requireInterruptedRow(t *testing.T, row restartRow, ret int64) {
	t.Helper()
	want := restartRow{name: "read", tid: restartTid, ret: ret, enterTime: restartBase, duration: 500}
	if row != want {
		t.Fatalf("released row = %+v, want the unchanged interrupted row %+v", row, want)
	}
}

// TestReexecutedCallFoldsWithoutAHandler is the positive case of the task:
// no handler runs (SIGSTOP/SIGCONT, a signal a sibling thread took), the
// kernel re-executes the call, BPF announces that with RESUME, and ior emits
// ONE row - the original enter with the final return value and the whole span
// as latency - for each of the three codes.
func TestReexecutedCallFoldsWithoutAHandler(t *testing.T) {
	for _, ret := range []int64{restartSys, restartNoIntr, restartNoHand} {
		f := newReexecFixture(t, globalfilter.Filter{})
		f.interruptRead(restartBase, restartTid, ret)
		f.feedNone(f.resumeRecord(restartBase+900, restartTid), "RESUME record")
		f.feedNone(f.readEnter(restartBase+900, restartTid), "re-executed read enter")
		row := f.feedOne(f.readExit(restartBase+3000, restartTid, 1), "re-executed read exit")

		want := restartRow{name: "read", tid: restartTid, ret: 1, enterTime: restartBase, duration: 3000}
		if row != want {
			t.Fatalf("ret %d: folded row = %+v, want %+v", ret, row, want)
		}
		if f.el.numSyscalls != 1 {
			t.Fatalf("ret %d: numSyscalls = %d, want 1 (one call)", ret, f.el.numSyscalls)
		}
		f.requireNothingHeld()
	}
}

// TestRestartSurvivesHandlerFollowsHandleSignal pins the kernel rule the
// HANDLER record is judged by: with a user handler -513 always restarts, -512
// only under SA_RESTART, -514 and -516 never.
func TestRestartSurvivesHandlerFollowsHandleSignal(t *testing.T) {
	for _, tc := range []struct {
		ret       int64
		saRestart bool
		want      bool
	}{
		{restartSys, true, true}, {restartSys, false, false},
		{restartNoIntr, true, true}, {restartNoIntr, false, true},
		{restartNoHand, true, false}, {restartNoHand, false, false},
		{-516, true, false}, {-516, false, false},
		{-4, true, false}, {0, true, false},
	} {
		if got := restartSurvivesHandler(tc.ret, tc.saRestart); got != tc.want {
			t.Errorf("restartSurvivesHandler(%d, SA_RESTART=%t) = %t, want %t", tc.ret, tc.saRestart, got, tc.want)
		}
	}
}

// TestReexecutedCallFoldsAfterARestartingHandler: a handler the call survives
// (-512 with SA_RESTART, -513 with any handler) runs first. Its syscalls are
// rows of their own, completed before the call they interrupted; then RESUME,
// and the re-execution folds. The handler's first row measures its gap from
// the interrupted exit, and the folded row keeps the gap of its own enter.
func TestReexecutedCallFoldsAfterARestartingHandler(t *testing.T) {
	for _, tc := range []struct {
		ret       int64
		saRestart bool
	}{{restartSys, true}, {restartNoIntr, false}, {restartNoIntr, true}} {
		f := newReexecFixture(t, globalfilter.Filter{})
		earlier := f.syncCall(restartBase-1000, restartTid) // exits at restartBase-950
		if earlier.name != "sync" {
			t.Fatalf("setup row = %+v", earlier)
		}
		f.interruptRead(restartBase, restartTid, tc.ret)
		f.feedNone(f.handlerRecord(restartBase+510, restartTid, tc.saRestart), "HANDLER record")
		inHandler := f.syncCall(restartBase+600, restartTid)
		if inHandler.name != "sync" || inHandler.gap != 100 {
			t.Fatalf("handler row = %+v, want sync with gap 100 from the interrupted exit", inHandler)
		}
		if ret := f.sigreturn(restartBase+700, restartTid); ret.name != "rt_sigreturn" {
			t.Fatalf("handler return row = %+v, want rt_sigreturn", ret)
		}
		f.feedNone(f.resumeRecord(restartBase+800, restartTid), "RESUME record")
		f.feedNone(f.readEnter(restartBase+800, restartTid), "re-executed read enter")
		row := f.feedOne(f.readExit(restartBase+4000, restartTid, 1), "re-executed read exit")

		want := restartRow{name: "read", tid: restartTid, ret: 1, enterTime: restartBase, duration: 4000, gap: 950}
		if row != want {
			t.Fatalf("ret %d: folded row = %+v, want %+v", tc.ret, row, want)
		}
		if f.el.numSyscalls != 4 {
			t.Fatalf("numSyscalls = %d, want 4 (sync, sync, rt_sigreturn, one read)", f.el.numSyscalls)
		}
		next := f.syncCall(restartBase+5000, restartTid)
		if next.gap != 1000 {
			t.Fatalf("next row = %+v, want gap 1000 from the folded exit", next)
		}
		f.requireNothingHeld()
	}
}

// TestHandledSignalThatEndsInEINTRIsNeverFolded is the task's negative
// control. A handler without SA_RESTART on -512, or any handler on -514,
// makes the program see EINTR; what it does next is its own. The HANDLER
// record releases the row at once, and the program's retry - same syscall,
// same thread, right away - is a second row. Not even a RESUME record (which
// BPF never sends here) may fold it afterwards.
func TestHandledSignalThatEndsInEINTRIsNeverFolded(t *testing.T) {
	for _, tc := range []struct {
		ret       int64
		saRestart bool
	}{{restartSys, false}, {restartNoHand, false}, {restartNoHand, true}} {
		f := newReexecFixture(t, globalfilter.Filter{})
		f.interruptRead(restartBase, restartTid, tc.ret)
		released := f.feedOne(f.handlerRecord(restartBase+510, restartTid, tc.saRestart), "HANDLER record")
		requireInterruptedRow(t, released, tc.ret)
		f.requireNothingHeld()

		f.sigreturn(restartBase+700, restartTid)
		f.feedNone(f.resumeRecord(restartBase+800, restartTid), "stray RESUME record")
		f.feedNone(f.readEnter(restartBase+800, restartTid), "the program's retry enter")
		retry := f.feedOne(f.readExit(restartBase+2000, restartTid, 1), "the program's retry exit")
		want := restartRow{name: "read", tid: restartTid, ret: 1, enterTime: restartBase + 800, duration: 1200, gap: 100}
		if retry != want {
			t.Fatalf("ret %d SA_RESTART=%t: retry row = %+v, want its own row %+v", tc.ret, tc.saRestart, retry, want)
		}
		if f.el.numSyscalls != 3 {
			t.Fatalf("numSyscalls = %d, want 3 (interrupted read, rt_sigreturn, retry)", f.el.numSyscalls)
		}
	}
}

// TestSameSyscallEnterWithoutResumeIsNotFolded: the enter of the same syscall
// alone proves nothing - it is what a program's own retry looks like, and
// what remains when the RESUME record was lost to ring-buffer backpressure.
// The held row is released unchanged and the new call is a row of its own.
func TestSameSyscallEnterWithoutResumeIsNotFolded(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	f.interruptRead(restartBase, restartTid, restartSys)
	released := f.feedOne(f.readEnter(restartBase+900, restartTid), "read enter without RESUME")
	requireInterruptedRow(t, released, restartSys)
	second := f.feedOne(f.readExit(restartBase+3000, restartTid, 1), "second read exit")
	if second.ret != 1 || second.enterTime != restartBase+900 || second.duration != 2100 {
		t.Fatalf("second row = %+v, want the second call on its own", second)
	}
	if f.el.numSyscalls != 2 {
		t.Fatalf("numSyscalls = %d, want 2", f.el.numSyscalls)
	}
}

// TestLostHandlerRecordDoesNotFold: the HANDLER record was lost, so the
// handler's first syscall finds the row still waiting and releases it. The
// RESUME that follows the handler has no row to work on, and the re-executed
// call stays a row of its own - unfolded, never wrongly folded.
func TestLostHandlerRecordDoesNotFold(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	f.interruptRead(restartBase, restartTid, restartSys)
	rows := f.feed(f.sigreturn0(restartBase + 700))
	if len(rows) != 2 || rows[1].name != "rt_sigreturn" {
		t.Fatalf("rows = %+v, want the released read, then rt_sigreturn", rows)
	}
	requireInterruptedRow(t, rows[0], restartSys)
	f.feedNone(f.resumeRecord(restartBase+800, restartTid), "RESUME without a held row")
	f.feedNone(f.readEnter(restartBase+800, restartTid), "re-executed read enter")
	row := f.feedOne(f.readExit(restartBase+2000, restartTid, 1), "re-executed read exit")
	if row.enterTime != restartBase+800 || row.ret != 1 {
		t.Fatalf("row = %+v, want the re-executed call as its own row", row)
	}
}

// sigreturn0 is the raw rt_sigreturn enter of the fixture's main tid.
func (f *restartFixture) sigreturn0(at uint64) []byte {
	f.t.Helper()
	_, raw := makeEnterNullEvent(f.t, at, restartPid, restartTid, types.SYS_ENTER_RT_SIGRETURN)
	return raw
}

// TestResumeMustBeFollowedByTheSameSyscall: RESUME licenses exactly the tid's
// next record, and only when it is the enter RESUME announced: the held
// syscall, at the RESUME record's own time. Another syscall's enter or a
// later enter of the same syscall (the announced enter was sampled out or
// lost), an exit, and a second RESUME all release the row unchanged.
func TestResumeMustBeFollowedByTheSameSyscall(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	_, syncEnter := makeEnterNullEvent(t, restartBase+900, restartPid, restartTid, types.SYS_ENTER_SYNC)
	for name, next := range map[string][]byte{
		"another syscall's enter":      syncEnter,
		"a sleep enter":                f.sleepEnter(restartBase+900, restartTid),
		"the same syscall, 1ns later":  f.readEnter(restartBase+801, restartTid),
		"the same syscall, 1ns before": f.readEnter(restartBase+799, restartTid),
		"an exit":                      f.readExit(restartBase+900, restartTid, 1),
		"a second RESUME":              f.resumeRecord(restartBase+900, restartTid),
	} {
		f := newReexecFixture(t, globalfilter.Filter{})
		f.interruptRead(restartBase, restartTid, restartSys)
		f.feedNone(f.resumeRecord(restartBase+800, restartTid), "RESUME record")
		rows := f.feed(next)
		if len(rows) == 0 {
			t.Fatalf("%s after RESUME released nothing", name)
		}
		requireInterruptedRow(t, rows[0], restartSys)
		f.requireNothingHeld()
	}
}

// TestSampledOutReexecutionIsNotFolded: BPF emits RESUME before the sampling
// decision, so at a 1-in-N rate the re-executed call's own enter and exit are
// suppressed N-1 times out of N. The row then stands in "resumed" until the
// thread's next read - a different call, any time later - and that call must
// not be taken for the re-execution: RESUME names its enter by time, and this
// enter has another one. The interrupted row is released unchanged and the
// later read is a row of its own, with its own enter time and latency (live,
// before the time check, a 100 ms read showed up as one row of 200-400 ms
// spanning several reads).
func TestSampledOutReexecutionIsNotFolded(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	f.interruptRead(restartBase, restartTid, restartSys)
	f.feedNone(f.resumeRecord(restartBase+800, restartTid), "RESUME record")
	// The re-executed read (enter at +800, some exit) was sampled out.
	released := f.feedOne(f.readEnter(restartBase+50000, restartTid), "a later read's enter")
	requireInterruptedRow(t, released, restartSys)
	f.requireNothingHeld()
	later := f.feedOne(f.readExit(restartBase+60000, restartTid, 7), "the later read's exit")
	want := restartRow{name: "read", tid: restartTid, ret: 7, enterTime: restartBase + 50000, duration: 10000, gap: 49500}
	if later != want {
		t.Fatalf("later read = %+v, want its own row %+v", later, want)
	}
	if f.el.numSyscalls != 2 {
		t.Fatalf("numSyscalls = %d, want 2 (the interrupted read and the later one)", f.el.numSyscalls)
	}
}

// TestLostContinuationRecordsNeverFoldAStranger covers the ways a full ring
// buffer can cut the continuation out of the stream while the records around
// it arrive. In each, a later call of the same syscall would complete the fold
// if nothing stopped it.
func TestLostContinuationRecordsNeverFoldAStranger(t *testing.T) {
	// RESUME arrived, the re-executed enter and exit were both refused, and
	// the loop has not seen the drop counter move yet: the time check alone
	// keeps the thread's next read out of the row.
	t.Run("enter and exit lost", func(t *testing.T) {
		f := newReexecFixture(t, globalfilter.Filter{})
		f.interruptRead(restartBase, restartTid, restartSys)
		f.feedNone(f.resumeRecord(restartBase+800, restartTid), "RESUME record")
		released := f.feedOne(f.readEnter(restartBase+5000, restartTid), "the next read's enter")
		requireInterruptedRow(t, released, restartSys)
		if next := f.feedOne(f.readExit(restartBase+6000, restartTid, 7), "the next read's exit"); next.enterTime != restartBase+5000 || next.ret != 7 {
			t.Fatalf("next read = %+v, want its own row", next)
		}
	})
	// The re-executed enter arrived and was consumed; its exit and the next
	// read's enter were refused. The next read's exit is the same syscall's
	// exit and the tid's next record - only the drop counter tells it is not
	// the continuation. The row is released unchanged; the exit has no enter
	// left and is dropped.
	t.Run("exit and the next enter lost", func(t *testing.T) {
		f := newReexecFixture(t, globalfilter.Filter{})
		f.interruptRead(restartBase, restartTid, restartSys)
		f.feedNone(f.resumeRecord(restartBase+800, restartTid), "RESUME record")
		f.feedNone(f.readEnter(restartBase+800, restartTid), "re-executed read enter")
		f.loseRecords(2, restartBase+9000)
		released := f.feedOne(f.readExit(restartBase+6000, restartTid, 7), "the next read's exit")
		requireInterruptedRow(t, released, restartSys)
		f.requireNothingHeld()
		if f.el.numSyscalls != 1 {
			t.Fatalf("numSyscalls = %d, want 1 (the unpaired exit is not a call ior saw start)", f.el.numSyscalls)
		}
	})
	// A read interrupted inside the restarting handler whose exit record was
	// refused: BPF now tracks the inner read and announces ITS re-execution,
	// while the loop still holds the outer row and saw nothing of the inner
	// interruption. RESUME arrives after a loss and releases the outer row;
	// the inner re-execution completes the inner enter that is still parked.
	t.Run("inner interrupted exit lost", func(t *testing.T) {
		f := newReexecFixture(t, globalfilter.Filter{})
		f.interruptRead(restartBase, restartTid, restartSys)
		f.feedNone(f.handlerRecord(restartBase+510, restartTid, true), "HANDLER record")
		f.feedNone(f.readEnter(restartBase+600, restartTid), "the handler's read enter")
		f.loseRecords(1, restartBase+9000)
		released := f.feedOne(f.resumeRecord(restartBase+900, restartTid), "RESUME for the inner read")
		requireInterruptedRow(t, released, restartSys)
		f.feedNone(f.readEnter(restartBase+900, restartTid), "the inner read's re-executed enter")
		inner := f.feedOne(f.readExit(restartBase+2000, restartTid, 7), "the inner read's exit")
		if inner.enterTime != restartBase+900 || inner.ret != 7 {
			t.Fatalf("inner read = %+v, want a row of its own from its re-executed enter", inner)
		}
	})
	// A counter that cannot be read vouches for nothing.
	t.Run("drop counter unreadable", func(t *testing.T) {
		f := newReexecFixture(t, globalfilter.Filter{})
		f.interruptRead(restartBase, restartTid, restartSys)
		f.drops.err = errors.New("map gone")
		released := f.feedOne(f.resumeRecord(restartBase+800, restartTid), "RESUME record")
		requireInterruptedRow(t, released, restartSys)
	})
}

// TestDropsBeforeTheInterruptionDoNotBlockTheFold: the drop check asks about
// the time since the interrupted exit only. Records lost - and noticed -
// before it say nothing about this call, and a later call folds again once the
// loss lies behind its interrupted exit.
func TestDropsBeforeTheInterruptionDoNotBlockTheFold(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	f.loseRecords(5, restartBase-100)
	fold := func(base uint64) restartRow {
		f.interruptRead(base, restartTid, restartSys)
		f.feedNone(f.resumeRecord(base+800, restartTid), "RESUME record")
		f.feedNone(f.readEnter(base+800, restartTid), "re-executed read enter")
		return f.feedOne(f.readExit(base+3000, restartTid, 1), "re-executed read exit")
	}
	if row := fold(restartBase); row.ret != 1 || row.enterTime != restartBase || row.duration != 3000 {
		t.Fatalf("row = %+v, want the fold: the loss was noticed before the interruption", row)
	}

	// A loss noticed while a row is held refuses that row's fold...
	f.interruptRead(restartBase+10000, restartTid, restartSys)
	f.loseRecords(1, restartBase+10600)
	released := f.feedOne(f.resumeRecord(restartBase+10800, restartTid), "RESUME after a loss")
	if released.ret != restartSys || released.enterTime != restartBase+10000 {
		t.Fatalf("released row = %+v, want the unchanged interrupted read", released)
	}
	// ...and the next interrupted call, after it, folds again.
	if row := fold(restartBase + 20000); row.ret != 1 || row.enterTime != restartBase+20000 {
		t.Fatalf("row = %+v, want the fold of a call interrupted after the loss", row)
	}
}

// TestRestartDropWatch pins the watch itself: a moved total is stamped with
// the time it is first seen, an unchanged total keeps its stamp, and a missing
// or failing counter always reports a loss.
func TestRestartDropWatch(t *testing.T) {
	var watch restartDropWatch
	now, total := uint64(100), uint64(0)
	src := ringbufDropSourceFunc(func() (uint64, error) { return total, nil })
	clock := func() uint64 { return now }
	if watch.lostSince(50, src, clock) {
		t.Fatal("a counter that never moved reported a loss")
	}
	total, now = 3, 200
	if !watch.lostSince(150, src, clock) || !watch.lostSince(200, src, clock) {
		t.Fatal("a loss first seen at 200 was not reported for a row interrupted at or before 200")
	}
	now = 900
	if watch.lostSince(201, src, clock) {
		t.Fatal("an unchanged total was stamped again: the loss predates a row interrupted at 201")
	}
	if !watch.lostSince(0, nil, clock) {
		t.Fatal("a missing counter did not report a loss")
	}
	failing := ringbufDropSourceFunc(func() (uint64, error) { return 0, errors.New("unreadable") })
	if !watch.lostSince(1000, failing, clock) {
		t.Fatal("an unreadable counter did not report a loss")
	}
}

// TestInterruptedCallInTheHandlerTakesTheRowsPlaceAtTheBound: with
// maxHeldRestarts rows held, a read interrupted inside the restarting handler
// still replaces the outer row - the outer row's release is what makes room
// for it. Judged against the bound first, the inner read was emitted unheld
// and the outer row stayed waiting; BPF, which had moved on to the inner
// read, then announced the inner read's re-execution, and the handler's read
// was folded into the call the handler had interrupted.
func TestInterruptedCallInTheHandlerTakesTheRowsPlaceAtTheBound(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	f.interruptRead(restartBase, restartTid, restartSys)
	f.feedNone(f.handlerRecord(restartBase+510, restartTid, true), "HANDLER record")
	// Fill the tracker to the bound with rows of other threads.
	for tid := uint32(1); len(f.el.restarts.held) < maxHeldRestarts; tid++ {
		f.el.restarts.held[tid] = &heldRestart{pair: &event.Pair{
			EnterEv: &types.FdEvent{TraceId: types.SYS_ENTER_READ, Tid: tid},
			ExitEv:  &types.RetEvent{TraceId: types.SYS_EXIT_READ, Tid: tid, Ret: restartSys},
		}}
	}

	f.feedNone(f.readEnter(restartBase+600, restartTid), "the handler's read enter")
	outer := f.feedOne(f.readExit(restartBase+700, restartTid, restartSys), "the handler's read, interrupted")
	requireInterruptedRow(t, outer, restartSys)
	held, ok := f.el.restarts.lookup(restartTid)
	if !ok || held.pair.EnterEv.GetTime() != restartBase+600 || held.phase != restartWaiting {
		t.Fatalf("the thread holds %+v (held=%t), want the handler's read, waiting", held, ok)
	}

	f.feedNone(f.resumeRecord(restartBase+900, restartTid), "RESUME for the handler's read")
	f.feedNone(f.readEnter(restartBase+900, restartTid), "the handler's read, re-executed")
	inner := f.feedOne(f.readExit(restartBase+2000, restartTid, 7), "its exit")
	if inner.enterTime != restartBase+600 || inner.ret != 7 || inner.duration != 1400 {
		t.Fatalf("row = %+v, want the handler's own read folded: enter +600, ret 7, duration 1400", inner)
	}
}

// TestReexecutionCutShortReleasesTheRow: the re-executed enter arrived but
// its exit did not (lost record); the tid's next enter releases the row
// unchanged instead of folding a stranger into it. A lost continuation never
// loses the row.
func TestReexecutionCutShortReleasesTheRow(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	f.interruptRead(restartBase, restartTid, restartSys)
	f.feedNone(f.resumeRecord(restartBase+800, restartTid), "RESUME record")
	f.feedNone(f.readEnter(restartBase+800, restartTid), "re-executed read enter")
	released := f.feedOne(f.readEnter(restartBase+5000, restartTid), "a later read enter")
	requireInterruptedRow(t, released, restartSys)
	f.requireNothingHeld()

	// The exit of another syscall cannot complete the fold either.
	f = newReexecFixture(t, globalfilter.Filter{})
	f.interruptRead(restartBase, restartTid, restartSys)
	f.feedNone(f.resumeRecord(restartBase+800, restartTid), "RESUME record")
	f.feedNone(f.readEnter(restartBase+800, restartTid), "re-executed read enter")
	_, writeExit := makeExitRetEvent(t, restartBase+900, restartPid, restartTid, types.SYS_EXIT_WRITE, 1)
	released = f.feedOne(writeExit, "a write exit")
	requireInterruptedRow(t, released, restartSys)
}

// TestSeveralSignalsBeforeTheReexecution: after the restarting handler
// returned, more handlers may run before the call is re-executed (BPF reports
// only the first; the later ones merely postpone RESUME). All their syscalls
// pass, and the fold still happens on RESUME. A second HANDLER record, which
// BPF never emits for one interrupted call, is not trusted: it releases.
func TestSeveralSignalsBeforeTheReexecution(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	f.interruptRead(restartBase, restartTid, restartSys)
	f.feedNone(f.handlerRecord(restartBase+510, restartTid, true), "HANDLER record")
	for i := uint64(0); i < 3; i++ {
		f.syncCall(restartBase+600+i*200, restartTid)
		f.sigreturn(restartBase+700+i*200, restartTid)
	}
	f.feedNone(f.resumeRecord(restartBase+1300, restartTid), "RESUME record")
	f.feedNone(f.readEnter(restartBase+1300, restartTid), "re-executed read enter")
	row := f.feedOne(f.readExit(restartBase+2000, restartTid, 1), "re-executed read exit")
	if row.ret != 1 || row.enterTime != restartBase || row.duration != 2000 {
		t.Fatalf("folded row = %+v, want the original enter with ret 1 and duration 2000", row)
	}

	f = newReexecFixture(t, globalfilter.Filter{})
	f.interruptRead(restartBase, restartTid, restartSys)
	f.feedNone(f.handlerRecord(restartBase+510, restartTid, true), "HANDLER record")
	released := f.feedOne(f.handlerRecord(restartBase+520, restartTid, true), "second HANDLER record")
	requireInterruptedRow(t, released, restartSys)
}

// TestRestartRecordsWithoutAHeldRowChangeNothing: a signal delivered to a tid
// that holds no row (its exit was not emitted, the row was released, another
// thread is the interrupted one) produces no row and leaves no state, and it
// does not touch the row another tid holds.
func TestRestartRecordsWithoutAHeldRowChangeNothing(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	f.feedNone(f.handlerRecord(restartBase, restartTid, true), "HANDLER without a held row")
	f.feedNone(f.resumeRecord(restartBase+10, restartTid), "RESUME without a held row")
	f.requireNothingHeld()
	f.feedNone(f.readEnter(restartBase+100, restartTid), "read enter")
	row := f.feedOne(f.readExit(restartBase+300, restartTid, 1), "read exit")
	if row.ret != 1 || row.duration != 200 {
		t.Fatalf("row = %+v, want an ordinary read row", row)
	}

	f.interruptRead(restartBase+1000, restartTid, restartSys)
	f.feedNone(f.resumeRecord(restartBase+1600, restartOtherTid), "another tid's RESUME")
	f.feedNone(f.readEnter(restartBase+1600, restartOtherTid), "another tid's read enter")
	other := f.feedOne(f.readExit(restartBase+1700, restartOtherTid, 1), "another tid's read exit")
	if other.tid != restartOtherTid || other.enterTime != restartBase+1600 {
		t.Fatalf("row = %+v, want the other tid's own read", other)
	}
	if held, ok := f.el.restarts.lookup(restartTid); !ok || held.phase != restartWaiting {
		t.Fatal("the first tid's interrupted row is no longer waiting")
	}
}

// TestHeldReexecRowIsReleasedWhenTheThreadExits: the continuation never
// arrives because the thread dies - killed while stopped, or while its
// handler runs, or between RESUME and the enter. In every phase the exit
// record emits the row unchanged before the tid's state is retired.
func TestHeldReexecRowIsReleasedWhenTheThreadExits(t *testing.T) {
	phases := map[string]func(f *restartFixture){
		"waiting": func(*restartFixture) {},
		"in the handler": func(f *restartFixture) {
			f.feedNone(f.handlerRecord(restartBase+510, restartTid, true), "HANDLER record")
			f.syncCall(restartBase+600, restartTid)
		},
		"resumed": func(f *restartFixture) {
			f.feedNone(f.resumeRecord(restartBase+800, restartTid), "RESUME record")
		},
		"continuing": func(f *restartFixture) {
			f.feedNone(f.resumeRecord(restartBase+800, restartTid), "RESUME record")
			f.feedNone(f.readEnter(restartBase+800, restartTid), "re-executed read enter")
		},
	}
	for name, advance := range phases {
		t.Run(name, func(t *testing.T) {
			f := newReexecFixture(t, globalfilter.Filter{})
			f.interruptRead(restartBase, restartTid, restartSys)
			advance(f)
			row := f.feedOne(makeThreadExitEvent(t, restartBase+9000, restartPid, restartTid), "thread exit record")
			requireInterruptedRow(t, row, restartSys)
			f.requireNothingHeld()
			if _, ok := f.el.pairs.prevTimes[restartTid]; ok {
				t.Fatal("the exit record did not retire the gap baseline after the released row")
			}
		})
	}
}

// TestHeldReexecRowsAreReleasedWhenTheLoopStops: rows still held when the
// trace ends - waiting, or parked behind a running handler - are emitted
// unchanged, oldest exit first, and counted once.
func TestHeldReexecRowsAreReleasedWhenTheLoopStops(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	var rows []restartRow
	f.el.SetPrintCallback(func(ep *event.Pair) {
		rows = append(rows, rowOf(ep))
		ep.Recycle()
	})
	rawCh := filledRawChannel([][]byte{
		f.readEnter(restartBase+100, restartOtherTid), f.readEnter(restartBase, restartTid),
		f.readExit(restartBase+600, restartOtherTid, restartNoHand), f.readExit(restartBase+500, restartTid, restartSys),
		f.handlerRecord(restartBase+510, restartTid, true),
	})
	close(rawCh)
	f.el.run(context.Background(), rawCh)

	if len(rows) != 2 || rows[0].tid != restartTid || rows[0].ret != restartSys ||
		rows[1].tid != restartOtherTid || rows[1].ret != restartNoHand {
		t.Fatalf("rows = %+v, want both interrupted rows unchanged, oldest exit first", rows)
	}
	if f.el.numSyscalls != 2 || f.el.numSyscallsAfterFilter != 2 {
		t.Fatalf("numSyscalls=%d afterFilter=%d, want 2 and 2", f.el.numSyscalls, f.el.numSyscallsAfterFilter)
	}
	f.requireNothingHeld()
}

// TestHandlerThatNeverReturnsReleasesTheRow: a handler that leaves through
// siglongjmp never reaches rt_sigreturn, so RESUME never comes (and neither
// does it when the record was lost). After maxHandlerRecords records of the
// tid the row is released unchanged, without disturbing the gap baseline the
// rows that passed meanwhile have set.
func TestHandlerThatNeverReturnsReleasesTheRow(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	f.interruptRead(restartBase, restartTid, restartSys)
	f.feedNone(f.handlerRecord(restartBase+510, restartTid, true), "HANDLER record")
	at := restartBase + 1000
	for passed := 0; passed+2 <= maxHandlerRecords; passed += 2 {
		f.syncCall(at, restartTid)
		at += 100
	}
	if _, held := f.el.restarts.lookup(restartTid); !held {
		t.Fatalf("the row was released before %d records passed", maxHandlerRecords)
	}
	_, syncEnter := makeEnterNullEvent(t, at, restartPid, restartTid, types.SYS_ENTER_SYNC)
	released := f.feedOne(syncEnter, "the record beyond the bound")
	if released.name != "read" || released.ret != restartSys || released.enterTime != restartBase {
		t.Fatalf("released row = %+v, want the unchanged interrupted read", released)
	}
	f.requireNothingHeld()

	// The late release must not move the tid's gap baseline back to the
	// interrupted exit: the next row still measures from the handler's last
	// row (the sync that exited 50ns before this enter).
	_, syncExit := makeExitNullEvent(t, at+50, restartPid, restartTid, types.SYS_EXIT_SYNC)
	if next := f.feedOne(syncExit, "the releasing record's own exit"); next.gap != 50 {
		t.Fatalf("row after the late release = %+v, want gap 50 from the previous handler row", next)
	}
}

// TestOtherControlRecordsEndTheHandlerWait: while a handler runs, only its
// syscalls and their name fixups pass. A record that says the task changed
// under the row - here a task_newtask reusing the tid - releases it.
func TestOtherControlRecordsEndTheHandlerWait(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	f.interruptRead(restartBase, restartTid, restartSys)
	f.feedNone(f.handlerRecord(restartBase+510, restartTid, true), "HANDLER record")
	fixup := types.OpenNameFixupEvent{EventType: types.OPEN_NAME_FIXUP_EVENT, Tid: restartTid}
	raw, err := fixup.Bytes()
	if err != nil {
		t.Fatalf("OpenNameFixupEvent.Bytes() error = %v", err)
	}
	f.feedNone(raw, "a name fixup of the handler's open")
	if _, held := f.el.restarts.lookup(restartTid); !held {
		t.Fatal("a name fixup released the row")
	}
	newtask := types.TaskNewtaskEvent{EventType: types.TASK_NEWTASK_EVENT, Time: restartBase + 700,
		Pid: restartPid, Tid: restartTid, CreatorPid: restartPid}
	raw, err = newtask.Bytes()
	if err != nil {
		t.Fatalf("TaskNewtaskEvent.Bytes() error = %v", err)
	}
	released := f.feedOne(raw, "a task_newtask record for the tid")
	if released.name != "read" || released.ret != restartSys {
		t.Fatalf("released row = %+v, want the unchanged interrupted read", released)
	}
}

// TestReexecutionInterruptedAgainFoldsIntoOneRow: the re-executed call is
// interrupted again (stopped twice). The fold ends in a restart code, so the
// row is held again and the next proven re-execution folds into the same row.
func TestReexecutionInterruptedAgainFoldsIntoOneRow(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	f.interruptRead(restartBase, restartTid, restartSys)
	f.feedNone(f.resumeRecord(restartBase+800, restartTid), "first RESUME")
	f.feedNone(f.readEnter(restartBase+800, restartTid), "first re-executed enter")
	f.feedNone(f.readExit(restartBase+1500, restartTid, restartSys), "first re-executed exit, interrupted again")
	f.feedNone(f.resumeRecord(restartBase+1800, restartTid), "second RESUME")
	f.feedNone(f.readEnter(restartBase+1800, restartTid), "second re-executed enter")
	row := f.feedOne(f.readExit(restartBase+4000, restartTid, 1), "second re-executed exit")

	want := restartRow{name: "read", tid: restartTid, ret: 1, enterTime: restartBase, duration: 4000}
	if row != want {
		t.Fatalf("folded row = %+v, want %+v", row, want)
	}
	if f.el.numSyscalls != 1 {
		t.Fatalf("numSyscalls = %d, want 1", f.el.numSyscalls)
	}
	f.requireNothingHeld()
}

// TestTheTwoFoldsDoNotMix: each restart code has its own continuation. A
// -516 row is resumed by restart_syscall only - a RESUME record releases it -
// and still folds with re-execution folding on; a -512 row is continued by
// re-execution only, so a restart_syscall enter releases it.
func TestTheTwoFoldsDoNotMix(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	f.interrupt(restartBase, restartTid)
	released := f.feedOne(f.resumeRecord(restartBase+800, restartTid), "RESUME for a -516 row")
	if released.name != "clock_nanosleep" || released.ret != -516 {
		t.Fatalf("released row = %+v, want the unchanged -516 sleep", released)
	}

	f = newReexecFixture(t, globalfilter.Filter{})
	f.interrupt(restartBase, restartTid)
	f.feedNone(f.restartEnter(restartBase+1500, restartTid), "restart_syscall enter")
	row := f.feedOne(f.restartExit(restartBase+3000, restartTid, 0), "restart_syscall exit")
	if row.name != "clock_nanosleep" || row.ret != 0 || row.duration != 3000 {
		t.Fatalf("folded row = %+v, want the sleep folded with restart_syscall", row)
	}

	f = newReexecFixture(t, globalfilter.Filter{})
	f.interruptRead(restartBase, restartTid, restartSys)
	released = f.feedOne(f.restartEnter(restartBase+900, restartTid), "restart_syscall enter for a -512 row")
	requireInterruptedRow(t, released, restartSys)
}

// TestCallInterruptedInsideTheHandlerTakesTheRowsPlace: the handler of a
// restarting signal makes a blocking call that is interrupted in turn. BPF
// tracks the latest interrupted call of a task, so the outer row is released
// unchanged and the inner one is held and folded on its own proof.
func TestCallInterruptedInsideTheHandlerTakesTheRowsPlace(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	f.interruptRead(restartBase, restartTid, restartSys)
	f.feedNone(f.handlerRecord(restartBase+510, restartTid, true), "HANDLER record")
	f.feedNone(f.sleepEnter(restartBase+600, restartTid), "the handler's sleep enter")
	outer := f.feedOne(f.sleepExit(restartBase+700, restartTid, -516), "the handler's sleep, interrupted")
	if outer.name != "read" || outer.ret != restartSys {
		t.Fatalf("released row = %+v, want the outer interrupted read", outer)
	}
	f.feedNone(f.restartEnter(restartBase+900, restartTid), "restart_syscall enter")
	inner := f.feedOne(f.restartExit(restartBase+1200, restartTid, 0), "restart_syscall exit")
	if inner.name != "clock_nanosleep" || inner.ret != 0 || inner.duration != 600 {
		t.Fatalf("inner row = %+v, want the handler's sleep folded with its restart_syscall", inner)
	}
	f.requireNothingHeld()
}

// TestReexecRowsStayUnfoldedWithoutTheProbe: when the signal_deliver probe
// did not attach (or the exit probe, or the drop counter is missing: see
// TestFoldReexecutedRestartsNeedsTheWholeProof), a RESUME record proves
// nothing - without signal_deliver it would also precede a program's own retry.
// The rows are then not held at all: the interrupted row is emitted at its
// exit and the re-execution is a second row, exactly as before task 103.
func TestReexecRowsStayUnfoldedWithoutTheProbe(t *testing.T) {
	f := newRestartFixture(t, globalfilter.Filter{})
	f.feedNone(f.readEnter(restartBase, restartTid), "read enter")
	first := f.feedOne(f.readExit(restartBase+500, restartTid, restartSys), "interrupted read exit")
	requireInterruptedRow(t, first, restartSys)
	f.feedNone(f.resumeRecord(restartBase+800, restartTid), "RESUME record")
	f.feedNone(f.readEnter(restartBase+800, restartTid), "re-executed read enter")
	second := f.feedOne(f.readExit(restartBase+3000, restartTid, 1), "re-executed read exit")
	if second.ret != 1 || second.enterTime != restartBase+800 {
		t.Fatalf("second row = %+v, want the re-execution as its own row", second)
	}
	if f.el.numSyscalls != 2 {
		t.Fatalf("numSyscalls = %d, want 2", f.el.numSyscalls)
	}
}

// TestReexecFoldIsFilteredAsOneRow: filters judge the folded row, not its
// pieces - the final return value, not the restart code, and the whole span.
func TestReexecFoldIsFilteredAsOneRow(t *testing.T) {
	tests := []struct {
		name   string
		filter globalfilter.Filter
		want   int
	}{
		{"ret is the final return", globalfilter.Filter{
			RetVal: &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: 1}}, 1},
		{"the restart code is gone", globalfilter.Filter{
			RetVal: &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: -512}}, 0},
		{"latency floor above the interrupted piece", globalfilter.Filter{
			LatencyNs: &globalfilter.NumericFilter{Op: globalfilter.OpGte, Value: 2000}}, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newReexecFixture(t, tc.filter)
			f.interruptRead(restartBase, restartTid, restartSys)
			f.feedNone(f.resumeRecord(restartBase+800, restartTid), "RESUME record")
			f.feedNone(f.readEnter(restartBase+800, restartTid), "re-executed read enter")
			rows := f.feed(f.readExit(restartBase+3000, restartTid, 1))
			if len(rows) != tc.want {
				t.Fatalf("rows = %+v, want %d", rows, tc.want)
			}
			if f.el.numSyscalls != 1 {
				t.Fatalf("numSyscalls = %d, want 1", f.el.numSyscalls)
			}
		})
	}
}

// TestReexecFoldTakesAnyExitKindAndItsNameFixup: the continuation's exit
// replaces the held one whatever its kind (accept returns an AcceptEvent, not
// a RetEvent), and a name fixup the re-executed enter triggered is consumed
// with that enter instead of releasing the row.
func TestReexecFoldTakesAnyExitKindAndItsNameFixup(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	acceptEnter := func(at uint64) []byte {
		ev := types.AcceptEvent{EventType: types.ENTER_ACCEPT_EVENT, TraceId: types.SYS_ENTER_ACCEPT4,
			Time: at, Pid: restartPid, Tid: restartTid, Fd: restartReadFd,
			SchemaVersion: types.ACCEPT_EVENT_SCHEMA_VERSION}
		raw, err := ev.Bytes()
		if err != nil {
			t.Fatalf("AcceptEvent.Bytes() error = %v", err)
		}
		return raw
	}
	acceptExit := func(at uint64, ret int64) []byte {
		ev := types.AcceptEvent{EventType: types.EXIT_ACCEPT_EVENT, TraceId: types.SYS_EXIT_ACCEPT4,
			Time: at, Pid: restartPid, Tid: restartTid, Ret: ret,
			SchemaVersion: types.ACCEPT_EVENT_SCHEMA_VERSION}
		raw, err := ev.Bytes()
		if err != nil {
			t.Fatalf("AcceptEvent.Bytes() error = %v", err)
		}
		return raw
	}
	f.feedNone(acceptEnter(restartBase), "accept4 enter")
	f.feedNone(acceptExit(restartBase+500, restartSys), "interrupted accept4 exit")
	if _, held := f.el.restarts.lookup(restartTid); !held {
		t.Fatal("the interrupted accept4 row is not held")
	}
	f.feedNone(f.resumeRecord(restartBase+800, restartTid), "RESUME record")
	f.feedNone(acceptEnter(restartBase+800), "re-executed accept4 enter")
	fixup := types.OpenNameFixupEvent{EventType: types.OPEN_NAME_FIXUP_EVENT, Tid: restartTid}
	raw, err := fixup.Bytes()
	if err != nil {
		t.Fatalf("OpenNameFixupEvent.Bytes() error = %v", err)
	}
	f.feedNone(raw, "a name fixup of the re-executed enter")
	row := f.feedOne(acceptExit(restartBase+3000, 7), "re-executed accept4 exit")
	if row.name != "accept4" || row.ret != 7 || row.enterTime != restartBase || row.duration != 3000 {
		t.Fatalf("folded row = %+v, want accept4 ret=7 from the original enter, duration 3000", row)
	}
	f.requireNothingHeld()
}
