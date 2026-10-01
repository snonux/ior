package internal

import (
	"context"
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

// newReexecFixture is newRestartFixture with BPF's re-execution proof on, as
// trace setup turns it on when the signal_deliver probe attached.
func newReexecFixture(t *testing.T, filter globalfilter.Filter) *restartFixture {
	t.Helper()
	f := newRestartFixture(t, filter)
	f.el.foldReexecutedRestarts(true)
	return f
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
// next record, and only when it is an enter of the held syscall. Another
// syscall's enter (the re-executed enter was sampled out or lost), an exit,
// and a second RESUME all release the row unchanged.
func TestResumeMustBeFollowedByTheSameSyscall(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	_, syncEnter := makeEnterNullEvent(t, restartBase+900, restartPid, restartTid, types.SYS_ENTER_SYNC)
	for name, next := range map[string][]byte{
		"another syscall's enter": syncEnter,
		"a sleep enter":           f.sleepEnter(restartBase+900, restartTid),
		"an exit":                 f.readExit(restartBase+900, restartTid, 1),
		"a second RESUME":         f.resumeRecord(restartBase+900, restartTid),
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
// did not attach, a RESUME record would also precede a program's own retry.
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
