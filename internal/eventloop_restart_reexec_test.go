package internal

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"

	"ior/internal/event"
	"ior/internal/file"
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

// reexecDrops scripts the kernel drop counter and the boot clock of a fixture
// that has one (newDropCountedFixture, newReexecFixture): total is what the
// counter reads, err makes the read fail, now is what the boot clock reads
// (clockAt), and monitor is the periodic drop monitor on that counter, polled
// by hand (monitorPoll).
type reexecDrops struct {
	total   uint64
	err     error
	now     uint64
	monitor *ringbufDropMonitor
}

// newReexecFixture is newRestartFixture with BPF's re-execution proof on, as
// trace setup turns it on when the signal_deliver and sched_process_exit
// probes attached and the drop counter can be read. The counter starts at 0
// and stays there unless the test moves it (loseRecords). The boot clock
// stands at 0 until the test sets it (clockAt, monitorPoll); a test about
// drops must move it the way a live clock moves, past the time of every
// record already fed, or it proves nothing about the order of things.
func newReexecFixture(t *testing.T, filter globalfilter.Filter) *restartFixture {
	t.Helper()
	f := newDropCountedFixture(t, filter)
	f.el.foldProvenRestarts(true, true)
	return f
}

// loseRecords moves the kernel drop counter by n, as n records refused by a
// full ring buffer do. Nobody has read the counter yet.
func (f *restartFixture) loseRecords(n uint64) {
	f.drops.total += n
}

// clockAt sets the boot clock: what the loop reads when it next checks the
// drop counter for a fold.
func (f *restartFixture) clockAt(now uint64) {
	f.drops.now = now
}

// monitorPoll is one poll of the periodic drop monitor at boot-clock time
// now, through the handler the running loop wires it to.
func (f *restartFixture) monitorPoll(now uint64) {
	f.clockAt(now)
	f.el.handleRingbufDropResult(f.drops.monitor.Tick())
}

// foldRead drives one interrupted read at base through its whole
// re-execution with a live clock - each record is processed 50ns after it was
// stamped - and returns what the continuation's exit emitted: the folded row,
// or, when the fold is refused, whatever came out instead.
func (f *restartFixture) foldRead(base uint64) []restartRow {
	f.t.Helper()
	f.interruptRead(base, restartTid, restartSys)
	f.clockAt(base + 850)
	if rows := f.feed(f.resumeRecord(base+800, restartTid)); len(rows) != 0 {
		return rows
	}
	f.feedNone(f.readEnter(base+800, restartTid), "re-executed read enter")
	f.clockAt(base + 3050)
	return f.feed(f.readExit(base+3000, restartTid, 1))
}

// requireFolded fails unless rows is the single folded row of the read
// interrupted at base (foldRead).
func requireFolded(t *testing.T, rows []restartRow, base uint64, why string) {
	t.Helper()
	if len(rows) != 1 || rows[0].ret != 1 || rows[0].enterTime != base || rows[0].duration != 3000 {
		t.Fatalf("rows = %+v, want one folded read from %d: %s", rows, base, why)
	}
}

// requireTwoRows fails unless rows are the interrupted read at base, unchanged,
// followed by the continuation as a row of its own: the re-executed enter at
// base+800 paired with an exit at exitAt returning ret.
func requireTwoRows(t *testing.T, rows []restartRow, base, exitAt uint64, ret int64) {
	t.Helper()
	if len(rows) != 2 {
		t.Fatalf("rows = %+v, want the interrupted row and the continuation's row", rows)
	}
	if rows[0].ret != restartSys || rows[0].enterTime != base || rows[0].duration != 500 {
		t.Fatalf("first row = %+v, want the unchanged interrupted read", rows[0])
	}
	want := restartRow{name: "read", tid: restartTid, ret: ret, enterTime: base + 800,
		duration: exitAt - base - 800, gap: 300}
	if rows[1] != want {
		t.Fatalf("second row = %+v, want the continuation as its own row %+v", rows[1], want)
	}
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
	// The re-executed enter arrived and was taken; its exit and the next
	// read's enter were refused. The next read's exit is the same syscall's
	// exit and the tid's next record - only the drop counter tells it is not
	// the continuation. The fold is refused and the stream is what it was
	// before ior folded anything: the interrupted row, and the re-executed
	// enter paired with the exit that follows it.
	t.Run("exit and the next enter lost", func(t *testing.T) {
		f := newReexecFixture(t, globalfilter.Filter{})
		f.interruptRead(restartBase, restartTid, restartSys)
		f.feedNone(f.resumeRecord(restartBase+800, restartTid), "RESUME record")
		f.feedNone(f.readEnter(restartBase+800, restartTid), "re-executed read enter")
		f.loseRecords(2)
		f.clockAt(restartBase + 9000)
		rows := f.feed(f.readExit(restartBase+6000, restartTid, 7))
		requireTwoRows(t, rows, restartBase, restartBase+6000, 7)
		f.requireNothingHeld()
		if f.el.numSyscalls != 2 {
			t.Fatalf("numSyscalls = %d, want 2 (the rows shown)", f.el.numSyscalls)
		}
	})
}

// TestLostRecordsRefuseTheFoldAtResume: a loss the loop can see when RESUME
// arrives releases the row there, before any enter is taken for the fold.
func TestLostRecordsRefuseTheFoldAtResume(t *testing.T) {
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
		f.loseRecords(1)
		f.clockAt(restartBase + 9000)
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

// TestRefusedFoldKeepsTheContinuationsRow is the case a refused fold must not
// make worse than no fold at all. A thread blocked in a read is stopped and
// continued; RESUME and the re-executed enter arrive and the enter is taken
// for the fold. The read blocks on, and meanwhile some other task on the host
// loses a record. When the thread's genuine exit arrives the fold is refused -
// but nothing of this thread was lost, and its result must still be a row:
// the interrupted read as it was, then the re-execution with its real return
// value, both counted. (With the taken enter recycled, the exit had no enter
// left and vanished: no row, no count, no warning.)
func TestRefusedFoldKeepsTheContinuationsRow(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	f.interruptRead(restartBase, restartTid, restartSys)
	f.clockAt(restartBase + 850)
	f.feedNone(f.resumeRecord(restartBase+800, restartTid), "RESUME record")
	f.feedNone(f.readEnter(restartBase+800, restartTid), "re-executed read enter")
	f.loseRecords(1)
	f.clockAt(restartBase + 9050)
	rows := f.feed(f.readExit(restartBase+9000, restartTid, 1))
	requireTwoRows(t, rows, restartBase, restartBase+9000, 1)
	f.requireNothingHeld()
	if f.el.numSyscalls != 2 || f.el.numTracepointMismatches != 0 {
		t.Fatalf("numSyscalls=%d mismatches=%d, want 2 and 0", f.el.numSyscalls, f.el.numTracepointMismatches)
	}
	if _, pending := f.el.pairs.pending(restartTid); pending {
		t.Fatal("the continuation's enter is still parked after its exit")
	}
}

// TestReexecutedEnterIsNotAskedAboutLostRecords pins where the re-execution
// fold asks about lost records: at RESUME and at the continuation's exit, not
// at the re-executed enter in between (heldRestart.commitsToFold). RESUME
// names that enter by time and was asked just before it, so the enter is
// taken even when a loss has become visible since - unlike a restart_syscall
// enter, which is itself the announcing step and releases the row. The loss
// refuses the fold where the next question is asked, at the exit: the row is
// released there, not one record earlier, and the kept enter pairs with it.
func TestReexecutedEnterIsNotAskedAboutLostRecords(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	f.interruptRead(restartBase, restartTid, restartSys)
	f.clockAt(restartBase + 850)
	f.feedNone(f.resumeRecord(restartBase+800, restartTid), "RESUME record")
	f.loseRecords(1)
	f.clockAt(restartBase + 860)
	f.feedNone(f.readEnter(restartBase+800, restartTid), "re-executed read enter after a loss")
	held, ok := f.el.restarts.lookup(restartTid)
	if !ok || held.phase != restartContinuing || held.continuation == nil {
		t.Fatal("the re-executed enter was not kept with the held row")
	}
	f.clockAt(restartBase + 3050)
	rows := f.feed(f.readExit(restartBase+3000, restartTid, 1))
	requireTwoRows(t, rows, restartBase, restartBase+3000, 1)
	f.requireNothingHeld()
	if f.el.numSyscalls != 2 || f.el.numTracepointMismatches != 0 {
		t.Fatalf("numSyscalls=%d mismatches=%d, want 2 and 0", f.el.numSyscalls, f.el.numTracepointMismatches)
	}
}

// TestReleaseAfterTheEnterWasTakenParksItAgain: once the continuation's enter
// is taken, any record of the tid that is not its exit releases the row - here
// a task_rename another thread caused by writing the tid's comm, which says
// nothing about the call. The enter goes back to where every enter waits, so
// the exit that arrives later is a row of its own with the call's result. The
// same holds for the restart_syscall fold of a -516 row.
func TestReleaseAfterTheEnterWasTakenParksItAgain(t *testing.T) {
	rename := makeTaskRenameEvent(t, restartPid, restartTid, "renamed")

	f := newReexecFixture(t, globalfilter.Filter{})
	f.interruptRead(restartBase, restartTid, restartSys)
	f.feedNone(f.resumeRecord(restartBase+800, restartTid), "RESUME record")
	f.feedNone(f.readEnter(restartBase+800, restartTid), "re-executed read enter")
	requireInterruptedRow(t, f.feedOne(rename, "task_rename record"), restartSys)
	f.requireNothingHeld()
	if parked, ok := f.el.pairs.pending(restartTid); !ok || parked.EnterEv.GetTime() != restartBase+800 {
		t.Fatalf("pending enter = %+v (parked=%t), want the re-executed read's", parked, ok)
	}
	row := f.feedOne(f.readExit(restartBase+3000, restartTid, 1), "re-executed read exit")
	want := restartRow{name: "read", tid: restartTid, ret: 1, enterTime: restartBase + 800, duration: 2200, gap: 300}
	if row != want || f.el.numSyscalls != 2 {
		t.Fatalf("row = %+v numSyscalls=%d, want %+v and 2", row, f.el.numSyscalls, want)
	}

	f = newReexecFixture(t, globalfilter.Filter{})
	f.interrupt(restartBase, restartTid)
	f.resume(restartBase+1500, restartTid)
	f.feedNone(f.restartEnter(restartBase+1500, restartTid), "restart_syscall enter")
	if sleep := f.feedOne(rename, "task_rename record"); sleep.name != "clock_nanosleep" || sleep.ret != -516 {
		t.Fatalf("released row = %+v, want the unchanged -516 sleep", sleep)
	}
	row = f.feedOne(f.restartExit(restartBase+3000, restartTid, 0), "restart_syscall exit")
	if row.name != "restart_syscall" || row.ret != 0 || row.enterTime != restartBase+1500 || f.el.numSyscalls != 2 {
		t.Fatalf("row = %+v numSyscalls=%d, want restart_syscall as its own row and 2", row, f.el.numSyscalls)
	}
}

// TestTakenEnterGoesBackThroughTheEnterFilter: the enter a release parks
// again takes the path every enter takes, so a run that does not want the
// call sheds it there exactly as it would have without the fold. An open that
// a -path filter rejects is not parked, and its exit stays the unpaired exit
// it always was.
func TestTakenEnterGoesBackThroughTheEnterFilter(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	openEnter := func(at uint64) []byte {
		ev, _ := makeEnterOpenEvent(t, at, restartPid, restartTid)
		copy(ev.Filename[:], "/fifo/wanted\x00")
		return eventBytes(t, &ev)
	}
	f.feedNone(openEnter(restartBase), "openat enter")
	exit, _ := makeExitOpenEvent(t, restartBase+500, restartPid, restartTid)
	exit.Ret = restartSys
	f.feedNone(eventBytes(t, &exit), "interrupted openat exit")
	f.feedNone(f.resumeRecord(restartBase+800, restartTid), "RESUME record")
	f.feedNone(openEnter(restartBase+800), "re-executed openat enter")
	if held, ok := f.el.restarts.lookup(restartTid); !ok || held.continuation == nil {
		t.Fatal("the re-executed openat enter was not taken for the fold")
	}

	f.el.SetFilter(globalfilter.Filter{File: &globalfilter.StringFilter{Pattern: "/elsewhere"}})
	f.feed(makeTaskRenameEvent(t, restartPid, restartTid, "renamed"))
	f.requireNothingHeld()
	if parked, ok := f.el.pairs.pending(restartTid); ok {
		t.Fatalf("pending enter = %+v, want none: the raw enter filter rejects the open", parked.EnterEv)
	}
}

// TestAcceptedFoldRecyclesTheTakenEnter: a fold that is accepted is done with
// the continuation's enter. When the fold ends in a restart code the row is
// held again, and it must not carry the old enter along: a later release
// would park it, and the tid would own a pending enter of a call that
// completed long ago.
func TestAcceptedFoldRecyclesTheTakenEnter(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	f.interruptRead(restartBase, restartTid, restartSys)
	f.feedNone(f.resumeRecord(restartBase+800, restartTid), "RESUME record")
	f.feedNone(f.readEnter(restartBase+800, restartTid), "re-executed read enter")
	f.feedNone(f.readExit(restartBase+1500, restartTid, restartSys), "re-executed exit, interrupted again")
	held, ok := f.el.restarts.lookup(restartTid)
	if !ok || held.continuation != nil {
		t.Fatalf("held = %+v (held=%t), want the row held again without a taken enter", held, ok)
	}
	row := f.feedOne(makeTaskRenameEvent(t, restartPid, restartTid, "renamed"), "task_rename record")
	if row.ret != restartSys || row.enterTime != restartBase || row.duration != 1500 {
		t.Fatalf("released row = %+v, want the read from its first enter to the second interruption", row)
	}
	if parked, ok := f.el.pairs.pending(restartTid); ok {
		t.Fatalf("pending enter = %+v, want none", parked.EnterEv)
	}
}

// TestInterruptedExitInTheHandlerReleasesTheRowUnpaired: BPF replaces or
// clears a task's entry on every emitted exit with a restart code, so from
// that record on a RESUME cannot be about the row the handler was running
// for. The row must go even when the exit pairs with nothing - its enter was
// shed by the raw enter filter (an open that -path or -comm rejects) or lost.
// Left waiting, the outer row took the inner call's re-execution for its own
// whenever both were the same syscall: RESUME, then an enter of that syscall
// with RESUME's time.
func TestInterruptedExitInTheHandlerReleasesTheRowUnpaired(t *testing.T) {
	for _, innerRet := range []int64{restartSys, restartNoIntr, restartNoHand, -516} {
		f := newReexecFixture(t, globalfilter.Filter{})
		f.interruptRead(restartBase, restartTid, restartSys)
		f.feedNone(f.handlerRecord(restartBase+510, restartTid, true), "HANDLER record")
		// The handler's own read: its enter never reached the pair table.
		outer := f.feedOne(f.readExit(restartBase+700, restartTid, innerRet), "the handler's read, interrupted, unpaired")
		requireInterruptedRow(t, outer, restartSys)
		f.requireNothingHeld()

		f.feedNone(f.resumeRecord(restartBase+900, restartTid), "RESUME for the handler's read")
		f.feedNone(f.readEnter(restartBase+900, restartTid), "the handler's read, re-executed")
		inner := f.feedOne(f.readExit(restartBase+2000, restartTid, 7), "its exit")
		want := restartRow{name: "read", tid: restartTid, ret: 7, enterTime: restartBase + 900, duration: 1100, gap: 400}
		if inner != want {
			t.Fatalf("inner ret %d: row = %+v, want the handler's read on its own %+v", innerRet, inner, want)
		}
	}
}

// TestHeldRowWithATakenEnterIsReleasedWhenTheLoopStops: the trace ends between
// the continuation's enter and its exit. The interrupted row is emitted as it
// was, once, and the enter is back among the pending enters, where every call
// still in flight at the stop is.
func TestHeldRowWithATakenEnterIsReleasedWhenTheLoopStops(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	var rows []restartRow
	f.el.SetPrintCallback(func(ep *event.Pair) {
		rows = append(rows, rowOf(ep))
		ep.Recycle()
	})
	rawCh := filledRawChannel([][]byte{
		f.readEnter(restartBase, restartTid), f.readExit(restartBase+500, restartTid, restartSys),
		f.resumeRecord(restartBase+800, restartTid), f.readEnter(restartBase+800, restartTid),
	})
	close(rawCh)
	f.el.run(context.Background(), rawCh)

	if len(rows) != 1 {
		t.Fatalf("rows = %+v, want the interrupted read alone", rows)
	}
	requireInterruptedRow(t, rows[0], restartSys)
	f.requireNothingHeld()
	if parked, ok := f.el.pairs.pending(restartTid); !ok || parked.EnterEv.GetTime() != restartBase+800 {
		t.Fatalf("pending enter = %+v (parked=%t), want the re-executed read's", parked, ok)
	}
	if f.el.numSyscalls != 1 || f.el.numSyscallsAfterFilter != 1 {
		t.Fatalf("numSyscalls=%d afterFilter=%d, want 1 and 1", f.el.numSyscalls, f.el.numSyscallsAfterFilter)
	}
}

// TestDropsBeforeTheInterruptionDoNotBlockTheFold: the drop check asks about
// the time since the interrupted exit only. A loss the periodic monitor saw
// before the call was interrupted - a second or an hour before - says nothing
// about this call: the counter stood at that total before the interruption
// and still does at RESUME and at the folding exit. The clock runs as it does
// live, so the fold's own checks read the counter after the interruption.
func TestDropsBeforeTheInterruptionDoNotBlockTheFold(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	f.loseRecords(5)
	f.monitorPoll(restartBase - 100)
	requireFolded(t, f.foldRead(restartBase), restartBase, "the monitor saw the loss before the interruption")
	// The same total, seen again by a later poll, is still the old loss.
	f.monitorPoll(restartBase + 9000)
	requireFolded(t, f.foldRead(restartBase+10000), restartBase+10000, "a poll that saw no change is no new loss")
	if f.el.numSyscalls != 2 {
		t.Fatalf("numSyscalls = %d, want 2 (two folded reads)", f.el.numSyscalls)
	}
}

// TestDropNoticedWhileTheCallBlockedDoesNotBlockTheFold: the question is
// asked from the interrupted EXIT's time, not from the call's enter. A read
// that blocks for a long time before it is interrupted may see any number of
// drops come and go meanwhile; they lie before the records the fold reasons
// about (those reserved after the interrupted exit).
func TestDropNoticedWhileTheCallBlockedDoesNotBlockTheFold(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	f.feedNone(f.readEnter(restartBase, restartTid), "read enter")
	f.loseRecords(1)
	f.monitorPoll(restartBase + 200)
	f.feedNone(f.readExit(restartBase+500, restartTid, restartSys), "interrupted read exit")
	f.clockAt(restartBase + 850)
	f.feedNone(f.resumeRecord(restartBase+800, restartTid), "RESUME record")
	f.feedNone(f.readEnter(restartBase+800, restartTid), "re-executed read enter")
	f.clockAt(restartBase + 3050)
	rows := f.feed(f.readExit(restartBase+3000, restartTid, 1))
	requireFolded(t, rows, restartBase, "the loss was seen before the interrupted exit")
}

// TestDropsAfterTheInterruptionRefuseTheFold is the negative of the two tests
// above: a loss that the first observation places at or after the interrupted
// exit refuses the fold, whoever notices it - the monitor while the row is
// held, the loop's own read at RESUME, or its read at the folding exit. And
// the call after it folds again: the loss then lies before its interruption.
func TestDropsAfterTheInterruptionRefuseTheFold(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	f.interruptRead(restartBase, restartTid, restartSys)
	f.loseRecords(1)
	f.monitorPoll(restartBase + 600)
	f.clockAt(restartBase + 850)
	released := f.feedOne(f.resumeRecord(restartBase+800, restartTid), "RESUME after the monitor saw a loss")
	requireInterruptedRow(t, released, restartSys)
	f.feedNone(f.readEnter(restartBase+800, restartTid), "re-executed read enter")
	f.feedOne(f.readExit(restartBase+3000, restartTid, 1), "re-executed read exit")

	const second, third = restartBase + 10000, restartBase + 20000
	requireFolded(t, f.foldRead(second), second, "the loss lies before this call's interruption")

	f.interruptRead(third, restartTid, restartSys)
	f.loseRecords(1)
	f.clockAt(third + 850)
	rows := f.feed(f.resumeRecord(third+800, restartTid))
	if len(rows) != 1 || rows[0].ret != restartSys || rows[0].enterTime != third {
		t.Fatalf("rows = %+v, want the row released by the loop's own read at RESUME", rows)
	}
	f.feedNone(f.readEnter(third+800, restartTid), "re-executed read enter")
	f.feedOne(f.readExit(third+3000, restartTid, 1), "re-executed read exit")
	if f.el.numSyscalls != 5 {
		t.Fatalf("numSyscalls = %d, want 5 (two refused folds of two rows each, one fold)", f.el.numSyscalls)
	}
}

// TestDropWithNoObservationBeforeTheInterruptionRefusesTheFold: the loss
// happened before the call was interrupted, but nobody read the counter
// between the loss and the interruption. A counter says how many, not when,
// so whoever sees the new total first - the fold's own read at RESUME, or a
// monitor poll that comes after the interruption - cannot place the loss
// before the interrupted exit. The proof is impossible and the fold is
// refused; the call after it folds.
func TestDropWithNoObservationBeforeTheInterruptionRefusesTheFold(t *testing.T) {
	for name, pollWhileHeld := range map[string]bool{"first seen at RESUME": false, "first seen by a poll while held": true} {
		t.Run(name, func(t *testing.T) {
			f := newReexecFixture(t, globalfilter.Filter{})
			f.monitorPoll(restartBase - 5000) // the last poll before the loss
			f.loseRecords(3)                  // lost at about restartBase-100, unobserved
			f.interruptRead(restartBase, restartTid, restartSys)
			if pollWhileHeld {
				f.monitorPoll(restartBase + 600)
			}
			f.clockAt(restartBase + 850)
			released := f.feedOne(f.resumeRecord(restartBase+800, restartTid), "RESUME record")
			requireInterruptedRow(t, released, restartSys)
			f.feedNone(f.readEnter(restartBase+800, restartTid), "re-executed read enter")
			f.feedOne(f.readExit(restartBase+3000, restartTid, 1), "re-executed read exit")

			const next = restartBase + 10000
			requireFolded(t, f.foldRead(next), next, "the loss is now covered by an observation before this interruption")
		})
	}
}

// TestRestartDropWatch pins the watch itself: a total is stamped with the
// time of the first observation that returned it, whoever made it, an
// unchanged total keeps that stamp, and a missing or failing counter always
// reports a loss.
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
	// An observation from elsewhere (the monitor) counts like the watch's own.
	total = 7
	if seen := watch.observe(7, 1000); seen != 1000 {
		t.Fatalf("observe(7, 1000) = %d, want 1000: the first observation of a new total stamps it", seen)
	}
	if seen := watch.observe(7, 1500); seen != 1000 {
		t.Fatalf("observe(7, 1500) = %d, want 1000: a repeated total keeps its first stamp", seen)
	}
	now = 5000
	if watch.lostSince(1001, src, clock) || !watch.lostSince(1000, src, clock) {
		t.Fatal("a loss first observed at 1000 must refuse a row interrupted at 1000 and no row interrupted later")
	}
	if !watch.lostSince(0, nil, clock) {
		t.Fatal("a missing counter did not report a loss")
	}
	failing := ringbufDropSourceFunc(func() (uint64, error) { return 0, errors.New("unreadable") })
	if !watch.lostSince(9000, failing, clock) {
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
	// Fill the tracker to the bound with rows of other threads, which are as
	// made up as the fixture's own (absentPidBase + n, n below restartPid's).
	for tid := uint32(absentPidBase + 1); len(f.el.restarts.held) < maxHeldRestarts; tid++ {
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

// TestTheTwoFoldsDoNotMix: both folds go by a RESUME record, but each restart
// code has its own continuation. A -516 row is resumed by restart_syscall
// only: the announced enter of its own syscall (what follows RESUME when
// restart_syscall is not traced and the thread's next traced call happens to
// be another sleep) releases it. A -512 row is continued by re-execution
// only, so an announced restart_syscall enter releases it.
func TestTheTwoFoldsDoNotMix(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	f.interrupt(restartBase, restartTid)
	f.resume(restartBase+800, restartTid)
	released := f.feedOne(f.sleepEnter(restartBase+800, restartTid), "announced clock_nanosleep enter for a -516 row")
	if released.name != "clock_nanosleep" || released.ret != -516 {
		t.Fatalf("released row = %+v, want the unchanged -516 sleep", released)
	}
	next := f.feedOne(f.sleepExit(restartBase+2000, restartTid, 0), "the next sleep's exit")
	if next.name != "clock_nanosleep" || next.ret != 0 || next.enterTime != restartBase+800 || f.el.numSyscalls != 2 {
		t.Fatalf("row = %+v numSyscalls=%d, want the next sleep as its own row and 2", next, f.el.numSyscalls)
	}

	f = newReexecFixture(t, globalfilter.Filter{})
	f.interrupt(restartBase, restartTid)
	f.resume(restartBase+1500, restartTid)
	f.feedNone(f.restartEnter(restartBase+1500, restartTid), "restart_syscall enter")
	row := f.feedOne(f.restartExit(restartBase+3000, restartTid, 0), "restart_syscall exit")
	if row.name != "clock_nanosleep" || row.ret != 0 || row.duration != 3000 {
		t.Fatalf("folded row = %+v, want the sleep folded with restart_syscall", row)
	}

	f = newReexecFixture(t, globalfilter.Filter{})
	f.interruptRead(restartBase, restartTid, restartSys)
	f.resume(restartBase+900, restartTid)
	released = f.feedOne(f.restartEnter(restartBase+900, restartTid), "announced restart_syscall enter for a -512 row")
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
	f.resume(restartBase+900, restartTid)
	f.feedNone(f.restartEnter(restartBase+900, restartTid), "restart_syscall enter")
	inner := f.feedOne(f.restartExit(restartBase+1200, restartTid, 0), "restart_syscall exit")
	if inner.name != "clock_nanosleep" || inner.ret != 0 || inner.duration != 600 {
		t.Fatalf("inner row = %+v, want the handler's sleep folded with its restart_syscall", inner)
	}
	f.requireNothingHeld()
}

// TestReexecRowsStayUnfoldedWithoutTheProbe: when the signal_deliver probe
// did not attach (or the exit probe, or the drop counter is missing: see
// TestFoldProvenRestartsNeedsTheWholeProof), a RESUME record proves
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

// execEnter is an execve enter of tid in the fixture's process.
func (f *restartFixture) execEnter(at uint64, tid uint32) []byte {
	f.t.Helper()
	return f.execEnterOf(types.SYS_ENTER_EXECVE, at, tid)
}

// execEnterOf is execEnter for either exec syscall: id is SYS_ENTER_EXECVE or
// SYS_ENTER_EXECVEAT, which share the enter record's kind.
func (f *restartFixture) execEnterOf(id types.TraceId, at uint64, tid uint32) []byte {
	f.t.Helper()
	enter := &types.ExecEvent{EventType: types.ENTER_EXEC_EVENT, TraceId: id, Time: at,
		Pid: restartPid, Tid: tid, Dirfd: -1, SchemaVersion: types.EXEC_EVENT_SCHEMA_VERSION}
	copy(enter.Filename[:], "/usr/bin/newprog")
	copy(enter.Comm[:], "sleeper")
	return mustRaw(f.t, enter)
}

func (f *restartFixture) execExit(at uint64, tid uint32, ret int64) []byte {
	f.t.Helper()
	return f.execExitOf(types.SYS_EXIT_EXECVE, at, tid, ret)
}

// execExitOf is execExit for either exec syscall (SYS_EXIT_EXECVE or
// SYS_EXIT_EXECVEAT).
func (f *restartFixture) execExitOf(id types.TraceId, at uint64, tid uint32, ret int64) []byte {
	f.t.Helper()
	_, raw := makeExitRetEvent(f.t, at, restartPid, tid, id, ret)
	return raw
}

// execRecord is the sched_process_exec record of an exec by the thread that
// ran as oldTid and continues as tid. exitUntraced marks the record of a run
// traced with -tid <oldTid>, whose execve exit never arrives.
func (f *restartFixture) execRecord(at uint64, tid, oldTid uint32, exitUntraced bool) []byte {
	f.t.Helper()
	ev := &types.ProcessExecEvent{EventType: types.PROCESS_EXEC_EVENT, Time: at, Pid: restartPid, Tid: tid, OldTid: oldTid}
	if exitUntraced {
		ev.ExitUntraced = 1
	}
	copy(ev.Comm[:], "newprog")
	return mustRaw(f.t, ev)
}

// interruptExecve drives an execve of tid that exits -513 (a signal arrived
// while it waited for cred_guard_mutex) up to the point where its re-executed
// enter has been taken for the fold: the row is held and the enter kept.
func (f *restartFixture) interruptExecve(tid uint32) {
	f.t.Helper()
	f.interruptExec(types.SYS_ENTER_EXECVE, tid)
}

// interruptExec is interruptExecve for either exec syscall, named by its enter
// trace ID (SYS_ENTER_EXECVE or SYS_ENTER_EXECVEAT).
func (f *restartFixture) interruptExec(enterID types.TraceId, tid uint32) {
	f.t.Helper()
	exitID, ok := execExitTraceID(enterID)
	if !ok {
		f.t.Fatalf("%s is not an exec enter", enterID.Name())
	}
	f.feedNone(f.execEnterOf(enterID, restartBase, tid), "exec enter")
	f.feedNone(f.execExitOf(exitID, restartBase+500, tid, restartNoIntr), "interrupted exec exit")
	f.feedNone(f.resumeRecord(restartBase+800, tid), "RESUME record")
	f.feedNone(f.execEnterOf(enterID, restartBase+800, tid), "re-executed exec enter")
	f.requireExecveStillContinuing(tid)
}

// holdReexecutedRead drives a read of restartTid that exits -512 up to the
// point where its re-executed enter has been taken for the fold, as
// interruptExecve does for an execve.
func (f *restartFixture) holdReexecutedRead() {
	f.t.Helper()
	f.interruptRead(restartBase, restartTid, restartSys)
	f.feedNone(f.resumeRecord(restartBase+800, restartTid), "RESUME record")
	f.feedNone(f.readEnter(restartBase+800, restartTid), "re-executed read enter")
}

// requireNoEnterPending fails when an enter is still parked under any of tids.
func (f *restartFixture) requireNoEnterPending(tids ...uint32) {
	f.t.Helper()
	for _, tid := range tids {
		if parked, ok := f.el.pairs.pending(tid); ok {
			f.t.Fatalf("enter %+v still parked under tid %d", parked.EnterEv, tid)
		}
	}
}

// The interrupted execve of interruptExecve as it was at its first exit, and
// its successful re-execution as a row of its own (exit at restartBase+3000).
var (
	interruptedExecveRow = restartRow{name: "execve", tid: restartTid, ret: restartNoIntr, enterTime: restartBase, duration: 500}
	reexecutedExecveRow  = restartRow{name: "execve", tid: restartTid, ret: 0, enterTime: restartBase + 800,
		duration: 2200, gap: 300}
)

// TestNonLeaderExecReleasesTheRowHeldUnderItsOldTid: a non-leader thread's
// execve exits -513 and is re-executed; the re-executed enter is taken for the
// fold, and then the exec succeeds. de_thread hands the thread the leader's
// tid, so everything that follows - the exec record, the execve's exit -
// arrives under that tid, and the thread never gets a sched_process_exit under
// its old one. The exec record is the last word about the old tid: it releases
// the row held there, the kept enter is parked again and moves to the leader
// tid with the rest of the caller's state, and the exit pairs with it. (Before,
// the row stayed held under the vanished tid and the successful execve's exit
// found no enter: no row for the exec at all.)
func TestNonLeaderExecReleasesTheRowHeldUnderItsOldTid(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	f.interruptExecve(restartTid)
	f.feedNone(makeThreadExitEvent(t, restartBase+2000, restartPid, restartPid), "the dead leader's exit record")
	released := f.feedOne(f.execRecord(restartBase+2100, restartPid, restartTid, false), "exec record")
	if released != interruptedExecveRow {
		t.Fatalf("released row = %+v, want the unchanged interrupted execve %+v", released, interruptedExecveRow)
	}
	f.requireNothingHeld()
	if parked, ok := f.el.pairs.pending(restartPid); !ok || parked.EnterEv.GetTime() != restartBase+800 {
		t.Fatalf("enter under the leader tid = %+v (parked=%t), want the re-executed execve's", parked, ok)
	}
	row := f.feedOne(f.execExit(restartBase+3000, restartPid, 0), "execve exit under the leader tid")
	if row != reexecutedExecveRow {
		t.Fatalf("row = %+v, want the successful execve %+v", row, reexecutedExecveRow)
	}
	if f.el.numSyscalls != 2 || f.el.numTracepointMismatches != 0 {
		t.Fatalf("numSyscalls=%d mismatches=%d, want 2 and 0", f.el.numSyscalls, f.el.numTracepointMismatches)
	}
	f.requireNoEnterPending(restartTid, restartPid)
	if _, ok := f.el.commState().cached(restartTid); ok {
		t.Fatal("the re-parked enter left a comm cached under the pre-exec tid")
	}
}

// TestNonLeaderExecFromARestartingHandlerReleasesTheHeldRow: a read of a
// non-leader thread exits -512, an SA_RESTART handler runs - and execs. The
// handler never returns, the thread continues under the leader's tid, and no
// record ever names its old tid again except the exec record's OldTid. That
// record releases the read, which will never be re-executed. (Before, the
// execve row came out but the read stayed held until the loop stopped.)
func TestNonLeaderExecFromARestartingHandlerReleasesTheHeldRow(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	f.interruptRead(restartBase, restartTid, restartSys)
	f.feedNone(f.handlerRecord(restartBase+510, restartTid, true), "HANDLER record")
	f.feedNone(f.execEnter(restartBase+800, restartTid), "the handler's execve enter")
	f.feedNone(makeThreadExitEvent(t, restartBase+2000, restartPid, restartPid), "the dead leader's exit record")
	released := f.feedOne(f.execRecord(restartBase+2100, restartPid, restartTid, false), "exec record")
	requireInterruptedRow(t, released, restartSys)
	f.requireNothingHeld()
	row := f.feedOne(f.execExit(restartBase+3000, restartPid, 0), "execve exit under the leader tid")
	if row != reexecutedExecveRow {
		t.Fatalf("row = %+v, want the handler's execve %+v", row, reexecutedExecveRow)
	}
	if f.el.numSyscalls != 2 {
		t.Fatalf("numSyscalls = %d, want 2 (the read and the execve)", f.el.numSyscalls)
	}
	f.requireNoEnterPending(restartTid, restartPid)
}

// TestExecReleasesTheHeldRowBeforeTheCloexecEviction pins the order inside
// handleProcessExecEvent: the row held under the caller's old tid is released
// before the exec record evicts the process's FD_CLOEXEC descriptors. The held
// call completed before the exec, so its row must name the file its descriptor
// had then - what it would have shown without the hold. Released after the
// eviction, a read on a close-on-exec descriptor came out without its path.
func TestExecReleasesTheHeldRowBeforeTheCloexecEviction(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	f.el.fdState().set(restartReadFd, restartPid,
		file.NewFd(restartReadFd, "/cloexec", syscall.O_RDONLY|syscall.O_CLOEXEC))
	f.interruptRead(restartBase, restartTid, restartSys)
	f.feedNone(f.handlerRecord(restartBase+510, restartTid, true), "HANDLER record")
	f.feedNone(f.execEnter(restartBase+800, restartTid), "the handler's execve enter")

	f.el.processRawEvent(f.execRecord(restartBase+2100, restartPid, restartTid, false), f.out)
	select {
	case released := <-f.out:
		defer released.Recycle()
		if got := released.FileName(); got != "/cloexec" {
			t.Fatalf("released read names %q, want the pre-exec file /cloexec", got)
		}
	default:
		t.Fatal("the exec record released no row")
	}
	if _, tracked := f.el.fdState().get(restartReadFd, restartPid); tracked {
		t.Fatal("the close-on-exec descriptor survived the exec record")
	}
}

// TestNonLeaderExecWithALostExecRecordReleasesTheHeldRow is the case above
// with the exec record lost: the successful execve exit under the leader tid
// adopts the enter still parked under the caller's (adoptLostExecCaller), and
// that adoption retires the old tid just as the record would have - the row
// held there included.
func TestNonLeaderExecWithALostExecRecordReleasesTheHeldRow(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	f.interruptRead(restartBase, restartTid, restartSys)
	f.feedNone(f.handlerRecord(restartBase+510, restartTid, true), "HANDLER record")
	f.feedNone(f.execEnter(restartBase+800, restartTid), "the handler's execve enter")
	rows := f.feed(f.execExit(restartBase+3000, restartPid, 0))
	if len(rows) != 2 || rows[1] != reexecutedExecveRow {
		t.Fatalf("rows = %+v, want the released read, then the execve %+v", rows, reexecutedExecveRow)
	}
	requireInterruptedRow(t, rows[0], restartSys)
	f.requireNothingHeld()
	f.requireNoEnterPending(restartTid, restartPid)
}

// TestReexecutedNonLeaderExecWithALostExecRecordIsRecovered is task r13: a
// non-leader thread's execve exits -513 and is re-executed, the re-executed
// enter is taken for the fold - and the exec record, the one record that names
// the thread's old tid, is lost. The successful exit under the leader tid finds
// no enter of its own and no parked caller, because the enter is kept with the
// held row. It finds that row instead, releases it and pairs with the enter the
// release parks again: the same two rows the delivered record produces. (Before,
// the exit was dropped - no row for the exec, not counted - and the -513 row
// stayed held under the vanished tid until the loop stopped.)
func TestReexecutedNonLeaderExecWithALostExecRecordIsRecovered(t *testing.T) {
	for name, leaderExitArrived := range map[string]bool{"leader's exit record arrived": true, "and lost too": false} {
		t.Run(name, func(t *testing.T) {
			f := newReexecFixture(t, globalfilter.Filter{})
			f.interruptExecve(restartTid)
			if leaderExitArrived {
				f.feedNone(makeThreadExitEvent(t, restartBase+2000, restartPid, restartPid), "the dead leader's exit record")
			}
			rows := f.feed(f.execExit(restartBase+3000, restartPid, 0))
			if len(rows) != 2 || rows[0] != interruptedExecveRow || rows[1] != reexecutedExecveRow {
				t.Fatalf("rows = %+v, want %+v, then %+v", rows, interruptedExecveRow, reexecutedExecveRow)
			}
			f.requireNothingHeld()
			f.requireNoEnterPending(restartTid, restartPid)
			if f.el.numSyscalls != 2 || f.el.numTracepointMismatches != 0 {
				t.Fatalf("numSyscalls=%d mismatches=%d, want 2 and 0", f.el.numSyscalls, f.el.numTracepointMismatches)
			}
			f.requireOldTidRetired()
			// The new program's first call measures its gap from the execve's return.
			if next := f.syncCall(restartBase+3400, restartPid); next.gap != 400 {
				t.Fatalf("the new program's first row = %+v, want gap 400 from the execve's exit", next)
			}
		})
	}
}

// TestReexecutedNonLeaderExecveatWithALostExecRecordIsRecovered: the recovery
// above is not execve's alone. execveat shares the enter record's kind and the
// exec path, so a re-executed execveat whose exec record was lost comes out as
// its two rows as well - which needs the held row to be matched against the
// exit's own syscall, not against execve (reexecutesExecOf).
func TestReexecutedNonLeaderExecveatWithALostExecRecordIsRecovered(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	f.interruptExec(types.SYS_ENTER_EXECVEAT, restartTid)
	rows := f.feed(f.execExitOf(types.SYS_EXIT_EXECVEAT, restartBase+3000, restartPid, 0))
	interrupted, reexecuted := interruptedExecveRow, reexecutedExecveRow
	interrupted.name, reexecuted.name = "execveat", "execveat"
	if len(rows) != 2 || rows[0] != interrupted || rows[1] != reexecuted {
		t.Fatalf("rows = %+v, want %+v, then %+v", rows, interrupted, reexecuted)
	}
	f.requireNothingHeld()
	f.requireNoEnterPending(restartTid, restartPid)
	if f.el.numSyscalls != 2 || f.el.numTracepointMismatches != 0 {
		t.Fatalf("numSyscalls=%d mismatches=%d, want 2 and 0", f.el.numSyscalls, f.el.numTracepointMismatches)
	}
	f.requireOldTidRetired()
}

// TestTwiceInterruptedExecveWithALostExecRecordIsRecovered: the execve exits
// -513, is re-executed, exits -513 again and is re-executed once more before it
// succeeds - and the exec record is lost. The first re-execution is an ordinary
// fold (its exit arrives under the caller's own tid): one row from the first
// enter to the second -513, held again. Only the last re-execution is completed
// under the leader tid, and the recovery gives it a row of its own after that
// folded one.
func TestTwiceInterruptedExecveWithALostExecRecordIsRecovered(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	f.interruptExecve(restartTid)
	f.feedNone(f.execExit(restartBase+1200, restartTid, restartNoIntr), "the re-execution's interrupted exit")
	f.feedNone(f.resumeRecord(restartBase+1500, restartTid), "second RESUME record")
	f.feedNone(f.execEnter(restartBase+1500, restartTid), "second re-executed execve enter")
	f.requireExecveStillContinuing(restartTid)

	rows := f.feed(f.execExit(restartBase+3000, restartPid, 0))
	folded := restartRow{name: "execve", tid: restartTid, ret: restartNoIntr, enterTime: restartBase, duration: 1200}
	succeeded := restartRow{name: "execve", tid: restartTid, ret: 0, enterTime: restartBase + 1500, duration: 1500, gap: 300}
	if len(rows) != 2 || rows[0] != folded || rows[1] != succeeded {
		t.Fatalf("rows = %+v, want the folded -513 row %+v, then %+v", rows, folded, succeeded)
	}
	f.requireNothingHeld()
	f.requireNoEnterPending(restartTid, restartPid)
	if f.el.numSyscalls != 2 || f.el.numTracepointMismatches != 0 {
		t.Fatalf("numSyscalls=%d mismatches=%d, want 2 and 0", f.el.numSyscalls, f.el.numTracepointMismatches)
	}
	f.requireOldTidRetired()
}

// requireOldTidRetired fails when the non-leader exec left anything behind
// under the caller's pre-exec tid: a comm, a gap baseline, or a hint in the
// index of parked exec callers.
func (f *restartFixture) requireOldTidRetired() {
	f.t.Helper()
	if _, ok := f.el.commState().cached(restartTid); ok {
		f.t.Fatal("a comm is still cached under the pre-exec tid")
	}
	if _, ok := f.el.pairs.prevTimes[restartTid]; ok {
		f.t.Fatal("the gap baseline stayed under the pre-exec tid")
	}
	if f.el.pairs.execCallerHints != 0 || len(f.el.pairs.execCallers) != 0 {
		f.t.Fatalf("exec caller hints left behind: %v", f.el.pairs.execCallers)
	}
}

// requireExecveStillContinuing fails unless tid still holds its interrupted
// execve with the re-executed enter kept for the fold.
func (f *restartFixture) requireExecveStillContinuing(tid uint32) {
	f.t.Helper()
	held, ok := f.el.restarts.lookup(tid)
	if !ok || held.phase != restartContinuing || held.continuation == nil {
		f.t.Fatalf("tid %d holds %+v (held=%t), want its execve with the re-executed enter kept", tid, held, ok)
	}
}

// lostExecNegative is one stream of
// TestLostExecRecordRecoveryTakesOnlyTheReexecutedExecve: hold leaves a row
// held under restartTid, exit is an unpaired exec exit that must not adopt it,
// and phase is the phase the row must still stand in afterwards.
type lostExecNegative struct {
	name  string
	hold  func(f *restartFixture)
	exit  func(f *restartFixture) []byte
	phase restartPhase
}

// lostExecNegatives lists the streams in which the lost-record recovery must
// keep its hands off the held row: each differs from the recovered stream
// (interruptExecve, then a successful execve exit under the leader tid) in one
// thing - the exit's process, its syscall or its outcome, or what the row is
// and how far its re-execution got.
func lostExecNegatives() []lostExecNegative {
	const exitAt = restartBase + 3000
	reexecuted := func(f *restartFixture) { f.interruptExecve(restartTid) }
	leaderExit := func(f *restartFixture) []byte { return f.execExit(exitAt, restartPid, 0) }
	otherProcessExit := func(f *restartFixture) []byte {
		_, raw := makeExitRetEvent(f.t, exitAt, restartOtherTid, restartOtherTid, types.SYS_EXIT_EXECVE, 0)
		return raw
	}
	execveatExit := func(f *restartFixture) []byte {
		return f.execExitOf(types.SYS_EXIT_EXECVEAT, exitAt, restartPid, 0)
	}
	// A failed execve returns under the tid it entered under: this one is the
	// leader's own, whose enter this run did not see. Nobody exec'd.
	failedExit := func(f *restartFixture) []byte { return f.execExit(exitAt, restartPid, -int64(syscall.ENOENT)) }
	return []lostExecNegative{
		{"the exit is another process's", reexecuted, otherProcessExit, restartContinuing},
		{"the exit is another exec syscall's", reexecuted, execveatExit, restartContinuing},
		{"the exit is a failed execve's", reexecuted, failedExit, restartContinuing},
		{"the kept enter is not an exec enter", (*restartFixture).holdReexecutedRead, leaderExit, restartContinuing},
		{"the execve was not re-executed yet", func(f *restartFixture) { f.interruptedExecve(false) },
			leaderExit, restartWaiting},
		{"the re-executed enter never arrived", func(f *restartFixture) { f.interruptedExecve(true) },
			leaderExit, restartResumed},
	}
}

// interruptedExecve feeds an execve of restartTid that exits -513 and, when
// resumed, the RESUME record that announces its re-execution - but not the
// re-executed enter: the row is held without a kept enter.
func (f *restartFixture) interruptedExecve(resumed bool) {
	f.t.Helper()
	f.feedNone(f.execEnter(restartBase, restartTid), "execve enter")
	f.feedNone(f.execExit(restartBase+500, restartTid, restartNoIntr), "interrupted execve exit")
	if resumed {
		f.feedNone(f.resumeRecord(restartBase+800, restartTid), "RESUME record")
	}
}

// TestLostExecRecordRecoveryTakesOnlyTheReexecutedExecve: the negatives of the
// recovery above. An unpaired exec exit under a leader tid adopts a held row
// only when the exit is a successful one and that row is a re-executed exec of
// the same syscall in the same process. In every other stream
// (lostExecNegatives) the exit stays the unpaired exit it was - no row, not
// counted - and the held row stays where it is.
func TestLostExecRecordRecoveryTakesOnlyTheReexecutedExecve(t *testing.T) {
	for _, tc := range lostExecNegatives() {
		t.Run(tc.name, func(t *testing.T) {
			f := newReexecFixture(t, globalfilter.Filter{})
			tc.hold(f)
			f.feedNone(tc.exit(f), "an unpaired exec exit")
			held, ok := f.el.restarts.lookup(restartTid)
			if !ok || held.phase != tc.phase || len(f.el.restarts.held) != 1 {
				t.Fatalf("held = %+v (held=%t, %d rows), want the row untouched in phase %d",
					held, ok, len(f.el.restarts.held), tc.phase)
			}
			if (held.continuation != nil) != (tc.phase == restartContinuing) {
				t.Fatalf("kept enter = %+v in phase %d, want it kept exactly while continuing", held.continuation, tc.phase)
			}
			if f.el.numSyscalls != 1 || f.el.numTracepointMismatches != 0 {
				t.Fatalf("numSyscalls=%d mismatches=%d, want 1 (the interrupted call) and 0",
					f.el.numSyscalls, f.el.numTracepointMismatches)
			}
			f.requireNoEnterPending(restartTid, restartPid, restartOtherTid)
		})
	}
}

// TestParkedExecCallerWinsOverAReexecutedOne: when the process has both a
// parked exec caller and a thread holding a re-executed execve, the lost-record
// adoption takes the parked one, as it did before task r13. Only one of the two
// threads can have won the exec; the other's row waits for its own records.
func TestParkedExecCallerWinsOverAReexecutedOne(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	f.interruptExecve(restartTid)
	f.feedNone(f.execEnter(restartBase+900, restartOtherTid), "a sibling's execve enter")
	row := f.feedOne(f.execExit(restartBase+3000, restartPid, 0), "execve exit under the leader tid")
	want := restartRow{name: "execve", tid: restartOtherTid, ret: 0, enterTime: restartBase + 900, duration: 2100}
	if row != want {
		t.Fatalf("row = %+v, want the sibling's parked execve %+v", row, want)
	}
	f.requireExecveStillContinuing(restartTid)
	f.requireNoEnterPending(restartTid, restartPid, restartOtherTid)
}

// TestReexecutingExecCallerChoosesOneRow pins the lookup itself on trackers
// built by hand: the leader's own row (which a stream never leaves for this
// lookup - the exit's tid finds it first) and another process's are not
// candidates, and of several candidates the execve entered last is taken, the
// higher tid on a tie, whatever the map order.
func TestReexecutingExecCallerChoosesOneRow(t *testing.T) {
	const pid, a, b = uint32(absentPidBase + 7), uint32(absentPidBase + 8), uint32(absentPidBase + 9)
	reexecuting := func(pid, tid uint32, enteredAt uint64) *heldRestart {
		return &heldRestart{
			pair: &event.Pair{
				EnterEv: &types.ExecEvent{TraceId: types.SYS_ENTER_EXECVE, Pid: pid, Tid: tid},
				ExitEv:  &types.RetEvent{TraceId: types.SYS_EXIT_EXECVE, Pid: pid, Tid: tid, Ret: restartNoIntr},
			},
			phase:        restartContinuing,
			continuation: &types.ExecEvent{TraceId: types.SYS_ENTER_EXECVE, Time: enteredAt, Pid: pid, Tid: tid},
		}
	}
	exit := &types.RetEvent{TraceId: types.SYS_EXIT_EXECVE, Pid: pid, Tid: pid}
	for _, tc := range []struct {
		name  string
		held  []*heldRestart
		want  uint32
		found bool
	}{
		{"nothing held", nil, 0, false},
		{"the leader's own row", []*heldRestart{reexecuting(pid, pid, 100)}, 0, false},
		{"another process's row", []*heldRestart{reexecuting(pid+100, a, 100)}, 0, false},
		{"one caller", []*heldRestart{reexecuting(pid, a, 100), reexecuting(pid, pid, 900)}, a, true},
		{"the execve entered last", []*heldRestart{reexecuting(pid, a, 300), reexecuting(pid, b, 200)}, a, true},
		{"a tie goes to the higher tid", []*heldRestart{reexecuting(pid, a, 300), reexecuting(pid, b, 300)}, b, true},
	} {
		// Go randomizes map iteration: the answer must hold for every order.
		for range 32 {
			tracker := restartTracker{held: make(map[uint32]*heldRestart)}
			for _, held := range tc.held {
				tracker.held[held.pair.ExitEv.GetTid()] = held
			}
			if got, found := tracker.reexecutingExecCaller(exit); got != tc.want || found != tc.found {
				t.Fatalf("%s: caller = %d (found=%t), want %d (found=%t)", tc.name, got, found, tc.want, tc.found)
			}
		}
	}
}

// newtaskRecord is a task_newtask record that hands tid to a new thread of the
// fixture's process, or - outOfScope - to a task the trace does not follow.
func (f *restartFixture) newtaskRecord(at uint64, tid uint32, outOfScope bool) []byte {
	f.t.Helper()
	ev := &types.TaskNewtaskEvent{EventType: types.TASK_NEWTASK_EVENT, Time: at, Pid: restartPid, Tid: tid,
		CloneFlags: cloneFlagThread, CreatorPid: restartPid}
	if outOfScope {
		ev.ScopeFlags = types.TaskNewtaskChildOutOfScope
	}
	copy(ev.Comm[:], "sleeper")
	return mustRaw(f.t, ev)
}

// TestOutOfScopeNewtaskDoesNotParkTheDeadTasksEnter: a thread dies inside its
// re-executed execve, its exit record is lost, and the tid is handed to a task
// the trace does not follow. That record releases the -513 row, but
// handleTaskNewtaskEvent does not retire the tid of an out-of-scope child, so
// an enter parked again here stayed parked for good - under a tid that is
// another task's now, and as a parked exec caller of the process. The next
// unpaired successful execve exit of the process (here: the leader's own exec,
// whose enter this run did not see) then adopted it: a row for an execve that
// never returned. The dead task's enter is recycled instead.
func TestOutOfScopeNewtaskDoesNotParkTheDeadTasksEnter(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	f.interruptExecve(restartTid)
	released := f.feedOne(f.newtaskRecord(restartBase+2000, restartTid, true), "out-of-scope task_newtask record")
	if released != interruptedExecveRow {
		t.Fatalf("released row = %+v, want the unchanged interrupted execve %+v", released, interruptedExecveRow)
	}
	f.requireNothingHeld()
	f.requireNoEnterPending(restartTid)
	if f.el.pairs.execCallerHints != 0 || len(f.el.pairs.execCallers) != 0 {
		t.Fatalf("the dead task is still a parked exec caller: %v", f.el.pairs.execCallers)
	}
	f.feedNone(f.execExit(restartBase+9000, restartPid, 0), "a later unpaired execve exit of the process")
	if f.el.numSyscalls != 1 || f.el.numTracepointMismatches != 0 {
		t.Fatalf("numSyscalls=%d mismatches=%d, want 1 (the interrupted execve) and 0",
			f.el.numSyscalls, f.el.numTracepointMismatches)
	}
}

// takenContinuations drives restartTid, per fold, up to the point where the
// continuation's enter has been taken - a re-executed read and a stopped
// sleep's restart_syscall - and returns the interrupted row a release must
// then emit unchanged.
func takenContinuations() map[string]func(f *restartFixture) restartRow {
	return map[string]func(f *restartFixture) restartRow{
		"re-executed read": func(f *restartFixture) restartRow {
			f.holdReexecutedRead()
			return restartRow{name: "read", tid: restartTid, ret: restartSys, enterTime: restartBase, duration: 500}
		},
		"restart_syscall": func(f *restartFixture) restartRow {
			f.interrupt(restartBase, restartTid)
			f.resume(restartBase+800, restartTid)
			f.feedNone(f.restartEnter(restartBase+800, restartTid), "restart_syscall enter")
			return restartRow{name: "clock_nanosleep", tid: restartTid, ret: -516, enterTime: restartBase,
				duration: 500, sleepNs: restartSleepNs}
		},
	}
}

// taskGoneRecords builds the two records that say restartTid's task no longer
// exists (reportsTaskGone): its exit record, and a task_newtask record that
// hands the tid to a new thread the trace follows.
func taskGoneRecords() map[string]func(f *restartFixture) []byte {
	return map[string]func(f *restartFixture) []byte{
		"exit record": func(f *restartFixture) []byte {
			return makeThreadExitEvent(f.t, restartBase+2000, restartPid, restartTid)
		},
		"task_newtask record": func(f *restartFixture) []byte { return f.newtaskRecord(restartBase+2000, restartTid, false) },
	}
}

// TestDeadTasksEnterDoesNotCrowdOutLiveEnters: the record that says a task is
// gone - its exit record, or a task_newtask record reusing its tid - releases
// the row the task held and recycles the continuation's enter without parking
// it. Its control handler would evict a parked one within the same record, but
// not before the parking could trim the pending-enter table: with the table at
// its limit, the oldest enters of live threads were recycled to make room for
// an enter that was thrown away a moment later, and their exits found nothing.
// Both folds (takenContinuations) and both records (taskGoneRecords).
func TestDeadTasksEnterDoesNotCrowdOutLiveEnters(t *testing.T) {
	const firstLive, secondLive = restartOtherTid, restartPid
	for contName, hold := range takenContinuations() {
		for goneName, record := range taskGoneRecords() {
			t.Run(contName+", "+goneName, func(t *testing.T) {
				f := newReexecFixture(t, globalfilter.Filter{})
				f.el.pairs.maxSize = 2
				wantReleased := hold(f)
				f.feedNone(f.readEnter(restartBase+900, firstLive), "a live thread's read enter")
				f.feedNone(f.readEnter(restartBase+950, secondLive), "another live thread's read enter")

				if released := f.feedOne(record(f), goneName); released != wantReleased {
					t.Fatalf("released row = %+v, want the unchanged interrupted row %+v", released, wantReleased)
				}
				f.requireNothingHeld()
				f.requireNoEnterPending(restartTid)
				for _, tid := range []uint32{firstLive, secondLive} {
					if _, ok := f.el.pairs.pending(tid); !ok {
						t.Fatalf("the enter of live tid %d was trimmed to park the dead task's enter", tid)
					}
				}
				row := f.feedOne(f.readExit(restartBase+4000, firstLive, 1), "the first live thread's read exit")
				if row.tid != firstLive || row.enterTime != restartBase+900 || row.ret != 1 {
					t.Fatalf("row = %+v, want the live thread's read from its own enter", row)
				}
			})
		}
	}
}

// TestLeaderExecReleasesItsOwnHeldRow: an exec that keeps its tid (the group
// leader's, or a record without OldTid) needs nothing special. The exec record
// carries the tid the row is held under, so it releases the row like any other
// record of that tid, and the execve's exit pairs with the enter parked again.
func TestLeaderExecReleasesItsOwnHeldRow(t *testing.T) {
	for _, oldTid := range []uint32{restartTid, 0} {
		f := newReexecFixture(t, globalfilter.Filter{})
		f.interruptExecve(restartTid)
		released := f.feedOne(f.execRecord(restartBase+2100, restartTid, oldTid, false), "exec record")
		if released != interruptedExecveRow {
			t.Fatalf("old tid %d: released row = %+v, want %+v", oldTid, released, interruptedExecveRow)
		}
		f.requireNothingHeld()
		row := f.feedOne(f.execExit(restartBase+3000, restartTid, 0), "execve exit")
		if row != reexecutedExecveRow || f.el.numSyscalls != 2 {
			t.Fatalf("old tid %d: row = %+v numSyscalls=%d, want %+v and 2", oldTid, row, f.el.numSyscalls, reexecutedExecveRow)
		}
		f.requireNoEnterPending(restartTid)
	}
}

// TestExecRecordMayCompleteThreeRows pins the pair channel's bound
// (pairChannelSlots). The exec record of a non-leader thread names two tids,
// and each may hold a row: the caller's old tid, and the leader's when the dead
// leader's own exit record was lost. Under -tid <caller> the record also
// stands in for the execve's exit (completeUntracedExec). All three rows are
// emitted, in stream order per thread, and none is dropped for want of a slot.
func TestExecRecordMayCompleteThreeRows(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	f.el.setCachedComm(restartPid, "leader")
	f.interruptRead(restartBase-100, restartPid, restartSys)
	f.interruptExecve(restartTid)
	rows := f.feed(f.execRecord(restartBase+3000, restartPid, restartTid, true))
	if len(rows) != 3 {
		t.Fatalf("rows = %+v, want the leader's read, the interrupted execve and the execve the record completes", rows)
	}
	if rows[0].tid != restartPid || rows[0].ret != restartSys || rows[1] != interruptedExecveRow || rows[2] != reexecutedExecveRow {
		t.Fatalf("rows = %+v, want the leader's -512 read, %+v, %+v", rows, interruptedExecveRow, reexecutedExecveRow)
	}
	f.requireNothingHeld()
	f.requireNoEnterPending(restartTid, restartPid)
	if f.el.numSyscalls != 3 {
		t.Fatalf("numSyscalls = %d, want 3", f.el.numSyscalls)
	}
}

// TestLostExecRecordExitMayCompleteThreeRows is the same bound reached without
// the exec record: when it is lost, the successful execve's exit under the
// leader tid is the record that names both tids. It releases the row the dead
// leader still holds (routeHeldRestart: the leader's exit record was lost too,
// and the row waits, so any syscall record of the tid releases it), then the
// caller's interrupted execve (adoptLostExecCaller), and completes the execve
// itself. Three rows from one record, in that order, into a channel of
// pairChannelSlots - the fixture's, where a fourth would panic.
func TestLostExecRecordExitMayCompleteThreeRows(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	f.el.setCachedComm(restartPid, "leader")
	f.interruptRead(restartBase-100, restartPid, restartSys)
	f.interruptExecve(restartTid)
	if cap(f.out) != pairChannelSlots {
		t.Fatalf("the fixture's pair channel has %d slots, want pairChannelSlots (%d)", cap(f.out), pairChannelSlots)
	}
	rows := f.feed(f.execExit(restartBase+3000, restartPid, 0))
	if len(rows) != 3 {
		t.Fatalf("rows = %+v, want the leader's read, the interrupted execve and the successful execve", rows)
	}
	leaderRead := restartRow{name: "read", tid: restartPid, ret: restartSys, enterTime: restartBase - 100, duration: 500}
	if rows[0] != leaderRead || rows[1] != interruptedExecveRow || rows[2] != reexecutedExecveRow {
		t.Fatalf("rows = %+v, want %+v, %+v, %+v", rows, leaderRead, interruptedExecveRow, reexecutedExecveRow)
	}
	f.requireNothingHeld()
	f.requireNoEnterPending(restartTid, restartPid)
	if f.el.numSyscalls != 3 || f.el.numTracepointMismatches != 0 {
		t.Fatalf("numSyscalls=%d mismatches=%d, want 3 and 0", f.el.numSyscalls, f.el.numTracepointMismatches)
	}
}

// TestPanicInTheReleasedRowsHandlerKeepsTheEnter: the release completes the
// held row first and parks the continuation's enter second, and the first step
// runs handler code that may panic (processRawEventSafe recovers it and the
// loop carries on). The enter must be parked all the same: the panic cost the
// interrupted row, it must not cost the continuation's row too. Here the
// panic is sendPair's, on a pair channel that is already full.
func TestPanicInTheReleasedRowsHandlerKeepsTheEnter(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	var warnings []string
	f.el.SetWarningCallback(func(message string) { warnings = append(warnings, message) })
	f.interruptRead(restartBase, restartTid, restartSys)
	f.feedNone(f.resumeRecord(restartBase+800, restartTid), "RESUME record")
	f.feedNone(f.readEnter(restartBase+800, restartTid), "re-executed read enter")

	full := make(chan *event.Pair, 1)
	full <- &event.Pair{}
	f.el.processRawEventSafe(makeTaskRenameEvent(t, restartPid, restartTid, "renamed"), full)
	if len(warnings) != 1 || !strings.Contains(warnings[0], extraPairPanic) {
		t.Fatalf("warnings = %q, want the recovered sendPair panic", warnings)
	}
	f.requireNothingHeld()
	if parked, ok := f.el.pairs.pending(restartTid); !ok || parked.EnterEv.GetTime() != restartBase+800 {
		t.Fatalf("pending enter = %+v (parked=%t), want the re-executed read's", parked, ok)
	}
	row := f.feedOne(f.readExit(restartBase+3000, restartTid, 1), "re-executed read exit")
	if row.enterTime != restartBase+800 || row.ret != 1 {
		t.Fatalf("row = %+v, want the re-execution as its own row", row)
	}
}

// TestFailedHandlerSyscallsDoNotReleaseTheRow: while a restarting handler
// runs, only an exit of the tid with a RESTART code ends the wait (BPF then
// tracks that inner call instead). A handler syscall that merely fails - a
// non-blocking read returning -EAGAIN, a call returning a literal -EINTR -
// leaves BPF's entry alone, and so must it leave the row; neither does an
// interrupted call of another thread touch it. The fold still happens.
func TestFailedHandlerSyscallsDoNotReleaseTheRow(t *testing.T) {
	const eagain, eintr = int64(-11), int64(-4)
	f := newReexecFixture(t, globalfilter.Filter{})
	f.interruptRead(restartBase, restartTid, restartSys)
	f.feedNone(f.handlerRecord(restartBase+510, restartTid, true), "HANDLER record")
	for i, errno := range []int64{eagain, eintr} {
		at := restartBase + 600 + uint64(i)*100
		f.feedNone(f.readEnter(at, restartTid), "the handler's read enter")
		if failed := f.feedOne(f.readExit(at+50, restartTid, errno), "the handler's failed read"); failed.ret != errno || failed.enterTime != at {
			t.Fatalf("row = %+v, want the handler's own read returning %d", failed, errno)
		}
	}
	f.interruptRead(restartBase+650, restartOtherTid, restartSys)
	if held, ok := f.el.restarts.lookup(restartTid); !ok || held.phase != restartInHandler {
		t.Fatalf("held = %+v (held=%t), want the row still waiting for its handler", held, ok)
	}

	f.sigreturn(restartBase+900, restartTid)
	f.feedNone(f.resumeRecord(restartBase+1000, restartTid), "RESUME record")
	f.feedNone(f.readEnter(restartBase+1000, restartTid), "re-executed read enter")
	row := f.feedOne(f.readExit(restartBase+3000, restartTid, 1), "re-executed read exit")
	if row.ret != 1 || row.enterTime != restartBase || row.duration != 3000 {
		t.Fatalf("folded row = %+v, want the original enter with ret 1 and duration 3000", row)
	}
	if _, ok := f.el.restarts.lookup(restartOtherTid); !ok || len(f.el.restarts.held) != 1 {
		t.Fatal("the other thread's interrupted row is not the one row still held")
	}
}

// TestRestartDropWatchIsSharedBetweenTheMonitorAndTheLoop: the drop watch is
// written from two goroutines - the periodic monitor's handler and the loop's
// own reads at RESUME and at the folding exit - so its two fields change under
// a lock. Run with -race, this is what notices the lock going missing.
func TestRestartDropWatchIsSharedBetweenTheMonitorAndTheLoop(t *testing.T) {
	const rounds = 2000
	var total, now atomic.Uint64
	el := &eventLoop{dropStampClock: func() uint64 { return now.Add(1) }}
	src := ringbufDropSourceFunc(func() (uint64, error) { return total.Load(), nil })

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range uint64(rounds) {
			// Alternating totals, so every poll moves the watch; delta 0 keeps
			// the poll free of the warning a real loss raises.
			total.Store(i % 2)
			el.handleRingbufDropResult(ringbufDropResult{total: i % 2})
		}
	}()
	for range rounds {
		el.restarts.drops.lostSince(now.Load(), src, el.readDropStampClock)
	}
	<-done
	if seen := el.restarts.drops.observe(total.Load(), now.Add(1)); seen == 0 || seen > now.Load() {
		t.Fatalf("first-seen stamp = %d, want one of the clock readings taken (1..%d)", seen, now.Load())
	}
}

// TestRestartDropWatchStampsAfterTheCounterRead: an observation's stamp must
// be a clock reading taken AFTER the counter was read. The counter says how
// many, not when; a stamp taken before the read would date a drop that happens
// between the two before an interruption that in truth preceded it, and the
// fold would be allowed across the loss. Here the counter read itself takes
// time: the row was interrupted at 300, the read starts at 100, sees a new
// total, and ends at 500.
func TestRestartDropWatchStampsAfterTheCounterRead(t *testing.T) {
	var watch restartDropWatch
	now := uint64(100)
	clock := func() uint64 { return now }
	slow := ringbufDropSourceFunc(func() (uint64, error) {
		now = 500
		return 3, nil
	})
	if !watch.lostSince(300, slow, clock) {
		t.Fatal("a new total was stamped with a clock reading taken before the counter was read")
	}
	if seen := watch.observe(3, 9000); seen != 500 {
		t.Fatalf("first-seen stamp = %d, want 500, the reading taken after the counter read", seen)
	}
}

// failedOpenEnter is an openat enter of the fixture's main tid whose path
// read faulted at sys_enter: no name, and the status that lets a name fixup
// fill it in.
func (f *restartFixture) failedOpenEnter(at uint64) []byte {
	f.t.Helper()
	ev, _ := makeEnterOpenEvent(f.t, at, restartPid, restartTid)
	ev.Filename = [types.MAX_FILENAME_LENGTH]byte{}
	ev.FilenameStatus = types.PATH_READ_FAILED
	return eventBytes(f.t, &ev)
}

// TestNameFixupReachesTheKeptEnter: the re-executed open's path read faulted
// again, and its name arrives in a fixup record while the enter is kept with
// the held row. The fixup is spliced into the kept enter, so when the fold is
// refused and the enter is parked again, the continuation's row has its
// filename - as it would have had with the enter parked all along.
func TestNameFixupReachesTheKeptEnter(t *testing.T) {
	const recovered = "/fifo/recovered"
	f := newReexecFixture(t, globalfilter.Filter{})
	f.feedNone(f.failedOpenEnter(restartBase), "openat enter")
	exit, _ := makeExitOpenEvent(t, restartBase+500, restartPid, restartTid)
	exit.Ret = restartSys
	f.feedNone(eventBytes(t, &exit), "interrupted openat exit")
	f.feedNone(f.resumeRecord(restartBase+800, restartTid), "RESUME record")
	f.feedNone(f.failedOpenEnter(restartBase+800), "re-executed openat enter")
	f.feedNone(makeOpenNameFixupEvent(t, restartTid, types.SYS_ENTER_OPENAT, recovered), "name fixup of the re-executed enter")
	if held, ok := f.el.restarts.lookup(restartTid); !ok || held.continuation == nil {
		t.Fatal("the name fixup released the row or cost it the kept enter")
	}

	// The fold is refused: a record was lost somewhere on the host.
	f.loseRecords(1)
	f.clockAt(restartBase + 9000)
	exit.Time, exit.Ret = restartBase+3000, 7
	f.el.processRawEvent(eventBytes(t, &exit), f.out)
	first, second := <-f.out, <-f.out
	defer first.Recycle()
	defer second.Recycle()
	if got := first.FileName(); got != "" {
		t.Fatalf("interrupted row's file = %q, want none: the fixup belongs to the re-executed enter", got)
	}
	if second.EnterEv.GetTime() != restartBase+800 || second.FileName() != recovered {
		t.Fatalf("continuation's row: enter time %d file %q, want %d and %q",
			second.EnterEv.GetTime(), second.FileName(), restartBase+800, recovered)
	}
}

// TestNameFixupIsNoStepOfTheRestartSyscallFold: restart_syscall has no path
// argument, so a name fixup between its enter and its exit cannot be its own.
// It is one more record that is not the next step: the -516 row is released
// unchanged and restart_syscall becomes a row of its own.
func TestNameFixupIsNoStepOfTheRestartSyscallFold(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	f.interrupt(restartBase, restartTid)
	f.resume(restartBase+1500, restartTid)
	f.feedNone(f.restartEnter(restartBase+1500, restartTid), "restart_syscall enter")
	sleep := f.feedOne(makeOpenNameFixupEvent(t, restartTid, types.SYS_ENTER_OPENAT, "/stray"), "a stray name fixup")
	if sleep.name != "clock_nanosleep" || sleep.ret != -516 {
		t.Fatalf("released row = %+v, want the unchanged -516 sleep", sleep)
	}
	f.requireNothingHeld()
	row := f.feedOne(f.restartExit(restartBase+3000, restartTid, 0), "restart_syscall exit")
	if row.name != "restart_syscall" || row.enterTime != restartBase+1500 {
		t.Fatalf("row = %+v, want restart_syscall as its own row", row)
	}
}
