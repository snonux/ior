package internal

import (
	"math"
	"testing"

	"ior/internal/globalfilter"
	"ior/internal/types"
)

// The restarts count of a folded row (task 203). A row the loop folded from
// kernel restarts shows the call's final return only, so event.Pair.Restarts
// is what says the call was interrupted: one per continuation the row took,
// restart_syscall and re-execution alike, and 0 on every row that took none -
// an uninterrupted call, a row whose fold was refused (it keeps its restart
// code), and the continuation that then became a row of its own.

// countedRow is a row together with its restarts count. The count is kept out
// of restartRow, which the other restart tests compare whole: they are about
// what a fold makes of the row, these about how often it folded.
type countedRow struct {
	restartRow
	restarts uint8
}

// feedCounted is restartFixture.feed for the tests here: it processes one raw
// record and returns the rows it emitted with their restarts count.
func (f *restartFixture) feedCounted(raw []byte) []countedRow {
	f.t.Helper()
	f.el.processRawEvent(raw, f.out)
	var rows []countedRow
	for {
		select {
		case ep := <-f.out:
			rows = append(rows, countedRow{restartRow: rowOf(ep), restarts: ep.Restarts})
			ep.Recycle()
		default:
			return rows
		}
	}
}

// feedOneCounted feeds raw and returns the single row it must emit.
func (f *restartFixture) feedOneCounted(raw []byte, what string) countedRow {
	f.t.Helper()
	rows := f.feedCounted(raw)
	if len(rows) != 1 {
		f.t.Fatalf("%s emitted %d rows (%+v), want 1", what, len(rows), rows)
	}
	return rows[0]
}

// requireCount fails unless row is the syscall name returning ret with the
// given restarts count.
func requireCount(t *testing.T, row countedRow, name string, ret int64, restarts uint8) {
	t.Helper()
	if row.name != name || row.ret != ret || row.restarts != restarts {
		t.Fatalf("row = %s ret=%d restarts=%d, want %s ret=%d restarts=%d",
			row.name, row.ret, row.restarts, name, ret, restarts)
	}
}

// stopAgain feeds one more hop of a stopped sleep whose row is held: the
// restart_syscall announced at `at`, which exits 400ns later with ret. With
// -516 the row is held again and nothing is emitted.
func (f *restartFixture) stopAgain(at uint64, ret int64) []countedRow {
	f.t.Helper()
	f.resume(at, restartTid)
	f.feedNone(f.restartEnter(at, restartTid), "restart_syscall enter")
	return f.feedCounted(f.restartExit(at+400, restartTid, ret))
}

// TestStoppedSleepCountsItsRestarts: a sleep stopped once is one row with
// restarts 1, stopped three times one row with restarts 3 - each
// restart_syscall the row took counts, not the row's having been folded - and
// the uninterrupted sleep that follows on the same thread is 0 again.
func TestStoppedSleepCountsItsRestarts(t *testing.T) {
	eachRestartFixture(t, func(t *testing.T, newFixture restartFixtureMaker) {
		for _, stops := range []uint8{1, 3} {
			f := newFixture(t, globalfilter.Filter{})
			f.interrupt(restartBase, restartTid)
			at := restartBase + 1000
			for hop := uint8(1); hop < stops; hop++ {
				if rows := f.stopAgain(at, -516); len(rows) != 0 {
					t.Fatalf("hop %d emitted %+v, want the row held again", hop, rows)
				}
				at += 1000
			}
			rows := f.stopAgain(at, 0)
			if len(rows) != 1 {
				t.Fatalf("%d stops: rows = %+v, want the one folded sleep", stops, rows)
			}
			requireCount(t, rows[0], "clock_nanosleep", 0, stops)

			f.feedNone(f.sleepEnter(at+5000, restartTid), "uninterrupted sleep enter")
			plain := f.feedOneCounted(f.sleepExit(at+6000, restartTid, 0), "uninterrupted sleep exit")
			requireCount(t, plain, "clock_nanosleep", 0, 0)
			f.requireNothingHeld()
		}
	})
}

// TestReexecutedCallCountsItsRestarts: the re-execution fold counts the same
// way, once per re-execution, for each of the three codes; a read that was
// never interrupted is 0.
func TestReexecutedCallCountsItsRestarts(t *testing.T) {
	for _, ret := range []int64{restartSys, restartNoIntr, restartNoHand} {
		f := newReexecFixture(t, globalfilter.Filter{})
		f.interruptRead(restartBase, restartTid, ret)
		f.feedNone(f.resumeRecord(restartBase+800, restartTid), "first RESUME")
		f.feedNone(f.readEnter(restartBase+800, restartTid), "first re-executed enter")
		f.feedNone(f.readExit(restartBase+1500, restartTid, ret), "first re-executed exit, interrupted again")
		f.feedNone(f.resumeRecord(restartBase+1800, restartTid), "second RESUME")
		f.feedNone(f.readEnter(restartBase+1800, restartTid), "second re-executed enter")
		twice := f.feedOneCounted(f.readExit(restartBase+4000, restartTid, 1), "second re-executed exit")
		requireCount(t, twice, "read", 1, 2)

		f.interruptRead(restartBase+5000, restartTid, ret)
		f.feedNone(f.resumeRecord(restartBase+5800, restartTid), "RESUME")
		f.feedNone(f.readEnter(restartBase+5800, restartTid), "re-executed enter")
		once := f.feedOneCounted(f.readExit(restartBase+7000, restartTid, 1), "re-executed exit")
		requireCount(t, once, "read", 1, 1)

		f.feedNone(f.readEnter(restartBase+8000, restartTid), "uninterrupted read enter")
		plain := f.feedOneCounted(f.readExit(restartBase+8100, restartTid, 1), "uninterrupted read exit")
		requireCount(t, plain, "read", 1, 0)
		f.requireNothingHeld()
	}
}

// TestHandlersRowsAreNotCounted: the syscalls a restarting handler makes pass
// while the interrupted row is held. They are calls of their own and stay at
// 0; only the read the kernel re-executes afterwards counts its restart.
func TestHandlersRowsAreNotCounted(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	f.interruptRead(restartBase, restartTid, restartSys)
	f.feedNone(f.handlerRecord(restartBase+510, restartTid, true), "HANDLER record")
	_, enter := makeEnterNullEvent(t, restartBase+600, restartPid, restartTid, types.SYS_ENTER_SYNC)
	f.feedNone(enter, "the handler's sync enter")
	_, exit := makeExitNullEvent(t, restartBase+650, restartPid, restartTid, types.SYS_EXIT_SYNC)
	requireCount(t, f.feedOneCounted(exit, "the handler's sync exit"), "sync", 0, 0)
	_, sigreturn := makeEnterNullEvent(t, restartBase+700, restartPid, restartTid, types.SYS_ENTER_RT_SIGRETURN)
	requireCount(t, f.feedOneCounted(sigreturn, "rt_sigreturn enter"), "rt_sigreturn", 0, 0)
	f.feedNone(f.resumeRecord(restartBase+800, restartTid), "RESUME record")
	f.feedNone(f.readEnter(restartBase+800, restartTid), "re-executed read enter")
	row := f.feedOneCounted(f.readExit(restartBase+4000, restartTid, 1), "re-executed read exit")
	requireCount(t, row, "read", 1, 1)
}

// TestRefusedFoldCountsNothing is the negative: a fold refused at the
// continuation's exit (a record was lost meanwhile) leaves two rows, the
// interrupted call with its restart code and the continuation, and neither
// was folded from anything. The same for a row released because nothing
// carried the call on (the program got EINTR and made another call).
func TestRefusedFoldCountsNothing(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	f.interruptRead(restartBase, restartTid, restartSys)
	f.clockAt(restartBase + 850)
	f.feedNone(f.resumeRecord(restartBase+800, restartTid), "RESUME record")
	f.feedNone(f.readEnter(restartBase+800, restartTid), "re-executed read enter")
	f.loseRecords(1)
	f.clockAt(restartBase + 9050)
	rows := f.feedCounted(f.readExit(restartBase+9000, restartTid, 1))
	if len(rows) != 2 {
		t.Fatalf("rows = %+v, want the interrupted row and the continuation's row", rows)
	}
	requireCount(t, rows[0], "read", restartSys, 0)
	requireCount(t, rows[1], "read", 1, 0)

	f = newRestartFixture(t, globalfilter.Filter{})
	f.interrupt(restartBase, restartTid)
	released := f.feedOneCounted(f.sleepEnter(restartBase+900, restartTid), "the program's next sleep")
	requireCount(t, released, "clock_nanosleep", -516, 0)
	next := f.feedOneCounted(f.sleepExit(restartBase+2000, restartTid, 0), "the next sleep's exit")
	requireCount(t, next, "clock_nanosleep", 0, 0)
}

// TestPartlyFoldedChainCountsTheHopsItTook: a sleep stopped twice whose second
// hop is refused keeps the first. Its row ends at the second interruption
// with -516 and restarts 1 - a restart code AND a count, which reads "carried
// on once, then interrupted again without proof of what followed" - and the
// second restart_syscall, a row of its own, is 0.
func TestPartlyFoldedChainCountsTheHopsItTook(t *testing.T) {
	f := newDropCountedFixture(t, globalfilter.Filter{})
	f.interrupt(restartBase, restartTid)
	f.clockAt(restartBase + 1050)
	f.resume(restartBase+1000, restartTid)
	f.feedNone(f.restartEnter(restartBase+1000, restartTid), "first restart_syscall enter")
	f.clockAt(restartBase + 1550)
	f.feedNone(f.restartExit(restartBase+1500, restartTid, -516), "first restart_syscall -516 exit")
	f.loseRecords(1)
	f.monitorPoll(restartBase + 1700)
	f.clockAt(restartBase + 2050)
	sleep := f.feedOneCounted(f.resumeRecord(restartBase+2000, restartTid), "second RESUME record")
	requireCount(t, sleep, "clock_nanosleep", -516, 1)
	f.feedNone(f.restartEnter(restartBase+2000, restartTid), "second restart_syscall enter")
	restart := f.feedOneCounted(f.restartExit(restartBase+4000, restartTid, 0), "second restart_syscall exit")
	requireCount(t, restart, "restart_syscall", 0, 0)
}

// TestRestartSyscallRowCountsItsOwnContinuation: when the first hop is
// refused, restart_syscall is a row of its own; stopped in turn, it is the row
// the second restart_syscall folds into. The sleep keeps -516 and 0, and the
// count sits on the restart_syscall row that took the continuation.
func TestRestartSyscallRowCountsItsOwnContinuation(t *testing.T) {
	f := newDropCountedFixture(t, globalfilter.Filter{})
	f.interrupt(restartBase, restartTid)
	f.loseRecords(1)
	f.monitorPoll(restartBase + 600)
	f.clockAt(restartBase + 1050)
	sleep := f.feedOneCounted(f.resumeRecord(restartBase+1000, restartTid), "first RESUME record")
	requireCount(t, sleep, "clock_nanosleep", -516, 0)
	f.feedNone(f.restartEnter(restartBase+1000, restartTid), "first restart_syscall enter")
	f.clockAt(restartBase + 1550)
	f.feedNone(f.restartExit(restartBase+1500, restartTid, -516), "first restart_syscall -516 exit")
	f.clockAt(restartBase + 2050)
	f.resume(restartBase+2000, restartTid)
	f.feedNone(f.restartEnter(restartBase+2000, restartTid), "second restart_syscall enter")
	f.clockAt(restartBase + 4050)
	restart := f.feedOneCounted(f.restartExit(restartBase+4000, restartTid, 0), "second restart_syscall exit")
	requireCount(t, restart, "restart_syscall", 0, 1)
}

// TestRestartCountSaturates: a sleep stopped more often than a uint8 holds
// stays at 255. Wrapping would make the 256th stop read 0, "never
// interrupted", which is the one thing the column must not say of such a row.
func TestRestartCountSaturates(t *testing.T) {
	f := newRestartFixture(t, globalfilter.Filter{})
	f.interrupt(restartBase, restartTid)
	at := restartBase + 1000
	for hop := 0; hop < math.MaxUint8+5; hop++ {
		if rows := f.stopAgain(at, -516); len(rows) != 0 {
			t.Fatalf("hop %d emitted %+v, want the row held again", hop, rows)
		}
		at += 1000
	}
	rows := f.stopAgain(at, 0)
	if len(rows) != 1 {
		t.Fatalf("rows = %+v, want the one folded sleep", rows)
	}
	requireCount(t, rows[0], "clock_nanosleep", 0, math.MaxUint8)
}
