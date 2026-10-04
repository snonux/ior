package internal

import (
	"strings"
	"syscall"
	"testing"

	"ior/internal/event"
	"ior/internal/types"
)

// noReturnEnters lists the sys_enter trace IDs of the three noreturn
// syscalls with the name their row must carry.
var noReturnEnters = []struct {
	name string
	id   types.TraceId
}{
	{"exit", types.SYS_ENTER_EXIT},
	{"exit_group", types.SYS_ENTER_EXIT_GROUP},
	{"rt_sigreturn", types.SYS_ENTER_RT_SIGRETURN},
}

// feedNoReturnEnter pushes one noreturn sys_enter record for execCommTid and
// returns the row it produced, or nil when none was emitted.
func feedNoReturnEnter(t *testing.T, el *eventLoop, out chan *event.Pair,
	at uint64, id types.TraceId) *event.Pair {
	t.Helper()
	_, raw := makeEnterNullEvent(t, at, execCommPid, execCommTid, id)
	el.processRawEvent(raw, out)
	return nextRow(out)
}

// TestNoReturnEnterEmitsARowAtOnce is the regression test for task pr2: the
// enter of exit, exit_group and rt_sigreturn used to be parked for a sys_exit
// that never fires, so tracing them produced no row at all. The enter itself
// must now be the complete row - right name, no return value, no latency -
// and nothing may stay parked under the tid.
func TestNoReturnEnterEmitsARowAtOnce(t *testing.T) {
	for _, tc := range noReturnEnters {
		t.Run(tc.name, func(t *testing.T) {
			el := newPairEvictionEventLoop(t)
			out := make(chan *event.Pair, 1)

			ep := feedNoReturnEnter(t, el, out, defaulTime, tc.id)
			if ep == nil {
				t.Fatalf("%s enter produced no row", tc.name)
			}
			defer ep.Recycle()
			assertNoReturnRow(t, ep, tc.name, tc.id)
			if el.numSyscalls != 1 || el.numTracepointMismatches != 0 {
				t.Fatalf("numSyscalls=%d mismatches=%d, want 1 and 0",
					el.numSyscalls, el.numTracepointMismatches)
			}
			if _, parked := el.pairs.pending(execCommTid); parked {
				t.Fatalf("%s enter is still parked after its row was emitted", tc.name)
			}
		})
	}
}

// assertNoReturnRow checks the shape of a noreturn row: the syscall's name,
// the NoReturn marker, a zero latency, a synthetic exit at the enter's own
// time and tid carrying the kernel's sys_exit ID (enter - 1), no ret field,
// and an empty ret column in the -plain CSV.
func assertNoReturnRow(t *testing.T, ep *event.Pair, name string, id types.TraceId) {
	t.Helper()
	if got := ep.EnterEv.GetTraceId().Name(); got != name {
		t.Errorf("row name = %q, want %q", got, name)
	}
	if !ep.NoReturn {
		t.Error("row is not marked NoReturn")
	}
	if ep.Duration != 0 {
		t.Errorf("Duration = %d, want 0 (no latency to measure)", ep.Duration)
	}
	if ep.ExitEv == nil {
		t.Fatal("row has no exit event")
	}
	if _, carriesRet := ep.ExitEv.(event.RetCarrier); carriesRet {
		t.Error("synthetic exit carries a return value")
	}
	if ep.ExitEv.GetTime() != ep.EnterEv.GetTime() || ep.ExitEv.GetTid() != ep.EnterEv.GetTid() {
		t.Errorf("synthetic exit time/tid = %d/%d, want the enter's %d/%d",
			ep.ExitEv.GetTime(), ep.ExitEv.GetTid(), ep.EnterEv.GetTime(), ep.EnterEv.GetTid())
	}
	if got := ep.ExitEv.GetTraceId(); got != id-1 {
		t.Errorf("synthetic exit trace ID = %d, want %d", got, id-1)
	}
	fields := strings.Split(ep.CSVRow(nil), ",")
	if len(fields) < 7 || fields[4] != name || fields[5] != "" {
		t.Errorf("-plain row %q: want name %q and an empty ret column", ep.CSVRow(nil), name)
	}
}

// TestNoReturnEnterSupersedesAStaleParkedEnter: a task that enters a syscall
// is at the syscall boundary, so an enter it left parked lost its exit record.
// Before task pr2 the noreturn enter itself replaced it and then sat parked,
// so the tid's next exit whose own enter was lost consumed it and was counted
// as a mismatch. Now the stale enter is dropped and the next exit finds
// nothing: no row, no mismatch.
func TestNoReturnEnterSupersedesAStaleParkedEnter(t *testing.T) {
	el := newPairEvictionEventLoop(t)
	out := make(chan *event.Pair, 1)

	feedAccessEnter(t, el, out, defaulTime, execCommTid, deadTaskPath)
	ep := feedNoReturnEnter(t, el, out, defaulTime+100, types.SYS_ENTER_RT_SIGRETURN)
	if ep == nil {
		t.Fatal("rt_sigreturn enter produced no row")
	}
	ep.Recycle()

	if stale := feedAccessExit(t, el, out, defaulTime+200, execCommTid); stale != nil {
		file := rowFile(stale)
		stale.Recycle()
		t.Fatalf("an exit paired with the enter the rt_sigreturn superseded: file=%s", file)
	}
	if el.numTracepointMismatches != 0 {
		t.Fatalf("mismatches = %d, want 0", el.numTracepointMismatches)
	}
}

// TestNoReturnRowCarriesAndAdvancesTheGap: the row's DurationToPrev is the real
// gap since the tid's previous row, and the row becomes the baseline of the
// next one - after a signal handler returns, the thread resumes at the
// rt_sigreturn, so the next syscall's gap is measured from there.
func TestNoReturnRowCarriesAndAdvancesTheGap(t *testing.T) {
	el := newPairEvictionEventLoop(t)
	out := make(chan *event.Pair, 1)

	feedAccessEnter(t, el, out, defaulTime, execCommTid, recycledTaskPath)
	first := feedAccessExit(t, el, out, defaulTime+100, execCommTid)
	if first == nil {
		t.Fatal("access pair produced no row")
	}
	first.Recycle()

	ep := feedNoReturnEnter(t, el, out, defaulTime+1100, types.SYS_ENTER_RT_SIGRETURN)
	if ep == nil {
		t.Fatal("rt_sigreturn enter produced no row")
	}
	gap, firstOnTID := ep.DurationToPrev, ep.FirstOnTID
	ep.Recycle()
	if firstOnTID || gap != 1000 {
		t.Fatalf("rt_sigreturn gap = %d (FirstOnTID %v), want 1000", gap, firstOnTID)
	}

	feedAccessEnter(t, el, out, defaulTime+1600, execCommTid, recycledTaskPath)
	next := feedAccessExit(t, el, out, defaulTime+1700, execCommTid)
	if next == nil {
		t.Fatal("access pair after rt_sigreturn produced no row")
	}
	defer next.Recycle()
	if next.DurationToPrev != 500 {
		t.Fatalf("gap after rt_sigreturn = %d, want 500 (measured from the rt_sigreturn)", next.DurationToPrev)
	}
}

// TestNoReturnRowHonoursThePairFilter: the row runs the same checkpoint as a
// paired exit, so -comm keeps the traced program's exit_group and drops
// another program's, which still counts as a formed pair.
func TestNoReturnRowHonoursThePairFilter(t *testing.T) {
	for _, tc := range []struct {
		comm    string
		wantRow bool
	}{
		{pairCommFilterPattern, true},
		{"other", false},
	} {
		t.Run(tc.comm, func(t *testing.T) {
			el := newPairCommFilterEventLoop(t, true, tc.comm)
			out := make(chan *event.Pair, 1)
			ep := feedNoReturnEnter(t, el, out, defaulTime, types.SYS_ENTER_EXIT_GROUP)
			if ep != nil {
				defer ep.Recycle()
			}
			if (ep != nil) != tc.wantRow {
				t.Fatalf("comm %q: row emitted = %v, want %v", tc.comm, ep != nil, tc.wantRow)
			}
			if el.numSyscalls != 1 {
				t.Fatalf("numSyscalls = %d, want 1", el.numSyscalls)
			}
		})
	}
}

// TestReturningNullSyscallStillPairs is the negative control: a null-kind
// syscall that does return (getpid) keeps the parked enter/exit pairing, with
// its return value and measured latency, and is not marked NoReturn.
func TestReturningNullSyscallStillPairs(t *testing.T) {
	el := newPairEvictionEventLoop(t)
	out := make(chan *event.Pair, 1)

	if ep := feedNoReturnEnter(t, el, out, defaulTime, types.SYS_ENTER_GETPID); ep != nil {
		ep.Recycle()
		t.Fatal("getpid enter emitted a row before its exit")
	}
	_, raw := makeExitRetEvent(t, defaulTime+250, execCommPid, execCommTid, types.SYS_EXIT_GETPID, 42)
	el.processRawEvent(raw, out)
	ep := nextRow(out)
	if ep == nil {
		t.Fatal("getpid pair produced no row")
	}
	defer ep.Recycle()
	if ep.NoReturn || ep.Duration != 250 {
		t.Fatalf("getpid row: NoReturn=%v Duration=%d, want false and 250", ep.NoReturn, ep.Duration)
	}
	if ret, ok := ep.ExitEv.(event.RetCarrier); !ok || ret.GetRet() != 42 {
		t.Fatalf("getpid row lost its return value")
	}
}

// TestDeniedSyscallExitAfterASignalReturnIsNotAMismatch is the regression test
// for the mismatch half of task qr2. A syscall a seccomp filter denies with an
// errno never fires sys_enter (the filter runs before the tracepoint) but still
// fires sys_exit, so the kernel delivers an exit with no enter - and in a
// signal-driven program the denied call follows an rt_sigreturn. While
// noreturn enters were parked, that orphan exit consumed the rt_sigreturn
// enter and was counted as a mismatch (10 denied fchmod calls showed "5
// mismatches (6.58%)"). The rt_sigreturn row is complete at enter now, so the
// orphan exit finds nothing parked: it is dropped without a row and without
// touching the mismatch counter or the counted syscalls.
func TestDeniedSyscallExitAfterASignalReturnIsNotAMismatch(t *testing.T) {
	el := newPairEvictionEventLoop(t)
	out := make(chan *event.Pair, 2)

	row := feedNoReturnEnter(t, el, out, defaulTime, types.SYS_ENTER_RT_SIGRETURN)
	if row == nil {
		t.Fatal("rt_sigreturn enter produced no row")
	}
	row.Recycle()

	_, deniedExit := makeExitRetEvent(t, defaulTime+10, execCommPid, execCommTid, types.SYS_EXIT_FCHMOD, -int64(syscall.EPERM))
	el.processRawEvent(deniedExit, out)

	if ep := nextRow(out); ep != nil {
		ep.Recycle()
		t.Fatal("an exit without an enter produced a row")
	}
	if el.numTracepointMismatches != 0 {
		t.Fatalf("numTracepointMismatches = %d, want 0: the denied exit consumed a parked enter", el.numTracepointMismatches)
	}
	if el.numSyscalls != 1 {
		t.Fatalf("numSyscalls = %d, want only the rt_sigreturn row", el.numSyscalls)
	}
}
