package internal

import (
	"context"
	"strings"
	"testing"

	"ior/internal/event"
	"ior/internal/types"
)

// What the review of task c23 found unpinned or wrong: the share of exits
// without an enter that have the shape of a seccomp filter's answer, the
// attach stamp and its boundary, the enters parked at the stop, what an exec
// move does to the thread's last enter, and the bound of lastEnters.

// A call a seccomp filter trapped (SECCOMP_RET_TRAP) "returns" its own
// syscall number, one it denied an errno: both look like a filter's answer.
// Any other return value of an exit without an enter does not.
func TestExitWithoutEnterLooksLikeAFilterAnswer(t *testing.T) {
	nr, known := types.SYS_EXIT_ACCESS.SyscallNumber()
	if !known {
		t.Skip("no syscall numbers for this architecture")
	}
	f := newHalfFeed(t, eventLoopConfig{})
	f.call(1000, execCommTid)
	f.exit(2000, execCommTid, nr) // trapped: the call's own number
	f.want(0, 1, 1)
	f.exit(3000, execCommTid, -int64(1)) // denied with EPERM
	f.want(0, 2, 2)
	f.exit(4000, execCommTid, 0) // a lost enter of a call that succeeded
	f.exit(5000, execCommTid, nr+1)
	f.want(0, 4, 2)
}

// An exit kind without a return value, or of an unknown trace ID, is no
// filter's answer.
func TestLooksLikeSeccompAnswerNeedsAReturnValueAndANumber(t *testing.T) {
	if looksLikeSeccompAnswer(&types.NullEvent{TraceId: types.SYS_EXIT_SYNC}) {
		t.Fatal("an exit without a return value looks like a filter's answer")
	}
	if looksLikeSeccompAnswer(&types.RetEvent{TraceId: 0, Ret: 0}) {
		t.Fatal("a return value of 0 for an unknown trace ID looks like a filter's answer")
	}
	if !looksLikeSeccompAnswer(&types.RetEvent{TraceId: 0, Ret: -38}) {
		t.Fatal("a failed exit does not look like a filter's answer")
	}
}

// Trace setup dates the end of the initial attach, on the boot clock the
// records carry. Without it a host-wide run counted halves of calls made
// while the probes went on one by one (1 enter / 16 exits with no drop).
func TestSetupJudgesHalvesFromTheEndOfTheAttach(t *testing.T) {
	assertCallArguments(t, capabilityCall(t, "judgeHalvesFrom"), []string{"bootClockNs()"})

	el := mustNewEventLoop(t, eventLoopConfig{})
	if el.lostHalvesFrom != 0 {
		t.Fatalf("a new loop judges halves from %d, want 0", el.lostHalvesFrom)
	}
	el.judgeHalvesFrom(5000)
	if el.lostHalvesFrom != 5000 {
		t.Fatalf("lostHalvesFrom = %d after judgeHalvesFrom(5000)", el.lostHalvesFrom)
	}
}

// The stamp is the first moment judged: every probe is attached at it, so
// an enter stamped exactly then is judged, and one a tick before is not.
func TestHalfAtTheAttachStampIsJudged(t *testing.T) {
	f := newHalfFeed(t, eventLoopConfig{})
	f.el.judgeHalvesFrom(5000)
	f.enter(4999, execCommTid) // its exit is lost, but during the attach
	f.enter(5000, execCommTid) // its exit is lost
	f.want(0, 0, 0)
	f.enter(6000, execCommTid)
	f.want(1, 0, 0)
	f.exit(6010, execCommTid, 0)
	f.exit(7000, execCommTid, 0) // last enter seen at 6000
	f.want(1, 1, 0)
}

// An enter still parked when the trace stops is a call in flight, not a lost
// exit: a run to its stop counts nothing for it.
func TestEnterParkedAtStopIsNoLostExit(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{commResolver: newHermeticCommResolver()})
	_, parked := makeEnterPathEvent(t, 1000, execCommPid, execCommTid, "/etc/hosts", types.SYS_ENTER_ACCESS)
	_, enter := makeEnterPathEvent(t, 2000, execCommPid, execCommTid+1, "/etc/hosts", types.SYS_ENTER_ACCESS)
	_, exit := makeExitRetEvent(t, 2010, execCommPid, execCommTid+1, types.SYS_EXIT_ACCESS, 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rows := 0
	el.SetPrintCallback(func(ep *event.Pair) {
		rows++
		ep.Recycle()
		cancel()
	})

	el.run(ctx, filledRawChannel([][]byte{parked, enter, exit}))

	if _, isParked := el.pairs.pending(execCommTid); rows != 1 || !isParked {
		t.Fatalf("%d rows, enter parked: %v; want 1 row and the enter parked", rows, isParked)
	}
	(&halfFeed{t: t, el: el}).want(0, 0, 0)
	if stats := el.stats(); !strings.Contains(stats, "\tenters without an exit: 0 (") {
		t.Fatalf("the statistics count the parked enter:\n%s", stats)
	}
}

// A non-leader exec carries what the tracker knows of the caller's last
// enter to the leader tid: the thread stays known there, so an exit of the
// new program that lost its enter is counted, and nothing stays behind
// under the caller's dead tid.
func TestExecMoveKeepsTheThreadKnown(t *testing.T) {
	el := newNonLeaderExecLoop(t)
	completeCallerAccess(t, el, 1000, 1100)
	el.processRawEvent(makeNonLeaderExecEnter(t, 1500, nleExecCaller), make(chan *event.Pair, 1))
	ep := feedNonLeaderExec(t, el, 2000)
	if ep == nil {
		t.Fatal("non-leader execve produced no row")
	}
	ep.Recycle()
	if _, stale := el.pairs.lastEnters[nleExecCaller]; stale {
		t.Fatal("the caller's last enter stayed under its dead tid")
	}
	_, exitRaw := makeExitRetEvent(t, 3000, nleExecPid, nleExecPid, types.SYS_EXIT_ACCESS, 0)
	el.processRawEvent(exitRaw, make(chan *event.Pair, 1)) // its enter is lost
	(&halfFeed{t: t, el: el}).want(0, 1, 0)
}

// An exec enter moved to the leader tid and then trimmed from the full
// pending table is forgotten under the tid it is parked under, the leader's:
// its exit arrives there and is no lost half. (The enter itself still
// carries the caller's tid.)
func TestTrimmedMovedExecEnterIsNoLostHalf(t *testing.T) {
	el := newNonLeaderExecLoop(t)
	completeCallerAccess(t, el, 1000, 1100)
	out := make(chan *event.Pair, pairChannelSlots)
	el.processRawEvent(makeNonLeaderExecEnter(t, 1500, nleExecCaller), out)
	el.processRawEvent(makeProcessExecEventFrom(t, 1600, nleExecPid, nleExecPid, nleExecCaller, "newprog"), out)
	if _, moved := el.pairs.pending(nleExecPid); !moved {
		t.Fatal("the exec enter was not moved to the leader tid")
	}
	el.pairs.maxSize = 4
	f := &halfFeed{t: t, el: el, out: out}
	for i := range uint32(8) {
		f.enter(2000+uint64(i), execCommTid+i)
	}
	if _, parked := el.pairs.pending(nleExecPid); parked {
		t.Fatal("the moved exec enter was not trimmed")
	}
	_, exitRaw := makeExitRetEvent(t, 3000, nleExecPid, nleExecPid, types.SYS_EXIT_EXECVE, 0)
	f.feed(exitRaw)
	f.want(0, 0, 0)
}

// lastEnters holds one entry per thread seen and is cleared whole at its
// bound, which makes every thread unknown: an undercount, never a false
// loss.
func TestLastEntersIsClearedAtItsBound(t *testing.T) {
	f := newHalfFeed(t, eventLoopConfig{})
	f.el.pairs.maxSize = 4
	bound := f.el.pairs.lastEnterLimit()
	if bound != 4*lastEnterLimitFactor {
		t.Fatalf("lastEnterLimit = %d, want %d", bound, 4*lastEnterLimitFactor)
	}
	for i := range uint32(bound) {
		f.call(1000+uint64(i)*20, execCommTid+i)
	}
	if got := len(f.el.pairs.lastEnters); got != bound {
		t.Fatalf("%d threads remembered, want %d (the bound)", got, bound)
	}
	f.call(9000, execCommTid+uint32(bound)) // one thread more: cleared
	if got := len(f.el.pairs.lastEnters); got != 1 {
		t.Fatalf("%d threads remembered above the bound, want 1", got)
	}
	f.exit(9500, execCommTid, 0) // a thread the clearing forgot: passes
	f.want(0, 0, 0)
	f.exit(9600, execCommTid, 0) // known again
	f.want(0, 1, 0)
}
