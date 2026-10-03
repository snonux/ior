package internal

import (
	"strings"
	"syscall"
	"testing"
	"time"

	"ior/internal/event"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

// The lost-half counters (task c23): a call whose exit record was lost shows
// as an enter superseded by its thread's next enter, a call whose enter
// record was lost as an exit without an enter of a thread seen before. These
// tests feed real raw records through the loop; each loss must be counted
// exactly once, and each benign look-alike not at all.

// halfFeed drives access(2) records (and others) of one process through the
// raw event path of a hermetic loop.
type halfFeed struct {
	t   *testing.T
	el  *eventLoop
	out chan *event.Pair
}

func newHalfFeed(t *testing.T, cfg eventLoopConfig) *halfFeed {
	t.Helper()
	cfg.commResolver = newHermeticCommResolver()
	el := mustNewEventLoop(t, cfg)
	t.Cleanup(el.commResolver.shutdown)
	return &halfFeed{t: t, el: el, out: make(chan *event.Pair, pairChannelSlots)}
}

// feed processes one raw record and recycles the rows it emitted, returning
// how many there were.
func (f *halfFeed) feed(raw []byte) int {
	f.t.Helper()
	f.el.processRawEvent(raw, f.out)
	rows := 0
	for {
		select {
		case ep := <-f.out:
			ep.Recycle()
			rows++
		default:
			return rows
		}
	}
}

func (f *halfFeed) enter(at uint64, tid uint32) {
	f.t.Helper()
	_, raw := makeEnterPathEvent(f.t, at, execCommPid, tid, "/etc/hosts", types.SYS_ENTER_ACCESS)
	f.feed(raw)
}

func (f *halfFeed) exit(at uint64, tid uint32, ret int64) int {
	f.t.Helper()
	_, raw := makeExitRetEvent(f.t, at, execCommPid, tid, types.SYS_EXIT_ACCESS, ret)
	return f.feed(raw)
}

// call feeds one complete access pair, which must emit its row.
func (f *halfFeed) call(at uint64, tid uint32) {
	f.t.Helper()
	f.enter(at, tid)
	if rows := f.exit(at+10, tid, 0); rows != 1 {
		f.t.Fatalf("access pair at %d emitted %d rows, want 1", at, rows)
	}
}

// want fails unless the counters are as given and no pair mismatched.
func (f *halfFeed) want(entersWithoutExit, exitsWithoutEnter, failed uint) {
	f.t.Helper()
	el := f.el
	if el.numEntersWithoutExit != entersWithoutExit || el.numExitsWithoutEnter != exitsWithoutEnter ||
		el.numFailedExitsWithoutEnter != failed {
		f.t.Fatalf("enters without exit/exits without enter/failed = %d/%d/%d, want %d/%d/%d",
			el.numEntersWithoutExit, el.numExitsWithoutEnter, el.numFailedExitsWithoutEnter,
			entersWithoutExit, exitsWithoutEnter, failed)
	}
	if el.numTracepointMismatches != 0 {
		f.t.Fatalf("numTracepointMismatches = %d, want 0", el.numTracepointMismatches)
	}
}

// An enter whose exit was lost is superseded by the thread's next enter: one
// lost exit, counted once, and the next call still pairs.
func TestLostExitIsCountedWhenTheNextEnterSupersedesIt(t *testing.T) {
	f := newHalfFeed(t, eventLoopConfig{})
	f.call(1000, execCommTid)
	f.want(0, 0, 0)
	f.enter(2000, execCommTid) // its exit is lost
	f.call(3000, execCommTid)
	f.want(1, 0, 0)
	if f.el.numSyscalls != 2 {
		t.Fatalf("numSyscalls = %d, want the two complete calls", f.el.numSyscalls)
	}
	// Another thread's enter supersedes nothing of this one.
	f.enter(4000, execCommTid)
	f.call(4100, execCommTid+1)
	f.want(1, 0, 0)
}

// An exit without an enter of a thread seen before lost its enter. A failed
// one is counted apart as well, the shape a seccomp-denied call has.
func TestLostEnterOfAKnownThreadIsCounted(t *testing.T) {
	f := newHalfFeed(t, eventLoopConfig{})
	f.call(1000, execCommTid)
	if rows := f.exit(2000, execCommTid, 0); rows != 0 {
		t.Fatalf("an exit without an enter emitted %d rows", rows)
	}
	f.want(0, 1, 0)
	f.exit(3000, execCommTid, -int64(syscall.EPERM))
	f.want(0, 2, 1)
	f.call(4000, execCommTid)
	f.want(0, 2, 1)
}

// The first record of a thread may be the exit of a call in flight when the
// trace started, or a clone child's first return: no loss. From then on the
// thread is known.
func TestFirstExitOfAThreadIsNoLostEnter(t *testing.T) {
	f := newHalfFeed(t, eventLoopConfig{})
	f.exit(1000, execCommTid, 0)
	f.want(0, 0, 0)
	f.exit(2000, execCommTid, 0)
	f.want(0, 1, 0)
}

// A task killed inside a syscall gets no exit, and its tid number goes to a
// new task: the evicted enter is no lost exit, and the new owner's first exit
// is no lost enter (task_newtask and sched_process_exit both evict).
func TestEvictedTasksAreNoLostHalves(t *testing.T) {
	f := newHalfFeed(t, eventLoopConfig{})
	f.call(1000, execCommTid)
	f.enter(2000, execCommTid)
	f.feed(makeProcessExitEvent(t, 2100, execCommPid, execCommTid))
	f.exit(3000, execCommTid, 0)
	f.want(0, 0, 0)

	f.enter(4000, execCommTid)
	f.feed(makeTaskNewtaskEvent(t, execCommPid, execCommTid, "child", 0))
	f.exit(5000, execCommTid, 0)
	f.enter(6000, execCommTid)
	f.want(0, 0, 0)
}

// A noreturn enter is a row at once and never waits for an exit; but it ends
// an enter the thread still had parked, which lost its exit.
func TestNoReturnEntersAreNoLostExits(t *testing.T) {
	f := newHalfFeed(t, eventLoopConfig{})
	for i := range 3 {
		_, raw := makeEnterNullEvent(t, 1000+uint64(i)*100, execCommPid, execCommTid, types.SYS_ENTER_RT_SIGRETURN)
		if rows := f.feed(raw); rows != 1 {
			t.Fatalf("rt_sigreturn enter emitted %d rows, want 1", rows)
		}
	}
	f.call(2000, execCommTid)
	f.want(0, 0, 0)

	f.enter(3000, execCommTid)
	_, raw := makeEnterNullEvent(t, 3100, execCommPid, execCommTid, types.SYS_ENTER_EXIT_GROUP)
	f.feed(raw)
	f.want(1, 0, 0)
}

// openEnterOf builds an openat enter of tid for path.
func openEnterOf(t *testing.T, at uint64, tid uint32, path string) []byte {
	t.Helper()
	ev, _ := makeEnterOpenEvent(t, at, execCommPid, tid)
	ev.Filename = [types.MAX_FILENAME_LENGTH]byte{}
	copy(ev.Filename[:], path)
	return eventBytes(t, &ev)
}

func openExitOf(t *testing.T, at uint64, tid uint32) []byte {
	t.Helper()
	_, raw := makeExitOpenEvent(t, at, execCommPid, tid)
	return raw
}

// An open the raw enter filter sheds (-path) leaves its exit without an
// enter: that is the filter's doing, not a loss. A shed enter whose exit was
// lost is superseded all the same, and an exit of another syscall after it
// lost its enter.
func TestShedEnterIsNoLostHalf(t *testing.T) {
	f := newHalfFeed(t, eventLoopConfig{filter: testFilter("", "^/etc/hosts")})
	f.call(1000, execCommTid)
	f.feed(openEnterOf(t, 2000, execCommTid, "/other"))
	if rows := f.feed(openExitOf(t, 2010, execCommTid)); rows != 0 {
		t.Fatalf("the shed open's exit emitted %d rows", rows)
	}
	f.want(0, 0, 0)

	f.feed(openEnterOf(t, 3000, execCommTid, "/other")) // its exit is lost
	f.call(4000, execCommTid)
	f.want(1, 0, 0)

	f.feed(openEnterOf(t, 5000, execCommTid, "/other")) // its exit is lost
	f.exit(6000, execCommTid, 0)                        // its enter is lost
	f.want(1, 1, 0)
}

// A shed enter ends an enter the thread still had parked: that one lost its
// exit, and the shed open's exit then neither mismatches with it nor counts.
func TestShedEnterSupersedesAParkedEnter(t *testing.T) {
	f := newHalfFeed(t, eventLoopConfig{filter: testFilter("", "^/etc/hosts")})
	f.enter(1000, execCommTid) // its exit is lost
	f.feed(openEnterOf(t, 2000, execCommTid, "/other"))
	f.feed(openExitOf(t, 2010, execCommTid))
	f.want(1, 0, 0)
}

// An enter the full pending table trims may still see its exit (the oldest
// are calls that block): no lost enter.
func TestTrimmedEnterIsNoLostHalf(t *testing.T) {
	f := newHalfFeed(t, eventLoopConfig{})
	f.el.pairs.maxSize = 4
	const tids = 12
	for i := range uint32(tids) {
		f.call(1000+uint64(i)*10, execCommTid+i)
		f.enter(5000+uint64(i)*10, execCommTid+i)
	}
	parked := len(f.el.pairs.enters)
	if parked >= tids {
		t.Fatalf("%d enters parked, want some trimmed", parked)
	}
	for i := range uint32(tids) {
		f.exit(9000+uint64(i)*10, execCommTid+i, 0)
	}
	if want := uint(tids + parked); f.el.numSyscalls != want {
		t.Fatalf("numSyscalls = %d, want %d: the parked enters pair", f.el.numSyscalls, want)
	}
	f.want(0, 0, 0)
}

// Halves of calls that may have begun before the trace's own attach was over
// are not judged: the probes go on one by one.
func TestHalvesBeforeTheAttachAreNotJudged(t *testing.T) {
	f := newHalfFeed(t, eventLoopConfig{})
	f.el.judgeHalvesFrom(5000)
	f.enter(1000, execCommTid) // superseded, but entered during the attach
	f.enter(2000, execCommTid)
	f.exit(2010, execCommTid, 0)
	f.exit(4000, execCommTid, 0) // last enter seen at 2000, during the attach
	f.enter(6000, execCommTid)
	f.want(0, 0, 0)

	f.enter(7000, execCommTid) // the enter at 6000 lost its exit
	f.exit(7010, execCommTid, 0)
	f.exit(8000, execCommTid, 0) // last enter seen at 7000
	f.want(1, 1, 0)
}

// A runtime probe change (the TUI's probes modal) at or after a thread's last
// enter means its call may have run with a probe off: not judged.
func TestHalvesAcrossAProbeChangeAreNotJudged(t *testing.T) {
	f := newHalfFeed(t, eventLoopConfig{})
	f.call(1000, execCommTid)
	f.enter(2000, execCommTid)
	f.el.restarts.probes.note(2500)
	f.enter(3000, execCommTid) // supersedes the enter at 2000
	f.exit(3010, execCommTid, 0)
	f.want(0, 0, 0)
	f.exit(4000, execCommTid, 0) // last enter seen at 3000, after the change
	f.want(0, 1, 0)
}

// A non-leader exec moves the caller's exec enter to the leader tid, where
// its exit finds it: nothing lost. A non-exec enter still parked under the
// caller lost its exit.
func TestNonLeaderExecMoveIsNoLostHalf(t *testing.T) {
	el := newNonLeaderExecLoop(t)
	completeCallerAccess(t, el, 1000, 1100)
	el.processRawEvent(makeNonLeaderExecEnter(t, 1500, nleExecCaller), make(chan *event.Pair, 1))
	ep := feedNonLeaderExec(t, el, 2000)
	if ep == nil {
		t.Fatal("non-leader execve produced no row")
	}
	ep.Recycle()
	f := &halfFeed{t: t, el: el}
	f.want(0, 0, 0)

	el = newNonLeaderExecLoop(t)
	completeCallerAccess(t, el, 1000, 1100)
	_, enterRaw := makeEnterPathEvent(t, 1500, nleExecPid, nleExecCaller, "/etc/hosts", types.SYS_ENTER_ACCESS)
	el.processRawEvent(enterRaw, make(chan *event.Pair, 1)) // its exit is lost
	el.processRawEvent(makeProcessExecEventFrom(t, 1900, nleExecPid, nleExecPid, nleExecCaller, "newprog"),
		make(chan *event.Pair, pairChannelSlots))
	f = &halfFeed{t: t, el: el}
	f.want(1, 0, 0)
}

// The restart fold takes the continuation's enter and exit for the held row
// (fold) or parks the kept enter again (release): neither is a lost half.
func TestRestartFoldLosesNoHalf(t *testing.T) {
	eachRestartFixture(t, func(t *testing.T, newFixture restartFixtureMaker) {
		f := newFixture(t, globalfilter.Filter{})
		f.interrupt(restartBase, restartTid)
		f.resume(restartBase+1500, restartTid)
		f.feedNone(f.restartEnter(restartBase+1500, restartTid), "restart_syscall enter")
		f.feedOne(f.restartExit(restartBase+3000, restartTid, 0), "restart_syscall exit")

		f.interrupt(restartBase+4000, restartTid)
		_, syncEnter := makeEnterNullEvent(t, restartBase+4800, restartPid, restartTid, types.SYS_ENTER_SYNC)
		f.feedOne(syncEnter, "sync enter")
		_, syncExit := makeExitNullEvent(t, restartBase+4900, restartPid, restartTid, types.SYS_EXIT_SYNC)
		f.feedOne(syncExit, "sync exit")
		(&halfFeed{t: t, el: f.el}).want(0, 0, 0)
	})
}

// The re-execution fold the same: accepted, it takes the re-executed enter and
// exit; refused at that exit (a record was lost meanwhile), it parks the kept
// enter again and the exit pairs with it. Neither is a lost half.
func TestReexecFoldLosesNoHalf(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	requireFolded(t, f.foldRead(restartBase), restartBase, "nothing was lost")
	(&halfFeed{t: t, el: f.el}).want(0, 0, 0)

	f = newReexecFixture(t, globalfilter.Filter{})
	f.interruptRead(restartBase, restartTid, restartSys)
	f.clockAt(restartBase + 850)
	f.feedNone(f.resumeRecord(restartBase+800, restartTid), "RESUME record")
	f.feedNone(f.readEnter(restartBase+800, restartTid), "re-executed read enter")
	f.loseRecords(1)
	f.clockAt(restartBase + 9050)
	if rows := f.feed(f.readExit(restartBase+9000, restartTid, 1)); len(rows) != 2 {
		t.Fatalf("rows = %+v, want the interrupted row and the continuation's row", rows)
	}
	(&halfFeed{t: t, el: f.el}).want(0, 0, 0)
}

// The statistics always print both lines, with the failed share.
func TestStatsReportLostHalves(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	el.numEntersWithoutExit, el.numExitsWithoutEnter, el.numFailedExitsWithoutEnter = 7, 5, 2
	el.startTime = time.Now().Add(-time.Second)
	close(el.done)
	stats := el.stats()
	for _, want := range []string{
		"\tenters without an exit: 7 (",
		"\texits without an enter: 5 (",
		"; 2 returned an error)",
	} {
		if !strings.Contains(stats, want) {
			t.Fatalf("stats lack %q:\n%s", want, stats)
		}
	}
	if i, j := strings.Index(stats, "mismatched"), strings.Index(stats, "enters without an exit"); i < 0 || j < i {
		t.Fatalf("lost-half lines are not behind the syscalls line:\n%s", stats)
	}
}

// The bookkeeping on the hot path allocates nothing once the map has grown.
func TestLostHalfBookkeepingDoesNotAllocate(t *testing.T) {
	p := newPairTracker()
	enter := &types.NullEvent{TraceId: types.SYS_ENTER_SYNC, Time: 1, Tid: execCommTid}
	exit := &types.NullEvent{TraceId: types.SYS_EXIT_SYNC, Time: 2, Tid: execCommTid}
	p.noteEnter(enter, 0)
	el := &eventLoop{}
	allocs := testing.AllocsPerRun(1000, func() {
		el.countSupersededEnter(p.noteEnter(enter, 0))
		p.unpairedExit(exit)
	})
	if allocs != 0 {
		t.Fatalf("lost-half bookkeeping allocated %.1f times per call", allocs)
	}
}
