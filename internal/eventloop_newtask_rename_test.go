package internal

import (
	"context"
	"testing"
	"time"

	"ior/internal/event"
	"ior/internal/globalfilter"
)

// A task_newtask record carries the name the child inherited, which is the
// creator's. A thread that renames itself first thing (prctl(PR_SET_NAME),
// pthread_setname_np - tokio, Java, Chrome and Bun worker pools) is reported by
// the task_rename record (eventloop_taskrename_test.go), but that record can be
// lost or its probe may not attach, so the seed must stay correctable by the one
// procfs read that its first use queues, without ever overriding a fresher
// kernel-reported name. These tests use a resolver whose /proc read is held on
// a gate, so the order "seed, first row, read lands" is fixed rather than a
// scheduling accident.

const (
	inheritedComm = "python3"
	renamedComm   = "wname0"
)

// gatedProcfs is a resolveFn stand-in for /proc/<tid>/comm of newTaskTid: it
// signals on entered when a read starts (the epoch sample was taken by then),
// blocks until release is closed, then answers name.
type gatedProcfs struct {
	name    string
	entered chan struct{}
	release chan struct{}
}

func newGatedProcfs(name string) *gatedProcfs {
	return &gatedProcfs{name: name, entered: make(chan struct{}, 16), release: make(chan struct{})}
}

func (g *gatedProcfs) resolve(ctx context.Context, tid uint32) (string, error) {
	if tid != newTaskTid {
		return "", nil
	}
	g.entered <- struct{}{}
	select {
	case <-g.release:
		return g.name, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func (g *gatedProcfs) waitEntered(t *testing.T) {
	t.Helper()
	select {
	case <-g.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the procfs read to start")
	}
}

// newGatedTaskEventLoop builds a loop over a gated resolver with an optional
// -comm filter.
func newGatedTaskEventLoop(t *testing.T, g *gatedProcfs, commPattern string) *eventLoop {
	t.Helper()
	resolver := newCommResolver(nil)
	resolver.resolveFn = g.resolve
	cfg := eventLoopConfig{commResolver: resolver}
	if commPattern != "" {
		cfg.filter = globalfilter.Filter{Comm: &globalfilter.StringFilter{Pattern: commPattern}}
	}
	el := mustNewEventLoop(t, cfg)
	t.Cleanup(func() {
		select {
		case <-g.release:
		default:
			close(g.release)
		}
		resolver.shutdown()
	})
	return el
}

// waitForCommLookupsToDrain waits until no procfs read is pending, i.e. the
// gated read has landed (or been discarded) and been stored.
func waitForCommLookupsToDrain(t *testing.T, el *eventLoop) {
	t.Helper()
	waitForCondition(t, 2*time.Second, "timed out waiting for the procfs read to land",
		func() bool { return pendingCount(el.commResolver) == 0 })
}

// TestTaskNewtaskSeedIsCorrectedByProcfsRead is the regression test for a
// thread that renames itself before its first traced syscall. The row emitted
// before the read lands carries the inherited name (there is no better one
// yet); once it lands, the tid is labelled with its own name for good and, under
// -comm <renamed>, its rows are kept. Before the fix the seed bumped the tid's
// rename generation, so the read was discarded and every row of the thread
// stayed 'python3' - and -comm wname0 kept none of them.
func TestTaskNewtaskSeedIsCorrectedByProcfsRead(t *testing.T) {
	for _, tc := range []struct {
		name         string
		commPattern  string
		wantFirst    string // "" together with firstKept=false: dropped
		firstKept    bool
		wantSecondIn string
	}{
		{name: "no filter", commPattern: "", wantFirst: inheritedComm, firstKept: true, wantSecondIn: renamedComm},
		// The first enter is judged against the provisional name and dropped,
		// exactly like the base behaviour before any name was known; the rows
		// after the read are kept.
		{name: "-comm renamed", commPattern: renamedComm, firstKept: false, wantSecondIn: renamedComm},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := newGatedProcfs(renamedComm)
			el := newGatedTaskEventLoop(t, g, tc.commPattern)
			el.processRawEvent(makeTaskNewtaskEvent(t, newTaskPid, newTaskTid, inheritedComm, cloneThread),
				make(chan *event.Pair, 1))

			first := feedNewTaskSyscall(t, el)
			if (first != nil) != tc.firstKept {
				t.Fatalf("first row emitted = %v, want %v", first != nil, tc.firstKept)
			}
			if first != nil {
				if first.Comm != tc.wantFirst {
					t.Errorf("first row comm = %q, want the inherited %q", first.Comm, tc.wantFirst)
				}
				first.Recycle()
			}

			// The first use of the tid queued exactly one read; let it land.
			g.waitEntered(t)
			close(g.release)
			waitForCommLookupsToDrain(t, el)

			second := feedNewTaskSyscall(t, el)
			if second == nil {
				t.Fatal("row after the procfs read was not emitted")
			}
			defer second.Recycle()
			if second.Comm != tc.wantSecondIn {
				t.Fatalf("row comm after the read = %q, want the renamed %q", second.Comm, tc.wantSecondIn)
			}
		})
	}
}

// TestTaskNewtaskSeedSurvivesAnEmptyProcfsRead: a thread that has exited by the
// time the read runs has no /proc entry. The read then comes back empty and the
// inherited name stays - still better than an empty comm, and the original
// symptom this record fixes.
func TestTaskNewtaskSeedSurvivesAnEmptyProcfsRead(t *testing.T) {
	g := newGatedProcfs("")
	el := newGatedTaskEventLoop(t, g, "")
	el.processRawEvent(makeTaskNewtaskEvent(t, newTaskPid, newTaskTid, inheritedComm, cloneThread),
		make(chan *event.Pair, 1))
	if ep := feedNewTaskSyscall(t, el); ep != nil {
		ep.Recycle()
	}
	g.waitEntered(t)
	close(g.release)
	waitForCommLookupsToDrain(t, el)

	ep := feedNewTaskSyscall(t, el)
	if ep == nil {
		t.Fatal("row was not emitted")
	}
	defer ep.Recycle()
	if ep.Comm != inheritedComm {
		t.Fatalf("comm = %q, want the inherited %q kept after an empty read", ep.Comm, inheritedComm)
	}
}

// TestTaskNewtaskSeedDoesNotOverrideAFresherKernelName: the procfs read that a
// provisional seed allows must still lose against an authoritative name that
// lands while it is in flight (an exec record, like an open event's payload
// comm, bumps the rename generation the read sampled before it started). The
// stale read holds the pre-exec name; if it won, the program's first syscalls
// and its -comm matches would use the old label again.
func TestTaskNewtaskSeedDoesNotOverrideAFresherKernelName(t *testing.T) {
	const execComm = "execd"
	g := newGatedProcfs("pre-exec-procfs-name")
	el := newGatedTaskEventLoop(t, g, "")
	out := make(chan *event.Pair, 1)
	el.processRawEvent(makeTaskNewtaskEvent(t, newTaskPid, newTaskTid, inheritedComm, 0), out)
	if ep := feedNewTaskSyscall(t, el); ep != nil {
		ep.Recycle()
	}
	g.waitEntered(t) // the read has sampled the generation and is in flight

	el.processRawEvent(makeProcessExecEvent(t, newTaskStart+50, newTaskPid, newTaskTid, execComm), out)
	close(g.release)
	waitForCommLookupsToDrain(t, el)

	if got, ok := el.commResolver.cached(newTaskTid); !ok || got != execComm {
		t.Fatalf("cached comm = %q (present=%v), want the exec record's %q to outrank the in-flight read",
			got, ok, execComm)
	}
}

// TestTaskNewtaskRecordRetiresARecycledTidsState: the record says the tid is a
// brand-new task, so parked enter, gap baseline, name_to_handle_at pathname and
// cached name of a dead previous owner whose exit record was lost must not
// reach it (handleProcessExitEvent retires the same four pieces when the exit
// record does arrive). The control run without the record shows the fixture
// really produces the fabricated row.
func TestTaskNewtaskRecordRetiresARecycledTidsState(t *testing.T) {
	for _, withRecord := range []bool{false, true} {
		name := "control without a record"
		if withRecord {
			name = "with the record"
		}
		t.Run(name, func(t *testing.T) {
			el := newPairEvictionEventLoop(t)
			out := make(chan *event.Pair, 4)
			leaveDeadOwnerState(t, el, out)

			if withRecord {
				el.processRawEvent(makeTaskNewtaskEvent(t, execCommPid, execCommTid, "fresh", 0), out)
			}
			ep := feedAccessExit(t, el, out, defaulTime+oneHourNs, execCommTid)
			if !withRecord {
				if ep == nil || rowFile(ep) != deadTaskPath {
					t.Fatalf("control: expected the fabricated row built from the dead enter, got %s", rowFile(ep))
				}
				ep.Recycle()
				return
			}
			if ep != nil {
				t.Fatalf("recycled tid emitted a row built from the dead owner's enter: file=%s", rowFile(ep))
			}
			assertRecycledTidIsClean(t, el, out)
		})
	}
}

// leaveDeadOwnerState makes execCommTid carry everything a task that died
// without an exit record would leave: a gap baseline (one completed pair), a
// parked enter (killed inside the next access()), an unconsumed
// name_to_handle_at pathname and a cached name.
func leaveDeadOwnerState(t *testing.T, el *eventLoop, out chan *event.Pair) {
	t.Helper()
	feedAccessEnter(t, el, out, defaulTime, execCommTid, siblingTaskPath)
	if ep := feedAccessExit(t, el, out, defaulTime+100, execCommTid); ep != nil {
		ep.Recycle()
	} else {
		t.Fatal("the dead owner's first pair was not emitted")
	}
	feedAccessEnter(t, el, out, defaulTime+300, execCommTid, deadTaskPath)
	el.pendingHandleState().set(execCommTid, deadTaskPath)
	el.setCachedComm(execCommTid, "victim")
}

// assertRecycledTidIsClean checks the new owner's view after its record: own
// row without a gap from the dead owner, no leftover handle pathname, and its
// own name rather than the dead owner's.
func assertRecycledTidIsClean(t *testing.T, el *eventLoop, out chan *event.Pair) {
	t.Helper()
	start := defaulTime + oneHourNs + 200
	feedAccessEnter(t, el, out, start, execCommTid, recycledTaskPath)
	ep := feedAccessExit(t, el, out, start+100, execCommTid)
	if ep == nil {
		t.Fatal("the recycled task's own pair was not emitted")
	}
	defer ep.Recycle()
	if got := rowFile(ep); got != recycledTaskPath {
		t.Errorf("row file = %s, want %s", got, recycledTaskPath)
	}
	if ep.DurationToPrev != 0 {
		t.Errorf("first row gap = %dns, want 0 (no baseline from the dead owner)", ep.DurationToPrev)
	}
	if path, ok := el.pendingHandleState().peek(execCommTid); ok {
		t.Errorf("pending handle pathname %q survived the record", path)
	}
	if ep.Comm != "fresh" {
		t.Errorf("row comm = %q, want the new task's \"fresh\", not the dead owner's", ep.Comm)
	}
}

// TestTaskNewtaskRecordKeepsSiblingState: the record retires the state of its
// own tid only; a sibling thread's parked enter must survive, as it does for
// an exit record (TestProcessExitEvictsOnlyTheExitedTasksPairState).
func TestTaskNewtaskRecordKeepsSiblingState(t *testing.T) {
	const siblingTid = execCommTid + 1
	el := newPairEvictionEventLoop(t)
	out := make(chan *event.Pair, 2)
	feedAccessEnter(t, el, out, defaulTime, siblingTid, siblingTaskPath)

	el.processRawEvent(makeTaskNewtaskEvent(t, execCommPid, execCommTid, "fresh", cloneThread), out)

	ep := feedAccessExit(t, el, out, defaulTime+100, siblingTid)
	if ep == nil {
		t.Fatal("a sibling's in-flight syscall was dropped by another task's newtask record")
	}
	defer ep.Recycle()
	if got := rowFile(ep); got != siblingTaskPath {
		t.Fatalf("sibling row file = %s, want %s", got, siblingTaskPath)
	}
}
