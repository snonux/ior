package internal

import (
	"testing"

	"ior/internal/event"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

// The task:task_newtask record names a new tid before its first syscall. These
// tests model the failure it fixes (task fr2): a hermetic resolver whose procfs
// read always comes back empty stands in for the lost race against a
// short-lived thread - the /proc entry is gone, or the lookup has not landed
// yet - so the comm can only come from the record.

const (
	newTaskPid   = 5000
	newTaskTid   = 5001
	newTaskComm  = "ioworkload"
	cloneThread  = 0x00010000
	newTaskStart = defaulTime
)

// makeTaskNewtaskEvent builds the kernel payload of a task_newtask record.
func makeTaskNewtaskEvent(t *testing.T, pid, tid uint32, comm string, cloneFlags uint64) []byte {
	t.Helper()
	ev := types.TaskNewtaskEvent{
		EventType:  types.TASK_NEWTASK_EVENT,
		Time:       newTaskStart - 10,
		Pid:        pid,
		Tid:        tid,
		CloneFlags: cloneFlags,
	}
	copy(ev.Comm[:], comm)
	raw, err := ev.Bytes()
	if err != nil {
		t.Fatalf("TaskNewtaskEvent.Bytes() error = %v", err)
	}
	if len(raw) != taskNewtaskEventWireSize {
		t.Fatalf("TaskNewtaskEvent wire size = %d, want %d", len(raw), taskNewtaskEventWireSize)
	}
	return raw
}

// taskNewtaskEventWireSize pins the kernel payload size of struct
// task_newtask_event (internal/c/types.h): 4+4+8+4+4+16+8(clone_flags), no
// padding. NewTaskNewtaskEventFast rejects anything shorter, so a drift would
// turn every record into a dropped malformed event.
const taskNewtaskEventWireSize = 48

// newTaskEventLoop builds a loop whose resolver never learns a name from
// procfs, optionally filtering on -comm.
func newTaskEventLoop(t *testing.T, commPattern string) *eventLoop {
	t.Helper()
	cfg := eventLoopConfig{commResolver: newHermeticCommResolver()}
	if commPattern != "" {
		cfg.filter = globalfilter.Filter{Comm: &globalfilter.StringFilter{Pattern: commPattern}}
	}
	el := mustNewEventLoop(t, cfg)
	t.Cleanup(el.commResolver.shutdown)
	return el
}

// feedNewTaskSyscall pushes the first syscall of the new task through the raw
// path, the way the ring buffer would deliver it after the newtask record, and
// returns the emitted pair (nil when the filter dropped it).
func feedNewTaskSyscall(t *testing.T, el *eventLoop) *event.Pair {
	t.Helper()
	_, enterRaw := makeEnterPathEvent(t, newTaskStart, newTaskPid, newTaskTid,
		"/etc/hosts", types.SYS_ENTER_ACCESS)
	_, exitRaw := makeExitRetEvent(t, newTaskStart+100, newTaskPid, newTaskTid,
		types.SYS_EXIT_ACCESS, 0)
	return feedRawPair(t, el, enterRaw, exitRaw)
}

// TestTaskNewtaskRecordNamesTheFirstSyscall: a thread record seeds the comm, so
// the row is labelled although no procfs lookup could ever have answered.
func TestTaskNewtaskRecordNamesTheFirstSyscall(t *testing.T) {
	el := newTaskEventLoop(t, "")
	el.processRawEvent(makeTaskNewtaskEvent(t, newTaskPid, newTaskTid, newTaskComm, cloneThread),
		make(chan *event.Pair, 1))

	ep := feedNewTaskSyscall(t, el)
	if ep == nil {
		t.Fatal("the new task's first syscall was not emitted")
	}
	defer ep.Recycle()
	if ep.Comm != newTaskComm {
		t.Fatalf("comm = %q, want %q", ep.Comm, newTaskComm)
	}
}

// TestNewTaskWithoutARecordHasNoComm keeps the fixture honest: with no record
// the same syscall carries an empty comm, which is the reported symptom. If the
// hermetic resolver ever started answering, the positive test would prove
// nothing.
func TestNewTaskWithoutARecordHasNoComm(t *testing.T) {
	el := newTaskEventLoop(t, "")

	ep := feedNewTaskSyscall(t, el)
	if ep == nil {
		t.Fatal("the syscall was not emitted")
	}
	defer ep.Recycle()
	if ep.Comm != "" {
		t.Fatalf("comm without a record = %q, want empty", ep.Comm)
	}
}

// TestTaskNewtaskRecordKeepsRowsUnderACommFilter: under -comm the exit-side
// comm check drops the row of a tid whose comm is not cached (its comm is "").
// The record makes the tid known, so a matching new task's rows survive; a new
// task whose inherited name does not match is still filtered.
func TestTaskNewtaskRecordKeepsRowsUnderACommFilter(t *testing.T) {
	for _, tc := range []struct {
		name     string
		record   string
		wantEmit bool
	}{
		{name: "matching comm is kept", record: newTaskComm, wantEmit: true},
		{name: "non-matching comm is dropped", record: "other", wantEmit: false},
		{name: "no record is dropped (the bug)", record: "", wantEmit: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			el := newTaskEventLoop(t, "ioworkload")
			if tc.record != "" {
				el.processRawEvent(makeTaskNewtaskEvent(t, newTaskPid, newTaskTid, tc.record, cloneThread),
					make(chan *event.Pair, 1))
			}
			ep := feedNewTaskSyscall(t, el)
			if (ep != nil) != tc.wantEmit {
				t.Fatalf("emitted = %v, want %v", ep != nil, tc.wantEmit)
			}
			if ep != nil {
				ep.Recycle()
			}
		})
	}
}

// TestTaskNewtaskRecordReplacesAStaleRecycledComm: a tid recycled after an exit
// record was lost still holds the dead task's name. The new task's record is
// authoritative and replaces it, exactly as an exec record would.
func TestTaskNewtaskRecordReplacesAStaleRecycledComm(t *testing.T) {
	el := newTaskEventLoop(t, "")
	el.setCachedComm(newTaskTid, "victim")

	el.processRawEvent(makeTaskNewtaskEvent(t, newTaskPid, newTaskTid, newTaskComm, 0),
		make(chan *event.Pair, 1))

	if got, ok := el.cachedComm(newTaskTid); !ok || got != newTaskComm {
		t.Fatalf("cached comm = %q (present=%v), want %q", got, ok, newTaskComm)
	}
}

// TestTaskNewtaskRecordWithEmptyCommSeedsNothing: an empty name carries no
// information, so nothing is seeded (the tid falls back to the procfs lookup).
// The cache entry a dead previous owner left behind is still retired - the
// record says the tid is a brand-new task, whatever its name - because keeping
// that name would label the new task with the dead one's.
func TestTaskNewtaskRecordWithEmptyCommSeedsNothing(t *testing.T) {
	el := newTaskEventLoop(t, "")
	el.setCachedComm(newTaskTid, "victim")

	el.processRawEvent(makeTaskNewtaskEvent(t, newTaskPid, newTaskTid, "", 0),
		make(chan *event.Pair, 1))

	if got, ok := el.commResolver.cached(newTaskTid); ok {
		t.Fatalf("cached comm = %q, want nothing (stale name retired, empty name not seeded)", got)
	}
}

// TestTaskNewtaskRecordSeedsOnlyTheChild: the record names exactly its own tid;
// the creating task's cache entry (the parent, here the process leader) is left
// alone.
func TestTaskNewtaskRecordSeedsOnlyTheChild(t *testing.T) {
	el := newTaskEventLoop(t, "")
	el.setCachedComm(newTaskPid, "leader")

	el.processRawEvent(makeTaskNewtaskEvent(t, newTaskPid, newTaskTid, "worker", cloneThread),
		make(chan *event.Pair, 1))

	if got, _ := el.cachedComm(newTaskPid); got != "leader" {
		t.Fatalf("parent comm = %q, want it untouched (\"leader\")", got)
	}
	if got, _ := el.cachedComm(newTaskTid); got != "worker" {
		t.Fatalf("child comm = %q, want \"worker\"", got)
	}
}

// TestTruncatedTaskNewtaskRecordIsRejected: a payload shorter than the layout
// must not be decoded at wrong offsets - no cache write and no row.
func TestTruncatedTaskNewtaskRecordIsRejected(t *testing.T) {
	el := newTaskEventLoop(t, "")
	raw := makeTaskNewtaskEvent(t, newTaskPid, newTaskTid, newTaskComm, cloneThread)

	el.processRawEvent(raw[:taskNewtaskEventWireSize-1], make(chan *event.Pair, 1))

	if got, ok := el.cachedComm(newTaskTid); ok {
		t.Fatalf("truncated record seeded comm %q, want nothing cached", got)
	}
}
