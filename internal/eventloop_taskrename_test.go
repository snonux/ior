package internal

import (
	"strings"
	"testing"

	"ior/internal/event"
	"ior/internal/types"
)

// The task:task_rename record reports a task changing its own name
// (prctl(PR_SET_NAME), pthread_setname_np) - the one comm change nothing else
// reports for a task that does not exec (task lr2). The tests share the
// fixtures of the newtask tests: a hermetic resolver whose procfs read never
// answers, so any name a row carries came from a record.

const taskRenameNewComm = "wk-renamed"

// taskRenameEventWireSize pins the kernel payload size of struct
// task_rename_event (internal/c/types.h): 4+4+8+4+4+16, no padding.
// NewTaskRenameEventFast drops anything shorter, so a drift would turn every
// record into a dropped malformed event.
const taskRenameEventWireSize = 40

// makeTaskRenameEvent builds the kernel payload of a task_rename record: the
// renamed task's tgid and tid and its new name.
func makeTaskRenameEvent(t *testing.T, pid, tid uint32, comm string) []byte {
	t.Helper()
	ev := types.TaskRenameEvent{
		EventType: types.TASK_RENAME_EVENT,
		Time:      newTaskStart + 50,
		Pid:       pid,
		Tid:       tid,
	}
	copy(ev.Comm[:], comm)
	raw, err := ev.Bytes()
	if err != nil {
		t.Fatalf("TaskRenameEvent.Bytes() error = %v", err)
	}
	if len(raw) != taskRenameEventWireSize {
		t.Fatalf("TaskRenameEvent wire size = %d, want %d", len(raw), taskRenameEventWireSize)
	}
	return raw
}

// nameNewTask delivers the task_newtask record that gives newTaskTid its first
// (inherited) name.
func nameNewTask(t *testing.T, el *eventLoop, comm string) {
	t.Helper()
	el.processRawEvent(makeTaskNewtaskEvent(t, newTaskPid, newTaskTid, comm, cloneThread),
		make(chan *event.Pair, 1))
}

// renameNewTask delivers a task_rename record for newTaskTid.
func renameNewTask(t *testing.T, el *eventLoop, comm string) {
	t.Helper()
	el.processRawEvent(makeTaskRenameEvent(t, newTaskPid, newTaskTid, comm), make(chan *event.Pair, 1))
}

// TestTaskRenameRecordRelabelsLaterRows: a named task renames itself, and the
// next row carries the new name. The row before it keeps the old one.
func TestTaskRenameRecordRelabelsLaterRows(t *testing.T) {
	el := newTaskEventLoop(t, "")
	nameNewTask(t, el, newTaskComm)

	before := feedNewTaskSyscall(t, el)
	if before == nil {
		t.Fatal("the row before the rename was not emitted")
	}
	defer before.Recycle()
	if before.Comm != newTaskComm {
		t.Fatalf("comm before the rename = %q, want %q", before.Comm, newTaskComm)
	}

	renameNewTask(t, el, taskRenameNewComm)
	after := feedNewTaskSyscall(t, el)
	if after == nil {
		t.Fatal("the row after the rename was not emitted")
	}
	defer after.Recycle()
	if after.Comm != taskRenameNewComm {
		t.Fatalf("comm after the rename = %q, want %q", after.Comm, taskRenameNewComm)
	}
}

// TestRenamedTaskWithoutARecordKeepsItsOldName keeps the fixture honest: with
// no rename record the same row still carries the old name, which is the
// reported bug. If the hermetic resolver ever started answering, the positive
// test above would prove nothing.
func TestRenamedTaskWithoutARecordKeepsItsOldName(t *testing.T) {
	el := newTaskEventLoop(t, "")
	nameNewTask(t, el, newTaskComm)
	if ep := feedNewTaskSyscall(t, el); ep != nil {
		ep.Recycle()
	}

	ep := feedNewTaskSyscall(t, el)
	if ep == nil {
		t.Fatal("the row was not emitted")
	}
	defer ep.Recycle()
	if ep.Comm != newTaskComm {
		t.Fatalf("comm = %q, want the old %q (no rename record was delivered)", ep.Comm, newTaskComm)
	}
}

// TestTaskRenameRecordMovesTheCommFilterVerdict is the -comm half of the bug:
// the filter judged a renamed task by its old name, so -comm <new> dropped its
// rows and -comm <old> kept admitting them. After the record the verdict
// follows the new name.
func TestTaskRenameRecordMovesTheCommFilterVerdict(t *testing.T) {
	for _, tc := range []struct {
		name          string
		pattern       string
		keptBefore    bool
		keptAfter     bool
		deliverRename bool
	}{
		{name: "-comm old: kept, then dropped", pattern: newTaskComm, keptBefore: true, keptAfter: false, deliverRename: true},
		{name: "-comm new: dropped, then kept", pattern: taskRenameNewComm, keptBefore: false, keptAfter: true, deliverRename: true},
		{name: "no record: -comm old keeps admitting (the bug)", pattern: newTaskComm, keptBefore: true, keptAfter: true},
		{name: "no record: -comm new keeps dropping (the bug)", pattern: taskRenameNewComm, keptBefore: false, keptAfter: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			el := newTaskEventLoop(t, tc.pattern)
			nameNewTask(t, el, newTaskComm)
			requireEmitted(t, "before the rename", feedNewTaskSyscall(t, el), tc.keptBefore)
			if tc.deliverRename {
				renameNewTask(t, el, taskRenameNewComm)
			}
			requireEmitted(t, "after the rename", feedNewTaskSyscall(t, el), tc.keptAfter)
		})
	}
}

// requireEmitted fails unless a row was emitted exactly when want says so, and
// recycles it.
func requireEmitted(t *testing.T, when string, ep *event.Pair, want bool) {
	t.Helper()
	if (ep != nil) != want {
		t.Fatalf("row %s: emitted = %v, want %v", when, ep != nil, want)
	}
	if ep != nil {
		ep.Recycle()
	}
}

// TestTaskRenameRecordOnlyRenamesItsOwnTid: the record carries the renamed
// task's tid, which a /proc/<tid>/comm write by a sibling makes different from
// any other record of the same process. Neighbouring tids keep their names.
func TestTaskRenameRecordOnlyRenamesItsOwnTid(t *testing.T) {
	el := newTaskEventLoop(t, "")
	const siblingTid = newTaskTid + 1
	el.processRawEvent(makeTaskNewtaskEvent(t, newTaskPid, siblingTid, newTaskComm, cloneThread),
		make(chan *event.Pair, 1))
	nameNewTask(t, el, newTaskComm)

	renameNewTask(t, el, taskRenameNewComm)

	if got, _ := el.commState().cached(newTaskTid); got != taskRenameNewComm {
		t.Fatalf("renamed tid cached comm = %q, want %q", got, taskRenameNewComm)
	}
	if got, _ := el.commState().cached(siblingTid); got != newTaskComm {
		t.Fatalf("sibling tid cached comm = %q, want it unchanged (%q)", got, newTaskComm)
	}
}

// TestTaskRenameRecordWithEmptyCommKeepsTheName: a record without a name carries
// no information, so the cache keeps whatever it has (and caches nothing for an
// unknown tid).
func TestTaskRenameRecordWithEmptyCommKeepsTheName(t *testing.T) {
	el := newTaskEventLoop(t, "")
	nameNewTask(t, el, newTaskComm)

	renameNewTask(t, el, "")
	renameNewTask(t, el, "")

	if got, _ := el.commState().cached(newTaskTid); got != newTaskComm {
		t.Fatalf("cached comm after empty rename records = %q, want %q", got, newTaskComm)
	}
	el.processRawEvent(makeTaskRenameEvent(t, newTaskPid, newTaskTid+9, ""), make(chan *event.Pair, 1))
	if _, ok := el.commState().cached(newTaskTid + 9); ok {
		t.Fatal("an empty rename record created a cache entry")
	}
}

// TestTaskRenameRecordSettlesAProvisionalSeed: the newtask seed is provisional
// (stale: the first use queues one corrective /proc read). A rename record is
// an authoritative name, so the flag is cleared and no read is needed any more.
func TestTaskRenameRecordSettlesAProvisionalSeed(t *testing.T) {
	el := newTaskEventLoop(t, "")
	nameNewTask(t, el, newTaskComm)
	if stale, present := commEntryStale(el.commResolver, newTaskTid); !present || !stale {
		t.Fatalf("seed stale=%v present=%v, want a provisional (stale) entry", stale, present)
	}

	renameNewTask(t, el, taskRenameNewComm)

	if stale, present := commEntryStale(el.commResolver, newTaskTid); !present || stale {
		t.Fatalf("after the rename stale=%v present=%v, want a settled entry", stale, present)
	}
}

// TestTaskRenameRecordWinsOverAnInFlightProcfsLookup is the logical race the
// epoch closes, with the rename in the role the exec record plays in
// TestExecRecordWinsOverAnInFlightProcfsLookup: a lookup read the old name, is
// descheduled, and lands only after the record installed the new one. Without
// the epoch bump (setCachedFromKernel) the stale read would undo the rename.
func TestTaskRenameRecordWinsOverAnInFlightProcfsLookup(t *testing.T) {
	gate := newGatedProcfs(newTaskComm)
	el := newGatedTaskEventLoop(t, gate, "")

	el.queueCommLookup(newTaskTid)
	gate.waitEntered(t)
	renameNewTask(t, el, taskRenameNewComm)
	close(gate.release)
	waitForCommLookupsToDrain(t, el)

	if got, ok := el.commState().cached(newTaskTid); !ok || got != taskRenameNewComm {
		t.Fatalf("cached comm after the stale lookup landed = %q (present=%v), want %q", got, ok, taskRenameNewComm)
	}
}

// TestMalformedTaskRenameRecordIsDroppedWithAWarning: a record shorter than the
// layout fails closed - nothing is renamed, the loop warns - rather than
// decoding fields at wrong offsets.
func TestMalformedTaskRenameRecordIsDroppedWithAWarning(t *testing.T) {
	el := newTaskEventLoop(t, "")
	nameNewTask(t, el, newTaskComm)
	warnings := make(chan string, 1)
	el.warningCb = func(message string) {
		select {
		case warnings <- message:
		default:
		}
	}

	raw := makeTaskRenameEvent(t, newTaskPid, newTaskTid, taskRenameNewComm)
	el.processRawEvent(raw[:taskRenameEventWireSize-1], make(chan *event.Pair, 1))

	if got, _ := el.commState().cached(newTaskTid); got != newTaskComm {
		t.Fatalf("cached comm after a truncated record = %q, want it unchanged (%q)", got, newTaskComm)
	}
	select {
	case message := <-warnings:
		if !strings.Contains(message, "malformed") {
			t.Fatalf("warning = %q, want it to mention a malformed event", message)
		}
	default:
		t.Fatal("expected a warning for the truncated record")
	}
}
