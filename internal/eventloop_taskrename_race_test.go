package internal

import (
	"syscall"
	"testing"

	"ior/internal/event"
	"ior/internal/types"
)

// The payload comm of an open or exec enter record is task->comm at the moment
// the syscall started. These tests pin where it is applied to the comm cache
// (task lr2 review): at the ENTER, in ring order with a task_rename record,
// not at the exit. Applied at exit, a rename that landed between enter and
// exit (a sibling's pthread_setname_np on a thread blocked in open(2) on a
// FIFO) was overwritten with the pre-rename name, and the thread's later rows
// kept the old label.

const (
	payloadOldComm = "blocked-old"
	payloadNewComm = "blocked-new"
)

// openEnterRaw builds an openat enter record of newTaskTid that carries comm.
func openEnterRaw(t *testing.T, comm string) []byte {
	t.Helper()
	ev := types.OpenEvent{
		EventType:     types.ENTER_OPEN_EVENT,
		TraceId:       types.SYS_ENTER_OPENAT,
		Time:          newTaskStart,
		Pid:           newTaskPid,
		Tid:           newTaskTid,
		Flags:         syscall.O_RDONLY,
		SchemaVersion: types.OPEN_EVENT_SCHEMA_VERSION,
	}
	copy(ev.Filename[:], "/tmp/fifo")
	copy(ev.Comm[:], comm)
	raw, err := ev.Bytes()
	if err != nil {
		t.Fatalf("encode open enter event: %v", err)
	}
	return raw
}

// execEnterRaw builds an execve enter record of newTaskTid that carries comm.
func execEnterRaw(t *testing.T, comm string) []byte {
	t.Helper()
	ev := types.ExecEvent{
		EventType:      types.ENTER_EXEC_EVENT,
		TraceId:        types.SYS_ENTER_EXECVE,
		Time:           newTaskStart,
		Pid:            newTaskPid,
		Tid:            newTaskTid,
		Dirfd:          -1, // plain execve, as the BPF side reports it
		FilenameStatus: types.PATH_READ_OK,
		SchemaVersion:  types.EXEC_EVENT_SCHEMA_VERSION,
	}
	copy(ev.Filename[:], "/usr/bin/does-not-exist")
	copy(ev.Comm[:], comm)
	raw, err := ev.Bytes()
	if err != nil {
		t.Fatalf("encode exec enter event: %v", err)
	}
	return raw
}

// payloadExitRaw builds the exit record paired with an enter of newTaskTid.
func payloadExitRaw(t *testing.T, id types.TraceId, ret int64) []byte {
	t.Helper()
	_, raw := makeExitRetEvent(t, newTaskStart+200, newTaskPid, newTaskTid, id, ret)
	return raw
}

// deliverRaw pushes records through the raw path in order and returns the pair the
// last one completed (nil when none did).
func deliverRaw(el *eventLoop, raws ...[]byte) *event.Pair {
	out := make(chan *event.Pair, 1)
	for _, raw := range raws {
		el.processRawEvent(raw, out)
	}
	select {
	case ep := <-out:
		return ep
	default:
		return nil
	}
}

// requireCachedComm fails unless the tid's cached comm is want.
func requireCachedComm(t *testing.T, el *eventLoop, when, want string) {
	t.Helper()
	if got, ok := el.commState().cached(newTaskTid); !ok || got != want {
		t.Fatalf("cached comm %s = %q (present=%v), want %q", when, got, ok, want)
	}
}

// TestOpenPayloadCommDoesNotUndoARenameBetweenEnterAndExit is the reviewer's
// scenario: open-enter(old), task_rename(new), open-exit. The cache must end on
// the new name and the thread's next row must carry it. The open's own row
// keeps the enter-time name: it is what task->comm read when the syscall
// started.
func TestOpenPayloadCommDoesNotUndoARenameBetweenEnterAndExit(t *testing.T) {
	el := newTaskEventLoop(t, "")

	ep := deliverRaw(el,
		openEnterRaw(t, payloadOldComm),
		makeTaskRenameEvent(t, newTaskPid, newTaskTid, payloadNewComm),
		payloadExitRaw(t, types.SYS_EXIT_OPENAT, 5))
	if ep == nil {
		t.Fatal("the open pair was not emitted")
	}
	defer ep.Recycle()
	if ep.Comm != payloadOldComm {
		t.Fatalf("open row comm = %q, want the enter-time %q", ep.Comm, payloadOldComm)
	}

	requireCachedComm(t, el, "after enter, rename, exit", payloadNewComm)
	next := feedNewTaskSyscall(t, el)
	if next == nil {
		t.Fatal("the row after the open was not emitted")
	}
	defer next.Recycle()
	if next.Comm != payloadNewComm {
		t.Fatalf("row after the open comm = %q, want the renamed %q", next.Comm, payloadNewComm)
	}
}

// TestOpenPayloadCommSeedsTheCacheWithoutARename is the negative control: with
// no rename in between the payload comm still names the tid, and it does so as
// soon as the enter is consumed, before any exit.
func TestOpenPayloadCommSeedsTheCacheWithoutARename(t *testing.T) {
	el := newTaskEventLoop(t, "")

	if ep := deliverRaw(el, openEnterRaw(t, payloadOldComm)); ep != nil {
		ep.Recycle()
		t.Fatal("an enter alone completed a pair")
	}
	requireCachedComm(t, el, "after the enter alone", payloadOldComm)

	ep := deliverRaw(el, payloadExitRaw(t, types.SYS_EXIT_OPENAT, 5))
	if ep == nil {
		t.Fatal("the open pair was not emitted")
	}
	ep.Recycle()
	requireCachedComm(t, el, "after the exit", payloadOldComm)
}

// TestFailedExecCommDoesNotUndoARenameBetweenEnterAndExit is the same ordering
// for the other payload writer. The execve fails, so no exec record ever
// replaces the caller's name; the rename is the only newer name there is.
func TestFailedExecCommDoesNotUndoARenameBetweenEnterAndExit(t *testing.T) {
	el := newTaskEventLoop(t, "")

	ep := deliverRaw(el,
		execEnterRaw(t, payloadOldComm),
		makeTaskRenameEvent(t, newTaskPid, newTaskTid, payloadNewComm),
		payloadExitRaw(t, types.SYS_EXIT_EXECVE, -int64(syscall.ENOENT)))
	if ep == nil {
		t.Fatal("the execve pair was not emitted")
	}
	ep.Recycle()
	requireCachedComm(t, el, "after exec enter, rename, failed exit", payloadNewComm)
}

// TestFailedExecCommSeedsTheCacheWithoutARename is the negative control: a
// failed execve with nothing in between leaves the task under the name its enter
// carried, which is what the cache must say.
func TestFailedExecCommSeedsTheCacheWithoutARename(t *testing.T) {
	el := newTaskEventLoop(t, "")

	ep := deliverRaw(el, execEnterRaw(t, payloadOldComm),
		payloadExitRaw(t, types.SYS_EXIT_EXECVE, -int64(syscall.ENOENT)))
	if ep == nil {
		t.Fatal("the execve pair was not emitted")
	}
	ep.Recycle()
	requireCachedComm(t, el, "after a failed execve", payloadOldComm)
}

// TestSuccessfulExecRecordReplacesTheCallerComm: the exec enter seeds the
// caller's name, and because the kernel's exec record follows in ring order the
// post-exec name wins - exactly as when the enter wrote nothing at all.
func TestSuccessfulExecRecordReplacesTheCallerComm(t *testing.T) {
	el := newTaskEventLoop(t, "")

	ep := deliverRaw(el,
		execEnterRaw(t, payloadOldComm),
		makeProcessExecEvent(t, newTaskStart+100, newTaskPid, newTaskTid, payloadNewComm),
		payloadExitRaw(t, types.SYS_EXIT_EXECVE, 0))
	if ep == nil {
		t.Fatal("the execve pair was not emitted")
	}
	defer ep.Recycle()
	if ep.Comm != payloadOldComm {
		t.Fatalf("execve row comm = %q, want the caller's %q", ep.Comm, payloadOldComm)
	}
	requireCachedComm(t, el, "after a successful execve", payloadNewComm)
}

// TestFilteredOutOpenStillSeedsTheCache: under -comm the raw gate drops an open
// whose payload comm does not match, and before the seed moved to the enter that
// drop meant the exit handler never ran, so the cache was never corrected. The
// payload is true whether or not the row is wanted.
func TestFilteredOutOpenStillSeedsTheCache(t *testing.T) {
	el := newTaskEventLoop(t, "^wanted$")

	if ep := deliverRaw(el, openEnterRaw(t, payloadOldComm)); ep != nil {
		ep.Recycle()
		t.Fatal("an enter alone completed a pair")
	}
	requireCachedComm(t, el, "after a filtered-out open enter", payloadOldComm)
	if ep := deliverRaw(el, payloadExitRaw(t, types.SYS_EXIT_OPENAT, 5)); ep != nil {
		ep.Recycle()
		t.Fatal("the -comm filter let the non-matching open through")
	}
}

// TestSameNameRenameIsANoOp: a task that renames itself to the name it already
// has changes nothing observable - the same cache entry, the same row label and
// no procfs lookup queued - so thread pools that re-apply their name on every
// task cost nothing but the record.
func TestSameNameRenameIsANoOp(t *testing.T) {
	el := newTaskEventLoop(t, "")
	nameNewTask(t, el, newTaskComm)
	renameNewTask(t, el, newTaskComm)
	before := pendingCount(el.commResolver)

	renameNewTask(t, el, newTaskComm)

	requireCachedComm(t, el, "after a same-name rename", newTaskComm)
	if got := pendingCount(el.commResolver); got != before {
		t.Fatalf("pending procfs lookups = %d, want %d: a same-name rename queued work", got, before)
	}
	ep := feedNewTaskSyscall(t, el)
	if ep == nil {
		t.Fatal("the row after the rename was not emitted")
	}
	defer ep.Recycle()
	if ep.Comm != newTaskComm {
		t.Fatalf("row comm = %q, want %q", ep.Comm, newTaskComm)
	}
}
