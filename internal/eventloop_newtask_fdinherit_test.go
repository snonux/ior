package internal

import (
	"os"
	"os/exec"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/types"
)

// Task gr2: a forked child starts with a copy of its creator's descriptor
// table, but the fd table is keyed by tgid and nothing modelled the fork, so
// every inherited descriptor of a new process fell back to /proc/<pid>/fd,
// which renames it (pipe:0:3:4 -> pipe:[N], memfd:x -> /memfd:x (deleted),
// eventfd:0 -> anon_inode:[eventfd]) and, once the child has exited before the
// lazy read, to an unresolvable E:name. The task:task_newtask record now carries
// the creator's tgid and the clone flags, which is what these tests feed.

const (
	forkParentPid = 7000
	forkChildPid  = 7100
	forkSigchld   = 17 // the flag word of a plain fork(): just the exit signal
	forkStart     = defaulTime + 1000
)

// makeForkRecord builds the task_newtask record of a new task created by
// creator. For a process the tid is the tgid; the thread tests pass their own.
func makeForkRecord(t *testing.T, creator, pid, tid uint32, flags uint64) []byte {
	t.Helper()
	ev := types.TaskNewtaskEvent{
		EventType:  types.TASK_NEWTASK_EVENT,
		Time:       forkStart - 10,
		Pid:        pid,
		Tid:        tid,
		CloneFlags: flags,
		CreatorPid: creator,
	}
	copy(ev.Comm[:], "forker")
	raw, err := ev.Bytes()
	if err != nil {
		t.Fatalf("TaskNewtaskEvent.Bytes() error = %v", err)
	}
	return raw
}

// feedForkRecord delivers the record through the raw event path, in ring-buffer
// order, the way production does.
func feedForkRecord(t *testing.T, el *eventLoop, creator, pid, tid uint32, flags uint64) {
	t.Helper()
	el.processRawEvent(makeForkRecord(t, creator, pid, tid, flags), make(chan *event.Pair, 1))
}

// feedReadOn feeds a read(fd) of pid/tid and returns the emitted row's file, so
// the test sees what the row would print.
func feedReadOn(t *testing.T, el *eventLoop, pid, tid uint32, fd int32) file.File {
	t.Helper()
	_, enterRaw := makeEnterFdEvent(t, forkStart, pid, tid, fd, types.SYS_ENTER_READ)
	_, exitRaw := makeExitRetEvent(t, forkStart+100, pid, tid, types.SYS_EXIT_READ, 1)
	ep := feedRawPair(t, el, enterRaw, exitRaw)
	if ep == nil {
		t.Fatalf("read(%d) of %d/%d produced no row", fd, pid, tid)
	}
	defer ep.Recycle()
	// The pair is recycled, so detach a copy of what it reports.
	return file.NewFd(fd, ep.File.Name(), int32(ep.File.Flags()))
}

// registerParentFds gives the creator the traced names the degraded procfs
// forms cannot reproduce.
func registerParentFds(el *eventLoop, pid uint32) {
	el.fdState().set(3, pid, file.NewFd(3, "pipe:0:3:4", syscall.O_RDONLY))
	el.fdState().set(5, pid, file.NewFd(5, "memfd:huntbuf", syscall.O_RDWR))
	el.fdState().set(6, pid, file.NewFd(6, "eventfd:0", syscall.O_RDWR))
}

// TestForkedChildInheritsTheCreatorsTracedFdNames is the reproduction: the
// child's first read on an inherited descriptor carries the parent's traced
// name, not a procfs answer (here: nothing, the child has no /proc entry).
func TestForkedChildInheritsTheCreatorsTracedFdNames(t *testing.T) {
	el := newTaskEventLoop(t, "")
	registerParentFds(el, forkParentPid)

	feedForkRecord(t, el, forkParentPid, forkChildPid, forkChildPid, forkSigchld)

	for fd, want := range map[int32]string{3: "pipe:0:3:4", 5: "memfd:huntbuf", 6: "eventfd:0"} {
		if got := feedReadOn(t, el, forkChildPid, forkChildPid, fd).Name(); got != want {
			t.Errorf("child fd %d = %q, want the inherited name %q", fd, got, want)
		}
	}
	// The copy does not move the parent's entries.
	if got := feedReadOn(t, el, forkParentPid, forkParentPid, 3).Name(); got != "pipe:0:3:4" {
		t.Errorf("parent fd 3 = %q after the fork, want it untouched", got)
	}
}

// TestChildWithoutARecordHasNoInheritedNames keeps the fixture honest (the
// negative control): the same read without the record resolves through procfs,
// which has no such process, so the name is empty. If this ever started
// answering, the positive test would prove nothing.
func TestChildWithoutARecordHasNoInheritedNames(t *testing.T) {
	el := newTaskEventLoop(t, "")
	registerParentFds(el, forkParentPid)

	if got := feedReadOn(t, el, forkChildPid, forkChildPid, 3).Name(); got != "" {
		t.Fatalf("child fd 3 without a record = %q, want empty", got)
	}
}

// TestForkedChildTracksItsTableIndependently: a change in one table after the
// fork must not leak into the other, and the flags of a copy are detached from
// the source (FD_CLOEXEC belongs to the descriptor, not to the shared open file
// description).
func TestForkedChildTracksItsTableIndependently(t *testing.T) {
	el := newTaskEventLoop(t, "")
	registerParentFds(el, forkParentPid)
	feedForkRecord(t, el, forkParentPid, forkChildPid, forkChildPid, forkSigchld)

	childFd, ok := el.fdState().get(3, forkChildPid)
	if !ok {
		t.Fatal("child fd 3 was not inherited")
	}
	parentFd, _ := el.fdState().get(3, forkParentPid)
	if childFd == parentFd {
		t.Fatal("child shares the parent's FdFile object, flag changes would leak")
	}
	childFd.(*file.FdFile).MergeFlags(syscall.O_CLOEXEC, syscall.O_CLOEXEC)
	if set, _ := parentFd.(*file.FdFile).CloseOnExec(); set {
		t.Fatal("setting close-on-exec on the child's copy changed the parent's descriptor")
	}

	// The child closes fd 5; the parent still has it, and the other way round.
	el.fdState().delete(5, forkChildPid)
	if _, ok := el.fdState().get(5, forkParentPid); !ok {
		t.Fatal("the child's close evicted the parent's entry")
	}
	el.fdState().delete(6, forkParentPid)
	if _, ok := el.fdState().get(6, forkChildPid); !ok {
		t.Fatal("the parent's close evicted the child's entry")
	}
}

// TestForkedChildInheritsTheProcfsCache: a descriptor the parent only ever
// resolved through procfs (opened before ior attached) sits in the procfs
// cache, and the child inherits that answer too instead of reading procfs for a
// process that may already be gone.
func TestForkedChildInheritsTheProcfsCache(t *testing.T) {
	el := newTaskEventLoop(t, "")
	el.fdState().setProcFdCache(9, forkParentPid, file.NewFd(9, "/var/log/pre-attach.log", syscall.O_WRONLY))

	feedForkRecord(t, el, forkParentPid, forkChildPid, forkChildPid, forkSigchld)

	if got := el.fdState().resolve(9, forkChildPid).Name(); got != "/var/log/pre-attach.log" {
		t.Fatalf("child fd 9 = %q, want the parent's cached procfs answer", got)
	}
	if got := el.fdState().resolve(9, forkParentPid).Name(); got != "/var/log/pre-attach.log" {
		t.Fatalf("parent fd 9 = %q, want its own cache entry kept", got)
	}
}

// TestCloneThreadAndCloneFilesDoNotCopyTheTable: a thread already reads the
// creator's entries through the shared tgid, so the record must change nothing
// (above all must not drop the creator's table), and a CLONE_FILES process
// shares the table rather than copying it, so it starts with none.
func TestCloneThreadAndCloneFilesDoNotCopyTheTable(t *testing.T) {
	t.Run("CLONE_THREAD keeps the shared table", func(t *testing.T) {
		el := newTaskEventLoop(t, "")
		registerParentFds(el, forkParentPid)
		feedForkRecord(t, el, forkParentPid, forkParentPid, forkParentPid+1, cloneFlagThread|cloneFlagFiles)
		if got := feedReadOn(t, el, forkParentPid, forkParentPid+1, 3).Name(); got != "pipe:0:3:4" {
			t.Fatalf("thread read of fd 3 = %q, want the process's entry", got)
		}
	})
	t.Run("CLONE_FILES process is not snapshotted", func(t *testing.T) {
		el := newTaskEventLoop(t, "")
		registerParentFds(el, forkParentPid)
		feedForkRecord(t, el, forkParentPid, forkChildPid, forkChildPid, cloneFlagFiles)
		if _, ok := el.fdState().get(3, forkChildPid); ok {
			t.Fatal("a shared-table child got a snapshot that would go stale on the first open or close")
		}
		if _, ok := el.fdState().get(3, forkParentPid); !ok {
			t.Fatal("the creator lost its entries")
		}
	})
}

// TestForkRecordWithoutACreatorCopiesNothing: an object that predates
// creator_pid (legacy 48-byte record, CreatorPid 0) cannot say whose table to
// copy, so the child starts empty (the old behaviour) and nothing is taken
// from pid 0.
func TestForkRecordWithoutACreatorCopiesNothing(t *testing.T) {
	el := newTaskEventLoop(t, "")
	registerParentFds(el, forkParentPid)
	el.fdState().set(3, 0, file.NewFd(3, "must-not-be-copied", syscall.O_RDONLY))

	legacy := makeForkRecord(t, 0, forkChildPid, forkChildPid, forkSigchld)[:taskNewtaskEventLegacySizeForTest]
	el.processRawEvent(legacy, make(chan *event.Pair, 1))

	if _, ok := el.fdState().get(3, forkChildPid); ok {
		t.Fatal("a record with no creator seeded the child's table")
	}
}

// taskNewtaskEventLegacySizeForTest is the pre-creator_pid record length; the
// decoder accepts it and reports CreatorPid 0.
const taskNewtaskEventLegacySizeForTest = 48

// TestForkedChildDropsAStaleTableOfARecycledPid: the new process's tgid can only
// be an old owner's whose exit record was lost; its entries must not survive
// into the child, whether the child copies a table or shares one.
func TestForkedChildDropsAStaleTableOfARecycledPid(t *testing.T) {
	for _, tc := range []struct {
		name  string
		flags uint64
	}{{"fork", forkSigchld}, {"CLONE_FILES", cloneFlagFiles}} {
		t.Run(tc.name, func(t *testing.T) {
			el := newTaskEventLoop(t, "")
			el.fdState().set(4, forkChildPid, file.NewFd(4, "/stale/previous-owner", syscall.O_RDONLY))
			el.fdState().setProcFdCache(8, forkChildPid, file.NewFd(8, "/stale/cache", syscall.O_RDONLY))

			feedForkRecord(t, el, forkParentPid, forkChildPid, forkChildPid, tc.flags)

			if _, ok := el.fdState().get(4, forkChildPid); ok {
				t.Error("stale fd-table entry of the previous owner survived")
			}
			if _, ok := el.fdState().cachedProcFdFile(8, forkChildPid); ok {
				t.Error("stale procfs-cache entry of the previous owner survived")
			}
		})
	}
}

// TestForkThenExecDropsInheritedCloseOnExecFds: the inherited copy must carry
// the close-on-exec state so the child's exec record evicts what the kernel
// closes (and keeps what survives) - the posix_spawn/fork+exec shape.
func TestForkThenExecDropsInheritedCloseOnExecFds(t *testing.T) {
	el := newTaskEventLoop(t, "")
	el.fdState().set(3, forkParentPid, file.NewFd(3, "/keep", syscall.O_RDONLY))
	el.fdState().set(4, forkParentPid, file.NewFd(4, "/drop", syscall.O_RDONLY|syscall.O_CLOEXEC))

	feedForkRecord(t, el, forkParentPid, forkChildPid, forkChildPid, forkSigchld)
	out := make(chan *event.Pair, 1)
	el.processRawEvent(makeProcessExecEvent(t, forkStart, forkChildPid, forkChildPid, "newprog"), out)

	if _, ok := el.fdState().get(3, forkChildPid); !ok {
		t.Error("an inherited descriptor without close-on-exec did not survive the exec")
	}
	if _, ok := el.fdState().get(4, forkChildPid); ok {
		t.Error("an inherited close-on-exec descriptor survived the exec")
	}
	if _, ok := el.fdState().get(4, forkParentPid); !ok {
		t.Error("the child's exec closed the parent's descriptor")
	}
}

// TestInheritSnapshotsBeforeWriting pins the LRU-safety of the copy: with the
// fd table at its cap, writing the child's entries evicts the oldest entries,
// which include the parent's own; the copy must still complete from the
// snapshot (a missing value would panic or copy nil) and leave the table at its
// cap.
func TestInheritSnapshotsBeforeWriting(t *testing.T) {
	tr := newFDTracker(nil)
	tr.maxFiles = 8
	for fd := int32(3); fd < 3+6; fd++ {
		tr.set(fd, forkParentPid, file.NewFd(fd, "/f", syscall.O_RDONLY))
	}

	tr.inherit(forkParentPid, forkChildPid)

	if len(tr.files) > tr.maxFiles {
		t.Fatalf("table holds %d entries, cap %d", len(tr.files), tr.maxFiles)
	}
	if _, ok := tr.get(8, forkChildPid); !ok {
		t.Fatal("the child's newest inherited entry is missing")
	}
	for key, f := range tr.files {
		if f == nil {
			pid, fd := fdKeyParts(key)
			t.Fatalf("nil entry for pid %d fd %d", pid, fd)
		}
	}
}

// TestRealForkedChildKeepsInheritedNamesAgainstProcfs runs against a real child
// process and the real /proc: the descriptors the child holds are a memfd and a
// pipe end, whose procfs spellings ("/memfd:huntbuf (deleted)", "pipe:[N]") are
// the degraded forms of the task's report. Without the record a row in the
// child shows the procfs form; with it, the creator's traced name.
func TestRealForkedChildKeepsInheritedNamesAgainstProcfs(t *testing.T) {
	memfd, err := unix.MemfdCreate("huntbuf", 0)
	if err != nil {
		t.Skipf("memfd_create unavailable: %v", err)
	}
	memFile := os.NewFile(uintptr(memfd), "memfd")
	defer func() { _ = memFile.Close() }()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer func() { _ = r.Close(); _ = w.Close() }()

	// ExtraFiles are numbered 3, 4 in the child; those are the descriptor
	// numbers the creator's table must name to model the same layout.
	cmd := exec.Command("sleep", "30")
	cmd.ExtraFiles = []*os.File{memFile, r}
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start a child: %v", err)
	}
	child := uint32(cmd.Process.Pid)
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()

	setup := func() *eventLoop {
		el := newTaskEventLoop(t, "")
		el.fdState().set(3, forkParentPid, file.NewFd(3, "memfd:huntbuf", syscall.O_RDWR))
		el.fdState().set(4, forkParentPid, file.NewFd(4, "pipe:0:4:9", syscall.O_RDONLY))
		return el
	}

	// Control: no record, the row shows what procfs says today.
	without := setup()
	if got := feedReadOn(t, without, child, child, 3).Name(); got != "/memfd:huntbuf (deleted)" {
		t.Fatalf("without the record the child's memfd reads %q, want the procfs form", got)
	}

	with := setup()
	feedForkRecord(t, with, forkParentPid, child, child, forkSigchld)
	if got := feedReadOn(t, with, child, child, 3).Name(); got != "memfd:huntbuf" {
		t.Errorf("child memfd = %q, want the inherited traced name", got)
	}
	if got := feedReadOn(t, with, child, child, 4).Name(); got != "pipe:0:4:9" {
		t.Errorf("child pipe end = %q, want the inherited traced name", got)
	}
}

// TestInheritFromItselfKeepsTheTable: a malformed record naming the creator as
// its own child must not wipe that process's table (the drop of the child's
// stale entries would otherwise hit the creator's live ones).
func TestInheritFromItselfKeepsTheTable(t *testing.T) {
	tr := newFDTracker(nil)
	tr.set(3, forkParentPid, file.NewFd(3, "/live", syscall.O_RDONLY))

	tr.inherit(forkParentPid, forkParentPid)

	if _, ok := tr.get(3, forkParentPid); !ok {
		t.Fatal("inherit(p, p) erased p's table")
	}
}
