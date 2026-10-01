package internal

import (
	"fmt"
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
// shares the table rather than copying it (task hr2): it reads the creator's
// very entries, not a snapshot that would go stale on the first open or close
// of either side (eventloop_fdshare_test.go pins that behaviour).
func TestCloneThreadAndCloneFilesDoNotCopyTheTable(t *testing.T) {
	t.Run("CLONE_THREAD keeps the shared table", func(t *testing.T) {
		el := newTaskEventLoop(t, "")
		registerParentFds(el, forkParentPid)
		feedForkRecord(t, el, forkParentPid, forkParentPid, forkParentPid+1, cloneFlagThread|cloneFlagFiles)
		if got := feedReadOn(t, el, forkParentPid, forkParentPid+1, 3).Name(); got != "pipe:0:3:4" {
			t.Fatalf("thread read of fd 3 = %q, want the process's entry", got)
		}
	})
	t.Run("CLONE_FILES process shares the entries, it does not copy them", func(t *testing.T) {
		el := newTaskEventLoop(t, "")
		registerParentFds(el, forkParentPid)
		feedForkRecord(t, el, forkParentPid, forkChildPid, forkChildPid, cloneFlagFiles)
		got, ok := el.fdState().get(3, forkChildPid)
		if !ok {
			t.Fatal("a shared-table child does not see the creator's entries")
		}
		if !el.fdState().tracksExactly(3, forkParentPid, got) {
			t.Fatal("the shared-table child got a copy (it would go stale), not the creator's entry")
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

// TestInheritNeverPrunesTheTable pins the cap rule of the copy: with the fd
// table too full for the copies, the fork copies nothing and evicts nothing. A
// copy that overran the cap triggered the LRU pruning, which trims the table to
// 75% of its cap and so threw out the parent's own entries (a copy stamped one
// age below its source lost parent entries to ties in exactly this setup).
func TestInheritNeverPrunesTheTable(t *testing.T) {
	tr := newFDTracker(nil)
	tr.maxFiles = 8
	for fd := int32(3); fd < 3+6; fd++ {
		tr.set(fd, forkParentPid, file.NewFd(fd, "/f", syscall.O_RDONLY))
	}

	tr.inherit(forkParentPid, forkChildPid)

	if got := len(tr.pidKeySets(forkParentPid).files); got != 6 {
		t.Errorf("the fork left the parent %d of 6 entries", got)
	}
	if tr.pidKeySets(forkChildPid) != nil {
		t.Error("a copy that does not fit under the cap was made anyway")
	}
	if tr.inheritSkipped != 1 {
		t.Errorf("inheritSkipped = %d, want 1", tr.inheritSkipped)
	}
	// With room for the copy it is made (same parent, larger cap).
	tr.maxFiles = 12
	tr.inherit(forkParentPid, forkChildPid)
	if got := len(tr.pidKeySets(forkChildPid).files); got != 6 {
		t.Errorf("child got %d of 6 entries although they fit", got)
	}
	assertFdIndexConsistent(t, tr)
}

// TestInheritedCopiesAreTheFirstToBePruned: the copies are stamped with the
// oldest age, so when a later insertion does prune, every child's unused copy
// goes before any entry a process really used.
func TestInheritedCopiesAreTheFirstToBePruned(t *testing.T) {
	tr := newFDTracker(nil)
	tr.maxFiles = 40
	for fd := int32(0); fd < 30; fd++ { // older than everything the parent holds
		tr.set(fd, 9000, file.NewFd(fd, "/other", syscall.O_RDONLY))
	}
	for fd := int32(3); fd < 3+4; fd++ {
		tr.set(fd, forkParentPid, file.NewFd(fd, "/f", syscall.O_RDONLY))
	}
	tr.inherit(forkParentPid, forkChildPid)
	for fd := int32(100); fd < 103; fd++ { // 30 + 4 + 4 + 3 = 41 > 40: prunes
		tr.set(fd, 9001, file.NewFd(fd, "/newer", syscall.O_RDONLY))
	}

	if keys := tr.pidKeySets(forkChildPid); keys != nil && len(keys.files) > 0 {
		t.Errorf("unused copies survived the pruning: %d left", len(keys.files))
	}
	if got := len(tr.pidKeySets(forkParentPid).files); got != 4 {
		t.Errorf("parent keeps %d of 4 entries", got)
	}
	assertFdIndexConsistent(t, tr)
}

// TestLargeParentDoesNotEvictItsOwnEntriesAcrossForks is the regression of the
// review finding: a parent with 4096 tracked descriptors forked 200 times used
// to copy all of them into each child (0.4 s of event-loop time, and with live
// children the 32768-entry cap was hit after 8 forks, evicting the parent's own
// entries). Above maxInheritedEntries nothing is copied, so the table does not
// grow and the parent keeps every entry.
func TestLargeParentDoesNotEvictItsOwnEntriesAcrossForks(t *testing.T) {
	const parentEntries, forks = 4096, 200
	tr := newFDTracker(nil)
	tr.maxFiles = parentEntries + 904 // room for under a thousand copies: the old eager copy overran it on the 1st fork
	for fd := int32(0); fd < parentEntries; fd++ {
		tr.set(fd, forkParentPid, file.NewFd(fd, "pipe:0:3:4", syscall.O_RDONLY))
	}

	for i := 0; i < forks; i++ {
		tr.inherit(forkParentPid, uint32(forkChildPid+i)) // children stay alive
	}

	if len(tr.files) != parentEntries {
		t.Errorf("table holds %d entries after %d forks, want the parent's %d only", len(tr.files), forks, parentEntries)
	}
	if got := len(tr.pidKeySets(forkParentPid).files); got != parentEntries {
		t.Errorf("parent keeps %d of %d entries", got, parentEntries)
	}
	if tr.inheritSkipped != forks {
		t.Errorf("inheritSkipped = %d, want %d", tr.inheritSkipped, forks)
	}
	assertFdIndexConsistent(t, tr)
}

// TestInheritCapBoundary pins the exact threshold: a parent holding
// maxInheritedEntries entries (files and procfs cache together) is copied, one
// more and it is not.
func TestInheritCapBoundary(t *testing.T) {
	for _, tc := range []struct {
		entries  int
		wantCopy bool
	}{{maxInheritedEntries, true}, {maxInheritedEntries + 1, false}} {
		tr := newFDTracker(nil)
		for i := 0; i < tc.entries; i++ {
			if i%2 == 0 {
				tr.set(int32(i), forkParentPid, file.NewFd(int32(i), "/f", syscall.O_RDONLY))
			} else {
				tr.setProcFdCache(int32(i), forkParentPid, file.NewFd(int32(i), "/c", syscall.O_RDONLY))
			}
		}
		tr.inherit(forkParentPid, forkChildPid)
		keys := tr.pidKeySets(forkChildPid)
		copied := keys != nil && len(keys.files)+len(keys.cache) == tc.entries
		if copied != tc.wantCopy {
			t.Errorf("parent with %d entries: copied = %v, want %v", tc.entries, copied, tc.wantCopy)
		}
		assertFdIndexConsistent(t, tr)
	}
}

// TestForkStormKeepsTheParentsAndOthersEntries: a parent at the copy cap forking
// 200 children that all stay alive, in a table that cannot hold all their
// copies. Copies are made while they fit and skipped after that; nothing is
// evicted, so the parent's entries and an unrelated process's survive.
func TestForkStormKeepsTheParentsAndOthersEntries(t *testing.T) {
	const forks, otherPid = 200, 9000
	tr := newFDTracker(nil)
	tr.maxFiles = 1000
	for fd := int32(0); fd < maxInheritedEntries; fd++ {
		tr.set(fd, forkParentPid, file.NewFd(fd, "pipe:0:3:4", syscall.O_RDONLY))
	}
	for fd := int32(0); fd < 100; fd++ {
		tr.set(fd, otherPid, file.NewFd(fd, "/other", syscall.O_RDONLY))
	}

	for i := 0; i < forks; i++ {
		tr.inherit(forkParentPid, uint32(forkChildPid+i))
	}

	if got := len(tr.pidKeySets(forkParentPid).files); got != maxInheritedEntries {
		t.Errorf("parent keeps %d of %d entries", got, maxInheritedEntries)
	}
	if got := len(tr.pidKeySets(otherPid).files); got != 100 {
		t.Errorf("the unrelated process keeps %d of 100 entries", got)
	}
	if len(tr.files) > tr.maxFiles {
		t.Errorf("table holds %d entries, cap %d", len(tr.files), tr.maxFiles)
	}
	if tr.inheritSkipped == 0 || tr.inheritSkipped == forks {
		t.Errorf("inheritSkipped = %d, want some forks copied and the rest skipped", tr.inheritSkipped)
	}
	assertFdIndexConsistent(t, tr)
}

// TestChildKeepsItsInheritedNameWhenTheParentChangesAfterTheFork pins the
// snapshot semantic: a fork copies the table as of the fork, so a parent that
// then closes a descriptor, or reuses its number for another file (the usual
// pipe plumbing after a fork), must not change what the child's rows say.
func TestChildKeepsItsInheritedNameWhenTheParentChangesAfterTheFork(t *testing.T) {
	el := newTaskEventLoop(t, "")
	registerParentFds(el, forkParentPid)
	feedForkRecord(t, el, forkParentPid, forkChildPid, forkChildPid, forkSigchld)

	el.fdState().delete(3, forkParentPid) // the parent closes its copy of the pipe end
	el.fdState().set(5, forkParentPid, file.NewFd(5, "/tmp/reopened", syscall.O_WRONLY))
	el.fdState().forget(6, forkParentPid)

	for fd, want := range map[int32]string{3: "pipe:0:3:4", 5: "memfd:huntbuf", 6: "eventfd:0"} {
		if got := feedReadOn(t, el, forkChildPid, forkChildPid, fd).Name(); got != want {
			t.Errorf("child fd %d = %q after the parent changed it, want the snapshot name %q", fd, got, want)
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

// BenchmarkForkStorm is the cost of one fork of a parent holding n fd-table
// entries, together with the exit-time cleanup that frees the child's copy
// (inherit + deletePid): what the single event-loop goroutine pays per fork in
// a fork storm. Above maxInheritedEntries the fork is skipped and costs a map
// lookup; at and below it the cost is bounded by the cap.
func BenchmarkForkStorm(b *testing.B) {
	for _, n := range []int{8, 64, 128, 1024, 8192} {
		b.Run(fmt.Sprintf("entries=%d", n), func(b *testing.B) {
			tr := newFDTracker(nil)
			for fd := 0; fd < n; fd++ {
				tr.set(int32(fd), forkParentPid, file.NewFd(int32(fd), "pipe:0:3:4", syscall.O_RDONLY))
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				child := uint32(forkChildPid + i)
				tr.inherit(forkParentPid, child)
				tr.deletePid(child)
			}
		})
	}
}
