package internal

import (
	"os"
	"syscall"
	"testing"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

// Task 603, which side of a disagreement is the older one. An fd table entry
// remembers when its number was bound (file.FdFile.BoundAt: the exit time of
// the call that made it), and a row whose call entered before that says
// nothing against it: the row may be of the file the number named earlier.
//
// The live shape: thread A blocks in read(N) on file X; thread B closes N and
// opens file Y, which gets N; A's read returns. Its row carries X's identity
// and is processed after B's open. Judged without the times, the entry for Y
// was dropped as a stale binding and Y's rows were named from procfs.

const laterOpenName = "/data/opened-later.txt"

// blockedRow is a read of the file ident on fd that entered beforeNs before
// boundNs and returned only afterwards, as a read does that blocked across
// another thread's close and open of the number.
func blockedRow(fd int32, ident uint32, boundNs, beforeNs uint64) identRow {
	return identRow{enter: types.SYS_ENTER_READ, exit: types.SYS_EXIT_READ, fd: fd, ident: ident,
		enterNs: boundNs - beforeNs, exitNs: boundNs + 500, ret: 1}
}

// rowAt is a read of the file ident on fd that entered at enterNs.
func rowAt(fd int32, ident uint32, enterNs uint64) identRow {
	row := readRow(fd, ident)
	row.enterNs = enterNs
	return row
}

// requireNothingCounted fails if the identity check counted a stale binding
// or a refused answer.
func requireNothingCounted(t *testing.T, el *eventLoop) {
	t.Helper()
	if el.fdState().staleBindings != 0 || el.fdState().rejectedAnswers != 0 {
		t.Fatalf("staleBindings = %d, rejectedAnswers = %d, want neither counted",
			el.fdState().staleBindings, el.fdState().rejectedAnswers)
	}
}

// The late row of the earlier file: the entry bound after the row entered is
// kept as it is, the row alone goes unnamed, procfs is not asked (it would
// name the newer file) and nothing is counted. A row of the entry's own file
// is still named by it.
func TestRowThatEnteredBeforeTheBindingLeavesTheEntryAlone(t *testing.T) {
	pid := uint32(os.Getpid())
	n := freeFdNumber(t)
	el := identLoop(t)
	placePipeOn(t, n) // what a procfs read would cache
	boundNs := bootClockNs()
	feedIdentOpenAt(t, el, laterOpenName, n, 4712, boundNs-openPairLatency)

	requireUnnamedOf(t, feedIdentRow(t, el, blockedRow(n, 4711, boundNs, 1000)).File, 4711)
	verifyFileDescriptor(t, el, pid, n, laterOpenName)
	verifyProcFdNotCached(t, el, pid, n)
	requireNothingCounted(t, el)
	if tracked, _ := el.fdState().get(n, pid); identOf(tracked) != 4712 {
		t.Fatalf("entry identity = %d after the late row, want 4712 unchanged", identOf(tracked))
	}

	if got := feedIdentRow(t, el, rowAt(n, 4712, boundNs+1)).File.Name(); got != laterOpenName {
		t.Fatalf("row of the entry's file named %q, want %q", got, laterOpenName)
	}
}

// The other order: a row of another file that entered when the entry was
// already bound proves the binding stale. The entry is dropped, counted, and
// the row named after what the number holds now. A row that entered at the
// very instant of the binding is not older than it.
func TestRowThatEnteredAfterTheBindingDropsTheStaleEntry(t *testing.T) {
	for name, afterNs := range map[string]uint64{"after": 1000, "at the binding time": 0} {
		t.Run(name, func(t *testing.T) {
			pid := uint32(os.Getpid())
			n := freeFdNumber(t)
			el := identLoop(t)
			reopened, reopenedIdent := placeFileOn(t, n, "reopened.txt")
			boundNs := bootClockNs()
			feedIdentOpenAt(t, el, laterOpenName, n, reopenedIdent+1, boundNs-openPairLatency)

			ep := feedIdentRow(t, el, rowAt(n, reopenedIdent, boundNs+afterNs))
			if got := ep.File.Name(); got != reopened {
				t.Fatalf("row named %q, want %q from procfs", got, reopened)
			}
			verifyFdNotTracked(t, el, pid, n)
			if el.fdState().staleBindings != 1 {
				t.Fatalf("staleBindings = %d, want 1", el.fdState().staleBindings)
			}
		})
	}
}

// An entry that does not know its file (a pipe, a socket) must not take the
// identity of a row that entered before it was bound: it would then drop
// itself on the first row of its own file. The late row goes unnamed; the
// first row that entered afterwards gives the entry its identity.
func TestEntryWithoutAnIdentityDoesNotTakeThatOfAnEarlierRow(t *testing.T) {
	pid := uint32(os.Getpid())
	n := freeFdNumber(t)
	el := identLoop(t)
	boundNs := bootClockNs()
	feedIdentOpenAt(t, el, laterOpenName, n, 0, boundNs-openPairLatency)

	requireUnnamedOf(t, feedIdentRow(t, el, blockedRow(n, 4711, boundNs, 1000)).File, 4711)
	if tracked, _ := el.fdState().get(n, pid); identOf(tracked) != 0 {
		t.Fatalf("entry took identity %d from a row that entered before it was bound", identOf(tracked))
	}

	if got := feedIdentRow(t, el, rowAt(n, 4712, boundNs+1)).File.Name(); got != laterOpenName {
		t.Fatalf("first row after the binding named %q, want %q", got, laterOpenName)
	}
	if tracked, _ := el.fdState().get(n, pid); identOf(tracked) != 4712 {
		t.Fatalf("entry identity = %d, want 4712 from the first row after the binding", identOf(tracked))
	}
	requireNothingCounted(t, el)
}

// A close releases the file it closed. When another thread's open returned
// the number and was processed before the close's exit record, the entry is
// of a later binding and must survive the close, whatever the close row says
// about its file; a close that entered after the binding releases it.
func TestCloseThatEnteredBeforeTheBindingDoesNotReleaseTheNewerEntry(t *testing.T) {
	tests := []struct {
		name      string
		ident     uint32
		beforeNs  uint64
		afterNs   uint64
		wantKept  bool
		wantNamed bool
	}{
		{name: "close of another file, entered before", ident: 4711, beforeNs: 1000, wantKept: true},
		{name: "close of the same file, entered before", ident: 4712, beforeNs: 1000, wantKept: true, wantNamed: true},
		{name: "close without identity, entered before", beforeNs: 1000, wantKept: true, wantNamed: true},
		{name: "close of the same file, entered after", ident: 4712, afterNs: 1000, wantNamed: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pid := uint32(os.Getpid())
			n := freeFdNumber(t)
			el := identLoop(t)
			boundNs := bootClockNs()
			feedIdentOpenAt(t, el, laterOpenName, n, 4712, boundNs-openPairLatency)

			row := closeRow(n, tc.ident, boundNs-tc.beforeNs+tc.afterNs)
			row.exitNs = boundNs + 2000
			ep := feedIdentRow(t, el, row)
			if named := ep.File.Name() == laterOpenName; named != tc.wantNamed {
				t.Fatalf("close row file = %v, want named=%v", ep.File, tc.wantNamed)
			}
			if _, kept := el.fdState().get(n, pid); kept != tc.wantKept {
				t.Fatalf("entry kept = %v after the close, want %v", kept, tc.wantKept)
			}
			requireNothingCounted(t, el)
		})
	}
}

// A duplicate is bound when the dup returns, not when its source was opened:
// a row on the new number that entered in between is of the number's earlier
// file and leaves the duplicate alone.
func TestDuplicateIsBoundWhenTheDupReturns(t *testing.T) {
	pid := uint32(os.Getpid())
	n := freeFdNumber(t)
	el := identLoop(t)
	feedIdentOpen(t, el, staleOpenName, n, 4711)
	dupNs := bootClockNs()
	dup := identRow{enter: types.SYS_ENTER_DUP, exit: types.SYS_EXIT_DUP, fd: n, ident: 4711, enterNs: dupNs, ret: int64(n + 1)}
	feedIdentRow(t, el, dup)

	source, _ := el.fdState().get(n, pid)
	copied, ok := el.fdState().get(n+1, pid)
	if !ok || copied.(*file.FdFile).BoundAt() != dupNs+openPairLatency {
		t.Fatalf("duplicate = %v (ok=%v), want it bound at the dup's exit %d", copied, ok, dupNs+openPairLatency)
	}
	if got := source.(*file.FdFile).BoundAt(); got != defaulTime+openPairLatency {
		t.Fatalf("source bound at %d, want its open's exit %d", got, defaulTime+openPairLatency)
	}

	requireUnnamedOf(t, feedIdentRow(t, el, blockedRow(n+1, 4712, dupNs+openPairLatency, 1000)).File, 4712)
	verifyFileDescriptor(t, el, pid, n+1, staleOpenName)
	requireNothingCounted(t, el)
}

// A flag change stores a fork's copy again and binds nothing, also if a
// procfs answer were cached for the key (a state set does not reach, built
// here by hand): the copy keeps no binding time, not the answer's read time,
// and the answer goes, as with every store.
func TestReStoredForkedCopyIgnoresACachedAnswer(t *testing.T) {
	const parent, child = absentPidBase + 7310, absentPidBase + 7311
	tr := identLoop(t).fdState()
	tr.bindNs = 5000
	opened := file.NewFd(5, "/data/inherited.txt", syscall.O_RDWR)
	tr.set(5, parent, opened)
	tr.inherit(parent, child)
	copied, ok := tr.get(5, child)
	if !ok {
		t.Fatal("child has no copy of the parent's entry")
	}
	answer := copied.(*file.FdFile)
	tr.setProcFdCacheRead(5, child, answer, 9000)

	tr.bindNs = 20000
	tr.set(5, child, answer)
	if got := answer.BoundAt(); got != 0 {
		t.Fatalf("re-stored fork's copy bound at %d, want no binding time", got)
	}
	if _, cached := tr.procFdCache[tr.key(child, 5)]; cached {
		t.Fatal("the store left the cached answer in place")
	}
}

// A fork's copy carries no binding time: no row of the child can have
// entered before the fork, so every row is younger than the copy, whenever
// the parent bound the number. A row of another file drops the child's entry
// and leaves the parent's.
func TestForkedCopyIsOlderThanEveryRowOfTheChild(t *testing.T) {
	const parent, child = absentPidBase + 7300, absentPidBase + 7301
	tr := identLoop(t).fdState()
	tr.bindNs = 5000
	opened := file.NewFd(5, "/data/inherited.txt", syscall.O_RDWR)
	opened.SetIdent(4711)
	tr.set(5, parent, opened)
	if opened.BoundAt() != 5000 {
		t.Fatalf("parent's entry bound at %d, want 5000", opened.BoundAt())
	}
	tr.inherit(parent, child)

	copied, ok := tr.get(5, child)
	if !ok || copied.(*file.FdFile).BoundAt() != 0 || identOf(copied) != 4711 {
		t.Fatalf("child's copy = %v (ok=%v), want identity 4711 and no binding time", copied, ok)
	}
	if _, ok := tr.trackedFile(5, child, 4712, 1000); ok || tr.staleBindings != 1 {
		t.Fatalf("row of another file kept the child's copy (ok=%v, staleBindings=%d)", ok, tr.staleBindings)
	}
	if _, ok := tr.get(5, parent); !ok {
		t.Fatalf("parent's entry went with the child's")
	}
}

// What set stamps: a new entry gets the exit time of the pair being handled,
// also when the object stored is the procfs answer cached for the key (no
// caller stores one since task a23, storeFcntlFdFile; its read time used to
// be taken), and an entry that is merely stored again (after a flag change)
// keeps its time. The store drops the cached answer either way.
func TestBindingTimeOfANewAndAReStoredEntry(t *testing.T) {
	pid := uint32(os.Getpid())
	n := freeFdNumber(t)
	tr := identLoop(t).fdState()
	answer := file.NewFd(n, "/data/cached.txt", syscall.O_RDWR)
	tr.setProcFdCacheRead(n, pid, answer, 9000)

	tr.bindNs = 5000
	tr.set(n, pid, answer)
	if answer.BoundAt() != 5000 {
		t.Fatalf("stored answer bound at %d, want the handled pair's exit 5000", answer.BoundAt())
	}
	if _, cached := tr.procFdCache[tr.key(pid, n)]; cached {
		t.Fatal("the store left the cached answer in place")
	}
	tr.bindNs = 20000
	tr.set(n, pid, answer)
	if answer.BoundAt() != 5000 {
		t.Fatalf("re-stored entry bound at %d, want 5000 unchanged", answer.BoundAt())
	}
	// A traced call binds the number while another object's answer is
	// cached for it: the entry is new, the answer's read time is not its.
	tr.delete(n, pid)
	tr.setProcFdCacheRead(n, pid, file.NewFd(n, "/data/other.txt", syscall.O_RDWR), 30000)
	fresh := file.NewFd(n, "/data/fresh.txt", syscall.O_RDWR)
	tr.set(n, pid, fresh)
	if fresh.BoundAt() != 20000 {
		t.Fatalf("new entry bound at %d, want the handled pair's exit 20000", fresh.BoundAt())
	}
}

// A run that does not capture identities keeps no binding times, so nothing
// there is judged by age: the late row keeps the traced name as it always
// did, and a close releases whatever the number holds.
func TestNoBindingTimeIsKeptWithoutTheCapture(t *testing.T) {
	pid := uint32(os.Getpid())
	n := freeFdNumber(t)
	el := newFilteredEventLoop(t, globalfilter.Filter{})
	boundNs := bootClockNs()
	feedIdentOpenAt(t, el, laterOpenName, n, 4712, boundNs-openPairLatency)

	tracked, _ := el.fdState().get(n, pid)
	if got := tracked.(*file.FdFile).BoundAt(); got != 0 {
		t.Fatalf("entry bound at %d in a run without identities, want 0", got)
	}
	if got := feedIdentRow(t, el, blockedRow(n, 4711, boundNs, 1000)).File.Name(); got != laterOpenName {
		t.Fatalf("late row named %q, want the traced %q as before", got, laterOpenName)
	}
	row := closeRow(n, 4711, boundNs-1000)
	row.exitNs = boundNs + 2000
	feedIdentRow(t, el, row)
	verifyFdNotTracked(t, el, pid, n)

	// Not even a stored procfs answer, which has a read time to offer.
	answer := file.NewFd(n, "/data/cached.txt", syscall.O_RDWR)
	el.fdState().setProcFdCacheRead(n, pid, answer, 9000)
	el.fdState().set(n, pid, answer)
	if answer.BoundAt() != 0 {
		t.Fatalf("promoted answer bound at %d in a run without identities, want 0", answer.BoundAt())
	}
}

// A close that does not say which file it closed (a record without the word,
// an inode whose low word is 0) cannot tell a cached answer for a later file
// from one for its own: the answer goes, as before the identity existed.
func TestCloseWithoutAnIdentityForgetsTheCachedAnswer(t *testing.T) {
	pid := uint32(os.Getpid())
	n := freeFdNumber(t)
	el := identLoop(t)
	closeNs := bootClockNs()
	cacheAnswer(el, n, "/data/cached.txt", 4712, closeNs+1000)

	feedIdentRow(t, el, closeRow(n, 0, closeNs))
	verifyProcFdNotCached(t, el, pid, n)
}

// An answer without a read time says nothing about when it was read, so a
// close of another file does not spare it: only an answer known to be later
// than the close survives.
func TestCloseOfAnotherFileForgetsACachedAnswerWithoutAReadTime(t *testing.T) {
	pid := uint32(os.Getpid())
	n := freeFdNumber(t)
	el := identLoop(t)
	answer := file.NewFd(n, "/data/cached.txt", syscall.O_RDWR)
	answer.SetIdent(4712)
	el.fdState().setProcFdCache(n, pid, answer)

	feedIdentRow(t, el, closeRow(n, 4711, bootClockNs()))
	verifyProcFdNotCached(t, el, pid, n)
}

// A flag change stores the entry it changed once more (storeFcntlFdFile, the
// FIOCLEX/FIONCLEX handler), which binds nothing: a fork's copy stays without
// a binding time, so a close in the child that entered before the fcntl
// returned still releases it.
func TestFlagChangeDoesNotBindAForkedCopy(t *testing.T) {
	const parent, child = absentPidBase + 7310, absentPidBase + 7311
	el := identLoop(t)
	tr := el.fdState()
	tr.bindNs = 5000
	opened := file.NewFd(5, "/data/inherited.txt", syscall.O_RDWR)
	opened.SetIdent(4711)
	tr.set(5, parent, opened)
	tr.inherit(parent, child)

	copied, _ := tr.get(5, child)
	tr.bindNs = 90000
	el.storeFcntlFdFile(&event.Pair{}, copied.(*file.FdFile), 5, child)
	if got := copied.(*file.FdFile).BoundAt(); got != 0 {
		t.Fatalf("forked copy bound at %d by a flag change, want 0", got)
	}
	tr.closeIdentified(5, child, 4711, 80000)
	if _, kept := tr.get(5, child); kept {
		t.Fatalf("a close of the copy's file left it in the child's table")
	}
}
