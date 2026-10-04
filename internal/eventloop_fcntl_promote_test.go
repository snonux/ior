package internal

import (
	"os"
	"syscall"
	"testing"

	"ior/internal/file"
	"ior/internal/types"
)

// Task a23: an fcntl or ioctl FIOCLEX/FIONCLEX on a descriptor known only to
// the procfs cache no longer promotes the answer into the fd table
// (storeFcntlFdFile). The answer was read when the loop got to the row and
// may be of the file that reused the number; the fcntl_event record has no
// identity word to check that. In the table it passed for a traced binding:
// a dup copied it to another number, and the next row of the file really
// behind the number dropped it as a "stale fd binding".

const laggingAnswerName = "/data/lagging-answer.txt"

// feedFcntlSetfdOf feeds a successful fcntl(fd, F_SETFD, FD_CLOEXEC) of this
// process that entered at enterNs and returns its row.
func feedFcntlSetfdOf(t *testing.T, el *eventLoop, fd int32, enterNs uint64) string {
	t.Helper()
	pid := uint32(os.Getpid())
	_, enterRaw := makeEnterFcntlEvent(t, enterNs, pid, execCommTid, uint32(fd), syscall.F_SETFD, syscall.FD_CLOEXEC)
	_, exitRaw := makeExitRetEvent(t, enterNs+openPairLatency, pid, execCommTid, types.SYS_EXIT_FCNTL, 0)
	return mustEmit(t, feedRawPair(t, el, enterRaw, exitRaw), "fcntl").File.Name()
}

// feedDup3Of feeds a successful dup3(fd, newFd, 0) of this process that
// entered at enterNs.
func feedDup3Of(t *testing.T, el *eventLoop, fd, newFd int32, enterNs uint64) {
	t.Helper()
	pid := uint32(os.Getpid())
	_, enterRaw := makeEnterDup3Event(t, enterNs, pid, execCommTid, fd, 0)
	_, exitRaw := makeExitRetEvent(t, enterNs+openPairLatency, pid, execCommTid, types.SYS_EXIT_DUP3, int64(newFd))
	mustEmit(t, feedRawPair(t, el, enterRaw, exitRaw), "dup3")
}

// The live shape: a cached answer of file X (read before the number was
// closed and reused for file Y by something the trace does not see), then an
// fcntl on the number, then a read of Y. The fcntl row is named after the
// answer as before - it has no identity to refuse it with - but the answer
// stays a cache entry with the new flag, so the read of Y only replaces it
// (procfs is read again and names the row) and no stale binding is counted.
func TestFcntlOnALaggingAnswerIsNotPromotedIntoTheTable(t *testing.T) {
	pid := uint32(os.Getpid())
	n := freeFdNumber(t)
	el := identLoop(t)
	cacheAnswer(el, n, laggingAnswerName, 4711, bootClockNs())
	name, ident := placeFileOn(t, n, "reused.txt")

	if got := feedFcntlSetfdOf(t, el, n, bootClockNs()); got != laggingAnswerName {
		t.Fatalf("fcntl row named %q, want the cached answer %q", got, laggingAnswerName)
	}
	verifyFdNotTracked(t, el, pid, n)
	cached, ok := el.fdState().cachedProcFdFile(n, pid)
	if set, known := cached.CloseOnExec(); !ok || !set || !known {
		t.Fatalf("cached answer = %v (ok=%v), want it kept with close-on-exec set", cached, ok)
	}

	if got := feedIdentRow(t, el, readRow(n, ident)).File.Name(); got != name {
		t.Fatalf("read of the file behind the number named %q, want %q", got, name)
	}
	requireNothingCounted(t, el)
}

// A dup3 of that descriptor copies nothing: the source is not a table entry
// (registerDup), so the new number is forgotten and resolved from procfs on
// its own first use, not bound to the lagging name for its whole life.
func TestDupOfAFcntlChangedAnswerIsNotCopied(t *testing.T) {
	pid := uint32(os.Getpid())
	n := freeFdNumber(t)
	el := identLoop(t)
	cacheAnswer(el, n, laggingAnswerName, 4711, bootClockNs())
	feedFcntlSetfdOf(t, el, n, bootClockNs())

	target := n + 1
	el.fdState().set(target, pid, file.NewFd(target, "/data/old-target.txt", syscall.O_RDONLY))
	feedDup3Of(t, el, n, target, bootClockNs())
	verifyFdNotTracked(t, el, pid, target)
	verifyProcFdNotCached(t, el, pid, target)
}

// The other side: an fcntl on a table entry stores it again, and a dup3 of a
// table entry whose name ior cannot vouch for (here: what an open_by_handle_at
// of an unknown handle stores) copies it with the mark and the identity, so
// the copy is no more trusted than its source (FdFile.Dup).
func TestDupOfAMarkedTableEntryKeepsTheMark(t *testing.T) {
	pid := uint32(os.Getpid())
	n := freeFdNumber(t)
	el := identLoop(t)
	marked := file.NewFd(n, laggingAnswerName, syscall.O_RDWR)
	marked.MarkNameFromProcFS()
	marked.SetIdent(4711)
	el.fdState().set(n, pid, marked)

	feedFcntlSetfdOf(t, el, n, bootClockNs())
	if !el.fdState().tracksExactly(n, pid, marked) {
		t.Fatal("fcntl on a table entry took it out of the table")
	}
	feedDup3Of(t, el, n, n+1, bootClockNs())
	copied, ok := el.fdState().get(n+1, pid)
	fdCopy, isFd := copied.(*file.FdFile)
	if !ok || !isFd || fdCopy.Name() != laggingAnswerName || !fdCopy.NameFromProcFS() || fdCopy.Ident() != 4711 {
		t.Fatalf("dup3 copy = %v (ok=%v), want the marked name with identity 4711", copied, ok)
	}
	if set, known := fdCopy.CloseOnExec(); set || !known {
		t.Fatalf("dup3 copy close-on-exec = (%v, %v), want known clear", set, known)
	}
}
