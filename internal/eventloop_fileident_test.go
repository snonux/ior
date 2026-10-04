package internal

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/globalfilter"
	"ior/internal/types"

	"golang.org/x/sys/unix"
)

// Task 603: a single-descriptor record says which file its descriptor named
// when the call entered, and a name is only given to the row when it belongs
// to that file (eventloop_fileident.go).
//
// Like the jr2 and ir2 tests these use this process's real pid and
// descriptors, so every procfs read and stat is genuine: the file placed on a
// number stands for what the traced process has there when the event loop
// gets to look, and the identity a row is fed with stands for what the kernel
// saw when the call entered - the same file, or the one that was there
// before.

// identLoop returns an event loop of a run whose BPF object captures file
// identities, with procfs read times on the records' clock whatever the
// test host's time namespace (the tests that need it otherwise say so).
func identLoop(t *testing.T) *eventLoop {
	t.Helper()
	el := newFilteredEventLoop(t, globalfilter.Filter{})
	el.trustFileIdents(true)
	el.fdState().readClockUnknown = false
	return el
}

// placeFileOn creates a file called name and makes fd n name it, without any
// traced syscall. It returns the name procfs gives the descriptor and the
// file's identity.
func placeFileOn(t *testing.T, n int32, name string) (string, uint32) {
	t.Helper()
	f, err := os.Create(filepath.Join(t.TempDir(), name))
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	defer func() { _ = f.Close() }()
	if err := unix.Dup3(int(f.Fd()), int(n), unix.O_CLOEXEC); err != nil {
		t.Fatalf("dup3 onto %d: %v", n, err)
	}
	t.Cleanup(func() { _ = unix.Close(int(n)) })
	return procNameAndIdent(t, n)
}

// procNameAndIdent returns what procfs calls this process's descriptor n and
// the identity of the file behind it.
func procNameAndIdent(t *testing.T, n int32) (string, uint32) {
	t.Helper()
	link := "/proc/self/fd/" + strconv.Itoa(int(n))
	name, err := os.Readlink(link)
	if err != nil {
		t.Fatalf("readlink %s: %v", link, err)
	}
	var st syscall.Stat_t
	if err := syscall.Stat(link, &st); err != nil {
		t.Fatalf("stat %s: %v", link, err)
	}
	ident := file.IdentOfInode(st.Ino)
	if ident == 0 {
		t.Skipf("inode %d of %s has a zero low word: it has no identity", st.Ino, name)
	}
	return name, ident
}

// identRow is one single-descriptor syscall of this process as the kernel
// reports it: the descriptor, the identity of the file it named at enterNs,
// and the return value.
type identRow struct {
	enter, exit types.TraceId
	fd          int32
	ident       uint32
	enterNs     uint64
	ret         int64
	// exitNs is when the call returned; 0 means openPairLatency after the
	// enter. A call that blocked sets it.
	exitNs uint64
}

func readRow(fd int32, ident uint32) identRow {
	return identRow{enter: types.SYS_ENTER_READ, exit: types.SYS_EXIT_READ, fd: fd, ident: ident, enterNs: bootClockNs(), ret: 1}
}

func closeRow(fd int32, ident uint32, enterNs uint64) identRow {
	return identRow{enter: types.SYS_ENTER_CLOSE, exit: types.SYS_EXIT_CLOSE, fd: fd, ident: ident, enterNs: enterNs}
}

// feedIdentRow feeds row as the lean 32-byte fd record the kernel writes, the
// only fd layout with an identity word, and its exit.
func feedIdentRow(t *testing.T, el *eventLoop, row identRow) *event.Pair {
	t.Helper()
	pid := uint32(os.Getpid())
	enter := types.FdEvent{EventType: types.ENTER_FD_EVENT, TraceId: row.enter, Time: row.enterNs,
		Pid: pid, Tid: execCommTid, Fd: row.fd, FileIdent: row.ident}
	enterRaw, err := enter.Bytes()
	if err != nil {
		t.Fatalf("FdEvent.Bytes: %v", err)
	}
	exitNs := row.exitNs
	if exitNs == 0 {
		exitNs = row.enterNs + openPairLatency
	}
	_, exitRaw := makeExitRetEvent(t, exitNs, pid, execCommTid, row.exit, row.ret)
	return mustEmit(t, feedRawPair(t, el, enterRaw, exitRaw), row.enter.Name())
}

// feedIdentOpen feeds an openat of pathname by this process that returned fd
// and whose exit record identifies the opened file as ident. It is an early
// call: every row built with bootClockNs entered long after it returned.
func feedIdentOpen(t *testing.T, el *eventLoop, pathname string, fd int32, ident uint32) {
	t.Helper()
	feedIdentOpenAt(t, el, pathname, fd, ident, defaulTime)
}

// feedIdentOpenAt is feedIdentOpen for an openat that entered at enterNs and
// returned openPairLatency later, which is when its number is bound.
func feedIdentOpenAt(t *testing.T, el *eventLoop, pathname string, fd int32, ident uint32, enterNs uint64) {
	t.Helper()
	pid := uint32(os.Getpid())
	enter := types.OpenEvent{EventType: types.ENTER_OPEN_EVENT, TraceId: types.SYS_ENTER_OPENAT, Time: enterNs,
		Pid: pid, Tid: execCommTid, Dirfd: defaultDirfd, Flags: syscall.O_RDWR, SchemaVersion: types.OPEN_EVENT_SCHEMA_VERSION}
	copy(enter.Filename[:], pathname)
	copy(enter.Comm[:], "ioworkload")
	enterRaw, err := enter.Bytes()
	if err != nil {
		t.Fatalf("OpenEvent.Bytes: %v", err)
	}
	exitRaw := identExit(t, types.SYS_EXIT_OPENAT, enterNs+openPairLatency, pid, fd, ident)
	mustEmit(t, feedRawPair(t, el, enterRaw, exitRaw), "openat")
}

// identExit builds the exit record of a call by execCommTid of pid that
// returned the descriptor fd at exitNs and identifies the file as ident.
func identExit(t *testing.T, trace types.TraceId, exitNs uint64, pid uint32, fd int32, ident uint32) []byte {
	t.Helper()
	exit := types.RetEvent{EventType: types.EXIT_RET_EVENT, TraceId: trace, Time: exitNs,
		Ret: int64(fd), Pid: pid, Tid: execCommTid, FileIdent: ident}
	raw, err := exit.Bytes()
	if err != nil {
		t.Fatalf("RetEvent.Bytes: %v", err)
	}
	return raw
}

// requireUnnamedOf fails unless f is the unnamed file of a row whose
// descriptor named the file ident: no name, unknown flags, that identity.
func requireUnnamedOf(t *testing.T, f file.File, ident uint32) {
	t.Helper()
	fdf, ok := f.(*file.FdFile)
	if !ok || fdf.Name() != "" || fdf.Flags() != file.Flags(-1) || fdf.Ident() != ident {
		t.Fatalf("row file = %v (ident %#x), want no name, unknown flags and identity %#x", f, identOf(f), ident)
	}
}

func identOf(f file.File) uint32 {
	if fdf, ok := f.(*file.FdFile); ok && fdf != nil {
		return fdf.Ident()
	}
	return 0
}

const staleOpenName = "/data/opened-first.txt"

// The task's live case: an open ior traced registered the number, something
// the trace cannot see (io_uring's IORING_OP_CLOSE and IORING_OP_OPENAT)
// closed it and put another file there, and the reads that follow carry that
// other file's identity. They must be named after it, not after the open.
func TestRowOnAReboundDescriptorIsNotNamedAfterTheTracedOpen(t *testing.T) {
	pid := uint32(os.Getpid())
	n := freeFdNumber(t)
	el := identLoop(t)
	reopened, reopenedIdent := placeFileOn(t, n, "reopened.txt")
	feedIdentOpen(t, el, staleOpenName, n, reopenedIdent+1)
	verifyFileDescriptor(t, el, pid, n, staleOpenName)

	first := feedIdentRow(t, el, readRow(n, reopenedIdent))
	if got := first.File.Name(); got != reopened {
		t.Fatalf("read after the invisible reopen named %q, want %q", got, reopened)
	}
	verifyFdNotTracked(t, el, pid, n)
	if el.fdState().staleBindings != 1 {
		t.Fatalf("staleBindings = %d, want 1", el.fdState().staleBindings)
	}

	// The answer is cached with its identity and serves the next row.
	second := feedIdentRow(t, el, readRow(n, reopenedIdent))
	if got := second.File.Name(); got != reopened || el.fdState().staleBindings != 1 {
		t.Fatalf("second read named %q with %d stale bindings, want %q and still 1", got, el.fdState().staleBindings, reopened)
	}
}

// The control for the test above, and the compatibility rule: a run that does
// not capture identities (an older BPF object leaves stale padding where the
// word is) must not read it. The row keeps the traced name, as before.
func TestIdentityWordIsIgnoredWhenTheRunDoesNotCaptureIt(t *testing.T) {
	pid := uint32(os.Getpid())
	n := freeFdNumber(t)
	el := newFilteredEventLoop(t, globalfilter.Filter{})
	_, otherIdent := placeFileOn(t, n, "other.txt")
	feedIdentOpen(t, el, staleOpenName, n, otherIdent+1)

	ep := feedIdentRow(t, el, readRow(n, otherIdent))
	if got := ep.File.Name(); got != staleOpenName {
		t.Fatalf("read named %q, want the traced %q: the identity word was read", got, staleOpenName)
	}
	verifyFileDescriptor(t, el, pid, n, staleOpenName)
	if identOf(ep.File) != 0 || el.fdState().staleBindings != 0 {
		t.Fatalf("ident=%#x staleBindings=%d, want neither", identOf(ep.File), el.fdState().staleBindings)
	}
}

// A row on the file the entry stands for keeps the traced name, whatever the
// number names in procfs.
func TestRowOnTheTrackedFileKeepsItsTracedName(t *testing.T) {
	pid := uint32(os.Getpid())
	n := freeFdNumber(t)
	el := identLoop(t)
	_, ident := placeFileOn(t, n, "same.txt")
	feedIdentOpen(t, el, staleOpenName, n, ident)

	ep := feedIdentRow(t, el, readRow(n, ident))
	if got := ep.File.Name(); got != staleOpenName {
		t.Fatalf("read named %q, want the traced %q", got, staleOpenName)
	}
	verifyFileDescriptor(t, el, pid, n, staleOpenName)
	if el.fdState().staleBindings != 0 || el.fdState().rejectedAnswers != 0 {
		t.Fatalf("a matching row was counted: %+v", el.fdState())
	}
}

// An entry whose creating call reported no identity takes the one of the
// first row that uses it; from then on a row of another file is a stale
// binding like any other.
func TestEntryWithoutAnIdentityTakesTheFirstRows(t *testing.T) {
	pid := uint32(os.Getpid())
	n := freeFdNumber(t)
	el := identLoop(t)
	reopened, ident := placeFileOn(t, n, "later.txt")
	feedIdentOpen(t, el, staleOpenName, n, 0)

	first := feedIdentRow(t, el, readRow(n, ident+1))
	if got := first.File.Name(); got != staleOpenName {
		t.Fatalf("first read named %q, want the traced %q", got, staleOpenName)
	}
	tracked, _ := el.fdState().get(n, pid)
	if identOf(tracked) != ident+1 {
		t.Fatalf("entry identity = %#x, want the first row's %#x", identOf(tracked), ident+1)
	}

	second := feedIdentRow(t, el, readRow(n, ident))
	if got := second.File.Name(); got != reopened {
		t.Fatalf("read of another file named %q, want %q", got, reopened)
	}
	verifyFdNotTracked(t, el, pid, n)
}

// A row without an identity (a kernel that cannot capture it, a record
// without the word) contradicts nothing and is named as before.
func TestRowWithoutAnIdentityIsResolvedAsBefore(t *testing.T) {
	pid := uint32(os.Getpid())
	n := freeFdNumber(t)
	el := identLoop(t)
	_, ident := placeFileOn(t, n, "whatever.txt")
	feedIdentOpen(t, el, staleOpenName, n, ident+1)

	ep := feedIdentRow(t, el, readRow(n, 0))
	if got := ep.File.Name(); got != staleOpenName {
		t.Fatalf("read named %q, want the traced %q", got, staleOpenName)
	}
	verifyFileDescriptor(t, el, pid, n, staleOpenName)
}

// Task yz2: a row on an untracked descriptor is processed after the program
// closed it and reused the number. procfs names the reuser; the row must not
// take that name, but the answer is kept for the rows of the reuser.
func TestProcfsAnswerForAnotherFileIsNotGivenToTheRow(t *testing.T) {
	pid := uint32(os.Getpid())
	n := freeFdNumber(t)
	el := identLoop(t)
	enterNs := bootClockNs()
	reuser := placePipeOn(t, n)
	_, reuserIdent := procNameAndIdent(t, n)
	closedIdent := reuserIdent + 1

	early := identRow{enter: types.SYS_ENTER_WRITE, exit: types.SYS_EXIT_WRITE, fd: n, ident: closedIdent, enterNs: enterNs, ret: 1}
	requireUnnamedOf(t, feedIdentRow(t, el, early).File, closedIdent)
	cached, ok := el.fdState().cachedProcFdFile(n, pid)
	if !ok || cached.Name() != reuser || cached.Ident() != reuserIdent {
		t.Fatalf("cache = %v (ok=%v), want the reuser %q with identity %#x", cached, ok, reuser, reuserIdent)
	}
	if el.fdState().rejectedAnswers != 1 {
		t.Fatalf("rejectedAnswers = %d, want 1", el.fdState().rejectedAnswers)
	}

	// A row of the reuser gets the cached answer itself.
	if got := feedIdentRow(t, el, readRow(n, reuserIdent)).File; got.Name() != reuser {
		t.Fatalf("row of the reuser named %q, want %q", got.Name(), reuser)
	}
}

// A second row of the closed file finds the reuser's answer in the cache,
// read after its own call entered: procfs can only be later still, so the row
// stays unnamed without another read, and the entry stays.
func TestRowOlderThanTheCachedAnswerDoesNotReadProcfsAgain(t *testing.T) {
	pid := uint32(os.Getpid())
	n := freeFdNumber(t)
	el := identLoop(t)
	enterNs := bootClockNs()
	reuser := placePipeOn(t, n)
	_, reuserIdent := procNameAndIdent(t, n)
	feedIdentRow(t, el, readRow(n, reuserIdent))
	cached, _ := el.fdState().cachedProcFdFile(n, pid)

	// Another file takes the number: a re-read would replace the entry.
	placeFileOn(t, n, "third.txt")
	old := identRow{enter: types.SYS_ENTER_WRITE, exit: types.SYS_EXIT_WRITE, fd: n, ident: reuserIdent + 1, enterNs: enterNs, ret: 1}
	requireUnnamedOf(t, feedIdentRow(t, el, old).File, reuserIdent+1)
	if now, ok := el.fdState().cachedProcFdFile(n, pid); !ok || now != cached || now.Name() != reuser {
		t.Fatalf("cache entry replaced by %v (ok=%v), want the reuser's answer kept", now, ok)
	}
}

// The other order: the cached answer was read before the row's call entered
// and describes another file, so it is the stale one. procfs is read again
// and the row is named after what the number holds now.
func TestCachedAnswerOlderThanTheRowIsReadAgain(t *testing.T) {
	pid := uint32(os.Getpid())
	n := freeFdNumber(t)
	el := identLoop(t)
	_, firstIdent := placeFileOn(t, n, "first.txt")
	feedIdentRow(t, el, readRow(n, firstIdent))

	second, secondIdent := placeFileOn(t, n, "second.txt")
	ep := feedIdentRow(t, el, readRow(n, secondIdent))
	if got := ep.File.Name(); got != second {
		t.Fatalf("read after the invisible rebind named %q, want %q", got, second)
	}
	if cached, ok := el.fdState().cachedProcFdFile(n, pid); !ok || cached.Ident() != secondIdent {
		t.Fatalf("cache = %v (ok=%v), want the new file with identity %#x", cached, ok, secondIdent)
	}
	if el.fdState().rejectedAnswers != 0 {
		t.Fatalf("rejectedAnswers = %d, want 0: the row was named", el.fdState().rejectedAnswers)
	}
}

// The stale answer goes even when the new read finds nothing (the number is
// closed by now): left in place it would name the next row that has no
// identity to refuse it with.
func TestStaleCachedAnswerIsDroppedWhenProcfsHasNoneNow(t *testing.T) {
	pid := uint32(os.Getpid())
	n := freeFdNumber(t)
	el := identLoop(t)
	cacheAnswer(el, n, "/data/cached.txt", 4711, bootClockNs())

	requireUnnamedOf(t, feedIdentRow(t, el, readRow(n, 4712)).File, 4712)
	verifyProcFdNotCached(t, el, pid, n)
}

// A cached answer that could not be told which file it describes (its fdinfo
// had no inode number, or its name changed while it was read) is used as
// before: an unknown identity contradicts nothing.
func TestCachedAnswerOfUnknownIdentityIsUsed(t *testing.T) {
	n := freeFdNumber(t)
	el := identLoop(t)
	placePipeOn(t, n) // a re-read would name the row after this
	cacheAnswer(el, n, "/data/cached.txt", 0, bootClockNs())

	if got := feedIdentRow(t, el, readRow(n, 4711)).File.Name(); got != "/data/cached.txt" {
		t.Fatalf("row named %q, want the cached answer of unknown identity", got)
	}
}

// Task as2's shape: the descriptor is gone when the row is processed (the
// process exited, or closed it). The row has no name but keeps its identity,
// which tells it from a descriptor that was never usable; nothing is cached.
func TestRowOfAVanishedDescriptorKeepsItsIdentity(t *testing.T) {
	pid := uint32(os.Getpid())
	n := freeFdNumber(t)
	el := identLoop(t)

	requireUnnamedOf(t, feedIdentRow(t, el, readRow(n, 4711)).File, 4711)
	verifyProcFdNotCached(t, el, pid, n)
}

// A known identity means the descriptor was open when the call entered, so an
// EBADF return is the call's own (a read on a write-only descriptor) and the
// row is named. Without an identity EBADF still means "no such descriptor".
func TestEBADFOnAnOpenDescriptorIsNamed(t *testing.T) {
	n := freeFdNumber(t)
	name, ident := placeFileOn(t, n, "writeonly.txt")
	ebadf := func(ident uint32) identRow {
		row := readRow(n, ident)
		row.ret = -int64(syscall.EBADF)
		return row
	}

	if got := feedIdentRow(t, identLoop(t), ebadf(ident)).File.Name(); got != name {
		t.Fatalf("EBADF read on an open descriptor named %q, want %q", got, name)
	}
	if got := feedIdentRow(t, identLoop(t), ebadf(0)).File.Name(); got != "" {
		t.Fatalf("EBADF read without an identity named %q, want no name", got)
	}
}

// cacheAnswer stores a procfs answer for this process's descriptor n that
// describes the file ident and was read at readNs.
func cacheAnswer(el *eventLoop, n int32, name string, ident uint32, readNs uint64) {
	answer := file.NewFd(n, name, syscall.O_RDWR)
	answer.SetIdent(ident)
	el.fdState().setProcFdCacheRead(n, uint32(os.Getpid()), answer, readNs)
}

// Close rows never read procfs and use a cached answer only if it was read
// before the close began (task jr2). The identity can only take an answer
// away: one that describes another file is refused whenever it was read, and
// an equal identity does not make a late answer usable - it may be of the
// file that took the number since (every eventfd and epoll descriptor has the
// same inode). A refused answer of another file is counted, and it survives
// the close when it was read after the close began: it describes the reuser.
func TestCloseRowUsesACachedAnswerOnlyIfReadBeforeAndNotOfAnotherFile(t *testing.T) {
	const closedIdent = 4711
	closeNs := bootClockNs()
	tests := []struct {
		name                            string
		ident                           uint32
		readNs                          uint64
		wantNamed, wantKept, wantRefuse bool
	}{
		{name: "same file, read before the close entered", ident: closedIdent, readNs: closeNs - 1000, wantNamed: true},
		{name: "same file, read after the close entered", ident: closedIdent, readNs: closeNs + 1000},
		{name: "another file, read before the close entered", ident: closedIdent + 1, readNs: closeNs - 1000, wantRefuse: true},
		{name: "another file, read after the close entered", ident: closedIdent + 1, readNs: closeNs + 1000,
			wantKept: true, wantRefuse: true},
		{name: "unknown file, read before the close entered", readNs: closeNs - 1000, wantNamed: true},
		{name: "unknown file, read after the close entered", readNs: closeNs + 1000},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			n := freeFdNumber(t)
			el := identLoop(t)
			cacheAnswer(el, n, "/data/cached.txt", tc.ident, tc.readNs)

			ep := feedIdentRow(t, el, closeRow(n, closedIdent, closeNs))
			if named := ep.File.Name() == "/data/cached.txt"; named != tc.wantNamed {
				t.Fatalf("close row file = %v, want named=%v", ep.File, tc.wantNamed)
			}
			if !tc.wantNamed {
				requireUnnamedOf(t, ep.File, closedIdent)
			}
			if _, kept := el.fdState().cachedProcFdFile(n, uint32(os.Getpid())); kept != tc.wantKept {
				t.Fatalf("cached answer kept = %v after the close, want %v", kept, tc.wantKept)
			}
			if refused := el.fdState().rejectedAnswers == 1; refused != tc.wantRefuse || el.fdState().rejectedAnswers > 1 {
				t.Fatalf("rejectedAnswers = %d, want refused=%v", el.fdState().rejectedAnswers, tc.wantRefuse)
			}
		})
	}
}

// A close through a stale binding: the entry is of another file, so the row
// is not named after it, and the number is released either way.
func TestCloseRowOnAReboundDescriptorIsNotNamedAfterTheTracedOpen(t *testing.T) {
	pid := uint32(os.Getpid())
	n := freeFdNumber(t)
	el := identLoop(t)
	placePipeOn(t, n) // a procfs read would name the row after this
	feedIdentOpen(t, el, staleOpenName, n, 4711)

	requireUnnamedOf(t, feedIdentRow(t, el, closeRow(n, 4712, bootClockNs())).File, 4712)
	verifyFdNotTracked(t, el, pid, n)
	verifyProcFdNotCached(t, el, pid, n)

	// The same close on the file the entry stands for is named.
	feedIdentOpen(t, el, staleOpenName, n, 4711)
	if got := feedIdentRow(t, el, closeRow(n, 4711, bootClockNs())).File.Name(); got != staleOpenName {
		t.Fatalf("close of the tracked file named %q, want %q", got, staleOpenName)
	}
}

// A duplicate is the same file: the entry dup registers carries the source's
// identity, so a row on the new number is checked like one on the old.
func TestDuplicatedDescriptorKeepsTheIdentity(t *testing.T) {
	pid := uint32(os.Getpid())
	n := freeFdNumber(t)
	el := identLoop(t)
	feedIdentOpen(t, el, staleOpenName, n, 4711)
	source, _ := el.fdState().get(n, pid)
	el.registerDup(source.(*file.FdFile), pid, n+1, 0)

	dup, ok := el.fdState().get(n+1, pid)
	if !ok || identOf(dup) != 4711 {
		t.Fatalf("duplicate = %v (ok=%v), want identity 4711", dup, ok)
	}
	requireUnnamedOf(t, feedIdentRow(t, el, readRow(n+1, 4712)).File, 4712)
	verifyFdNotTracked(t, el, pid, n+1)
	verifyFileDescriptor(t, el, pid, n, staleOpenName)
}

func TestFileIdentStatLine(t *testing.T) {
	el := identLoop(t)
	if got := el.fileIdentStatLine(); got != "" {
		t.Fatalf("stat line of a run without findings = %q, want none", got)
	}
	el.fdState().staleBindings, el.fdState().rejectedAnswers = 3, 5
	got := el.fileIdentStatLine()
	if !strings.Contains(got, "3 stale fd bindings dropped") || !strings.Contains(got, "5 rows refused a procfs answer for another file") {
		t.Fatalf("stat line = %q, want both counts", got)
	}
}
