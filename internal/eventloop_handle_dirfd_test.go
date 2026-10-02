package internal

import (
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"ior/internal/file"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

// These tests cover the procfs mark of a name that was BUILT from a look at
// procfs (task 523): a call that opens a descriptor by a pathname resolved
// against a dirfd ior did not see being opened stores a name whose directory
// part - or, for an empty pathname, all of it - is the dirfd's /proc link as
// it was when the loop handled the exit. The fd table entry must say so
// (FdFile.NameFromProcFS), and a file handle taken through it must not be
// filed under that name.

// dirfdCall is one syscall that opens a descriptor by (dirfd, pathname).
type dirfdCall struct {
	name  string
	enter types.TraceId
	exit  types.TraceId
	// pathEvent says the enter record is a path event (fspick); the others
	// are open events.
	pathEvent bool
	// emptyFlag is the flag with which an empty pathname names the dirfd
	// itself; 0 for a call that has no such form.
	emptyFlag uint32
}

func dirfdCalls() []dirfdCall {
	return []dirfdCall{
		{name: "openat", enter: types.SYS_ENTER_OPENAT, exit: types.SYS_EXIT_OPENAT},
		{name: "openat2", enter: types.SYS_ENTER_OPENAT2, exit: types.SYS_EXIT_OPENAT2},
		{name: "open_tree", enter: types.SYS_ENTER_OPEN_TREE, exit: types.SYS_EXIT_OPEN_TREE,
			emptyFlag: unix.AT_EMPTY_PATH},
		{name: "open_tree_attr", enter: types.SYS_ENTER_OPEN_TREE_ATTR, exit: types.SYS_EXIT_OPEN_TREE_ATTR,
			emptyFlag: unix.AT_EMPTY_PATH},
		{name: "fspick", enter: types.SYS_ENTER_FSPICK, exit: types.SYS_EXIT_FSPICK,
			pathEvent: true, emptyFlag: unix.FSPICK_EMPTY_PATH},
	}
}

// pathnames returns the pathnames the call is tested with: one below the
// dirfd and, where the call has that form, the empty one.
func (c dirfdCall) pathnames() []string {
	if c.emptyFlag == 0 {
		return []string{"below.txt"}
	}
	return []string{"below.txt", ""}
}

// enterRecord builds the call's enter record for the feed's task.
func (c dirfdCall) enterRecord(f *handleFeed, dirfd int32, pathname string) []byte {
	f.t.Helper()
	var flags uint32
	if pathname == "" {
		flags = c.emptyFlag
	}
	if c.pathEvent {
		ev, _ := makeEnterPathEvent(f.t, f.time, f.pid, f.tid, pathname, c.enter)
		ev.Dirfd, ev.Flags = dirfd, flags
		return eventBytes(f.t, &ev)
	}
	ev, _ := makeEnterOpenEvent(f.t, f.time, f.pid, f.tid)
	ev.TraceId, ev.Dirfd, ev.Flags = c.enter, dirfd, int32(flags)
	ev.Filename = [types.MAX_FILENAME_LENGTH]byte{}
	copy(ev.Filename[:], pathname)
	return eventBytes(f.t, &ev)
}

// dirfdOpen feeds one successful call c(dirfd, pathname) that returned fd and
// returns the fd table entry it left; its row (a snapshot of the entry) must
// show the same name on the same descriptor.
func (f *handleFeed) dirfdOpen(c dirfdCall, dirfd int32, pathname string, fd int32) *file.FdFile {
	f.t.Helper()
	_, exit := makeExitRetEvent(f.t, f.time+100, f.pid, f.tid, c.exit, int64(fd))
	before := len(f.rows)
	f.consume(c.enterRecord(f, dirfd, pathname), exit)
	f.time += 1000
	if len(f.rows) != before+1 {
		f.t.Fatalf("%s emitted %d rows, want 1", c.name, len(f.rows)-before)
	}
	tracked, ok := f.el.fdState().get(fd, f.pid)
	fdFile, isFd := tracked.(*file.FdFile)
	if !ok || !isFd {
		f.t.Fatalf("fd table entry (pid=%d, fd=%d) = %v (ok=%v), want an FdFile", f.pid, fd, tracked, ok)
	}
	if row := f.rows[before].File; row.Name() != fdFile.Name() || row.FD() != fd {
		f.t.Fatalf("row file %v does not show the fd table entry %v", row, fdFile)
	}
	return fdFile
}

// assertEntry checks the name and the procfs mark of an fd table entry.
func assertEntry(t *testing.T, fdFile *file.FdFile, wantName string, wantMarked bool) {
	t.Helper()
	if got := fdFile.Name(); got != wantName {
		t.Fatalf("entry named %q, want %q", got, wantName)
	}
	if got := fdFile.NameFromProcFS(); got != wantMarked {
		t.Fatalf("entry %q: NameFromProcFS() = %v, want %v", wantName, got, wantMarked)
	}
}

// forEachDirfdCall runs fn once per call and pathname form.
func forEachDirfdCall(t *testing.T, fn func(t *testing.T, c dirfdCall, pathname string)) {
	t.Helper()
	for _, c := range dirfdCalls() {
		for _, pathname := range c.pathnames() {
			form := "a pathname below the dirfd"
			if pathname == "" {
				form = "the dirfd itself"
			}
			t.Run(c.name+"/"+form, func(t *testing.T) { fn(t, c, pathname) })
		}
	}
}

// procfsDirSource is one way the directory of such a call has a name that is
// a look at procfs. prepare makes descriptor decoy of the feed's (live)
// process that kind of dirfd and returns the dirfd to use.
type procfsDirSource struct {
	name    string
	prepare func(feed *handleFeed, decoy int32) int32
}

func procfsDirSources() []procfsDirSource {
	return []procfsDirSource{
		{"an untracked dirfd", func(_ *handleFeed, decoy int32) int32 { return decoy }},
		{"a table entry named from procfs", func(feed *handleFeed, decoy int32) int32 {
			feed.trackFromProcfs(decoy)
			return decoy
		}},
		{"a duplicate of a table entry named from procfs", func(feed *handleFeed, decoy int32) int32 {
			const dupFd = unopenedFd + 1
			feed.el.registerDup(feed.trackFromProcfs(decoy), feed.pid, dupFd, 0)
			feed.requireNamedEntry(dupFd)
			return dupFd
		}},
	}
}

// TestOpenBelowAProcfsNamedDirfdIsMarked: the directory is known from procfs
// only, read when the loop handles the exit, and here it is a decoy standing
// for the newer file under a reused number. The entry the call leaves is
// named after it - that is all a row can show - but carries the mark, and a
// handle taken through the entry files no name, whether the directory is the
// procfs answer itself or a table entry that was one.
func TestOpenBelowAProcfsNamedDirfdIsMarked(t *testing.T) {
	const openedFd = unopenedFd + 2
	for _, source := range procfsDirSources() {
		t.Run(source.name, func(t *testing.T) {
			forEachDirfdCall(t, func(t *testing.T, c dirfdCall, pathname string) {
				dir := t.TempDir()
				decoy := int32(openTestFd(t, dir, syscall.O_RDONLY|syscall.O_DIRECTORY))
				feed := newLiveHandleFeed(t)
				dirfd := source.prepare(feed, decoy)

				opened := feed.dirfdOpen(c, dirfd, pathname, openedFd)
				assertEntry(t, opened, filepath.Join(dir, pathname), true)
				feed.nameToHandleOfFd(openedFd, testHandleA)
				feed.nameToHandleUnder(openedFd, "deeper.txt", 0, testHandleB)
				assertNoHandleNames(t, feed)
			})
		})
	}
}

// TestOpenBelowAMarkedEntryStaysMarked: the mark is not lost one step
// further on either - a descriptor opened below an entry that was itself
// opened below a procfs-named dirfd.
func TestOpenBelowAMarkedEntryStaysMarked(t *testing.T) {
	const firstFd, secondFd = unopenedFd + 2, unopenedFd + 3
	forEachDirfdCall(t, func(t *testing.T, c dirfdCall, pathname string) {
		dir := t.TempDir()
		decoy := int32(openTestFd(t, dir, syscall.O_RDONLY|syscall.O_DIRECTORY))
		feed := newLiveHandleFeed(t)
		feed.dirfdOpen(dirfdCalls()[0], decoy, "sub", firstFd)

		second := feed.dirfdOpen(c, firstFd, pathname, secondFd)
		assertEntry(t, second, filepath.Join(dir, "sub", pathname), true)
		feed.nameToHandleOfFd(secondFd, testHandleA)
		assertNoHandleNames(t, feed)
	})
}

// TestOpenBelowAnUnresolvableDirfdIsMarked: procfs has no answer for the
// dirfd (the task is gone), so the entry is the bare pathname. It is not a
// path relative to the working directory, which is what an unmarked entry
// of that name would be taken for and filed as.
func TestOpenBelowAnUnresolvableDirfdIsMarked(t *testing.T) {
	for _, c := range dirfdCalls() {
		t.Run(c.name, func(t *testing.T) {
			feed := newHandleFeed(t, globalfilter.Filter{})
			opened := feed.dirfdOpen(c, 5, "below.txt", 70)
			assertEntry(t, opened, "below.txt", true)
			feed.nameToHandleOfFd(70, testHandleA)
			assertNoHandleNames(t, feed)
		})
	}
}

// TestOpenBelowATrackedDirfdIsNotMarked is the other side: a dirfd ior saw
// being opened has a traced name, so the entry is a traced name too and a
// handle taken through it is filed for every opener.
func TestOpenBelowATrackedDirfdIsNotMarked(t *testing.T) {
	forEachDirfdCall(t, func(t *testing.T, c dirfdCall, pathname string) {
		feed := newHandleFeed(t, globalfilter.Filter{})
		feed.el.fdState().set(5, feed.pid, file.NewFd(5, "/data/dir", syscall.O_RDONLY|syscall.O_DIRECTORY))
		want := filepath.Join("/data/dir", pathname)

		assertEntry(t, feed.dirfdOpen(c, 5, pathname, 70), want, false)
		feed.nameToHandleOfFd(70, testHandleA)
		feed.asOtherProcess()
		assertHandleRow(t, feed, feed.openByHandle(testHandleA, 71), 71, want)
	})
}

// TestOpenByTheCallersOwnPathnameIsNotMarked: an absolute pathname is the
// caller's and the dirfd is not looked at, whatever procfs would say about
// it; a pathname relative to the working directory has no dirfd at all.
// creat, which stores its name the same way as fspick, has no dirfd either.
func TestOpenByTheCallersOwnPathnameIsNotMarked(t *testing.T) {
	calls := append(dirfdCalls(), dirfdCall{name: "creat", enter: types.SYS_ENTER_CREAT,
		exit: types.SYS_EXIT_CREAT, pathEvent: true})
	for _, c := range calls {
		t.Run(c.name, func(t *testing.T) {
			decoy := int32(openTestFd(t, t.TempDir(), syscall.O_RDONLY|syscall.O_DIRECTORY))
			feed := newLiveHandleFeed(t)

			assertEntry(t, feed.dirfdOpen(c, decoy, "/data/abs.txt", unopenedFd), "/data/abs.txt", false)
			assertEntry(t, feed.dirfdOpen(c, unix.AT_FDCWD, "rel.txt", unopenedFd+1), "rel.txt", false)
			feed.nameToHandleOfFd(unopenedFd, testHandleA)
			feed.nameToHandleOfFd(unopenedFd+1, testHandleB)
			assertHandleRow(t, feed, feed.openByHandle(testHandleA, unopenedFd+2), unopenedFd+2, "/data/abs.txt")
			assertHandleRow(t, feed, feed.openByHandle(testHandleB, unopenedFd+3), unopenedFd+3, "rel.txt")
		})
	}
}
