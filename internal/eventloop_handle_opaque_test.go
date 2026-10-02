package internal

import (
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"ior/internal/file"
	"ior/internal/types"
)

// These tests cover a stash ior cannot compare with any descriptor (task m03):
// a relative path, a traced name that is not a link text, the directory an
// O_TMPFILE descriptor is tracked under. Such a stash contradicts every
// descriptor, its own included, so a contradiction says nothing about which
// handle was opened; it used to stay in the slot and name a later, unrelated
// open_by_handle_at of the thread.

// trackAs registers fd in the feed's fd table under name, as the exit handler
// of the syscall that created it would.
func (f *handleFeed) trackAs(fd int, name string, flags int32) {
	f.t.Helper()
	f.el.fdState().set(int32(fd), f.pid, file.NewFd(int32(fd), name, flags))
}

// nameToHandleUnder feeds a successful name_to_handle_at(dirfd, pathname, 0)
// with a relative pathname, which is resolved against the descriptor.
func (f *handleFeed) nameToHandleUnder(dirfd int, pathname string) {
	f.t.Helper()
	ev, _ := makeEnterPathEvent(f.t, f.time, f.pid, f.pid, pathname, types.SYS_ENTER_NAME_TO_HANDLE_AT)
	ev.Dirfd = int32(dirfd)
	ev.PathnameStatus = types.PATH_READ_OK
	ev.TargetStatus = types.PATH_TARGET_REQUIRED
	enter, err := ev.Bytes()
	if err != nil {
		f.t.Fatal(err)
	}
	_, exit := makeExitRetEvent(f.t, f.time+1, f.pid, f.pid, types.SYS_EXIT_NAME_TO_HANDLE_AT, 0)
	f.time += 10
	f.el.processRawEvent(enter, f.out)
	f.el.processRawEvent(exit, f.out)
}

// feedPair runs one syscall's enter and exit records through the loop and
// drops the row it emits, so that the next openByHandle reads its own row.
func (f *handleFeed) feedPair(enter, exit []byte) {
	f.t.Helper()
	f.time += 10
	f.el.processRawEvent(enter, f.out)
	f.el.processRawEvent(exit, f.out)
	for len(f.out) > 0 {
		<-f.out
	}
}

// open feeds a successful openat(AT_FDCWD, path, flags) that returned fd, so
// the fd table entry is the one handleOpenExit builds for a traced open - for
// an O_TMPFILE open, named after the directory and marked so.
func (f *handleFeed) open(fd int, path string, flags int32) {
	f.t.Helper()
	enterEv, _ := makeEnterOpenEvent(f.t, f.time, f.pid, f.pid)
	enterEv.Flags = flags
	enterEv.Filename = [types.MAX_FILENAME_LENGTH]byte{}
	copy(enterEv.Filename[:], path)
	exitEv, _ := makeExitOpenEvent(f.t, f.time+1, f.pid, f.pid)
	exitEv.Ret = int64(fd)
	enter, enterErr := enterEv.Bytes()
	exit, exitErr := exitEv.Bytes()
	if enterErr != nil || exitErr != nil {
		f.t.Fatalf("encode open events: %v, %v", enterErr, exitErr)
	}
	f.feedPair(enter, exit)
}

// dup feeds a successful dup(fd) that returned newFd.
func (f *handleFeed) dup(fd, newFd int) {
	f.t.Helper()
	_, enter := makeEnterFdEvent(f.t, f.time, f.pid, f.pid, int32(fd), types.SYS_ENTER_DUP)
	_, exit := makeExitRetEvent(f.t, f.time+1, f.pid, f.pid, types.SYS_EXIT_DUP, int64(newFd))
	f.feedPair(enter, exit)
}

// promoteByFcntl feeds the fcntl(fd, F_GETFL) glibc's fdopen issues, with the
// word the kernel really returns. On a descriptor ior did not see opened that
// stores the procfs-resolved file in the fd table (storeFcntlFdFile): named by
// its link, with the fdinfo flags. It returns that entry.
func (f *handleFeed) promoteByFcntl(fd int) *file.FdFile {
	f.t.Helper()
	word, err := unix.FcntlInt(uintptr(fd), syscall.F_GETFL, 0)
	if err != nil {
		f.t.Fatalf("F_GETFL: %v", err)
	}
	_, enter := makeEnterFcntlEvent(f.t, f.time, f.pid, f.pid, uint32(fd), syscall.F_GETFL, 0)
	_, exit := makeExitRetEvent(f.t, f.time+1, f.pid, f.pid, types.SYS_EXIT_FCNTL, int64(word))
	f.feedPair(enter, exit)
	tracked, ok := f.el.fdState().get(int32(fd), f.pid)
	promoted, isFd := tracked.(*file.FdFile)
	if !ok || !isFd {
		f.t.Fatalf("fcntl did not promote descriptor %d into the fd table (%v, %v)", fd, tracked, ok)
	}
	return promoted
}

// linkatEmptyPath feeds a successful linkat(fd, "", AT_FDCWD, newpath,
// AT_EMPTY_PATH), the call that gives an O_TMPFILE file its name.
func (f *handleFeed) linkatEmptyPath(fd int, newpath string) {
	f.t.Helper()
	ev, _ := makeEnterNameEvent(f.t, f.time, f.pid, f.pid, "", newpath, types.SYS_ENTER_LINKAT)
	ev.Olddirfd = int32(fd)
	ev.OldnameStatus = types.PATH_READ_OK
	ev.NewnameStatus = types.PATH_READ_OK
	ev.Flags = unix.AT_EMPTY_PATH
	enter, err := ev.Bytes()
	if err != nil {
		f.t.Fatal(err)
	}
	_, exit := makeExitRetEvent(f.t, f.time+1, f.pid, f.pid, types.SYS_EXIT_LINKAT, 0)
	f.feedPair(enter, exit)
}

// assertStash checks what the thread's slot holds.
func assertStash(t *testing.T, feed *handleFeed, want string) {
	t.Helper()
	if got, ok := feed.el.pendingHandleState().peek(feed.pid); !ok || got != want {
		t.Fatalf("stash = %q (ok=%v), want %q", got, ok, want)
	}
}

// dirOpenFlags are the flags openReusingDirFd opens with, minus O_CLOEXEC:
// what an open_by_handle_at must have asked for to return such a descriptor.
const dirOpenFlags = syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_NOFOLLOW

// tmpfileFds creates an O_TMPFILE file in dir and opens it a second time
// through procfs: source stands in for the descriptor the handle is taken
// from, opened for the one its open_by_handle_at returns (a new open file
// description without the O_TMPFILE flags, as a handle open produces). link is
// the /proc link text of both, "<dir>/#<inode> (deleted)".
func tmpfileFds(t *testing.T, dir string) (source, opened int, link string) {
	t.Helper()
	source, err := unix.Open(dir, unix.O_TMPFILE|unix.O_RDWR|unix.O_CLOEXEC, 0o600)
	if err != nil {
		t.Skipf("O_TMPFILE in %s: %v", dir, err)
	}
	t.Cleanup(func() { _ = unix.Close(source) })
	procPath := filepath.Join("/proc/self/fd", strconv.Itoa(source))
	opened, err = unix.Open(procPath, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("reopen %s: %v", procPath, err)
	}
	t.Cleanup(func() { _ = unix.Close(opened) })
	link, err = os.Readlink(procPath)
	if err != nil {
		t.Fatal(err)
	}
	return source, opened, link
}

// fdLink reads the /proc link text of one of the test's own descriptors.
func fdLink(t *testing.T, fd int) string {
	t.Helper()
	link, err := os.Readlink(filepath.Join("/proc/self/fd", strconv.Itoa(fd)))
	if err != nil {
		t.Fatal(err)
	}
	return link
}

// linkTmpfile gives the O_TMPFILE file behind fd the name path, through its
// /proc link (the AT_EMPTY_PATH form needs CAP_DAC_READ_SEARCH).
func linkTmpfile(t *testing.T, fd int, path string) {
	t.Helper()
	procPath := filepath.Join("/proc/self/fd", strconv.Itoa(fd))
	if err := unix.Linkat(unix.AT_FDCWD, procPath, unix.AT_FDCWD, path, unix.AT_SYMLINK_FOLLOW); err != nil {
		t.Skipf("linkat %s: %v", path, err)
	}
}

// promotedTmpfileStash takes an AT_EMPTY_PATH handle of an O_TMPFILE descriptor
// ior did not see opened but has in its fd table all the same, promoted by an
// fcntl. The entry has the O_TMPFILE flags (from fdinfo) and is named by its
// link, which the stash therefore is - a name that leads to the file.
func promotedTmpfileStash(t *testing.T, feed *handleFeed, source int) string {
	t.Helper()
	promoted := feed.promoteByFcntl(source)
	if !promoted.Flags().Is(unix.O_TMPFILE) {
		t.Fatalf("promoted entry has flags %v, want O_TMPFILE among them", promoted.Flags())
	}
	feed.nameToHandleEmptyPath(source)
	return fdLink(t, source)
}

// opaqueStashCase takes one handle whose stash ior cannot compare (stash
// returns what the slot must hold) and says which descriptor its
// open_by_handle_at returned; a nil open is an O_RDONLY open of path.
type opaqueStashCase struct {
	name  string
	stash func(t *testing.T, feed *handleFeed, dir, path string) (wantStash string)
	open  func(t *testing.T, dir string) (fd int, flags int32, wantRow string)
}

var opaqueStashCases = []opaqueStashCase{
	{
		name: "relative path, AT_FDCWD",
		stash: func(_ *testing.T, feed *handleFeed, _, _ string) string {
			feed.nameToHandle("rel.txt")
			return "rel.txt"
		},
	},
	{
		name: "relative path under a dirfd tracked as a relative name",
		stash: func(t *testing.T, feed *handleFeed, dir, _ string) string {
			dirfd := openReusingDirFd(t, dir)
			feed.trackAs(dirfd, ".", dirOpenFlags)
			feed.nameToHandleUnder(dirfd, "rel.txt")
			return "rel.txt"
		},
	},
	{
		name: "AT_EMPTY_PATH on a file tracked under a relative name",
		stash: func(t *testing.T, feed *handleFeed, _, path string) string {
			source := openHandleFd(t, path)
			feed.trackAs(source, "sub/rel.txt", syscall.O_RDONLY)
			feed.nameToHandleEmptyPath(source)
			return "sub/rel.txt"
		},
	},
	{
		name: "AT_EMPTY_PATH on an fsmount descriptor",
		stash: func(t *testing.T, feed *handleFeed, dir, _ string) string {
			// registerEventfdResult tracks the fsmount descriptor under
			// its fs-context's name; the link of the descriptor a handle
			// of it opens is the mount's root directory.
			source := openReusingDirFd(t, dir)
			name := feed.traceSource(source, types.SYS_ENTER_FSOPEN, "tmpfs")
			feed.nameToHandleEmptyPath(source)
			return name
		},
		open: func(t *testing.T, dir string) (int, int32, string) {
			return openReusingDirFd(t, dir), dirOpenFlags, dir
		},
	},
}

// TestOpenByHandleAtOpaqueStashIsSpentOnTheNextOpen is the regression. Each
// case takes one handle and opens it; the descriptor is still there with the
// call's flags, so procfs names the row, as it did before. What changed is the
// stash: ior cannot recognise its own descriptor by it, so it is spent on this
// open instead of being left to name the next one.
func TestOpenByHandleAtOpaqueStashIsSpentOnTheNextOpen(t *testing.T) {
	dir := tempDir(t)
	path := writeHandleFile(t, dir, "rel.txt")

	for _, tt := range opaqueStashCases {
		t.Run(tt.name, func(t *testing.T) {
			feed := newHandleFeed(t)
			assertStash(t, feed, tt.stash(t, feed, dir, path))
			fd, flags, wantRow := openHandleFd(t, path), int32(syscall.O_RDONLY), path
			if tt.open != nil {
				fd, flags, wantRow = tt.open(t, dir)
			}
			assertStashSpentOnItsOwnOpen(t, feed, fd, flags, wantRow)
		})
	}
}

// tmpfileOpenFlags are the flags the tests' O_TMPFILE opens are traced with.
const tmpfileOpenFlags = unix.O_TMPFILE | unix.O_RDWR

// TestOpenByHandleAtTrackedTmpfileStashIsSpentOnTheNextOpen: handleOpenExit
// names an O_TMPFILE descriptor after the directory it was created in, so the
// AT_EMPTY_PATH stash of a tracked one is that directory - an absolute path
// that names another inode than the file the handle opens.
func TestOpenByHandleAtTrackedTmpfileStashIsSpentOnTheNextOpen(t *testing.T) {
	dir := tempDir(t)
	source, opened, link := tmpfileFds(t, dir)

	feed := newHandleFeed(t)
	feed.open(source, dir, tmpfileOpenFlags)
	stashFromEmptyPath(t, feed, source, dir)
	assertStashSpentOnItsOwnOpen(t, feed, opened, syscall.O_RDWR, link)
}

// TestOpenByHandleAtDupOfTrackedTmpfileStashIsSpentOnTheNextOpen: a duplicate
// is another number for the same open file description and carries the same
// name, the directory, so a handle taken through it is as opaque as one taken
// through the descriptor the open returned.
func TestOpenByHandleAtDupOfTrackedTmpfileStashIsSpentOnTheNextOpen(t *testing.T) {
	dir := tempDir(t)
	source, opened, link := tmpfileFds(t, dir)
	duplicate, err := unix.Dup(source)
	if err != nil {
		t.Fatalf("dup: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(duplicate) })

	feed := newHandleFeed(t)
	feed.open(source, dir, tmpfileOpenFlags)
	feed.dup(source, duplicate)
	stashFromEmptyPath(t, feed, duplicate, dir)
	assertStashSpentOnItsOwnOpen(t, feed, opened, syscall.O_RDWR, link)
}

// TestOpenByHandleAtLinkedTrackedTmpfileStashIsStillSpent pins what a linkat
// changes for a tracked O_TMPFILE descriptor: nothing. The file now has a
// name, but the fd table entry keeps the one the open gave it (no syscall
// renames an entry), so the stash is still the directory, still another inode
// than the file the handle opens, and still opaque. Clearing the mark on a
// linkat would leave that directory stash in the slot after its own open.
func TestOpenByHandleAtLinkedTrackedTmpfileStashIsStillSpent(t *testing.T) {
	dir := tempDir(t)
	source, _, _ := tmpfileFds(t, dir)
	linked := filepath.Join(dir, "linked")

	feed := newHandleFeed(t)
	feed.open(source, dir, tmpfileOpenFlags)
	linkTmpfile(t, source, linked)
	feed.linkatEmptyPath(source, linked)
	stashFromEmptyPath(t, feed, source, dir)
	assertStashSpentOnItsOwnOpen(t, feed, openHandleFd(t, linked), syscall.O_RDONLY, linked)
}

// TestOpenedFdFileMarksOnlyAnOTmpfileOpen: the mark that makes a stash opaque
// is given by the open's flags, and only by both O_TMPFILE bits. O_DIRECTORY
// alone is a directory open, whose name IS the descriptor's path, and unknown
// flags (-1, every bit set) say nothing.
func TestOpenedFdFileMarksOnlyAnOTmpfileOpen(t *testing.T) {
	tests := []struct {
		name  string
		flags int32
		want  bool
	}{
		{"O_TMPFILE", tmpfileOpenFlags, true},
		{"O_TMPFILE with O_CLOEXEC", tmpfileOpenFlags | syscall.O_CLOEXEC, true},
		{"a directory", dirOpenFlags, false},
		{"a plain file", syscall.O_RDWR | syscall.O_CREAT, false},
		{"unknown flags", -1, false},
	}
	for _, tt := range tests {
		if got := openedFdFile(3, "/dir", tt.flags).NamedAfterTmpfileDir(); got != tt.want {
			t.Errorf("%s: marked = %v, want %v", tt.name, got, tt.want)
		}
	}
}

// TestOpenByHandleAtOpaqueStashStillNamesAnUnconfirmedDescriptor is the j03
// protection, unchanged: procfs shows a descriptor the call cannot have
// returned (a directory under a plain O_RDONLY request - the number was
// reused), so it is not believed and the stash names the row, opaque or not.
func TestOpenByHandleAtOpaqueStashStillNamesAnUnconfirmedDescriptor(t *testing.T) {
	reused := openReusingDirFd(t, tempDir(t))

	feed := newHandleFeed(t)
	feed.nameToHandle("rel.txt")
	if got := feed.openByHandle(reused).File.Name(); got != "rel.txt" {
		t.Fatalf("row named %q, want the stashed %q (the number was reused)", got, "rel.txt")
	}
	if got, ok := feed.el.pendingHandleState().peek(feed.pid); ok {
		t.Fatalf("stash %q named the row, so it must be consumed", got)
	}
}

// comparableStashCase takes one handle whose stash ior can compare; stash
// returns what the slot must hold. target is a file in dir.
type comparableStashCase struct {
	name  string
	stash func(t *testing.T, feed *handleFeed, dir, target string) (wantStash string)
}

var comparableStashCases = []comparableStashCase{
	{"relative name under a dirfd tracked by an absolute path", func(t *testing.T, feed *handleFeed, dir, target string) string {
		dirfd := openReusingDirFd(t, dir)
		feed.trackAs(dirfd, dir, dirOpenFlags)
		feed.nameToHandleUnder(dirfd, "target")
		return target
	}},
	{"relative name under a dirfd tracked as an O_TMPFILE open", func(t *testing.T, feed *handleFeed, dir, target string) string {
		// Only a handle taken of the descriptor itself (empty pathname)
		// stashes a tmpfile's directory. A name below the descriptor is
		// a path like any other, whatever the entry is marked as.
		dirfd := openReusingDirFd(t, dir)
		feed.open(dirfd, dir, tmpfileOpenFlags)
		feed.nameToHandleUnder(dirfd, "target")
		return target
	}},
	{"AT_EMPTY_PATH on a tracked directory", func(t *testing.T, feed *handleFeed, dir, _ string) string {
		dirfd := openReusingDirFd(t, dir)
		feed.open(dirfd, dir, dirOpenFlags)
		feed.nameToHandleEmptyPath(dirfd)
		return dir
	}},
	{"AT_EMPTY_PATH on an untracked O_TMPFILE descriptor", func(t *testing.T, feed *handleFeed, dir, _ string) string {
		source, _, link := tmpfileFds(t, dir)
		feed.nameToHandleEmptyPath(source)
		return link
	}},
	{"AT_EMPTY_PATH on an O_TMPFILE descriptor promoted from procfs", func(t *testing.T, feed *handleFeed, dir, _ string) string {
		// Opened before ior attached, then an fcntl: in the fd table with
		// the O_TMPFILE flags, but under its link text, not its directory.
		source, _, _ := tmpfileFds(t, dir)
		return promotedTmpfileStash(t, feed, source)
	}},
	{"AT_EMPTY_PATH on a linked O_TMPFILE descriptor promoted from procfs", func(t *testing.T, feed *handleFeed, dir, _ string) string {
		// The same after a linkat gave the file a name. The descriptor's
		// link keeps reading "<dir>/#<inode> (deleted)" (Linux 7.2.5), and
		// whatever it reads is a name of the file, never the directory.
		source, _, _ := tmpfileFds(t, dir)
		linkTmpfile(t, source, filepath.Join(dir, "linked"))
		return promotedTmpfileStash(t, feed, source)
	}},
	{"AT_EMPTY_PATH on an untracked namespace descriptor", func(t *testing.T, feed *handleFeed, _, _ string) string {
		source := openHandleFd(t, "/proc/self/ns/net")
		feed.nameToHandleEmptyPath(source)
		return fdLink(t, source)
	}},
}

// TestOpenByHandleAtComparableStashSurvivesAnotherHandlesOpen is the negative
// side: a stash ior CAN recognise its descriptor by is contradicted by another
// handle's open and must be kept for its own. The cases are the neighbours of
// the opaque ones: a relative name under a dirfd tracked by an absolute path
// (joined to an absolute stash), a tracked directory that is no O_TMPFILE
// descriptor, an O_TMPFILE descriptor ior did not see opened (stashed as its
// link text, whether it is in no table or was promoted into the fd table from
// procfs) and a namespace descriptor (a link text that is not a path).
func TestOpenByHandleAtComparableStashSurvivesAnotherHandlesOpen(t *testing.T) {
	dir := tempDir(t)
	target := writeHandleFile(t, dir, "target")
	other := writeHandleFile(t, dir, "other")

	for _, tt := range comparableStashCases {
		t.Run(tt.name, func(t *testing.T) {
			feed := newHandleFeed(t)
			stash := tt.stash(t, feed, dir, target)
			assertStash(t, feed, stash)
			if got := feed.openByHandle(openHandleFd(t, other)).File.Name(); got != other {
				t.Errorf("row named %q, want procfs's %q", got, other)
			}
			assertStash(t, feed, stash)
		})
	}
}

// TestOpenByHandleAtJoinedAbsoluteStashMatchesItsOwnOpen: a relative name under
// a dirfd whose tracked name is absolute is stashed as the joined absolute
// path (resolveDirfdPath, in event order), so it is compared by inode like a
// path the task passed in full and names its own row.
func TestOpenByHandleAtJoinedAbsoluteStashMatchesItsOwnOpen(t *testing.T) {
	dir := tempDir(t)
	target := writeHandleFile(t, dir, "target")
	dirfd := openReusingDirFd(t, dir)

	feed := newHandleFeed(t)
	feed.trackAs(dirfd, dir, dirOpenFlags)
	feed.nameToHandleUnder(dirfd, "target")
	assertStash(t, feed, target)
	assertStashSpentOnItsOwnOpen(t, feed, openHandleFd(t, target), syscall.O_RDONLY, target)
}

// tracedHandleName is the name eventfdDescriptorName gives a descriptor ior
// saw created by traceID; an empty identity is a name BPF could not read.
func tracedHandleName(traceID types.TraceId, flags int32, identity string) string {
	return eventfdDescriptorName(traceID, flags, identity, identity != "")
}

// comparableHandleNames lists stashed names and whether ior can recognise a
// descriptor by them.
var comparableHandleNames = []struct {
	name string
	want bool
}{
	{"/tmp/file", true},
	{"/tmp/file (deleted)", true},
	{"/memfd:x (deleted)", true},
	{tracedHandleName(types.SYS_ENTER_MEMFD_CREATE, 0, "x"), true},
	{tracedHandleName(types.SYS_ENTER_MEMFD_CREATE, 0, "7 up"), true},
	{tracedHandleName(types.SYS_ENTER_PIDFD_OPEN, unix.PIDFD_NONBLOCK, ""), true},
	{pidfdLinkText, true},
	{"net:[4026531833]", true},
	{"time:[4026531834]", true},
	// Relative paths.
	{"rel.txt", false},
	{"sub/rel.txt", false},
	{"./rel.txt", false},
	{"../rel.txt", false},
	{".", false},
	{"sub/net:[1]", false},
	// Traced names that are no link text.
	{tracedHandleName(types.SYS_ENTER_FSOPEN, 0, "tmpfs"), false},
	{tracedHandleName(types.SYS_ENTER_FSOPEN, 1, ""), false},
	{tracedHandleName(types.SYS_ENTER_MEMFD_SECRET, 0, ""), false},
	// A memfd whose name was not read carries its flags instead; a
	// MFD_HUGE_* size sets the top bit, which prints negative.
	{tracedHandleName(types.SYS_ENTER_MEMFD_CREATE, unix.MFD_CLOEXEC, ""), false},
	{tracedHandleName(types.SYS_ENTER_MEMFD_CREATE, -2013265920, ""), false},
	// Link texts no handle can be taken of are not links ior read.
	{"socket:[42]", false},
	{"pipe:[42]", false},
	{"anon_inode:[fscontext]", false},
	{"anon_inode:[eventfd]", false},
	// Not the namespace shape.
	{"net:[]", false},
	{"net:[12", false},
	{"net:[1x]", false},
	{":[1]", false},
	{"net:1", false},
}

// TestComparableHandleName pins which stashed names ior can recognise a
// descriptor by, against the names eventfdDescriptorName really produces.
func TestComparableHandleName(t *testing.T) {
	for _, tt := range comparableHandleNames {
		if got := comparableHandleName(tt.name); got != tt.want {
			t.Errorf("comparableHandleName(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

// TestPendingHandleTrackerOpacityFollowsTheStash: opacity belongs to the
// entry, so a later comparable stash of the thread clears it, an empty name
// drops the entry whichever setter was used, and a thread without a stash is
// not opaque.
func TestPendingHandleTrackerOpacityFollowsTheStash(t *testing.T) {
	var tracker pendingHandleTracker
	if tracker.isOpaque(1) {
		t.Fatal("a zero-value tracker reported an opaque stash")
	}
	tracker.setOpaque(1, "rel.txt")
	if got, ok := tracker.peek(1); !ok || got != "rel.txt" || !tracker.isOpaque(1) {
		t.Fatalf("after setOpaque: peek = %q, %v, opaque = %v", got, ok, tracker.isOpaque(1))
	}
	tracker.set(1, "/abs")
	if tracker.isOpaque(1) {
		t.Error("a comparable stash inherited the opacity of the one it replaced")
	}
	tracker.setOpaque(1, "rel.txt")
	tracker.setOpaque(1, "")
	if _, ok := tracker.peek(1); ok || tracker.isOpaque(1) {
		t.Error("an empty opaque name must drop the entry")
	}
}
