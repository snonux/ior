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

// TestOpenByHandleAtOpaqueStashIsSpentOnTheNextOpen is the regression. Each
// case takes one handle and opens it; the descriptor is still there with the
// call's flags, so procfs names the row, as it did before. What changed is the
// stash: ior cannot recognise its own descriptor by it, so it is spent on this
// open instead of being left to name the next one.
func TestOpenByHandleAtOpaqueStashIsSpentOnTheNextOpen(t *testing.T) {
	dir := tempDir(t)
	path := writeHandleFile(t, dir, "rel.txt")

	tests := []struct {
		name  string
		stash func(t *testing.T, feed *handleFeed) (wantStash string)
		open  func(t *testing.T) (fd int, flags int32, wantRow string)
	}{
		{
			name: "relative path, AT_FDCWD",
			stash: func(_ *testing.T, feed *handleFeed) string {
				feed.nameToHandle("rel.txt")
				return "rel.txt"
			},
		},
		{
			name: "relative path under a dirfd tracked as a relative name",
			stash: func(t *testing.T, feed *handleFeed) string {
				dirfd := openReusingDirFd(t, dir)
				feed.trackAs(dirfd, ".", dirOpenFlags)
				feed.nameToHandleUnder(dirfd, "rel.txt")
				return "rel.txt"
			},
		},
		{
			name: "AT_EMPTY_PATH on a file tracked under a relative name",
			stash: func(t *testing.T, feed *handleFeed) string {
				source := openHandleFd(t, path)
				feed.trackAs(source, "sub/rel.txt", syscall.O_RDONLY)
				feed.nameToHandleEmptyPath(source)
				return "sub/rel.txt"
			},
		},
		{
			name: "AT_EMPTY_PATH on an fsmount descriptor",
			stash: func(t *testing.T, feed *handleFeed) string {
				// registerEventfdResult tracks the fsmount descriptor under
				// its fs-context's name; the link of the descriptor a handle
				// of it opens is the mount's root directory.
				source := openReusingDirFd(t, dir)
				name := feed.traceSource(source, types.SYS_ENTER_FSOPEN, "tmpfs")
				feed.nameToHandleEmptyPath(source)
				return name
			},
			open: func(t *testing.T) (int, int32, string) {
				return openReusingDirFd(t, dir), dirOpenFlags, dir
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			feed := newHandleFeed(t)
			assertStash(t, feed, tt.stash(t, feed))
			fd, flags, wantRow := openHandleFd(t, path), int32(syscall.O_RDONLY), path
			if tt.open != nil {
				fd, flags, wantRow = tt.open(t)
			}
			assertStashSpentOnItsOwnOpen(t, feed, fd, flags, wantRow)
		})
	}
}

// TestOpenByHandleAtTrackedTmpfileStashIsSpentOnTheNextOpen: handleOpenExit
// names an O_TMPFILE descriptor after the directory it was created in, so the
// AT_EMPTY_PATH stash of a tracked one is that directory - an absolute path
// that names another inode than the file the handle opens.
func TestOpenByHandleAtTrackedTmpfileStashIsSpentOnTheNextOpen(t *testing.T) {
	dir := tempDir(t)
	source, opened, link := tmpfileFds(t, dir)

	feed := newHandleFeed(t)
	feed.trackAs(source, dir, unix.O_TMPFILE|unix.O_RDWR)
	stashFromEmptyPath(t, feed, source, dir)
	assertStashSpentOnItsOwnOpen(t, feed, opened, syscall.O_RDWR, link)
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

// TestOpenByHandleAtComparableStashSurvivesAnotherHandlesOpen is the negative
// side: a stash ior CAN recognise its descriptor by is contradicted by another
// handle's open and must be kept for its own. The cases are the neighbours of
// the opaque ones: a relative name under a dirfd tracked by an absolute path
// (joined to an absolute stash), a tracked directory that is no O_TMPFILE
// descriptor, an O_TMPFILE descriptor ior does not track (stashed as its link
// text) and a namespace descriptor (a link text that is not a path).
func TestOpenByHandleAtComparableStashSurvivesAnotherHandlesOpen(t *testing.T) {
	dir := tempDir(t)
	target := writeHandleFile(t, dir, "target")
	other := writeHandleFile(t, dir, "other")

	tests := []struct {
		name  string
		stash func(t *testing.T, feed *handleFeed) (wantStash string)
	}{
		{"relative name under a dirfd tracked by an absolute path", func(t *testing.T, feed *handleFeed) string {
			dirfd := openReusingDirFd(t, dir)
			feed.trackAs(dirfd, dir, dirOpenFlags)
			feed.nameToHandleUnder(dirfd, "target")
			return target
		}},
		{"relative name under a dirfd whose entry carries O_TMPFILE", func(t *testing.T, feed *handleFeed) string {
			// Only a handle taken of the descriptor itself (empty pathname)
			// stashes a tmpfile's directory. A name below the descriptor is
			// a path like any other, whatever the entry's flags say.
			dirfd := openReusingDirFd(t, dir)
			feed.trackAs(dirfd, dir, unix.O_TMPFILE|unix.O_RDWR)
			feed.nameToHandleUnder(dirfd, "target")
			return target
		}},
		{"AT_EMPTY_PATH on a tracked directory", func(t *testing.T, feed *handleFeed) string {
			dirfd := openReusingDirFd(t, dir)
			feed.trackAs(dirfd, dir, dirOpenFlags)
			feed.nameToHandleEmptyPath(dirfd)
			return dir
		}},
		{"AT_EMPTY_PATH on an untracked O_TMPFILE descriptor", func(t *testing.T, feed *handleFeed) string {
			source, _, link := tmpfileFds(t, dir)
			feed.nameToHandleEmptyPath(source)
			return link
		}},
		{"AT_EMPTY_PATH on an untracked namespace descriptor", func(t *testing.T, feed *handleFeed) string {
			source := openHandleFd(t, "/proc/self/ns/net")
			link, err := os.Readlink(filepath.Join("/proc/self/fd", strconv.Itoa(source)))
			if err != nil {
				t.Fatal(err)
			}
			feed.nameToHandleEmptyPath(source)
			return link
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			feed := newHandleFeed(t)
			stash := tt.stash(t, feed)
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

// TestComparableHandleName pins which stashed names ior can recognise a
// descriptor by, against the names eventfdDescriptorName really produces.
func TestComparableHandleName(t *testing.T) {
	traced := func(traceID types.TraceId, flags int32, identity string) string {
		return eventfdDescriptorName(traceID, flags, identity, identity != "")
	}
	tests := []struct {
		name string
		want bool
	}{
		{"/tmp/file", true},
		{"/tmp/file (deleted)", true},
		{"/memfd:x (deleted)", true},
		{traced(types.SYS_ENTER_MEMFD_CREATE, 0, "x"), true},
		{traced(types.SYS_ENTER_MEMFD_CREATE, 0, "7 up"), true},
		{traced(types.SYS_ENTER_PIDFD_OPEN, unix.PIDFD_NONBLOCK, ""), true},
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
		{traced(types.SYS_ENTER_FSOPEN, 0, "tmpfs"), false},
		{traced(types.SYS_ENTER_FSOPEN, 1, ""), false},
		{traced(types.SYS_ENTER_MEMFD_SECRET, 0, ""), false},
		// A memfd whose name was not read carries its flags instead; a
		// MFD_HUGE_* size sets the top bit, which prints negative.
		{traced(types.SYS_ENTER_MEMFD_CREATE, unix.MFD_CLOEXEC, ""), false},
		{traced(types.SYS_ENTER_MEMFD_CREATE, -2013265920, ""), false},
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
	for _, tt := range tests {
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
