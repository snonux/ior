package internal

import (
	"os"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"ior/internal/file"
	"ior/internal/types"
)

// These tests cover a name_to_handle_at(fd, "", AT_EMPTY_PATH) whose source
// descriptor is in ior's fd table (review of 9f02f3a, task l03). The stash is
// then fdTracker.resolve's answer from the table - ior's traced name
// "memfd:<name>" or "pidfd:<flags>" - and not the /proc link text the tests in
// eventloop_handle_deleted_test.go get from their untracked descriptors.

// traceSource registers fd in the feed's fd table under the name ior gives a
// descriptor created by the syscall traceID, as handleEventfdExit does when it
// sees the memfd_create or pidfd_open, and returns that name.
func (f *handleFeed) traceSource(fd int, traceID types.TraceId, identity string) string {
	f.t.Helper()
	name := eventfdDescriptorName(traceID, 0, identity, identity != "")
	f.el.fdState().set(int32(fd), f.pid, file.NewFd(int32(fd), name, syscall.O_RDWR))
	return name
}

// memfdPair creates a memfd called name and a duplicate of it: source stands
// in for the descriptor the handle is taken from, opened for the one its
// open_by_handle_at returns.
func memfdPair(t *testing.T, name string) (source, opened int) {
	t.Helper()
	source, err := unix.MemfdCreate(name, unix.MFD_CLOEXEC)
	if err != nil {
		t.Skipf("memfd_create: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(source) })
	opened, err = unix.Dup(source)
	if err != nil {
		t.Fatalf("dup: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(opened) })
	return source, opened
}

// openPidfd opens a pidfd of the test process.
func openPidfd(t *testing.T) int {
	t.Helper()
	pidfd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		t.Skipf("pidfd_open: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(pidfd) })
	return pidfd
}

// assertStashSpentOnItsOwnOpen checks the three things a matching stash owes:
// the row carries the stashed name, the slot is empty afterwards, and an
// unrelated later open_by_handle_at of the thread (its descriptor already
// closed, so procfs cannot answer) is not named after the spent stash.
func assertStashSpentOnItsOwnOpen(t *testing.T, feed *handleFeed, opened int, flags int32, want string) {
	t.Helper()
	if got := feed.openByHandleWithFlags(opened, flags).File.Name(); got != want {
		t.Errorf("row named %q, want %q", got, want)
	}
	if got, ok := feed.el.pendingHandleState().peek(feed.pid); ok {
		t.Errorf("stash %q survived its own open; it must be consumed", got)
	}
	if got := feed.openByHandle(1 << 20).File.Name(); got != "" {
		t.Errorf("unrelated later open named %q, want no name (nothing is stashed for it)", got)
	}
}

// TestOpenByHandleAtTracedMemfdStashMatchesTheMemfd: the memfd_create was
// traced, so the stash is "memfd:handlebuf" while the descriptor the handle
// opens reads "/memfd:handlebuf (deleted)". Compared as text the two never
// agreed, so the stash outlived its own open and named the next one. The row
// carries the traced name, like every other row on a traced memfd.
func TestOpenByHandleAtTracedMemfdStashMatchesTheMemfd(t *testing.T) {
	source, opened := memfdPair(t, "handlebuf")
	feed := newHandleFeed(t)
	want := feed.traceSource(source, types.SYS_ENTER_MEMFD_CREATE, "handlebuf")
	if want != "memfd:handlebuf" {
		t.Fatalf("traced memfd name = %q, want %q", want, "memfd:handlebuf")
	}

	stashFromEmptyPath(t, feed, source, want)
	assertStashSpentOnItsOwnOpen(t, feed, opened, syscall.O_RDWR, want)
}

// TestOpenByHandleAtTracedPidfdStashMatchesAPidfd: the pidfd_open was traced,
// so the stash is "pidfd:0" while the opened descriptor reads
// "anon_inode:[pidfd]".
func TestOpenByHandleAtTracedPidfdStashMatchesAPidfd(t *testing.T) {
	source, opened := openPidfd(t), openPidfd(t)
	feed := newHandleFeed(t)
	want := feed.traceSource(source, types.SYS_ENTER_PIDFD_OPEN, "")
	if want != "pidfd:0" {
		t.Fatalf("traced pidfd name = %q, want %q", want, "pidfd:0")
	}

	stashFromEmptyPath(t, feed, source, want)
	assertStashSpentOnItsOwnOpen(t, feed, opened, syscall.O_RDONLY, want)
}

// TestOpenByHandleAtTracedStashButOtherHandleOpened is the negative side: a
// traced name still contradicts every descriptor that is not of its kind and
// name, so the row is named from procfs and the stash is kept for its own
// open.
func TestOpenByHandleAtTracedStashButOtherHandleOpened(t *testing.T) {
	memfd, _ := memfdPair(t, "handlebuf")
	_, otherMemfd := memfdPair(t, "otherbuf")
	pidfd := openPidfd(t)
	path := writeHandleFile(t, tempDir(t), "other.txt")
	regular := openHandleFd(t, path)

	tests := []struct {
		name    string
		source  int
		traceID types.TraceId
		ident   string
		opened  int
		flags   int32
		wantRow string
	}{
		{"memfd stash, file opened", memfd, types.SYS_ENTER_MEMFD_CREATE, "handlebuf", regular, syscall.O_RDONLY, path},
		{"memfd stash, other memfd opened", memfd, types.SYS_ENTER_MEMFD_CREATE, "handlebuf", otherMemfd, syscall.O_RDWR, "/memfd:otherbuf" + deletedSuffix},
		{"memfd stash, pidfd opened", memfd, types.SYS_ENTER_MEMFD_CREATE, "handlebuf", pidfd, syscall.O_RDONLY, pidfdLinkText},
		{"pidfd stash, file opened", pidfd, types.SYS_ENTER_PIDFD_OPEN, "", regular, syscall.O_RDONLY, path},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			feed := newHandleFeed(t)
			stash := feed.traceSource(tt.source, tt.traceID, tt.ident)
			stashFromEmptyPath(t, feed, tt.source, stash)
			if got := feed.openByHandleWithFlags(tt.opened, tt.flags).File.Name(); got != tt.wantRow {
				t.Errorf("row named %q, want procfs's %q", got, tt.wantRow)
			}
			if got, ok := feed.el.pendingHandleState().peek(feed.pid); !ok || got != stash {
				t.Errorf("stash = %q (ok=%v), want %q kept for its own open", got, ok, stash)
			}
		})
	}
}

// TestOpenByHandleAtUnnamedTracedMemfdStashIsNotMatched pins the documented
// gap: a memfd whose name BPF could not read is tracked as "memfd:<flags>",
// which translates to no link its descriptor has. The row is right (procfs),
// the stash is left behind.
func TestOpenByHandleAtUnnamedTracedMemfdStashIsNotMatched(t *testing.T) {
	source, opened := memfdPair(t, "handlebuf")
	feed := newHandleFeed(t)
	stash := feed.traceSource(source, types.SYS_ENTER_MEMFD_CREATE, "")

	stashFromEmptyPath(t, feed, source, stash)
	const want = "/memfd:handlebuf" + deletedSuffix
	if got := feed.openByHandleWithFlags(opened, syscall.O_RDWR).File.Name(); got != want {
		t.Errorf("row named %q, want procfs's %q", got, want)
	}
	if got, ok := feed.el.pendingHandleState().peek(feed.pid); !ok || got != stash {
		t.Errorf("stash = %q (ok=%v), want %q left in the slot", got, ok, stash)
	}
}

// TestTracedHandleLink pins the translation against the names
// eventfdDescriptorName really produces, so the two cannot drift apart.
func TestTracedHandleLink(t *testing.T) {
	memfd := eventfdDescriptorName(types.SYS_ENTER_MEMFD_CREATE, unix.MFD_CLOEXEC, "x", true)
	pidfd := eventfdDescriptorName(types.SYS_ENTER_PIDFD_OPEN, unix.PIDFD_NONBLOCK, "", false)
	secret := eventfdDescriptorName(types.SYS_ENTER_MEMFD_SECRET, 0, "", false)
	eventFd := eventfdDescriptorName(types.SYS_ENTER_EVENTFD2, 0, "", false)

	tests := []struct {
		stash  string
		want   string
		wantOK bool
	}{
		{memfd, "/memfd:x (deleted)", true},
		{"memfd:a b (deleted)", "/memfd:a b (deleted) (deleted)", true},
		{"memfd:", "/memfd: (deleted)", true},
		{pidfd, pidfdLinkText, true},
		// Neither is a name a file handle can be taken of, and neither starts
		// with one of the two prefixes.
		{secret, "", false},
		{eventFd, "", false},
		// Link texts and paths are compared as they stand.
		{"/memfd:x (deleted)", "", false},
		{pidfdLinkText, "", false},
		{"/tmp/memfd:x", "", false},
		// The prefix includes the colon.
		{"pidfdx", "", false},
		{"memfdx", "", false},
		{"dir/pidfd:0", "", false},
		{"", "", false},
	}
	for _, tt := range tests {
		got, ok := tracedHandleLink(tt.stash)
		if got != tt.want || ok != tt.wantOK {
			t.Errorf("tracedHandleLink(%q) = %q, %v, want %q, %v", tt.stash, got, ok, tt.want, tt.wantOK)
		}
	}
}

// TestOpenByHandleAtSameLinkTextIsTakenForTheSameFile pins the false match the
// link-text rule cannot avoid: two different files whose /proc links read the
// same - two unlinked files that lived at one path, two memfds of one name -
// are one name to it, so a stash taken from the first is consumed by the open
// of the second. The row still carries the name procfs gives that descriptor;
// only the stash is spent on the wrong open.
func TestOpenByHandleAtSameLinkTextIsTakenForTheSameFile(t *testing.T) {
	dir := tempDir(t)
	path, first, _ := unlinkedHandleFds(t, dir, "x")
	_, _, second := unlinkedHandleFds(t, dir, "x")
	firstMemfd, _ := memfdPair(t, "buf")
	_, secondMemfd := memfdPair(t, "buf")

	tests := []struct {
		name   string
		source int
		opened int
		flags  int32
		link   string
	}{
		{"unlinked files at one path", first, second, syscall.O_RDONLY, path + deletedSuffix},
		{"memfds of one name", firstMemfd, secondMemfd, syscall.O_RDWR, "/memfd:buf" + deletedSuffix},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var a, b syscall.Stat_t
			if err := syscall.Fstat(tt.source, &a); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Fstat(tt.opened, &b); err != nil {
				t.Fatal(err)
			}
			if a.Dev == b.Dev && a.Ino == b.Ino {
				t.Fatalf("both descriptors are inode %d; the test needs two files", a.Ino)
			}
			feed := newHandleFeed(t)
			stashFromEmptyPath(t, feed, tt.source, tt.link)
			if got := feed.openByHandleWithFlags(tt.opened, tt.flags).File.Name(); got != tt.link {
				t.Errorf("row named %q, want %q", got, tt.link)
			}
			if got, ok := feed.el.pendingHandleState().peek(feed.pid); ok {
				t.Errorf("stash %q was kept; equal link text is a match and consumes it", got)
			}
		})
	}
}
