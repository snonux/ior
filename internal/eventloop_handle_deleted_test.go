package internal

import (
	"os"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// These tests cover a stash that already carries procfs's " (deleted)" suffix
// (task l03). name_to_handle_at(fd, "", AT_EMPTY_PATH) on a descriptor that is
// not in ior's fd table is resolved from the descriptor's /proc link, so a
// handle taken of an already-unlinked file - or of a memfd, which is born
// unlinked - is stashed as "<path> (deleted)". None of the source descriptors
// here is registered in the fd table; a traced source, whose stash is ior's
// own name for it, is eventloop_handle_traced_test.go.

// unlinkedHandleFds creates dir/name, opens it twice and unlinks it. source
// stands in for the descriptor the task took the handle from, opened for the
// one its open_by_handle_at returned; both read "<path> (deleted)" in procfs.
func unlinkedHandleFds(t *testing.T, dir, name string) (path string, source, opened int) {
	t.Helper()
	path = writeHandleFile(t, dir, name)
	source = openHandleFd(t, path)
	opened = openHandleFd(t, path)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	return path, source, opened
}

// stashFromEmptyPath feeds name_to_handle_at(source, "", AT_EMPTY_PATH) and
// checks that the stash is the link text want.
func stashFromEmptyPath(t *testing.T, feed *handleFeed, source int, want string) {
	t.Helper()
	feed.nameToHandleEmptyPath(source)
	if got, ok := feed.el.pendingHandleState().peek(feed.pid); !ok || got != want {
		t.Fatalf("AT_EMPTY_PATH stash = %q (ok=%v), want %q", got, ok, want)
	}
}

// TestOpenByHandleAtUnlinkedEmptyPathStashMatchesItsOwnFile is the regression:
// the stash and the descriptor's link are the same text, "<path> (deleted)",
// yet the comparison stripped the suffix from the link only, so the stash
// "contradicted" its own file. The row was still named correctly (from
// procfs), but the stash stayed in the slot and named the thread's NEXT
// open_by_handle_at whenever procfs could not answer for that one.
func TestOpenByHandleAtUnlinkedEmptyPathStashMatchesItsOwnFile(t *testing.T) {
	path, source, opened := unlinkedHandleFds(t, tempDir(t), "gone")
	want := path + deletedSuffix

	feed := newHandleFeed(t)
	stashFromEmptyPath(t, feed, source, want)
	// The project's convention for an unlinked file is procfs's own spelling,
	// suffix included (as for an inherited or procfs-resolved descriptor).
	if got := feed.openByHandle(opened).File.Name(); got != want {
		t.Fatalf("row named %q, want %q", got, want)
	}
	if got, ok := feed.el.pendingHandleState().peek(feed.pid); ok {
		t.Errorf("stash %q survived its own open; it must be consumed", got)
	}
	// The harm of the leftover: an unrelated open_by_handle_at of the thread
	// whose descriptor is already closed took the stale name.
	if got := feed.openByHandle(1 << 20).File.Name(); got != "" {
		t.Fatalf("unrelated later open named %q, want no name (nothing is stashed for it)", got)
	}
}

// TestOpenByHandleAtMemfdStashMatchesTheMemfd: a memfd is unlinked from birth,
// so the handle of one ior does not track is stashed as
// "/memfd:<name> (deleted)" and never matched the descriptor the handle opens.
func TestOpenByHandleAtMemfdStashMatchesTheMemfd(t *testing.T) {
	source, err := unix.MemfdCreate("handlebuf", unix.MFD_CLOEXEC)
	if err != nil {
		t.Skipf("memfd_create: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(source) })
	opened, err := unix.Dup(source)
	if err != nil {
		t.Fatalf("dup: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(opened) })
	const want = "/memfd:handlebuf" + deletedSuffix

	feed := newHandleFeed(t)
	stashFromEmptyPath(t, feed, source, want)
	if got := feed.openByHandleWithFlags(opened, syscall.O_RDWR).File.Name(); got != want {
		t.Fatalf("row named %q, want %q", got, want)
	}
	if got, ok := feed.el.pendingHandleState().peek(feed.pid); ok {
		t.Fatalf("stash %q survived its own open; it must be consumed", got)
	}
}

// TestOpenByHandleAtUnlinkedStashButOtherHandleOpened is the negative side: a
// stash carrying the suffix still contradicts any other file, so the row is
// named from procfs and the stash is kept for its own open. The second case is
// the one a suffix-blind comparison (strip it from both sides) gets wrong: a
// NEW file created at the unlinked file's old path is live under exactly the
// stash minus its suffix, and is a different file - an unlinked file never
// gets its name back.
func TestOpenByHandleAtUnlinkedStashButOtherHandleOpened(t *testing.T) {
	dir := tempDir(t)
	path, source, _ := unlinkedHandleFds(t, dir, "gone")
	stash := path + deletedSuffix
	other := writeHandleFile(t, dir, "other")
	recreated := writeHandleFile(t, dir, "gone")

	for _, live := range []string{other, recreated} {
		feed := newHandleFeed(t)
		stashFromEmptyPath(t, feed, source, stash)
		if got := feed.openByHandle(openHandleFd(t, live)).File.Name(); got != live {
			t.Errorf("row named %q, want procfs's %q", got, live)
		}
		if got, ok := feed.el.pendingHandleState().peek(feed.pid); !ok || got != stash {
			t.Errorf("opening %q: stash = %q (ok=%v), want %q kept for its own open", live, got, ok, stash)
		}
	}
}

// TestOpenByHandleAtNameLiterallyEndingInDeleted: a file whose own name ends in
// " (deleted)" has its handle taken by path and is then unlinked, so procfs
// reads "<name> (deleted) (deleted)". Exactly one suffix is the kernel's, and
// stripping one from the link gives the stash. A comparison that stripped the
// stash too would compare "<name> (deleted)" with "<name>" and miss it.
func TestOpenByHandleAtNameLiterallyEndingInDeleted(t *testing.T) {
	path, _, opened := unlinkedHandleFds(t, tempDir(t), "odd"+deletedSuffix)

	feed := newHandleFeed(t)
	feed.nameToHandle(path)
	if got := feed.openByHandle(opened).File.Name(); got != path {
		t.Fatalf("row named %q, want the stashed %q", got, path)
	}
	if got, ok := feed.el.pendingHandleState().peek(feed.pid); ok {
		t.Fatalf("stash %q survived its own open; it must be consumed", got)
	}
}

// TestCompareHandleLinkText pins the rule itself: the stash matches the link as
// it stands, the link minus ONE kernel suffix, or - when it is ior's traced
// name of a memfd or pidfd - the link such a descriptor has, and nothing else.
// The rule sees names, not files: the rows marked "same text" are the false
// match of two different files with one link text, which it cannot tell from
// the first rows.
func TestCompareHandleLinkText(t *testing.T) {
	tests := []struct {
		name   string
		target string
		stash  string
		want   handleVerdict
	}{
		{"live, same text", "/d/f", "/d/f", handleMatches},
		{"unlinked since the handle was taken", "/d/f (deleted)", "/d/f", handleMatches},
		{"unlinked before the handle was taken", "/d/f (deleted)", "/d/f (deleted)", handleMatches},
		{"memfd", "/memfd:x (deleted)", "/memfd:x (deleted)", handleMatches},
		{"literal suffix, unlinked since", "/d/f (deleted) (deleted)", "/d/f (deleted)", handleMatches},
		{"pidfd", pidfdLinkText, pidfdLinkText, handleMatches},
		{"same text: other unlinked file that lived at the path", "/d/f (deleted)", "/d/f (deleted)", handleMatches},
		{"same text: other memfd of the name", "/memfd:x (deleted)", "/memfd:x (deleted)", handleMatches},
		{"traced memfd", "/memfd:x (deleted)", "memfd:x", handleMatches},
		{"traced pidfd", pidfdLinkText, "pidfd:0", handleMatches},
		{"traced memfd, other memfd", "/memfd:y (deleted)", "memfd:x", handleMismatch},
		{"traced memfd, link without the suffix", "/memfd:x", "memfd:x", handleMismatch},
		{"traced memfd, file", "/d/f", "memfd:x", handleMismatch},
		{"traced pidfd, other anonymous inode", "anon_inode:[eventfd]", "pidfd:0", handleMismatch},
		{"relative path", "/d/f", "f", handleMismatch},
		{"unlinked stash, live file at the old path", "/d/f", "/d/f (deleted)", handleMismatch},
		{"unlinked stash, other unlinked file", "/d/g (deleted)", "/d/f (deleted)", handleMismatch},
		{"two suffixes are not stripped", "/d/f (deleted) (deleted)", "/d/f", handleMismatch},
		{"other file", "/d/g", "/d/f", handleMismatch},
	}
	for _, tt := range tests {
		if got := compareHandleLinkText(handleFdProbe{target: tt.target}, tt.stash); got != tt.want {
			t.Errorf("%s: compareHandleLinkText(%q, %q) = %d, want %d", tt.name, tt.target, tt.stash, got, tt.want)
		}
	}
	unreadable := handleFdProbe{target: "/d/f", linkErr: os.ErrNotExist}
	if got := compareHandleLinkText(unreadable, "/d/f"); got != handleUnverified {
		t.Errorf("unreadable link: verdict = %d, want unverified", got)
	}
}
