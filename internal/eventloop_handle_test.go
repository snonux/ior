package internal

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"ior/internal/event"
	"ior/internal/types"
)

// handleFeed drives name_to_handle_at / open_by_handle_at events for the test
// process itself, so the descriptor an open_by_handle_at "returns" is a real
// one whose /proc/<pid>/fd entry the production code can stat.
type handleFeed struct {
	t    *testing.T
	el   *eventLoop
	out  chan *event.Pair
	pid  uint32
	time uint64
}

func newHandleFeed(t *testing.T) *handleFeed {
	t.Helper()
	return &handleFeed{
		t:    t,
		el:   mustNewEventLoop(t, eventLoopConfig{}),
		out:  make(chan *event.Pair, 4),
		pid:  uint32(os.Getpid()),
		time: defaulTime,
	}
}

// nameToHandle feeds one successful name_to_handle_at(pathname).
func (f *handleFeed) nameToHandle(pathname string) {
	f.t.Helper()
	_, enter := makeEnterPathEvent(f.t, f.time, f.pid, f.pid, pathname, types.SYS_ENTER_NAME_TO_HANDLE_AT)
	_, exit := makeExitRetEvent(f.t, f.time+1, f.pid, f.pid, types.SYS_EXIT_NAME_TO_HANDLE_AT, 0)
	f.time += 10
	f.el.processRawEvent(enter, f.out)
	f.el.processRawEvent(exit, f.out)
}

// openByHandle feeds an open_by_handle_at that returned fd and yields the row.
func (f *handleFeed) openByHandle(fd int) *event.Pair {
	f.t.Helper()
	_, enter := makeEnterOpenByHandleAtEvent(f.t, f.time, f.pid, f.pid, syscall.O_RDONLY)
	_, exit := makeExitRetEvent(f.t, f.time+1, f.pid, f.pid, types.SYS_EXIT_OPEN_BY_HANDLE_AT, int64(fd))
	f.time += 10
	f.el.processRawEvent(enter, f.out)
	f.el.processRawEvent(exit, f.out)
	select {
	case ep := <-f.out:
		return ep
	default:
		f.t.Fatal("open_by_handle_at row was not emitted")
		return nil
	}
}

func writeHandleFile(t *testing.T, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(name), 0o600); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

func openHandleFd(t *testing.T, path string) int {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return int(f.Fd())
}

// TestOpenByHandleAtNamesTheOpenedHandleNotTheLastOne is the regression: two
// handles are taken (A then B) and the FIRST is opened. The stash holds B, the
// thread's last name_to_handle_at, but the descriptor is A, so the row - and
// every later row on that fd - must say A. Before the fix it said B.
func TestOpenByHandleAtNamesTheOpenedHandleNotTheLastOne(t *testing.T) {
	dir := t.TempDir()
	pathA := writeHandleFile(t, dir, "hostname")
	pathB := writeHandleFile(t, dir, "os-release")
	fdA := openHandleFd(t, pathA)

	feed := newHandleFeed(t)
	feed.nameToHandle(pathA)
	feed.nameToHandle(pathB)
	ep := feed.openByHandle(fdA)

	if got := ep.File.Name(); got != pathA {
		t.Fatalf("open_by_handle_at row named %q, want %q (the handle actually opened)", got, pathA)
	}
	tracked, ok := feed.el.fdState().get(int32(fdA), feed.pid)
	if !ok || tracked.Name() != pathA {
		t.Fatalf("fd table entry for fd %d = %v (ok=%v), want %q", fdA, tracked, ok, pathA)
	}
	// B's own open has not happened yet, so its stash must survive to name it.
	if got, ok := feed.el.pendingHandleState().peek(feed.pid); !ok || got != pathB {
		t.Fatalf("pending stash after opening A = %q (ok=%v), want %q kept for B's open", got, ok, pathB)
	}
}

// TestOpenByHandleAtBothHandlesOpenedInEitherOrder opens the later handle first
// (stash used and consumed) and the earlier one second (stash empty, procfs).
func TestOpenByHandleAtBothHandlesOpenedInEitherOrder(t *testing.T) {
	dir := t.TempDir()
	pathA := writeHandleFile(t, dir, "a.txt")
	pathB := writeHandleFile(t, dir, "b.txt")
	fdA := openHandleFd(t, pathA)
	fdB := openHandleFd(t, pathB)

	feed := newHandleFeed(t)
	feed.nameToHandle(pathA)
	feed.nameToHandle(pathB)
	if got := feed.openByHandle(fdB).File.Name(); got != pathB {
		t.Fatalf("first open named %q, want %q", got, pathB)
	}
	if _, ok := feed.el.pendingHandleState().peek(feed.pid); ok {
		t.Fatal("a verified stash must be consumed")
	}
	if got := feed.openByHandle(fdA).File.Name(); got != pathA {
		t.Fatalf("second open named %q, want %q", got, pathA)
	}
}

// TestOpenByHandleAtKeepsTheSymlinkSpelling pins the negative side of the
// check: a stash that names the same inode through a symlink or a hard link is
// a match, so the user's own spelling is still what the row prints.
func TestOpenByHandleAtKeepsTheSymlinkSpelling(t *testing.T) {
	dir := t.TempDir()
	target := writeHandleFile(t, dir, "target")
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	hard := filepath.Join(dir, "hard")
	if err := os.Link(target, hard); err != nil {
		t.Fatal(err)
	}
	fd := openHandleFd(t, target)

	for _, spelling := range []string{link, hard} {
		feed := newHandleFeed(t)
		feed.nameToHandle(spelling)
		if got := feed.openByHandle(fd).File.Name(); got != spelling {
			t.Errorf("row named %q, want the stashed spelling %q", got, spelling)
		}
	}
}

// TestOpenByHandleAtFallsBackToTheStashWhenUnverifiable covers the legacy
// behaviour that must survive: a file deleted after its handle was taken (the
// classic use of handles) cannot be stat'ed by name, and procfs would only say
// "<path> (deleted)", so the stashed name is used; the same goes for a
// descriptor procfs cannot answer for.
func TestOpenByHandleAtFallsBackToTheStashWhenUnverifiable(t *testing.T) {
	dir := t.TempDir()
	gone := writeHandleFile(t, dir, "gone")
	fd := openHandleFd(t, gone)
	if err := os.Remove(gone); err != nil {
		t.Fatal(err)
	}

	feed := newHandleFeed(t)
	feed.nameToHandle(gone)
	if got := feed.openByHandle(fd).File.Name(); got != gone {
		t.Fatalf("deleted-file row named %q, want the stashed %q", got, gone)
	}

	// A descriptor number that is not open in this process: unverifiable.
	feed = newHandleFeed(t)
	feed.nameToHandle("/tmp/handle_stash.txt")
	if got := feed.openByHandle(1 << 20).File.Name(); got != "/tmp/handle_stash.txt" {
		t.Fatalf("unverifiable fd row named %q, want the stashed name", got)
	}
}

func TestClassifyHandlePath(t *testing.T) {
	dir := t.TempDir()
	a := writeHandleFile(t, dir, "a")
	b := writeHandleFile(t, dir, "b")
	fd := openHandleFd(t, a)
	pid := uint32(os.Getpid())

	tests := []struct {
		name string
		path string
		fd   int32
		want handleVerdict
	}{
		{"same file", a, int32(fd), handleMatches},
		{"different file", b, int32(fd), handleMismatch},
		{"missing path", filepath.Join(dir, "nope"), int32(fd), handleUnverified},
		{"empty path", "", int32(fd), handleUnverified},
		{"closed fd", a, 1 << 20, handleUnverified},
	}
	for _, tt := range tests {
		if got := classifyHandlePath(pid, tt.fd, tt.path); got != tt.want {
			t.Errorf("%s: classifyHandlePath = %d, want %d", tt.name, got, tt.want)
		}
	}
}
