package internal

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

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

// nameToHandleEmptyPath feeds a successful name_to_handle_at(dirfd, "",
// AT_EMPTY_PATH), whose stash is resolved from the descriptor, not a string.
func (f *handleFeed) nameToHandleEmptyPath(dirfd int) {
	f.t.Helper()
	ev, _ := makeEnterPathEvent(f.t, f.time, f.pid, f.pid, "", types.SYS_ENTER_NAME_TO_HANDLE_AT)
	ev.Dirfd = int32(dirfd)
	ev.Flags = unix.AT_EMPTY_PATH
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

// tempDir is t.TempDir with symlinks resolved, so the name procfs reports for
// a descriptor is literally the path the test built.
func tempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
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
	dir := tempDir(t)
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
	dir := tempDir(t)
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
	dir := tempDir(t)
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
// behaviour that must survive: a descriptor procfs cannot answer for (closed,
// task gone) cannot contradict the stash, so the stashed name is used.
func TestOpenByHandleAtFallsBackToTheStashWhenUnverifiable(t *testing.T) {
	feed := newHandleFeed(t)
	feed.nameToHandle("/tmp/handle_stash.txt")
	if got := feed.openByHandle(1 << 20).File.Name(); got != "/tmp/handle_stash.txt" {
		t.Fatalf("unverifiable fd row named %q, want the stashed name", got)
	}
	if _, ok := feed.el.pendingHandleState().peek(feed.pid); ok {
		t.Fatal("an unverifiable stash is used and must be consumed")
	}
}

// TestOpenByHandleAtSameDeletedFileKeepsTheStashedName: the file is unlinked
// after its handle was taken (the classic use of handles). The stashed path is
// gone, procfs says "<path> (deleted)", and the two are the same name, so the
// stashed spelling is the clean name to show.
func TestOpenByHandleAtSameDeletedFileKeepsTheStashedName(t *testing.T) {
	dir := tempDir(t)
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
	if _, ok := feed.el.pendingHandleState().peek(feed.pid); ok {
		t.Fatal("a matching stash must be consumed")
	}
}

// TestOpenByHandleAtDeletedStashButOtherHandleOpened is the gap the inode check
// alone left: the stashed file no longer exists, so it cannot be stat'ed, yet
// the descriptor is demonstrably another file. The row must be named from
// procfs and the stash kept for its own open.
func TestOpenByHandleAtDeletedStashButOtherHandleOpened(t *testing.T) {
	dir := tempDir(t)
	gone := writeHandleFile(t, dir, "gone")
	other := writeHandleFile(t, dir, "other")
	fdOther := openHandleFd(t, other)
	if err := os.Remove(gone); err != nil {
		t.Fatal(err)
	}

	feed := newHandleFeed(t)
	feed.nameToHandle(gone)
	if got := feed.openByHandle(fdOther).File.Name(); got != other {
		t.Fatalf("row named %q, want procfs's %q, not the deleted stash", got, other)
	}
	if got, ok := feed.el.pendingHandleState().peek(feed.pid); !ok || got != gone {
		t.Fatalf("stash = %q (ok=%v), want %q kept for its own open", got, ok, gone)
	}
}

// TestOpenByHandleAtRenamedStash: the stashed path was renamed away after the
// handle was taken. Opening the other handle is a mismatch (procfs name); so is
// opening the renamed file itself, where procfs simply reports its new name.
func TestOpenByHandleAtRenamedStash(t *testing.T) {
	dir := tempDir(t)
	oldPath := writeHandleFile(t, dir, "old")
	other := writeHandleFile(t, dir, "other")
	fdOld := openHandleFd(t, oldPath)
	fdOther := openHandleFd(t, other)
	newPath := filepath.Join(dir, "renamed")
	if err := os.Rename(oldPath, newPath); err != nil {
		t.Fatal(err)
	}

	feed := newHandleFeed(t)
	feed.nameToHandle(oldPath)
	if got := feed.openByHandle(fdOther).File.Name(); got != other {
		t.Errorf("other handle row named %q, want %q", got, other)
	}
	if got := feed.openByHandle(fdOld).File.Name(); got != newPath {
		t.Errorf("renamed file row named %q, want its current name %q", got, newPath)
	}
}

// TestOpenByHandleAtDifferentFileAtStashedPath models a mount namespace whose
// view differs from the task's (a container's /etc/passwd): ior sees a file at
// the stashed path, but it is not the descriptor's inode. Procfs wins, exactly
// as for every other fd row ior resolves.
func TestOpenByHandleAtDifferentFileAtStashedPath(t *testing.T) {
	dir := tempDir(t)
	visible := writeHandleFile(t, dir, "passwd")
	real := writeHandleFile(t, dir, "container-passwd")
	fd := openHandleFd(t, real)

	feed := newHandleFeed(t)
	feed.nameToHandle(visible)
	if got := feed.openByHandle(fd).File.Name(); got != real {
		t.Fatalf("row named %q, want procfs's %q", got, real)
	}
}

// TestOpenByHandleAtRelativeStash: a relative stash (AT_FDCWD, relative name)
// means nothing against ior's own working directory, so it is never trusted
// over procfs, even when ior's directory holds a same-named file.
func TestOpenByHandleAtRelativeStash(t *testing.T) {
	dir := tempDir(t)
	real := writeHandleFile(t, dir, "real")
	fd := openHandleFd(t, real)
	t.Chdir(dir)
	writeHandleFile(t, dir, "rel.txt") // a decoy in ior's cwd

	feed := newHandleFeed(t)
	feed.nameToHandle("rel.txt")
	if got := feed.openByHandle(fd).File.Name(); got != real {
		t.Fatalf("row named %q, want procfs's absolute %q", got, real)
	}
}

// TestOpenByHandleAtEmptyPathStash: name_to_handle_at(dirfd, "", AT_EMPTY_PATH)
// stashes the descriptor's resolved path, which then verifies normally.
func TestOpenByHandleAtEmptyPathStash(t *testing.T) {
	dir := tempDir(t)
	target := writeHandleFile(t, dir, "target")
	dirfd := openHandleFd(t, target)
	fd := openHandleFd(t, target)

	feed := newHandleFeed(t)
	feed.nameToHandleEmptyPath(dirfd)
	if got, ok := feed.el.pendingHandleState().peek(feed.pid); !ok || got != target {
		t.Fatalf("AT_EMPTY_PATH stash = %q (ok=%v), want %q", got, ok, target)
	}
	if got := feed.openByHandle(fd).File.Name(); got != target {
		t.Fatalf("row named %q, want %q", got, target)
	}
	if _, ok := feed.el.pendingHandleState().peek(feed.pid); ok {
		t.Fatal("a matching AT_EMPTY_PATH stash must be consumed")
	}
}

// TestOpenByHandleAtSymlinkHandleFd: a handle taken of the symlink itself (no
// AT_SYMLINK_FOLLOW) opens, with O_PATH, to a descriptor on the symlink. The
// stashed link path must not be reported as a mismatch.
func TestOpenByHandleAtSymlinkHandleFd(t *testing.T) {
	dir := tempDir(t)
	target := writeHandleFile(t, dir, "target")
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(link, unix.O_PATH|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatalf("O_PATH open of symlink: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })

	feed := newHandleFeed(t)
	feed.nameToHandle(link)
	got := feed.openByHandle(fd).File.Name()
	if got != link {
		t.Fatalf("row named %q, want the link %q", got, link)
	}
	if _, ok := feed.el.pendingHandleState().peek(feed.pid); ok {
		t.Fatal("the symlink stash must verify as a match and be consumed")
	}
}

func TestClassifyHandlePath(t *testing.T) {
	dir := tempDir(t)
	a := writeHandleFile(t, dir, "a")
	b := writeHandleFile(t, dir, "b")
	fd := openHandleFd(t, a)
	pid := uint32(os.Getpid())
	live := probeHandleFd(pid, int32(fd))
	closed := probeHandleFd(pid, 1<<20)

	deleted := writeHandleFile(t, dir, "deleted")
	fdDeleted := openHandleFd(t, deleted)
	if err := os.Remove(deleted); err != nil {
		t.Fatal(err)
	}
	deadFile := probeHandleFd(pid, int32(fdDeleted))

	tests := []struct {
		name  string
		probe handleFdProbe
		path  string
		want  handleVerdict
	}{
		{"same file", live, a, handleMatches},
		{"different file", live, b, handleMismatch},
		{"missing path, live fd is another file", live, filepath.Join(dir, "nope"), handleMismatch},
		{"empty path", live, "", handleUnverified},
		{"closed fd", closed, a, handleUnverified},
		{"closed fd, missing path", closed, filepath.Join(dir, "nope"), handleUnverified},
		{"relative path", live, "a", handleMismatch},
		{"deleted file, same name", deadFile, deleted, handleMatches},
		{"deleted file, other name", deadFile, a, handleMismatch},
		{"deleted file, missing other name", deadFile, filepath.Join(dir, "nope"), handleMismatch},
	}
	for _, tt := range tests {
		if got := classifyHandlePath(tt.probe, tt.path); got != tt.want {
			t.Errorf("%s: classifyHandlePath = %d, want %d", tt.name, got, tt.want)
		}
	}
}

// TestProcFdFileWhenProcfsIsUnreadableAfterMismatch: the stat said "a different
// file" but the readlink of the same descriptor failed (closed in between). The
// row must not borrow the stash; it is unnamed and carries the event's flags.
func TestProcFdFileWhenProcfsIsUnreadableAfterMismatch(t *testing.T) {
	dir := tempDir(t)
	a := writeHandleFile(t, dir, "a")
	b := writeHandleFile(t, dir, "b")
	info, err := os.Stat(a)
	if err != nil {
		t.Fatal(err)
	}
	probe := handleFdProbe{info: info, linkErr: os.ErrNotExist}
	if got := classifyHandlePath(probe, b); got != handleMismatch {
		t.Fatalf("verdict = %d, want mismatch", got)
	}

	// A fd number nothing has open, so the fresh procfs lookup fails too.
	got := procFdFile(&probe, uint32(os.Getpid()), 1<<20, syscall.O_WRONLY)
	if got.Name() != "" {
		t.Errorf("unreadable procfs row named %q, want an empty name", got.Name())
	}
	if int32(got.Flags()) != syscall.O_WRONLY {
		t.Errorf("flags = %d, want the event's %d", got.Flags(), syscall.O_WRONLY)
	}
}

// TestProcFdFileUsesTheProbedLinkText pins the TOCTOU fix: when the probe
// already read the link, the row carries exactly that text, without a second
// readlink that could see another file.
func TestProcFdFileUsesTheProbedLinkText(t *testing.T) {
	dir := tempDir(t)
	a := writeHandleFile(t, dir, "a")
	fd := openHandleFd(t, a)
	probe := handleFdProbe{target: "/probed/elsewhere"}
	got := procFdFile(&probe, uint32(os.Getpid()), int32(fd), syscall.O_RDONLY)
	if got.Name() != "/probed/elsewhere" {
		t.Fatalf("name = %q, want the probed link text, not a fresh readlink", got.Name())
	}
}
