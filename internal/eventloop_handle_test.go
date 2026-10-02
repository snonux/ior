package internal

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

// testHandle is a file handle as the records carry it: the type and the bytes
// of a struct file_handle.
type testHandle struct {
	handleType int32
	bytes      []byte
}

// Fixture handles. A and B differ in their bytes, as two files of one
// filesystem do (inode number and generation); defaultTestHandle is the one
// the helpers of other test files use when the handle is not their subject.
var (
	testHandleA       = testHandle{handleType: 1, bytes: []byte{0x11, 0, 0, 0, 0xa1, 0xa2, 0xa3, 0xa4}}
	testHandleB       = testHandle{handleType: 1, bytes: []byte{0x22, 0, 0, 0, 0xb1, 0xb2, 0xb3, 0xb4}}
	defaultTestHandle = testHandle{handleType: 1, bytes: []byte{0x33, 0, 0, 0, 0xc1, 0xc2, 0xc3, 0xc4}}
)

// fHandle returns the handle bytes in a record's fixed field, zero padded as
// the BPF side leaves it.
func (h testHandle) fHandle() (out [types.IOR_MAX_HANDLE_SZ]byte) {
	copy(out[:], h.bytes)
	return out
}

// key is the tracker key the event loop must derive from the handle.
func (h testHandle) key() handleKey {
	return handleKey{handleType: h.handleType, size: uint32(len(h.bytes)), bytes: h.fHandle()}
}

// makeFileHandleEvent builds the control record a successful
// name_to_handle_at emits for handle h. time must be the time of the exit
// record that follows it.
func makeFileHandleEvent(t *testing.T, time uint64, pid, tid uint32, h testHandle) (types.FileHandleEvent, []byte) {
	t.Helper()
	ev := types.FileHandleEvent{
		EventType:    types.FILE_HANDLE_EVENT,
		TraceId:      types.SYS_ENTER_NAME_TO_HANDLE_AT,
		Time:         time,
		Pid:          pid,
		Tid:          tid,
		HandleStatus: types.FILE_HANDLE_OK,
		HandleBytes:  uint32(len(h.bytes)),
		HandleType:   h.handleType,
		FHandle:      h.fHandle(),
	}
	return ev, eventBytes(t, &ev)
}

// makeEnterOpenByHandleEvent builds the enter record of an
// open_by_handle_at(mount_fd, h, flags).
func makeEnterOpenByHandleEvent(t *testing.T, time uint64, pid, tid uint32, flags int32, h testHandle) (types.OpenByHandleAtEvent, []byte) {
	t.Helper()
	ev := types.OpenByHandleAtEvent{
		EventType:    types.ENTER_OPEN_BY_HANDLE_AT_EVENT,
		TraceId:      types.SYS_ENTER_OPEN_BY_HANDLE_AT,
		Time:         time,
		Pid:          pid,
		Tid:          tid,
		Flags:        flags,
		HandleStatus: types.FILE_HANDLE_OK,
		HandleBytes:  uint32(len(h.bytes)),
		HandleType:   h.handleType,
		FHandle:      h.fHandle(),
	}
	return ev, eventBytes(t, &ev)
}

// makeNameToHandleAtRecords builds the three records of a successful
// name_to_handle_at(pathname) that returned handle h, in ring order: the
// enter at time, then the handle record and the exit, which share one time
// as the BPF exit handler stamps both with its single clock read.
func makeNameToHandleAtRecords(t *testing.T, time uint64, pid, tid uint32, pathname string, h testHandle) [][]byte {
	t.Helper()
	_, enter := makeEnterPathEvent(t, time, pid, tid, pathname, types.SYS_ENTER_NAME_TO_HANDLE_AT)
	_, handle := makeFileHandleEvent(t, time+100, pid, tid, h)
	_, exit := makeExitRetEvent(t, time+100, pid, tid, types.SYS_EXIT_NAME_TO_HANDLE_AT, 0)
	return [][]byte{enter, handle, exit}
}

// handleFeed drives name_to_handle_at / open_by_handle_at records through
// consumeRaw - the loop's real per-record step - so the tests observe what a
// run reports: the emitted rows (through the print callback) and the
// "syscalls after filter" counter, not just what the exit handler returned.
// pid and tid are the task the next call is made by; tests change them to
// model another thread or process.
type handleFeed struct {
	t     *testing.T
	el    *eventLoop
	pairs chan *event.Pair
	rows  []*event.Pair
	pid   uint32
	tid   uint32
	time  uint64
}

// newHandleFeed builds a feed whose calls are made by a task that does not
// exist on this host, so that any name procfs is asked for is unavailable and
// a row can only be named by what the loop itself knows.
func newHandleFeed(t *testing.T, filter globalfilter.Filter) *handleFeed {
	t.Helper()
	f := &handleFeed{
		t:     t,
		el:    mustNewEventLoop(t, eventLoopConfig{commResolver: newHermeticCommResolver()}),
		pairs: make(chan *event.Pair, 1),
		pid:   defaultPid,
		tid:   defaultTid,
		time:  defaulTime,
	}
	f.el.SetFilter(filter)
	f.el.SetPrintCallback(func(ep *event.Pair) { f.rows = append(f.rows, ep) })
	return f
}

// newLiveHandleFeed is newHandleFeed for calls made by this test process, so
// that the descriptors the test opens are what procfs shows for them.
func newLiveHandleFeed(t *testing.T) *handleFeed {
	t.Helper()
	f := newHandleFeed(t, globalfilter.Filter{})
	f.pid = uint32(os.Getpid())
	f.tid = f.pid
	return f
}

func (f *handleFeed) consume(raws ...[]byte) {
	for _, raw := range raws {
		f.el.consumeRaw(raw, f.pairs, nil)
	}
}

// nameToHandle feeds one successful name_to_handle_at(pathname) that returned
// handle h.
func (f *handleFeed) nameToHandle(pathname string, h testHandle) {
	f.t.Helper()
	f.consume(makeNameToHandleAtRecords(f.t, f.time, f.pid, f.tid, pathname, h)...)
	f.time += 1000
}

// openByHandle feeds one open_by_handle_at of handle h that returned ret, and
// returns the row it emitted (nil when the filter dropped it).
func (f *handleFeed) openByHandle(h testHandle, ret int64) *event.Pair {
	f.t.Helper()
	_, enter := makeEnterOpenByHandleEvent(f.t, f.time, f.pid, f.tid, syscall.O_RDONLY, h)
	return f.finishOpen(enter, ret)
}

// finishOpen feeds an open_by_handle_at enter record and its exit with ret.
func (f *handleFeed) finishOpen(enter []byte, ret int64) *event.Pair {
	f.t.Helper()
	_, exit := makeExitRetEvent(f.t, f.time+100, f.pid, f.tid, types.SYS_EXIT_OPEN_BY_HANDLE_AT, ret)
	f.time += 1000
	before := len(f.rows)
	f.consume(enter, exit)
	if len(f.rows) == before {
		return nil
	}
	return f.rows[len(f.rows)-1]
}

// assertHandleRow checks an open_by_handle_at row that returned descriptor fd:
// its name, its descriptor and the fd table entry behind it, which every later
// row on that descriptor is named from.
func assertHandleRow(t *testing.T, feed *handleFeed, ep *event.Pair, fd int32, wantName string) {
	t.Helper()
	if ep == nil {
		t.Fatal("open_by_handle_at emitted no row")
	}
	if !ep.Is(types.SYS_ENTER_OPEN_BY_HANDLE_AT) {
		t.Fatalf("row is %s, want open_by_handle_at", ep.EnterEv.GetTraceId().Name())
	}
	if got := ep.File.Name(); got != wantName {
		t.Fatalf("row named %q, want %q", got, wantName)
	}
	if got, ok := ep.FileDescriptor(); !ok || got != fd {
		t.Fatalf("row fd = %d (ok=%v), want %d", got, ok, fd)
	}
	tracked, ok := feed.el.fdState().get(fd, feed.pid)
	if !ok || tracked.Name() != wantName {
		t.Fatalf("fd table entry (pid=%d, fd=%d) = %v (ok=%v), want %q", feed.pid, fd, tracked, ok, wantName)
	}
}

// TestOpenByHandleAtIsNamedByItsHandle is the core of task k03: a thread that
// holds several handles and opens them in any order gets each row named after
// the file its own handle belongs to. The tid-keyed stash this replaced kept
// only the thread's last name_to_handle_at, so the first open below was named
// after /b (or after whatever procfs showed under the number).
func TestOpenByHandleAtIsNamedByItsHandle(t *testing.T) {
	feed := newHandleFeed(t, globalfilter.Filter{})
	feed.nameToHandle("/data/a.txt", testHandleA)
	feed.nameToHandle("/data/b.txt", testHandleB)

	assertHandleRow(t, feed, feed.openByHandle(testHandleA, 70), 70, "/data/a.txt")
	assertHandleRow(t, feed, feed.openByHandle(testHandleB, 71), 71, "/data/b.txt")
	if got := feed.el.numSyscallsAfterFilter; got != 2 {
		t.Fatalf("syscalls after filter = %d, want 2 (name_to_handle_at is never a row)", got)
	}
}

// TestOpenByHandleAtFlagsAreTheCalls: a handle-named descriptor carries the
// flags the call asked for, on the row and in the fd table.
func TestOpenByHandleAtFlagsAreTheCalls(t *testing.T) {
	feed := newHandleFeed(t, globalfilter.Filter{})
	feed.nameToHandle("/data/a.txt", testHandleA)
	_, enter := makeEnterOpenByHandleEvent(t, feed.time, feed.pid, feed.tid, syscall.O_RDWR|syscall.O_APPEND, testHandleA)
	ep := feed.finishOpen(enter, 70)
	assertHandleRow(t, feed, ep, 70, "/data/a.txt")

	fdFile, isFd := ep.File.(*file.FdFile)
	if !isFd {
		t.Fatalf("row file is %T, want *file.FdFile", ep.File)
	}
	if got, want := fdFile.Flags(), file.Flags(syscall.O_RDWR|syscall.O_APPEND); got != want {
		t.Fatalf("row flags = %v, want the call's %v", got, want)
	}
}

// reusedNumberCase is one way the descriptor number an open_by_handle_at
// returned can be handed on before the event loop looks at it.
type reusedNumberCase struct {
	name string
	// open returns a descriptor of this test process that stands for the
	// newer file under the number.
	open func(t *testing.T, dir string) int
}

func reusedNumberCases() []reusedNumberCase {
	return []reusedNumberCase{
		{"another file with the same flags", func(t *testing.T, dir string) int {
			return openTestFd(t, writeTestFile(t, dir, "other.txt"), syscall.O_RDONLY)
		}},
		{"the directory", func(t *testing.T, dir string) int {
			return openTestFd(t, dir, syscall.O_RDONLY|syscall.O_DIRECTORY)
		}},
		{"a pipe", func(t *testing.T, _ string) int {
			var p [2]int
			if err := syscall.Pipe(p[:]); err != nil {
				t.Fatalf("pipe: %v", err)
			}
			t.Cleanup(func() { _ = syscall.Close(p[0]); _ = syscall.Close(p[1]) })
			return p[0]
		}},
	}
}

func writeTestFile(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func openTestFd(t *testing.T, path string, flags int) int {
	t.Helper()
	fd, err := syscall.Open(path, flags, 0)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	t.Cleanup(func() { _ = syscall.Close(fd) })
	return fd
}

// TestOpenByHandleAtIgnoresWhatTheNumberIsNow pins the residual the task was
// filed for. The event loop handles the exit some time after the call, and a
// task that closed the descriptor has usually handed the number to its next
// open by then. The procfs check that used to arbitrate believed such a newer
// descriptor whenever it had the call's fixed flags - another file opened
// O_RDONLY is exactly that - and named the row and the fd table entry after
// it. With the handle in the record procfs is not asked at all, so the
// descriptor this process really has under the number changes nothing.
func TestOpenByHandleAtIgnoresWhatTheNumberIsNow(t *testing.T) {
	for _, tc := range reusedNumberCases() {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			opened := filepath.Join(dir, "handle.txt")
			feed := newLiveHandleFeed(t)
			feed.nameToHandle(opened, testHandleA)

			fd := int32(tc.open(t, dir))
			assertHandleRow(t, feed, feed.openByHandle(testHandleA, int64(fd)), fd, opened)
		})
	}
}

// TestUnknownHandleIsNamedFromProcfs is the other side: a handle ior never saw
// being taken has no name of its own, so the row falls back to what procfs
// shows under the returned number - the behaviour an open_by_handle_at without
// any stash always had - and stays unnamed when procfs has no answer.
func TestUnknownHandleIsNamedFromProcfs(t *testing.T) {
	dir := t.TempDir()
	other := writeTestFile(t, dir, "other.txt")

	live := newLiveHandleFeed(t)
	live.nameToHandle(filepath.Join(dir, "handle.txt"), testHandleA)
	fd := int32(openTestFd(t, other, syscall.O_RDONLY))
	assertHandleRow(t, live, live.openByHandle(testHandleB, int64(fd)), fd, other)

	absent := newHandleFeed(t, globalfilter.Filter{})
	absent.nameToHandle("/data/a.txt", testHandleA)
	assertHandleRow(t, absent, absent.openByHandle(testHandleB, 70), 70, "")
}

// TestHandleMatchesAcrossThreadsAndProcesses: a handle is valid system-wide
// and passing it on is what the API is for. The name is filed under the
// handle, so the thread or process that opens it need not be the one that
// took it; the tid-keyed stash never matched these.
func TestHandleMatchesAcrossThreadsAndProcesses(t *testing.T) {
	feed := newHandleFeed(t, globalfilter.Filter{})
	feed.nameToHandle("/data/a.txt", testHandleA)

	feed.tid = defaultTid + 1
	assertHandleRow(t, feed, feed.openByHandle(testHandleA, 70), 70, "/data/a.txt")

	feed.pid, feed.tid = defaultPid+100, defaultPid+100
	assertHandleRow(t, feed, feed.openByHandle(testHandleA, 70), 70, "/data/a.txt")
}

// TestHandleNameIsNotConsumedByAnOpen pins the decision that an entry stays
// until it is replaced or evicted: one handle can be opened any number of
// times, and a failed open (here ESTALE, then a retry that works) says
// nothing against the name.
func TestHandleNameIsNotConsumedByAnOpen(t *testing.T) {
	feed := newHandleFeed(t, globalfilter.Filter{})
	feed.nameToHandle("/data/a.txt", testHandleA)

	assertHandleRow(t, feed, feed.openByHandle(testHandleA, 70), 70, "/data/a.txt")
	assertHandleRow(t, feed, feed.openByHandle(testHandleA, 71), 71, "/data/a.txt")

	failed := feed.openByHandle(testHandleA, -int64(syscall.ESTALE))
	assertFailedHandleRow(t, failed, syscall.ESTALE, "/data/a.txt")
	assertHandleRow(t, feed, feed.openByHandle(testHandleA, 72), 72, "/data/a.txt")
}

// TestLatestNameToHandleAtOfAHandleWins: the same handle returned again (the
// file was renamed, or is reached by another hard link) is filed under the
// pathname of the later call, the freshest name ior has for the file.
func TestLatestNameToHandleAtOfAHandleWins(t *testing.T) {
	feed := newHandleFeed(t, globalfilter.Filter{})
	feed.nameToHandle("/data/old-name.txt", testHandleA)
	feed.nameToHandle("/data/new-name.txt", testHandleA)

	assertHandleRow(t, feed, feed.openByHandle(testHandleA, 70), 70, "/data/new-name.txt")
	if got := len(feed.el.handleState().names); got != 1 {
		t.Fatalf("handle tracker holds %d names for one handle, want 1", got)
	}
}
