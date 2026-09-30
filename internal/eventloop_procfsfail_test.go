package internal

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

// Task ir2: resolve used to cache a FAILED procfs lookup (empty name, unknown
// flags) exactly like a successful one, and an EBADF exit left the entry in
// place. After a close loop that answers EBADF for every number, a descriptor
// later created on one of those numbers by an untraced syscall (pipe(2),
// socketpair(2)) therefore stayed nameless with O_NONE for good, while procfs
// named it correctly.
//
// The tests use this process's real fd table and pid so every procfs read is
// genuine: a fake pid would fail every lookup and could not show recovery.

// freeFdNumber returns a descriptor number that is not open in this process:
// a high number is taken with F_DUPFD and closed again. The number is picked
// from the real RLIMIT_NOFILE (F_DUPFD fails with EINVAL at or above it, and a
// container or CI job can run with a limit of 256 or less); the test is
// skipped, with the reason, when the limit leaves no room.
func freeFdNumber(t *testing.T) int32 {
	t.Helper()
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &lim); err != nil {
		t.Fatalf("getrlimit NOFILE: %v", err)
	}
	const minFree = 64 // the go test runtime keeps a few dozen descriptors open
	if lim.Cur < minFree+1 {
		t.Skipf("RLIMIT_NOFILE soft limit %d leaves no free descriptor number to use", lim.Cur)
	}
	start := min(700, int(lim.Cur)-1)
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open /dev/null: %v", err)
	}
	defer func() { _ = f.Close() }()
	n, err := unix.FcntlInt(f.Fd(), unix.F_DUPFD_CLOEXEC, start)
	if err != nil {
		t.Fatalf("F_DUPFD at %d (limit %d): %v", start, lim.Cur, err)
	}
	if err := unix.Close(n); err != nil {
		t.Fatalf("close %d: %v", n, err)
	}
	return int32(n)
}

// placePipeOn makes fd n name a pipe end without any traced syscall, the way
// an untraced pipe(2) would, and returns the procfs name it then has.
func placePipeOn(t *testing.T, n int32) string {
	t.Helper()
	var p [2]int
	if err := unix.Pipe2(p[:], unix.O_CLOEXEC); err != nil {
		t.Fatalf("pipe2: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(p[0]); _ = unix.Close(p[1]) })
	if err := unix.Dup3(p[0], int(n), unix.O_CLOEXEC); err != nil {
		t.Fatalf("dup3 onto %d: %v", n, err)
	}
	t.Cleanup(func() { _ = unix.Close(int(n)) })
	name, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(n)))
	if err != nil {
		t.Fatalf("readlink: %v", err)
	}
	return name
}

func TestResolveDoesNotCacheAFailedProcfsLookup(t *testing.T) {
	pid := uint32(os.Getpid())
	n := freeFdNumber(t)
	el := mustNewEventLoop(t, eventLoopConfig{})

	first := el.fdState().resolve(n, pid)
	if first.Name() != "" {
		t.Fatalf("closed fd %d resolved to %q, want no name", n, first.Name())
	}
	if _, ok := el.fdState().cachedProcFdFile(n, pid); ok {
		t.Fatal("a failed procfs lookup was cached")
	}

	want := placePipeOn(t, n)
	second := el.fdState().resolve(n, pid)
	if second.Name() != want || !strings.HasPrefix(want, "pipe:[") {
		t.Fatalf("fd %d resolved to %q after the untraced pipe appeared, want %q", n, second.Name(), want)
	}
	if fdf, ok := second.(*file.FdFile); !ok || fdf.Flags() == file.Flags(-1) {
		t.Fatalf("recovered resolution kept unknown flags: %v", second)
	}
}

// A successful lookup is still cached: the fix must not turn every event on a
// pre-existing descriptor into a procfs read.
func TestResolveStillCachesASuccessfulProcfsLookup(t *testing.T) {
	pid := uint32(os.Getpid())
	n := freeFdNumber(t)
	want := placePipeOn(t, n)
	el := mustNewEventLoop(t, eventLoopConfig{})

	first := el.fdState().resolve(n, pid)
	if first.Name() != want {
		t.Fatalf("resolved %q, want %q", first.Name(), want)
	}
	cached, ok := el.fdState().cachedProcFdFile(n, pid)
	if !ok || cached != first {
		t.Fatalf("successful lookup not cached: cached=%v ok=%v", cached, ok)
	}
}

// feedRealPidFdPair feeds one fd syscall pair attributed to this process.
func feedRealPidFdPair(t *testing.T, el *eventLoop, enter, exit types.TraceId, fd int32, ret int64) *event.Pair {
	t.Helper()
	pid := uint32(os.Getpid())
	_, enterRaw := makeEnterFdEvent(t, defaulTime, pid, execCommTid, fd, enter)
	_, exitRaw := makeExitRetEvent(t, defaulTime+openPairLatency, pid, execCommTid, exit, ret)
	return feedRawPair(t, el, enterRaw, exitRaw)
}

// TestEBADFCloseLoopThenUntracedPipeIsNamed is the live scenario: close()
// answers EBADF for a number, then an untraced pipe() lands on it and later
// reads must report the pipe.
func TestEBADFCloseLoopThenUntracedPipeIsNamed(t *testing.T) {
	n := freeFdNumber(t)
	el := newFilteredEventLoop(t, globalfilter.Filter{})

	for range 3 {
		ep := feedRealPidFdPair(t, el, types.SYS_ENTER_CLOSE, types.SYS_EXIT_CLOSE, n, -int64(syscall.EBADF))
		if ep == nil {
			t.Fatal("failed close row must be emitted")
		}
		ep.Recycle()
	}

	want := placePipeOn(t, n)
	ep := feedRealPidFdPair(t, el, types.SYS_ENTER_READ, types.SYS_EXIT_READ, n, 1)
	if ep == nil {
		t.Fatal("read row must be emitted")
	}
	defer ep.Recycle()
	if ep.File.Name() != want {
		t.Fatalf("read on the pipe that replaced a closed number reports %q, want %q", ep.File.Name(), want)
	}
}

// An EBADF answer proves a procfs-resolved entry stale and evicts it, but not
// the fd-table entry (traced syscalls own that, and a reordered exit must not
// erase a correct name); any other errno leaves the cache alone.
func TestEBADFEvictsOnlyTheProcfsCacheEntry(t *testing.T) {
	pid := uint32(os.Getpid())
	el := newFilteredEventLoop(t, globalfilter.Filter{})
	const cachedFd, trackedFd int32 = 801, 802
	el.fdState().setProcFdCache(cachedFd, pid, file.NewFd(cachedFd, "stale-procfs", syscall.O_RDONLY))
	el.fdState().set(trackedFd, pid, file.NewFd(trackedFd, "traced-open", syscall.O_RDONLY))

	// Negative: a non-EBADF failure keeps the cached entry.
	if ep := feedRealPidFdPair(t, el, types.SYS_ENTER_READ, types.SYS_EXIT_READ, cachedFd, -int64(syscall.EAGAIN)); ep != nil {
		ep.Recycle()
	}
	verifyProcFdCached(t, el, pid, cachedFd)

	for _, fd := range []int32{cachedFd, trackedFd} {
		if ep := feedRealPidFdPair(t, el, types.SYS_ENTER_READ, types.SYS_EXIT_READ, fd, -int64(syscall.EBADF)); ep != nil {
			ep.Recycle()
		}
	}
	verifyProcFdNotCached(t, el, pid, cachedFd)
	verifyFileDescriptor(t, el, pid, trackedFd, "traced-open")
}

// ebadfHandlerCase feeds one enter/exit pair of a fd-resolving handler family
// whose descriptor argument is fd and whose exit carries ret.
type ebadfHandlerCase struct {
	name string
	feed func(t *testing.T, el *eventLoop, fd int32, ret int64) *event.Pair
}

func ebadfHandlerCases() []ebadfHandlerCase {
	pid := uint32(os.Getpid())
	exit := func(t *testing.T, id types.TraceId, ret int64) []byte {
		_, raw := makeExitRetEvent(t, defaulTime+openPairLatency, pid, execCommTid, id, ret)
		return raw
	}
	return []ebadfHandlerCase{
		{"read/handleFdExit", func(t *testing.T, el *eventLoop, fd int32, ret int64) *event.Pair {
			return feedRealPidFdPair(t, el, types.SYS_ENTER_READ, types.SYS_EXIT_READ, fd, ret)
		}},
		{"fcntl/handleFcntlExit", func(t *testing.T, el *eventLoop, fd int32, ret int64) *event.Pair {
			_, enter := makeEnterFcntlEvent(t, defaulTime, pid, execCommTid, uint32(fd), unix.F_GETFD, 0)
			return feedRawPair(t, el, enter, exit(t, types.SYS_EXIT_FCNTL, ret))
		}},
		{"dup3/handleDup3Exit", func(t *testing.T, el *eventLoop, fd int32, ret int64) *event.Pair {
			_, enter := makeEnterDup3Event(t, defaulTime, pid, execCommTid, fd, 0)
			return feedRawPair(t, el, enter, exit(t, types.SYS_EXIT_DUP3, ret))
		}},
		{"mmap/handleMmapExit", func(t *testing.T, el *eventLoop, fd int32, ret int64) *event.Pair {
			_, enter := makeEnterMmapEvent(t, defaulTime, pid, execCommTid, fd, 4096, unix.MAP_PRIVATE)
			return feedRawPair(t, el, enter, exit(t, types.SYS_EXIT_MMAP, ret))
		}},
	}
}

// TestEBADFExitNeverReadsProcfs: EBADF proves the number is not open, so the
// handler must not consult procfs at all. The fd number here IS open in procfs
// (a pipe), which makes a procfs read observable: a row named after it, or a
// procfs-cache entry, means the shortcut is gone. The same pair with a
// successful exit is the control that the procfs path itself is live.
func TestEBADFExitNeverReadsProcfs(t *testing.T) {
	pid := uint32(os.Getpid())
	for _, tc := range ebadfHandlerCases() {
		t.Run(tc.name, func(t *testing.T) {
			n := freeFdNumber(t)
			pipeName := placePipeOn(t, n)
			el := newFilteredEventLoop(t, globalfilter.Filter{})

			ep := tc.feed(t, el, n, -int64(syscall.EBADF))
			if ep == nil {
				t.Fatal("EBADF row must still be emitted")
			}
			if got := ep.File.Name(); got != "" {
				t.Errorf("EBADF row named %q from procfs, want no procfs read", got)
			}
			verifyProcFdNotCached(t, el, pid, n)
			ep.Recycle()

			// Control: a successful exit on the same number does use procfs.
			ok := tc.feed(t, el, n, 0)
			if ok == nil {
				t.Fatal("control row must be emitted")
			}
			defer ok.Recycle()
			if got := ok.File.Name(); got != pipeName {
				t.Errorf("control: successful exit named %q, want %q (procfs path dead?)", got, pipeName)
			}
		})
	}
}

// An EBADF exit still labels the row from the fd table when a traced syscall
// registered the number, and leaves that entry in place.
func TestEBADFExitUsesFdTableEntry(t *testing.T) {
	pid := uint32(os.Getpid())
	for _, tc := range ebadfHandlerCases() {
		t.Run(tc.name, func(t *testing.T) {
			n := freeFdNumber(t)
			el := newFilteredEventLoop(t, globalfilter.Filter{})
			el.fdState().set(n, pid, file.NewFd(n, "traced-open", syscall.O_RDONLY))

			ep := tc.feed(t, el, n, -int64(syscall.EBADF))
			if ep == nil {
				t.Fatal("EBADF row must be emitted")
			}
			defer ep.Recycle()
			if got := ep.File.Name(); got != "traced-open" {
				t.Errorf("EBADF row named %q, want the fd-table name", got)
			}
			verifyFileDescriptor(t, el, pid, n, "traced-open")
		})
	}
}

// resolveOnExit covers every exit kind with a ret field, not only RetEvent:
// accept carries its own payload, and must skip procfs on EBADF too.
func TestResolveOnExitEBADFCoversRetCarriers(t *testing.T) {
	pid := uint32(os.Getpid())
	n := freeFdNumber(t)
	placePipeOn(t, n)
	el := newFilteredEventLoop(t, globalfilter.Filter{})

	for name, exitEv := range map[string]event.Event{
		"RetEvent":    &types.RetEvent{Ret: -int64(syscall.EBADF)},
		"AcceptEvent": &types.AcceptEvent{Ret: -int64(syscall.EBADF)},
	} {
		got := el.resolveOnExit(&event.Pair{ExitEv: exitEv}, n, pid)
		if got.Name() != "" {
			t.Errorf("%s: EBADF resolved %q from procfs", name, got.Name())
		}
	}
	// Negative: another errno, or no exit record, resolves from procfs.
	ok := el.resolveOnExit(&event.Pair{ExitEv: &types.RetEvent{Ret: -int64(syscall.EAGAIN)}}, n, pid)
	if !strings.HasPrefix(ok.Name(), "pipe:[") {
		t.Errorf("EAGAIN exit resolved %q, want the pipe from procfs", ok.Name())
	}
}

// TestEveryFdResolveGoesThroughTheEBADFHelper guards "all fd-resolving
// handlers": a new handler calling fdTracker.resolve directly would put
// the failing-readlink cost back on its EBADF stream. The allowed direct
// callers are the success-only eventfd lookups, the dirfd path resolver (no
// exit record) and resolveOnExit itself; anything else must use resolveOnExit.
func TestEveryFdResolveGoesThroughTheEBADFHelper(t *testing.T) {
	allowed := map[string]int{
		"eventloop_exit.go":         3, // resolveDirfdPath, two success-only eventfd lookups
		"eventloop_procfs_ebadf.go": 1, // resolveOnExit's non-EBADF branch
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Count(string(src), "fdState().resolve("); got != allowed[f] {
			t.Errorf("%s has %d direct fdState().resolve( calls, want %d: use e.resolveOnExit(ep, ...) in exit handlers", f, got, allowed[f])
		}
	}
}
