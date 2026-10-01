package internal

import (
	"os"
	"syscall"
	"testing"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

// handleFailFeed drives name_to_handle_at / open_by_handle_at records through
// consumeRaw - the loop's real per-record step - so the tests observe what a
// run reports: the emitted rows (through the print callback) and the
// "syscalls after filter" counter, not just what the exit handler returned.
type handleFailFeed struct {
	t     *testing.T
	el    *eventLoop
	pairs chan *event.Pair
	rows  []*event.Pair
	pid   uint32
	time  uint64
}

func newHandleFailFeed(t *testing.T, filter globalfilter.Filter) *handleFailFeed {
	t.Helper()
	f := &handleFailFeed{
		t:     t,
		el:    mustNewEventLoop(t, eventLoopConfig{commResolver: newHermeticCommResolver()}),
		pairs: make(chan *event.Pair, 1),
		pid:   uint32(os.Getpid()),
		time:  defaulTime,
	}
	f.el.SetFilter(filter)
	f.el.SetPrintCallback(func(ep *event.Pair) { f.rows = append(f.rows, ep) })
	return f
}

func (f *handleFailFeed) consume(raw []byte) {
	f.el.consumeRaw(raw, f.pairs, nil)
}

// nameToHandle feeds one successful name_to_handle_at(pathname).
func (f *handleFailFeed) nameToHandle(pathname string) {
	f.t.Helper()
	_, enter := makeEnterPathEvent(f.t, f.time, f.pid, f.pid, pathname, types.SYS_ENTER_NAME_TO_HANDLE_AT)
	_, exit := makeExitRetEvent(f.t, f.time+1, f.pid, f.pid, types.SYS_EXIT_NAME_TO_HANDLE_AT, 0)
	f.time += 10
	f.consume(enter)
	f.consume(exit)
}

// openByHandle feeds one open_by_handle_at that returned ret.
func (f *handleFailFeed) openByHandle(ret int64) {
	f.t.Helper()
	_, enter := makeEnterOpenByHandleAtEvent(f.t, f.time, f.pid, f.pid, syscall.O_RDONLY)
	_, exit := makeExitRetEvent(f.t, f.time+1, f.pid, f.pid, types.SYS_EXIT_OPEN_BY_HANDLE_AT, ret)
	f.time += 10
	f.consume(enter)
	f.consume(exit)
}

// onlyRow asserts that exactly one row was emitted and counted, and returns it.
func (f *handleFailFeed) onlyRow() *event.Pair {
	f.t.Helper()
	if len(f.rows) != 1 {
		f.t.Fatalf("emitted %d open_by_handle_at rows, want 1", len(f.rows))
	}
	if f.el.numSyscallsAfterFilter != 1 {
		f.t.Fatalf("syscalls after filter = %d, want 1", f.el.numSyscallsAfterFilter)
	}
	return f.rows[0]
}

func pairRet(t *testing.T, ep *event.Pair) int64 {
	t.Helper()
	retEv, ok := ep.ExitEv.(*types.RetEvent)
	if !ok {
		t.Fatalf("exit event is %T, want *types.RetEvent", ep.ExitEv)
	}
	return retEv.Ret
}

// TestFailedOpenByHandleAtEmitsAnErrorRow is the regression for task eq2: a
// failed open_by_handle_at used to be recycled in the exit handler, so EPERM
// (no CAP_DAC_READ_SEARCH), EBADF (bad mount_fd) and ESTALE (file gone) calls
// produced no row, no error and no "syscalls after filter" count. Each must now
// be one error row named after the thread's stashed name_to_handle_at path (or
// unnamed without one), carrying no descriptor, exactly like a failed open.
func TestFailedOpenByHandleAtEmitsAnErrorRow(t *testing.T) {
	const stashed = "/tmp/eq2-handle.txt"
	for _, errno := range []syscall.Errno{syscall.EPERM, syscall.EBADF, syscall.ESTALE} {
		for _, withStash := range []bool{true, false} {
			name := errno.Error() + map[bool]string{true: "/stashed", false: "/no stash"}[withStash]
			t.Run(name, func(t *testing.T) {
				feed := newHandleFailFeed(t, globalfilter.Filter{})
				want := ""
				if withStash {
					feed.nameToHandle(stashed)
					want = stashed
				}
				feed.openByHandle(-int64(errno))
				ep := feed.onlyRow()
				assertFailedHandleRow(t, ep, errno, want)
				if _, ok := feed.el.pendingHandleState().peek(feed.pid); ok {
					t.Fatal("a failed open_by_handle_at must consume the thread's stash")
				}
			})
		}
	}
}

func assertFailedHandleRow(t *testing.T, ep *event.Pair, errno syscall.Errno, wantName string) {
	t.Helper()
	if !ep.Is(types.SYS_ENTER_OPEN_BY_HANDLE_AT) {
		t.Fatalf("row is %s, want open_by_handle_at", ep.EnterEv.GetTraceId().Name())
	}
	if got := pairRet(t, ep); got != -int64(errno) || !event.IsErrorRet(got) {
		t.Fatalf("row ret = %d, want the error -%d (%v)", got, int64(errno), errno)
	}
	if ep.File == nil {
		t.Fatal("failed row carries no file; want a descriptor-less pathname like a failed open")
	}
	if got := ep.File.Name(); got != wantName {
		t.Fatalf("failed row named %q, want %q", got, wantName)
	}
	if fd, ok := ep.FileDescriptor(); ok {
		t.Fatalf("failed row reports fd %d, want none", fd)
	}
}

// TestFailedOpenByHandleAtRegistersNoFd: a failed call returns no descriptor,
// so the fd table must not gain an entry - not even for the number the errno
// would be if it were mistaken for an fd.
func TestFailedOpenByHandleAtRegistersNoFd(t *testing.T) {
	feed := newHandleFailFeed(t, globalfilter.Filter{})
	feed.nameToHandle("/tmp/eq2-handle.txt")
	before := len(feed.el.fdState().files)
	feed.openByHandle(-int64(syscall.EBADF))
	if after := len(feed.el.fdState().files); after != before {
		t.Fatalf("fd table grew from %d to %d entries after a failed open_by_handle_at", before, after)
	}
}

// TestSuccessfulOpenByHandleAtIsUnchanged is the negative control: a call that
// returns a descriptor is still a descriptor row, named and registered in the
// fd table as before the fix.
func TestSuccessfulOpenByHandleAtIsUnchanged(t *testing.T) {
	dir := tempDir(t)
	path := writeHandleFile(t, dir, "ok.txt")
	fd := openHandleFd(t, path)

	feed := newHandleFailFeed(t, globalfilter.Filter{})
	feed.nameToHandle(path)
	feed.openByHandle(int64(fd))
	ep := feed.onlyRow()

	if got := ep.File.Name(); got != path {
		t.Fatalf("row named %q, want %q", got, path)
	}
	if got, ok := ep.FileDescriptor(); !ok || got != int32(fd) {
		t.Fatalf("row fd = %d (ok=%v), want %d", got, ok, fd)
	}
	if _, isFd := ep.File.(*file.FdFile); !isFd {
		t.Fatalf("row file is %T, want *file.FdFile", ep.File)
	}
	tracked, ok := feed.el.fdState().get(int32(fd), feed.pid)
	if !ok || tracked.Name() != path {
		t.Fatalf("fd table entry = %v (ok=%v), want %q", tracked, ok, path)
	}
}

// TestFailedOpenByHandleAtFilterDimensions pins how the pair filter treats a
// failed row, which has a (stashed) path but no descriptor - the same shape as
// a failed open: -path matches the stash, -fd never matches, and an
// errors-only filter keeps it.
func TestFailedOpenByHandleAtFilterDimensions(t *testing.T) {
	const stashed = "/tmp/eq2-filtered.txt"
	tests := []struct {
		name   string
		filter globalfilter.Filter
		kept   bool
	}{
		{"path matches stash", testFilter("", "eq2-filtered"), true},
		{"path does not match", testFilter("", "something-else"), false},
		{"fd filter", globalfilter.Filter{FD: globalfilter.NewEqFilter(3)}, false},
		{"errors only", globalfilter.Filter{ErrorsOnly: true}, true},
		{"ret equals errno", globalfilter.Filter{RetVal: globalfilter.NewEqFilter(-int64(syscall.EBADF))}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			feed := newHandleFailFeed(t, tc.filter)
			feed.nameToHandle(stashed)
			feed.openByHandle(-int64(syscall.EBADF))
			if got := len(feed.rows); got != map[bool]int{true: 1, false: 0}[tc.kept] {
				t.Fatalf("emitted %d rows, want kept=%v", got, tc.kept)
			}
			if got := int(feed.el.numSyscallsAfterFilter); got != len(feed.rows) {
				t.Fatalf("syscalls after filter = %d, emitted %d", got, len(feed.rows))
			}
		})
	}
}
