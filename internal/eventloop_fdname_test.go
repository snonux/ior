package internal

import (
	"os"
	"strings"
	"syscall"
	"testing"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/types"
)

// Task xz2: on a kernel that captures file identities, close's enter record
// carries the last path component of the closed file (fd_name_event), and a
// close row that nothing else can name takes it (eventloop_fdname.go). These
// tests feed the 104-byte record the kernel writes through the loop's own
// decoder table; like the identity tests they use this process's pid, so
// what procfs would say about the number is real.

// feedNamedRow feeds row with the enter record the kernel sends for a file
// that has a last path component: leaf, of real length nameLen.
func feedNamedRow(t *testing.T, el *eventLoop, row identRow, leaf string, nameLen uint32) *event.Pair {
	t.Helper()
	pid := uint32(os.Getpid())
	enter := types.FdNameEvent{EventType: types.ENTER_FD_NAME_EVENT, TraceId: row.enter, Time: row.enterNs,
		Pid: pid, Tid: execCommTid, Fd: row.fd, FileIdent: row.ident, NameLen: nameLen}
	copy(enter.Name[:], leaf)
	enterRaw, err := enter.Bytes()
	if err != nil {
		t.Fatalf("FdNameEvent.Bytes: %v", err)
	}
	_, exitRaw := makeExitRetEvent(t, row.enterNs+openPairLatency, pid, execCommTid, row.exit, row.ret)
	return mustEmit(t, feedRawPair(t, el, enterRaw, exitRaw), row.enter.Name())
}

// feedNamedClose is feedNamedRow for a close of fd that entered at closeNs
// on the file ident, called leaf.
func feedNamedClose(t *testing.T, el *eventLoop, fd int32, ident uint32, closeNs uint64, leaf string) *event.Pair {
	t.Helper()
	return feedNamedRow(t, el, closeRow(fd, ident, closeNs), leaf, uint32(len(leaf)))
}

// requireLeafOf fails unless f is a file named by the last component leaf
// alone: that name, unknown flags, the identity, and the cannot-vouch mark.
func requireLeafOf(t *testing.T, f file.File, leaf string, ident uint32) {
	t.Helper()
	fdf, ok := f.(*file.FdFile)
	if !ok || fdf.Name() != file.LeafPrefix+leaf || fdf.Flags() != file.Flags(-1) || fdf.Ident() != ident ||
		!fdf.NameFromProcFS() {
		t.Fatalf("row file = %v (ident %#x), want %q with unknown flags, identity %#x and the cannot-vouch mark",
			f, identOf(f), file.LeafPrefix+leaf, ident)
	}
}

// The task's case: a descriptor ior never saw opened is closed, and a pipe
// has the number by the time the row is processed. The row is named by the
// component the kernel read, not after the pipe and not left empty.
func TestCloseOfAnUntrackedDescriptorTakesTheCapturedComponent(t *testing.T) {
	pid := uint32(os.Getpid())
	n := freeFdNumber(t)
	el := identLoop(t)
	placePipeOn(t, n)

	ep := feedNamedClose(t, el, n, 4711, bootClockNs(), "app.log")
	requireLeafOf(t, ep.File, "app.log", 4711)
	if got := ep.File.String(); !strings.HasPrefix(got, "*/app.log%(") {
		t.Fatalf("plain rendering = %q, want it to begin with */app.log%%(", got)
	}
	verifyFdNotTracked(t, el, pid, n)
	verifyProcFdNotCached(t, el, pid, n)
}

// A name ior already has says more than a last component and is kept: the
// path of a traced open, and a procfs answer read before the close began.
func TestCapturedComponentNeverReplacesAName(t *testing.T) {
	t.Run("traced open", func(t *testing.T) {
		n := freeFdNumber(t)
		el := identLoop(t)
		feedIdentOpen(t, el, staleOpenName, n, 4711)
		ep := feedNamedClose(t, el, n, 4711, bootClockNs(), "opened-first.txt")
		if got := ep.File.Name(); got != staleOpenName || ep.File.Flags() != file.Flags(syscall.O_RDWR) {
			t.Fatalf("close of a tracked file = %v, want %q with its open flags", ep.File, staleOpenName)
		}
	})
	t.Run("procfs answer read before the close", func(t *testing.T) {
		n := freeFdNumber(t)
		el := identLoop(t)
		closeNs := bootClockNs()
		cacheAnswer(el, n, "/data/cached.txt", 4711, closeNs-1000)
		if got := feedNamedClose(t, el, n, 4711, closeNs, "cached.txt").File.Name(); got != "/data/cached.txt" {
			t.Fatalf("close named %q, want the answer read before it", got)
		}
	})
}

// The rows the identity rules leave unnamed on purpose are named by the
// component: it was read from the closed file itself, so it cannot be of the
// file that took the number.
func TestCapturedComponentNamesWhatTheIdentityRulesRefuse(t *testing.T) {
	closeNs := bootClockNs()
	tests := []struct {
		name   string
		ident  uint32
		readNs uint64
	}{
		{name: "cached answer of another file", ident: 4712, readNs: closeNs - 1000},
		{name: "cached answer read after the close entered", ident: 4711, readNs: closeNs + 1000},
		{name: "cached answer of the reuser, read later", ident: 4712, readNs: closeNs + 1000},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			n := freeFdNumber(t)
			el := identLoop(t)
			cacheAnswer(el, n, "pipe:[77]", tc.ident, tc.readNs)
			requireLeafOf(t, feedNamedClose(t, el, n, 4711, closeNs, "app.log").File, "app.log", 4711)
		})
	}
	t.Run("fd table entry of another file", func(t *testing.T) {
		n := freeFdNumber(t)
		el := identLoop(t)
		feedIdentOpen(t, el, staleOpenName, n, 4712)
		requireLeafOf(t, feedNamedClose(t, el, n, 4711, bootClockNs(), "app.log").File, "app.log", 4711)
		verifyFdNotTracked(t, el, uint32(os.Getpid()), n)
	})
	t.Run("fd table entry bound after the close entered", func(t *testing.T) {
		n := freeFdNumber(t)
		el := identLoop(t)
		closeNs := bootClockNs()
		feedIdentOpenAt(t, el, staleOpenName, n, 4712, closeNs+1000)
		requireLeafOf(t, feedNamedClose(t, el, n, 4711, closeNs, "app.log").File, "app.log", 4711)
		if tracked, ok := el.fdState().get(n, uint32(os.Getpid())); !ok || tracked.Name() != staleOpenName {
			t.Fatalf("the later binding did not survive the close: %v, %v", tracked, ok)
		}
	})
}

// A record that carries no usable component leaves the row as the other
// rules made it: unnamed, with its identity.
func TestCloseWithoutAComponentStaysUnnamed(t *testing.T) {
	tests := []struct {
		name    string
		leaf    string
		nameLen uint32
	}{
		{name: "name the kernel could not read", leaf: "stale-bytes", nameLen: 0},
		{name: "empty name", leaf: "", nameLen: 4},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			n := freeFdNumber(t)
			el := identLoop(t)
			ep := feedNamedRow(t, el, closeRow(n, 4711, bootClockNs()), tc.leaf, tc.nameLen)
			requireUnnamedOf(t, ep.File, 4711)
		})
	}
	t.Run("plain record", func(t *testing.T) {
		n := freeFdNumber(t)
		el := identLoop(t)
		requireUnnamedOf(t, feedIdentRow(t, el, closeRow(n, 4711, bootClockNs())).File, 4711)
	})
}

// A component longer than the record is marked as cut, and the stale bytes
// behind a short one's terminator never reach the name.
func TestCapturedComponentIsCutAndTerminated(t *testing.T) {
	long := strings.Repeat("k", types.IOR_FD_NAME_LENGTH-1)
	n := freeFdNumber(t)
	el := identLoop(t)
	ep := feedNamedRow(t, el, closeRow(n, 4711, bootClockNs()), long, 200)
	if got, want := ep.File.Name(), "*/"+long+types.TruncatedPathSuffix; got != want {
		t.Fatalf("cut component named %q, want %q", got, want)
	}
	ep = feedNamedRow(t, el, closeRow(n, 4711, bootClockNs()), "a.b\x00/etc/shadow", 3)
	if got := ep.File.Name(); got != "*/a.b" {
		t.Fatalf("component with a stale tail named %q, want */a.b", got)
	}
}

// The name is the pair's own: it is not stored for the number, so the next
// call on it - the file that reused the number - starts from nothing.
func TestCapturedComponentIsNotKeptForTheNumber(t *testing.T) {
	pid := uint32(os.Getpid())
	n := freeFdNumber(t)
	el := identLoop(t)
	feedNamedClose(t, el, n, 4711, bootClockNs(), "app.log")
	verifyFdNotTracked(t, el, pid, n)
	verifyProcFdNotCached(t, el, pid, n)

	name, ident := placeFileOn(t, n, "reuser.txt")
	if got := feedIdentRow(t, el, readRow(n, ident)).File.Name(); got != name {
		t.Fatalf("read on the reused number named %q, want %q", got, name)
	}
}

// leafNamed is the whole rule; the cases the loop cannot produce (a pair
// without a resolved file) are pinned here.
func TestLeafNamed(t *testing.T) {
	named := &types.FdEvent{Fd: 7, NameLen: 3}
	copy(named.Name[:], "a.b")
	if got := leafNamed(nil, named, 9); got == nil || got.Name() != "*/a.b" || got.FD() != 7 {
		t.Fatalf("leafNamed(nil) = %v, want */a.b on fd 7", got)
	}
	full := file.NewFd(7, "/full/path", syscall.O_RDONLY)
	if got := leafNamed(full, named, 9); got != file.File(full) {
		t.Fatalf("leafNamed replaced a named file by %v", got)
	}
	unnamed := unnamedFile(7, 9)
	if got := leafNamed(unnamed, &types.FdEvent{Fd: 7}, 9); got != file.File(unnamed) {
		t.Fatalf("leafNamed without a component returned %v, want the unnamed file itself", got)
	}
}
