package internal

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"ior/internal/file"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

// Task er2: the dup family copies its source's answer onto the new descriptor.
// When the source is not in the fd table (a pipe/socket outside the traced
// set, or anything opened before ior attached) that answer is a procfs read
// taken when the exit event is processed, which lags the syscall - the program
// has often closed and reused the source number by then. The copy used to be
// registered with close-on-exec known clear, so every later row on the new
// descriptor carried the wrong file for its whole life, across execve too.
//
// These tests use the real kernel fd table of the test process so the procfs
// read is genuine: the source number is made to name a regular file (the
// "reuse") while the descriptor the dup actually created names a pipe.

// staleDupScenario is a real descriptor layout: srcFd now names a regular file
// (it was a pipe end when the dup ran), and dupFd - the descriptor that dup
// returned - names the pipe.
type staleDupScenario struct {
	pid      uint32
	srcFd    int32
	dupFd    int32
	filePath string // what /proc/self/fd/<srcFd> reads now (the stale answer)
	pipeName string // what /proc/self/fd/<dupFd> reads (the truth for dupFd)
}

func newStaleDupScenario(t *testing.T) staleDupScenario {
	t.Helper()
	var p [2]int
	if err := unix.Pipe2(p[:], unix.O_CLOEXEC); err != nil {
		t.Fatalf("pipe2: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(p[0]) })
	srcFd := p[1]
	// The dup that the program really performed.
	dupFd, err := unix.FcntlInt(uintptr(srcFd), unix.F_DUPFD, 100)
	if err != nil {
		t.Fatalf("dup pipe write end: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(dupFd) })

	// Then the program "closes" srcFd and something else takes the number.
	// dup3 does both atomically, so no other test goroutine can win the race
	// for the lowest free descriptor.
	f, err := os.Create(filepath.Join(t.TempDir(), "reused.txt"))
	if err != nil {
		t.Fatalf("create reused file: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if err := unix.Dup3(int(f.Fd()), srcFd, 0); err != nil {
		t.Fatalf("dup3 onto source number: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(srcFd) })

	sc := staleDupScenario{pid: uint32(os.Getpid()), srcFd: int32(srcFd), dupFd: int32(dupFd)}
	sc.filePath = readSelfFd(t, srcFd)
	sc.pipeName = readSelfFd(t, dupFd)
	if !strings.HasPrefix(sc.pipeName, "pipe:") || strings.HasPrefix(sc.filePath, "pipe:") {
		t.Fatalf("scenario is not set up: src=%q dup=%q", sc.filePath, sc.pipeName)
	}
	return sc
}

func readSelfFd(t *testing.T, fd int) string {
	t.Helper()
	name, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		t.Fatalf("readlink fd %d: %v", fd, err)
	}
	return name
}

// feedStaleDup feeds the exit of one dup-family call whose source is the
// scenario's (now reused) srcFd and which returned dupFd.
func (sc staleDupScenario) feedStaleDup(t *testing.T, el *eventLoop, kind string) {
	t.Helper()
	ret := int64(sc.dupFd)
	tid := sc.pid
	var enterRaw, exitRaw []byte
	switch kind {
	case "dup", "dup2":
		enter, exit := types.SYS_ENTER_DUP, types.SYS_EXIT_DUP
		if kind == "dup2" {
			enter, exit = types.SYS_ENTER_DUP2, types.SYS_EXIT_DUP2
		}
		_, enterRaw = makeEnterFdEvent(t, dupPairStart, sc.pid, tid, sc.srcFd, enter)
		_, exitRaw = makeExitRetEvent(t, dupPairStart+openPairLatency, sc.pid, tid, exit, ret)
	case "dup3":
		_, enterRaw = makeEnterDup3Event(t, dupPairStart, sc.pid, tid, sc.srcFd, syscall.O_CLOEXEC)
		_, exitRaw = makeExitRetEvent(t, dupPairStart+openPairLatency, sc.pid, tid, types.SYS_EXIT_DUP3, ret)
	case "F_DUPFD", "F_DUPFD_CLOEXEC":
		cmd := uint32(syscall.F_DUPFD)
		if kind == "F_DUPFD_CLOEXEC" {
			cmd = syscall.F_DUPFD_CLOEXEC
		}
		_, enterRaw = makeEnterFcntlEvent(t, dupPairStart, sc.pid, tid, uint32(sc.srcFd), cmd, 0)
		_, exitRaw = makeExitRetEvent(t, dupPairStart+openPairLatency, sc.pid, tid, types.SYS_EXIT_FCNTL, ret)
	default:
		t.Fatalf("unknown dup kind %q", kind)
	}
	if ep := feedRawPair(t, el, enterRaw, exitRaw); ep != nil {
		ep.Recycle()
	}
}

var staleDupKinds = []string{"dup", "dup2", "dup3", "F_DUPFD", "F_DUPFD_CLOEXEC"}

// TestDupOfUntrackedSourceDoesNotCopyAStaleProcfsAnswer is the reproduction:
// with the source untracked, the dup used to bind dupFd to whatever the source
// number names by the time the event is processed (the regular file), instead
// of what dupFd itself is (the pipe).
func TestDupOfUntrackedSourceDoesNotCopyAStaleProcfsAnswer(t *testing.T) {
	for _, kind := range staleDupKinds {
		t.Run(kind, func(t *testing.T) {
			sc := newStaleDupScenario(t)
			el := newFilteredEventLoop(t, globalfilter.Filter{})

			sc.feedStaleDup(t, el, kind)

			if _, ok := el.fdState().get(sc.dupFd, sc.pid); ok {
				t.Fatalf("%s: dup target %d was stored in the fd table from a procfs-resolved source",
					kind, sc.dupFd)
			}
			got := el.fdState().resolve(sc.dupFd, sc.pid)
			if got.Name() != sc.pipeName {
				t.Fatalf("%s: dup target %d resolves to %q, want its own file %q (the source number now names %q)",
					kind, sc.dupFd, got.Name(), sc.pipeName, sc.filePath)
			}
		})
	}
}

// TestDupOfUntrackedSourceForgetsAStaleTargetEntry pins the other half: the
// kernel's dup2/dup3 close whatever the target number held, and an untracked
// source gives no replacement to store, so the old fd-table and procfs-cache
// entries for the target must both go rather than keep labelling the number.
func TestDupOfUntrackedSourceForgetsAStaleTargetEntry(t *testing.T) {
	for _, kind := range staleDupKinds {
		t.Run(kind, func(t *testing.T) {
			sc := newStaleDupScenario(t)
			el := newFilteredEventLoop(t, globalfilter.Filter{})
			el.fdState().set(sc.dupFd, sc.pid, file.NewFd(sc.dupFd, "/old/tracked", syscall.O_RDONLY))
			el.fdState().setProcFdCache(sc.dupFd, sc.pid, file.NewFd(sc.dupFd, "/old/cached", syscall.O_RDONLY))

			sc.feedStaleDup(t, el, kind)

			if _, ok := el.fdState().get(sc.dupFd, sc.pid); ok {
				t.Fatalf("%s: stale fd-table entry for target %d survived", kind, sc.dupFd)
			}
			if _, ok := el.fdState().cachedProcFdFile(sc.dupFd, sc.pid); ok {
				t.Fatalf("%s: stale procfs-cache entry for target %d survived", kind, sc.dupFd)
			}
		})
	}
}

// TestDupOfProcfsCachedSourceIsNotCopied covers the second procfs-derived
// origin: a source known only to the procfs cache was equally read after the
// fact, so it is no more copyable than one resolved on the spot.
func TestDupOfProcfsCachedSourceIsNotCopied(t *testing.T) {
	sc := newStaleDupScenario(t)
	el := newFilteredEventLoop(t, globalfilter.Filter{})
	el.fdState().setProcFdCache(sc.srcFd, sc.pid, file.NewFd(sc.srcFd, "/stale/cached", syscall.O_RDONLY))

	sc.feedStaleDup(t, el, "dup")

	if got := el.fdState().resolve(sc.dupFd, sc.pid); got.Name() != sc.pipeName {
		t.Fatalf("dup target resolves to %q, want %q", got.Name(), sc.pipeName)
	}
}

// TestDupOfTrackedSourceStillCopies is the negative test: a source that a
// traced syscall named is authoritative, so the copy is registered exactly as
// before - with the source's name, the shared status flags and the
// descriptor-specific close-on-exec state.
func TestDupOfTrackedSourceStillCopies(t *testing.T) {
	for _, kind := range staleDupKinds {
		t.Run(kind, func(t *testing.T) {
			sc := newStaleDupScenario(t)
			el := newFilteredEventLoop(t, globalfilter.Filter{})
			const tracked = "/tracked/by/open.txt"
			el.fdState().set(sc.srcFd, sc.pid, file.NewFd(sc.srcFd, tracked, syscall.O_RDWR))

			sc.feedStaleDup(t, el, kind)

			got, ok := el.fdState().get(sc.dupFd, sc.pid)
			if !ok || got.Name() != tracked {
				t.Fatalf("%s: dup target %d = %v (tracked=%v), want a copy of %q", kind, sc.dupFd, got, ok, tracked)
			}
			wantCloexec := kind == "dup3" || kind == "F_DUPFD_CLOEXEC"
			cloexec, known := got.(*file.FdFile).CloseOnExec()
			if !known || cloexec != wantCloexec {
				t.Fatalf("%s: close-on-exec = %v (known=%v), want %v", kind, cloexec, known, wantCloexec)
			}
		})
	}
}

// TestPidfdGetfdDoesNotStoreALaggingProcfsRead pins the pidfd_getfd half: the
// returned descriptor has no traced open, so its name is a procfs read taken
// after the syscall. The row may print it, but nothing may be stored - and an
// old entry on the number goes, since the kernel handed out a fresh
// descriptor there.
func TestPidfdGetfdDoesNotStoreALaggingProcfsRead(t *testing.T) {
	sc := newStaleDupScenario(t)
	el := newFilteredEventLoop(t, globalfilter.Filter{})
	el.fdState().set(sc.dupFd, sc.pid, file.NewFd(sc.dupFd, "/old/tracked", syscall.O_RDONLY))

	const pidfd = 9999
	_, enterRaw := makeEnterFdEvent(t, dupPairStart, sc.pid, sc.pid, pidfd, types.SYS_ENTER_PIDFD_GETFD)
	_, exitRaw := makeExitRetEvent(t, dupPairStart+openPairLatency, sc.pid, sc.pid,
		types.SYS_EXIT_PIDFD_GETFD, int64(sc.dupFd))
	ep := feedRawPair(t, el, enterRaw, exitRaw)
	if ep == nil {
		t.Fatal("pidfd_getfd row was dropped")
	}
	defer ep.Recycle()

	if ep.File.Name() != sc.pipeName {
		t.Fatalf("row reports %q, want %q", ep.File.Name(), sc.pipeName)
	}
	if _, ok := el.fdState().get(sc.dupFd, sc.pid); ok {
		t.Fatal("pidfd_getfd result was stored in the fd table")
	}
	if _, ok := el.fdState().cachedProcFdFile(sc.dupFd, sc.pid); ok {
		t.Fatal("pidfd_getfd result was stored in the procfs cache")
	}
}
