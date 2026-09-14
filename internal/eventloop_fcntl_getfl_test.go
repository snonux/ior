package internal

import (
	"math"
	"syscall"
	"testing"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

const (
	fGetflFd       = int32(73)
	fGetflFilename = "/tmp/f-getfl.txt"
	// syscall.O_LARGEFILE is zero on linux/amd64 even though the kernel's
	// F_GETFL return includes this 0x8000 bit.
	linuxOLargefile = int32(0x8000)
)

func TestFGetflMakesUnknownFlagsConcreteAndPropagatesThem(t *testing.T) {
	const wantFlags = int32(syscall.O_RDWR) | linuxOLargefile
	el := newFilteredEventLoop(t, globalfilter.Filter{})
	// Model a descriptor whose opening syscall was missed and whose procfs
	// lookup could not recover metadata. F_GETFL is the first authoritative
	// flag word the tracer sees for it.
	el.fdState().setProcFdCache(fGetflFd, execCommPid,
		file.NewFd(fGetflFd, "", -1))
	if _, ok := el.fdState().get(fGetflFd, execCommPid); ok {
		t.Fatalf("fd %d must start outside the tracked fd table", fGetflFd)
	}

	fcntlPair := feedFGetflPair(t, el, int64(wantFlags))
	if fcntlPair == nil {
		t.Fatal("an unfiltered successful F_GETFL must be emitted")
	}
	assertPairFdFlags(t, fcntlPair, fGetflFd, wantFlags)
	fcntlPair.Recycle()
	assertTrackedFdFlags(t, el, fGetflFd, wantFlags)
	if _, ok := el.fdState().get(wantFlags, execCommPid); ok {
		t.Fatalf("F_GETFL return %d was incorrectly registered as a new fd", wantFlags)
	}
	if got := len(el.fdState().files); got != 1 {
		t.Fatalf("F_GETFL left %d tracked fds, want only fd %d", got, fGetflFd)
	}

	readPair := feedFdPair(t, el, types.SYS_ENTER_READ, types.SYS_EXIT_READ,
		fGetflFd, 1, writePairStart, writePairStart+openPairLatency)
	if readPair == nil {
		t.Fatal("an unfiltered read after F_GETFL must be emitted")
	}
	defer readPair.Recycle()
	assertPairFdFlags(t, readPair, fGetflFd, wantFlags)
}

func TestFGetflReplacesAStaleKnownFlagWord(t *testing.T) {
	const (
		staleFlags = syscall.O_WRONLY | syscall.O_APPEND | syscall.O_CLOEXEC | syscall.O_CREAT
		wantFlags  = int32(syscall.O_RDWR|syscall.O_NONBLOCK) | linuxOLargefile
	)
	el := newFilteredEventLoop(t, globalfilter.Filter{})
	el.fdState().set(fGetflFd, execCommPid,
		file.NewFd(fGetflFd, fGetflFilename, staleFlags))

	ep := feedFGetflPair(t, el, int64(wantFlags))
	if ep == nil {
		t.Fatal("an unfiltered successful F_GETFL must be emitted")
	}
	defer ep.Recycle()
	assertPairFdFlags(t, ep, fGetflFd, wantFlags)
	if ep.File.Name() != fGetflFilename {
		t.Fatalf("F_GETFL changed the tracked name to %q, want %q", ep.File.Name(), fGetflFilename)
	}
	assertTrackedFdFlags(t, el, fGetflFd, wantFlags)
}

func TestFailedFGetflKeepsTheTrackedFlagWord(t *testing.T) {
	const originalFlags = syscall.O_WRONLY | syscall.O_APPEND
	el := newFilteredEventLoop(t, globalfilter.Filter{})
	el.fdState().set(fGetflFd, execCommPid,
		file.NewFd(fGetflFd, fGetflFilename, originalFlags))

	ep := feedFGetflPair(t, el, -int64(syscall.EBADF))
	if ep == nil {
		t.Fatal("an unfiltered failed F_GETFL must remain observable")
	}
	defer ep.Recycle()
	assertPairFdFlags(t, ep, fGetflFd, originalFlags)
	assertTrackedFdFlags(t, el, fGetflFd, originalFlags)
}

func TestDroppedFGetflStillResynchronizesFdState(t *testing.T) {
	const wantFlags = syscall.O_RDWR | syscall.O_NONBLOCK
	el := newFilteredEventLoop(t, dropsEveryPairOfLatency())
	el.fdState().set(fGetflFd, execCommPid,
		file.NewFd(fGetflFd, fGetflFilename, syscall.O_WRONLY|syscall.O_APPEND))

	if ep := feedFGetflPair(t, el, wantFlags); ep != nil {
		defer ep.Recycle()
		t.Fatalf("F_GETFL row survived a -latency filter it cannot satisfy: %v", ep)
	}
	assertTrackedFdFlags(t, el, fGetflFd, wantFlags)

	readPair := feedFdPair(t, el, types.SYS_ENTER_READ, types.SYS_EXIT_READ,
		fGetflFd, 1, writePairStart, writePairStart+openPairLatency+1)
	if readPair == nil {
		t.Fatal("the later read must survive the latency filter")
	}
	defer readPair.Recycle()
	assertPairFdFlags(t, readPair, fGetflFd, wantFlags)
}

func TestOverflowingFGetflReturnIsMalformedAndKeepsFdState(t *testing.T) {
	const originalFlags = syscall.O_RDWR | syscall.O_APPEND
	el := newFilteredEventLoop(t, globalfilter.Filter{})
	el.fdState().set(fGetflFd, execCommPid,
		file.NewFd(fGetflFd, fGetflFilename, originalFlags))

	var warning string
	el.SetWarningCallback(func(message string) { warning = message })
	if ep := feedFGetflPair(t, el, int64(math.MaxInt32)+1); ep != nil {
		defer ep.Recycle()
		t.Fatalf("overflowing F_GETFL return was emitted: %v", ep)
	}
	assertTrackedFdFlags(t, el, fGetflFd, originalFlags)
	if warning != "Dropped malformed fcntl F_GETFL return value" {
		t.Fatalf("warning = %q, want malformed F_GETFL warning", warning)
	}
}

func feedFGetflPair(t *testing.T, el *eventLoop, ret int64) *event.Pair {
	t.Helper()
	_, enterRaw := makeEnterFcntlEvent(t, dupPairStart, execCommPid, execCommTid,
		uint32(fGetflFd), syscall.F_GETFL, 0)
	_, exitRaw := makeExitRetEvent(t, dupPairStart+openPairLatency, execCommPid, execCommTid,
		types.SYS_EXIT_FCNTL, ret)
	return feedRawPair(t, el, enterRaw, exitRaw)
}

func assertPairFdFlags(t *testing.T, ep *event.Pair, wantFd, wantFlags int32) {
	t.Helper()
	fdFile, ok := ep.File.(*file.FdFile)
	if !ok {
		t.Fatalf("pair reported %T, want *file.FdFile", ep.File)
	}
	if fdFile.FD() != wantFd {
		t.Fatalf("pair fd = %d, want %d", fdFile.FD(), wantFd)
	}
	if fdFile.Flags() != file.Flags(wantFlags) {
		t.Fatalf("pair flags = %v, want %v", fdFile.Flags(), file.Flags(wantFlags))
	}
}
