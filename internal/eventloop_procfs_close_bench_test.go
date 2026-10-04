package internal

import (
	"os"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

// Benchmarks for task jr2 (eventloop_procfs_close.go). They use this process's
// real pid and a pipe placed on a free number, so a procfs read is a genuine
// one (readlink plus the fdinfo read for the flags).
//
// Reference numbers (amd64 on a busy host, so the times are noisy; before ->
// after jr2):
//   - BenchmarkCloseUntrackedOpenFd: 33-79 us, 22-23 allocs, ~6.3 KB ->
//     4-6 us, 2 allocs, ~100 B, i.e. the same as a tracked close: the close
//     row of an untracked descriptor no longer reads procfs.
//   - BenchmarkCloseTrackedFd: unchanged, 4-8 us, 2 allocs (fd-table path).
//   - BenchmarkProcfsResolveMiss: unchanged allocations (21, 6235 B) and time
//     within noise; the read stamp is one clock_gettime syscall (x/sys's
//     unix.ClockGettime does not go through the vDSO) and a map write next to
//     the procfs reads.

// benchClosePair encodes one close(fd) pair of this process returning ret.
func benchClosePair(b *testing.B, fd int32, ret int64) (enterRaw, exitRaw []byte) {
	b.Helper()
	pid := uint32(os.Getpid())
	enter := types.FdEvent{
		EventType: types.ENTER_FD_EVENT, TraceId: types.SYS_ENTER_CLOSE,
		Time: defaulTime, Pid: pid, Tid: execCommTid, Fd: fd,
		SchemaVersion: types.FD_EVENT_SCHEMA_VERSION,
	}
	exit := types.RetEvent{
		EventType: types.EXIT_RET_EVENT, TraceId: types.SYS_EXIT_CLOSE,
		Time: defaulTime + openPairLatency, Ret: ret, Pid: pid, Tid: execCommTid,
	}
	var err error
	if enterRaw, err = enter.Bytes(); err != nil {
		b.Fatal(err)
	}
	if exitRaw, err = exit.Bytes(); err != nil {
		b.Fatal(err)
	}
	return enterRaw, exitRaw
}

// benchFeed pushes one encoded pair and recycles the pair it produced.
func benchFeed(el *eventLoop, out chan *event.Pair, enterRaw, exitRaw []byte) {
	el.processRawEvent(enterRaw, out)
	el.processRawEvent(exitRaw, out)
	select {
	case ep := <-out:
		ep.Recycle()
	default:
	}
}

// BenchmarkCloseUntrackedOpenFd is a close row of a descriptor the fd table
// does not know while procfs can still answer for its number. Before jr2 each
// such row cost a successful procfs resolution; now it costs none.
func BenchmarkCloseUntrackedOpenFd(b *testing.B) {
	n := benchPipeOnFreeNumber(b)
	el := mustNewEventLoop(b, eventLoopConfig{filter: globalfilter.Filter{}})
	enterRaw, exitRaw := benchClosePair(b, n, 0)
	out := make(chan *event.Pair, 1)
	b.ReportAllocs()
	for b.Loop() {
		benchFeed(el, out, enterRaw, exitRaw)
	}
}

// BenchmarkCloseTrackedFd is the unchanged path: the fd table names the row.
func BenchmarkCloseTrackedFd(b *testing.B) {
	pid := uint32(os.Getpid())
	n := benchPipeOnFreeNumber(b)
	el := mustNewEventLoop(b, eventLoopConfig{filter: globalfilter.Filter{}})
	enterRaw, exitRaw := benchClosePair(b, n, 0)
	out := make(chan *event.Pair, 1)
	b.ReportAllocs()
	for b.Loop() {
		el.fdState().set(n, pid, file.NewFd(n, "traced-open", syscall.O_RDWR))
		benchFeed(el, out, enterRaw, exitRaw)
	}
}

// BenchmarkProcfsResolveMiss is one successful procfs resolution that is then
// cached, which jr2 stamps with a boot-clock reading (bootClockNs).
func BenchmarkProcfsResolveMiss(b *testing.B) {
	pid := uint32(os.Getpid())
	n := benchPipeOnFreeNumber(b)
	el := mustNewEventLoop(b, eventLoopConfig{})
	b.ReportAllocs()
	for b.Loop() {
		el.fdState().deleteProcFdCache(n, pid)
		_ = el.fdState().resolve(n, pid)
	}
}

// benchPipeOnFreeNumber puts a pipe's read end on a high free descriptor
// number (F_DUPFD from 700, as freeFdNumber does) and returns the number.
func benchPipeOnFreeNumber(b *testing.B) int32 {
	b.Helper()
	var p [2]int
	if err := unix.Pipe2(p[:], unix.O_CLOEXEC); err != nil {
		b.Fatalf("pipe2: %v", err)
	}
	b.Cleanup(func() { _ = unix.Close(p[0]); _ = unix.Close(p[1]) })
	n, err := unix.FcntlInt(uintptr(p[0]), unix.F_DUPFD_CLOEXEC, 700)
	if err != nil {
		b.Skipf("F_DUPFD at 700: %v", err)
	}
	b.Cleanup(func() { _ = unix.Close(n) })
	return int32(n)
}
