package internal

import (
	"os"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"ior/internal/event"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

// Task ir2 benchmarks. A failing procfs lookup is not cached any more (that was
// the bug), so its per-call cost is what an unknown-or-closed descriptor pays
// on every event; the EBADF loops are the hot shape that must not pay it.
//
// Reference numbers (amd64, -benchtime 2s; see the commit message of the
// change that introduced resolveOnExit for the before/after comparison):
// resolve of a closed fd ~4.5 us / 7 allocs against ~50 ns for a cached hit.

// BenchmarkResolveFailingProcfs is the raw cost of one fdTracker.resolve on a
// number procfs cannot answer: Sprintf path, failing readlink, PathError and an
// unresolved FdFile, every time.
func BenchmarkResolveFailingProcfs(b *testing.B) {
	pid := uint32(os.Getpid())
	el := mustNewEventLoop(b, eventLoopConfig{})
	const fd int32 = 900 // not open in the benchmark process
	if _, err := os.Readlink("/proc/self/fd/900"); err == nil {
		b.Skip("fd 900 is open in this process")
	}
	b.ReportAllocs()
	for b.Loop() {
		_ = el.fdState().resolve(fd, pid)
	}
}

// BenchmarkEBADFLoopThroughEventLoop pushes enter/exit pairs that all answer
// EBADF on a number without any fd-table entry through the real raw-event
// path, the closefrom/close-loop shape. Each iteration is one pair: decode,
// pairing, handler, filter checkpoint, emission.
func BenchmarkEBADFLoopThroughEventLoop(b *testing.B) {
	pid := uint32(os.Getpid())
	fcntlEnter := mustBenchBytes(b, &types.FcntlEvent{EventType: types.ENTER_FCNTL_EVENT, TraceId: types.SYS_ENTER_FCNTL,
		Time: defaulTime, Pid: pid, Tid: execCommTid, Fd: 901, Cmd: unix.F_GETFD})
	readEnter := mustBenchBytes(b, &types.FdEvent{EventType: types.ENTER_FD_EVENT, TraceId: types.SYS_ENTER_READ,
		Time: defaulTime, Pid: pid, Tid: execCommTid, Fd: 901, SchemaVersion: types.FD_EVENT_SCHEMA_VERSION})
	exitOf := func(id types.TraceId) []byte {
		return mustBenchBytes(b, &types.RetEvent{EventType: types.EXIT_RET_EVENT, TraceId: id,
			Time: defaulTime + openPairLatency, Pid: pid, Tid: execCommTid, Ret: -int64(syscall.EBADF)})
	}
	fcntlExit, readExit := exitOf(types.SYS_EXIT_FCNTL), exitOf(types.SYS_EXIT_READ)

	for _, tc := range []struct {
		name        string
		enter, exit []byte
	}{
		{"read", readEnter, readExit},
		{"fcntl_getfd", fcntlEnter, fcntlExit},
	} {
		b.Run(tc.name, func(b *testing.B) {
			el := mustNewEventLoop(b, eventLoopConfig{filter: globalfilter.Filter{}, commResolver: newHermeticCommResolver()})
			b.Cleanup(el.commResolver.shutdown)
			el.setCachedComm(execCommTid, "ioworkload")
			out := make(chan *event.Pair, 1)
			b.ReportAllocs()
			for b.Loop() {
				el.processRawEvent(tc.enter, out)
				el.processRawEvent(tc.exit, out)
				select {
				case ep := <-out:
					ep.Recycle()
				default:
					b.Fatal("pair was not emitted")
				}
			}
		})
	}
}

// mustBenchBytes serialises one wire event for replay. (The makeEnter*
// helpers of the unit tests take a *testing.T and cannot be used here.)
func mustBenchBytes(b *testing.B, ev interface{ Bytes() ([]byte, error) }) []byte {
	b.Helper()
	raw, err := ev.Bytes()
	if err != nil {
		b.Fatal(err)
	}
	return raw
}
