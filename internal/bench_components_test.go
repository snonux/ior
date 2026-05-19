package internal

import (
	"fmt"
	"syscall"
	"testing"

	"ior/internal/benchutil"
	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/types"
)

const (
	componentBenchPID uint32 = 4242
	componentBenchTID uint32 = 4343
)

type recyclable interface {
	Recycle()
}

func BenchmarkDeserializeOpenEvent(b *testing.B) {
	gen := benchutil.NewEventGenerator()
	_, raw, err := gen.EnterOpenEvent(1, componentBenchPID, componentBenchTID)
	if err != nil {
		b.Fatal(err)
	}
	benchmarkDeserialize(b, raw, types.NewOpenEvent)
}

func BenchmarkDeserializeFdEvent(b *testing.B) {
	gen := benchutil.NewEventGenerator()
	_, raw, err := gen.EnterFdEvent(1, componentBenchPID, componentBenchTID, 12, types.SYS_ENTER_READ)
	if err != nil {
		b.Fatal(err)
	}
	benchmarkDeserialize(b, raw, types.NewFdEvent)
}

func BenchmarkDeserializeNullEvent(b *testing.B) {
	gen := benchutil.NewEventGenerator()
	_, raw, err := gen.EnterNullEvent(1, componentBenchPID, componentBenchTID, types.SYS_ENTER_SYNC)
	if err != nil {
		b.Fatal(err)
	}
	benchmarkDeserialize(b, raw, types.NewNullEvent)
}

func BenchmarkDeserializeRetEvent(b *testing.B) {
	gen := benchutil.NewEventGenerator()
	_, raw, err := gen.ExitRetEvent(1, componentBenchPID, componentBenchTID, types.SYS_EXIT_READ, 64)
	if err != nil {
		b.Fatal(err)
	}
	benchmarkDeserialize(b, raw, types.NewRetEvent)
}

func BenchmarkDeserializePathEvent(b *testing.B) {
	gen := benchutil.NewEventGenerator()
	_, raw, err := gen.EnterPathEvent(1, componentBenchPID, componentBenchTID, "/tmp/p", types.SYS_ENTER_MKDIR)
	if err != nil {
		b.Fatal(err)
	}
	benchmarkDeserialize(b, raw, types.NewPathEvent)
}

func BenchmarkDeserializeNameEvent(b *testing.B) {
	gen := benchutil.NewEventGenerator()
	_, raw, err := gen.EnterNameEvent(1, componentBenchPID, componentBenchTID, "/tmp/a", "/tmp/b", types.SYS_ENTER_RENAME)
	if err != nil {
		b.Fatal(err)
	}
	benchmarkDeserialize(b, raw, types.NewNameEvent)
}

func BenchmarkDeserializeFcntlEvent(b *testing.B) {
	gen := benchutil.NewEventGenerator()
	_, raw, err := gen.EnterFcntlEvent(1, componentBenchPID, componentBenchTID, 33, syscall.F_SETFL, syscall.O_NONBLOCK)
	if err != nil {
		b.Fatal(err)
	}
	benchmarkDeserialize(b, raw, types.NewFcntlEvent)
}

func BenchmarkDeserializeDup3Event(b *testing.B) {
	gen := benchutil.NewEventGenerator()
	_, raw, err := gen.EnterDup3Event(1, componentBenchPID, componentBenchTID, 8, syscall.O_CLOEXEC)
	if err != nil {
		b.Fatal(err)
	}
	benchmarkDeserialize(b, raw, types.NewDup3Event)
}

func BenchmarkRawHandlerLookup(b *testing.B) {
	b.ReportAllocs()

	el := mustNewEventLoop(b, eventLoopConfig{})
	eventTypes := []types.EventType{
		types.ENTER_OPEN_EVENT,
		types.EXIT_OPEN_EVENT,
		types.ENTER_FD_EVENT,
		types.EXIT_FD_EVENT,
		types.ENTER_NULL_EVENT,
		types.EXIT_NULL_EVENT,
		types.EXIT_RET_EVENT,
		types.ENTER_NAME_EVENT,
		types.ENTER_PATH_EVENT,
		types.ENTER_FCNTL_EVENT,
		types.ENTER_DUP3_EVENT,
		types.ENTER_SOCKET_EVENT,
		types.ENTER_SOCKETPAIR_EVENT,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = el.rawHandlers[eventTypes[i%len(eventTypes)]]
	}
}

func BenchmarkTracepointEntered(b *testing.B) {
	b.ReportAllocs()

	gen := benchutil.NewEventGenerator()
	_, raw, err := gen.EnterOpenEvent(1, componentBenchPID, componentBenchTID)
	if err != nil {
		b.Fatal(err)
	}
	el := newComponentBenchEventLoop(b, componentBenchTID)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		enterEv := types.NewOpenEvent(raw)
		el.tracepointEntered(enterEv)
		if ep, ok := el.pairs.enters[componentBenchTID]; ok {
			delete(el.pairs.enters, componentBenchTID)
			// tracepointEntered stores only EnterEv; provide a placeholder so Pair.Recycle can return to the pool.
			ep.ExitEv = &types.NullEvent{}
			ep.Recycle()
		}
	}
}

func BenchmarkTracepointExited(b *testing.B) {
	b.ReportAllocs()

	gen := benchutil.NewEventGenerator()
	_, enterRaw, err := gen.EnterNullEvent(1, componentBenchPID, componentBenchTID, types.SYS_ENTER_SYNC)
	if err != nil {
		b.Fatal(err)
	}
	_, exitRaw, err := gen.ExitNullEvent(2, componentBenchPID, componentBenchTID, types.SYS_EXIT_SYNC)
	if err != nil {
		b.Fatal(err)
	}
	el := newComponentBenchEventLoop(b, componentBenchTID)
	out := make(chan *event.Pair, 1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		enterEv := types.NewNullEvent(enterRaw)
		el.pairs.enters[componentBenchTID] = event.NewPair(enterEv)
		exitEv := types.NewNullEvent(exitRaw)
		el.tracepointExited(exitEv, out)
		(<-out).Recycle()
	}
}

func BenchmarkHandleOpenExit(b *testing.B) {
	b.ReportAllocs()

	gen := benchutil.NewEventGenerator()
	enterTemplate, _, err := gen.EnterOpenEvent(1, componentBenchPID, componentBenchTID)
	if err != nil {
		b.Fatal(err)
	}
	exitTemplate, _, err := gen.ExitOpenEvent(2, componentBenchPID, componentBenchTID)
	if err != nil {
		b.Fatal(err)
	}
	el := newComponentBenchEventLoop(b, componentBenchTID)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		enter := enterTemplate
		enter.Time = uint64(i*2 + 1)
		exit := exitTemplate
		exit.Time = uint64(i*2 + 2)
		ep := event.NewPair(&enter)
		ep.ExitEv = &exit
		if !el.handleOpenExit(ep, &enter) {
			b.Fatal("handleOpenExit returned false")
		}
		ep.Recycle()
	}
}

func BenchmarkHandleFdExit(b *testing.B) {
	b.ReportAllocs()

	gen := benchutil.NewEventGenerator()
	enterTemplate, _, err := gen.EnterFdEvent(1, componentBenchPID, componentBenchTID, 99, types.SYS_ENTER_READ)
	if err != nil {
		b.Fatal(err)
	}
	exitTemplate, _, err := gen.ExitRetEvent(2, componentBenchPID, componentBenchTID, types.SYS_EXIT_READ, 128)
	if err != nil {
		b.Fatal(err)
	}
	el := newComponentBenchEventLoop(b, componentBenchTID)
	el.fdState().set(99, file.NewFd(99, "/tmp/fd", syscall.O_RDONLY))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		enter := enterTemplate
		enter.Time = uint64(i*2 + 1)
		exit := exitTemplate
		exit.Time = uint64(i*2 + 2)
		ep := event.NewPair(&enter)
		ep.ExitEv = &exit
		if !el.handleFdExit(ep, &enter) {
			b.Fatal("handleFdExit returned false")
		}
		ep.Recycle()
	}
}

func BenchmarkHandlePathExit(b *testing.B) {
	b.ReportAllocs()

	gen := benchutil.NewEventGenerator()
	enterTemplate, _, err := gen.EnterPathEvent(1, componentBenchPID, componentBenchTID, "/tmp/path", types.SYS_ENTER_MKDIR)
	if err != nil {
		b.Fatal(err)
	}
	exitTemplate, _, err := gen.ExitRetEvent(2, componentBenchPID, componentBenchTID, types.SYS_EXIT_MKDIR, 0)
	if err != nil {
		b.Fatal(err)
	}
	el := newComponentBenchEventLoop(b, componentBenchTID)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		enter := enterTemplate
		enter.Time = uint64(i*2 + 1)
		exit := exitTemplate
		exit.Time = uint64(i*2 + 2)
		ep := event.NewPair(&enter)
		ep.ExitEv = &exit
		if !el.handlePathExit(ep, &enter) {
			b.Fatal("handlePathExit returned false")
		}
		ep.Recycle()
	}
}

func BenchmarkHandleNameExit(b *testing.B) {
	b.ReportAllocs()

	gen := benchutil.NewEventGenerator()
	enterTemplate, _, err := gen.EnterNameEvent(1, componentBenchPID, componentBenchTID, "/tmp/a", "/tmp/b", types.SYS_ENTER_RENAME)
	if err != nil {
		b.Fatal(err)
	}
	exitTemplate, _, err := gen.ExitRetEvent(2, componentBenchPID, componentBenchTID, types.SYS_EXIT_RENAME, 0)
	if err != nil {
		b.Fatal(err)
	}
	el := newComponentBenchEventLoop(b, componentBenchTID)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		enter := enterTemplate
		enter.Time = uint64(i*2 + 1)
		exit := exitTemplate
		exit.Time = uint64(i*2 + 2)
		ep := event.NewPair(&enter)
		ep.ExitEv = &exit
		if !el.handleNameExit(ep, &enter) {
			b.Fatal("handleNameExit returned false")
		}
		ep.Recycle()
	}
}

func BenchmarkHandleNullExit(b *testing.B) {
	b.ReportAllocs()

	gen := benchutil.NewEventGenerator()
	enterTemplate, _, err := gen.EnterNullEvent(1, componentBenchPID, componentBenchTID, types.SYS_ENTER_SYNC)
	if err != nil {
		b.Fatal(err)
	}
	exitTemplate, _, err := gen.ExitNullEvent(2, componentBenchPID, componentBenchTID, types.SYS_EXIT_SYNC)
	if err != nil {
		b.Fatal(err)
	}
	el := newComponentBenchEventLoop(b, componentBenchTID)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		enter := enterTemplate
		enter.Time = uint64(i*2 + 1)
		exit := exitTemplate
		exit.Time = uint64(i*2 + 2)
		ep := event.NewPair(&enter)
		ep.ExitEv = &exit
		if !el.handleNullExit(ep, &enter) {
			b.Fatal("handleNullExit returned false")
		}
		ep.Recycle()
	}
}

func BenchmarkHandleFcntlExit(b *testing.B) {
	b.ReportAllocs()

	gen := benchutil.NewEventGenerator()
	enterTemplate, _, err := gen.EnterFcntlEvent(1, componentBenchPID, componentBenchTID, 7, syscall.F_SETFL, syscall.O_NONBLOCK)
	if err != nil {
		b.Fatal(err)
	}
	exitTemplate, _, err := gen.ExitRetEvent(2, componentBenchPID, componentBenchTID, types.SYS_EXIT_FCNTL, 0)
	if err != nil {
		b.Fatal(err)
	}
	el := newComponentBenchEventLoop(b, componentBenchTID)
	el.fdState().set(7, file.NewFd(7, "/tmp/fcntl", syscall.O_RDONLY))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		enter := enterTemplate
		enter.Time = uint64(i*2 + 1)
		exit := exitTemplate
		exit.Time = uint64(i*2 + 2)
		ep := event.NewPair(&enter)
		ep.ExitEv = &exit
		if !el.handleFcntlExit(ep, &enter) {
			b.Fatal("handleFcntlExit returned false")
		}
		ep.Recycle()
	}
}

func BenchmarkHandleDup3Exit(b *testing.B) {
	b.ReportAllocs()

	gen := benchutil.NewEventGenerator()
	enterTemplate, _, err := gen.EnterDup3Event(1, componentBenchPID, componentBenchTID, 9, syscall.O_CLOEXEC)
	if err != nil {
		b.Fatal(err)
	}
	exitTemplate, _, err := gen.ExitRetEvent(2, componentBenchPID, componentBenchTID, types.SYS_EXIT_DUP3, 10)
	if err != nil {
		b.Fatal(err)
	}
	el := newComponentBenchEventLoop(b, componentBenchTID)
	el.fdState().set(9, file.NewFd(9, "/tmp/dup3", syscall.O_RDONLY))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		enter := enterTemplate
		enter.Time = uint64(i*2 + 1)
		exit := exitTemplate
		exit.Time = uint64(i*2 + 2)
		ep := event.NewPair(&enter)
		ep.ExitEv = &exit
		if !el.handleDup3Exit(ep, &enter) {
			b.Fatal("handleDup3Exit returned false")
		}
		ep.Recycle()
	}
}

func BenchmarkFdTrackerGetSet(b *testing.B) {
	b.ReportAllocs()

	tracker := newFDTracker(nil)
	fdFile := file.NewFd(11, "/tmp/tracker", syscall.O_RDONLY)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fd := int32(i % 1024)
		tracker.set(fd, fdFile)
		_, _ = tracker.get(fd)
	}
}

func BenchmarkCommResolverCachedHit(b *testing.B) {
	b.ReportAllocs()

	resolver := newCommResolver(nil)
	const tid = componentBenchTID
	resolver.setCached(tid, "bench")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if resolver.comm(tid) == "" {
			b.Fatal("unexpected cache miss")
		}
	}
}

func BenchmarkEventPoolGetPut(b *testing.B) {
	b.ReportAllocs()

	gen := benchutil.NewEventGenerator()
	enterTemplate, _, err := gen.EnterNullEvent(1, componentBenchPID, componentBenchTID, types.SYS_ENTER_SYNC)
	if err != nil {
		b.Fatal(err)
	}
	exitTemplate, _, err := gen.ExitNullEvent(2, componentBenchPID, componentBenchTID, types.SYS_EXIT_SYNC)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		enter := enterTemplate
		enter.Time = uint64(i*2 + 1)
		exit := exitTemplate
		exit.Time = uint64(i*2 + 2)
		ep := event.NewPair(&enter)
		ep.ExitEv = &exit
		ep.Recycle()
	}
}

func benchmarkDeserialize[T recyclable](b *testing.B, raw []byte, decode func([]byte) T) {
	b.Helper()
	b.ReportAllocs()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ev := decode(raw)
		ev.Recycle()
	}
}

func newComponentBenchEventLoop(tb testing.TB, tids ...uint32) *eventLoop {
	tb.Helper()
	el := mustNewEventLoop(tb, eventLoopConfig{})
	for _, tid := range tids {
		el.setCachedComm(tid, fmt.Sprintf("bench-%d", tid))
	}
	return el
}
