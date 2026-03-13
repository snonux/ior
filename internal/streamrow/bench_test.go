package streamrow

import (
	"testing"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/types"
)

var benchmarkRowSink Row

func BenchmarkNew(b *testing.B) {
	pair := benchmarkPair()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkRowSink = New(uint64(i+1), pair)
	}
}

func benchmarkPair() *event.Pair {
	enter := &types.OpenEvent{TraceId: types.SYS_ENTER_OPENAT, Time: 1234, Pid: 42, Tid: 84}
	exit := &types.RetEvent{TraceId: types.SYS_EXIT_OPENAT, Time: 1300, Ret: 64, Pid: 42, Tid: 84}
	pair := event.NewPair(enter)
	pair.ExitEv = exit
	pair.File = file.NewFd(7, "/tmp/bench.txt", 0)
	pair.Comm = "bench"
	pair.Duration = 66
	pair.DurationToPrev = 19
	pair.Bytes = 512
	return pair
}
