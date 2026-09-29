package statsengine

import (
	"math/rand/v2"
	"testing"
	"time"

	"ior/internal/types"
)

func BenchmarkSyscallAccumulatorSnapshot(b *testing.B) {
	acc := newSyscallAccumulatorWithConfig(10_000, rand.New(rand.NewPCG(123, 0)))
	traceIDs := []types.TraceId{
		types.SYS_ENTER_READ,
		types.SYS_ENTER_WRITE,
		types.SYS_ENTER_OPENAT,
		types.SYS_ENTER_CLOSE,
		types.SYS_ENTER_COPY_FILE_RANGE,
	}
	for i := 0; i < 100_000; i++ {
		id := traceIDs[i%len(traceIDs)]
		acc.Add(newPair(id, uint64((i%2000)+1), uint64(i%65536), 0))
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = acc.Snapshot(5 * time.Second)
	}
}

// BenchmarkEngineSnapshotCaptureLockHold measures the part of Engine.Snapshot
// that runs under e.mu (and therefore blocks Ingest) with 60 active syscalls
// whose full 10k-sample reservoirs all have stale percentiles. Before the
// percentile sort moved out of the lock this took ~25ms per op; now it only
// copies the reservoirs into the syscalls' scratch buffers, which the untimed
// warm-up and write-back steps populate exactly as Snapshot does.
func BenchmarkEngineSnapshotCaptureLockHold(b *testing.B) {
	engine := NewEngine(DefaultTopN)
	ids := fillReservoirs(engine, 60, syscallReservoirSampleCapDefault)

	capture := func() {
		b.StopTimer()
		for _, id := range ids {
			engine.syscalls.byID[id].lastPercentileVersion = 0
		}
		b.StartTimer()
		in := engine.captureSnapshotInputs()
		b.StopTimer()
		if len(in.syscalls.jobs) != 60 {
			b.Fatalf("expected 60 stale reservoirs, got %d", len(in.syscalls.jobs))
		}
		engine.storeSyscallPercentiles(in.syscalls.jobs)
		b.StartTimer()
	}
	capture()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		capture()
	}
}

// BenchmarkEngineSnapshotStaleReservoirs measures a whole Engine.Snapshot
// (capture, lock-free percentile selection, cached write-back) when every one
// of 60 full reservoirs needs a percentile recompute.
func BenchmarkEngineSnapshotStaleReservoirs(b *testing.B) {
	engine := NewEngine(DefaultTopN)
	ids := fillReservoirs(engine, 60, syscallReservoirSampleCapDefault)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		for _, id := range ids {
			engine.syscalls.byID[id].lastPercentileVersion = 0
		}
		b.StartTimer()
		if _, err := engine.Snapshot(); err != nil {
			b.Fatal(err)
		}
	}
}
