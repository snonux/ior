package statsengine

import (
	"math/rand"
	"testing"
	"time"

	"ior/internal/types"
)

func BenchmarkSyscallAccumulatorSnapshot(b *testing.B) {
	acc := newSyscallAccumulatorWithConfig(10_000, rand.New(rand.NewSource(123)))
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
