package internal

import (
	"encoding/binary"
	"testing"

	"ior/internal/types"
)

// TestAggregateDrainFailureKeepsBaselines pins that a drain which fails
// part-way does not advance the baselines of the keys it had already read:
// the rows are discarded with the error, so the next successful drain must
// still report their counts.
func TestAggregateDrainFailureKeepsBaselines(t *testing.T) {
	first, second := uint32(types.SYS_ENTER_READ), uint32(types.SYS_ENTER_WRITE)
	source := newFakeSyscallAggregateMap(first, encodeRawAggregates(t, rawSyscallAggregate{Count: 5}))
	secondKey := make([]byte, 4)
	binary.LittleEndian.PutUint32(secondKey, second)
	source.keys = append(source.keys, secondKey) // no value yet: GetValue fails

	consumer := &syscallAggregateConsumer{aggregateMap: source, last: make(map[types.TraceId]rawSyscallAggregate)}
	if _, err := consumer.Drain(); err == nil {
		t.Fatal("drain with an unreadable key succeeded")
	}

	source.values[second] = encodeRawAggregates(t, rawSyscallAggregate{Count: 1})
	rows, err := consumer.Drain()
	if err != nil {
		t.Fatalf("second drain: %v", err)
	}
	counts := map[types.TraceId]uint64{}
	for _, row := range rows {
		counts[row.TraceID] = row.Count
	}
	if counts[types.TraceId(first)] != 5 || counts[types.TraceId(second)] != 1 {
		t.Fatalf("counts after a failed drain = %v, want 5 and 1", counts)
	}
}
