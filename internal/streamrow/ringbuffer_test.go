package streamrow

import (
	"testing"
)

// TestRingBufferPushAndSnapshot verifies that pushed rows are retrievable in
// insertion order.
func TestRingBufferPushAndSnapshot(t *testing.T) {
	rb := NewRingBuffer()

	if got := rb.Len(); got != 0 {
		t.Fatalf("expected empty buffer, got len=%d", got)
	}

	rows := []Row{
		{Seq: 1, Syscall: "read"},
		{Seq: 2, Syscall: "write"},
		{Seq: 3, Syscall: "openat"},
	}
	for _, r := range rows {
		rb.Push(r)
	}

	if got := rb.Len(); got != 3 {
		t.Fatalf("expected len=3, got %d", got)
	}
	if got := rb.TotalPushed(); got != 3 {
		t.Fatalf("expected totalPushed=3, got %d", got)
	}

	snap := rb.Snapshot()
	if len(snap) != 3 {
		t.Fatalf("expected snapshot len 3, got %d", len(snap))
	}
	for i, want := range rows {
		if snap[i].Seq != want.Seq || snap[i].Syscall != want.Syscall {
			t.Fatalf("row[%d] = %+v, want %+v", i, snap[i], want)
		}
	}
}

// TestRingBufferWrapsAroundCapacity verifies that the ring buffer overwrites the
// oldest entry when full and preserves insertion order in the snapshot.
func TestRingBufferWrapsAroundCapacity(t *testing.T) {
	rb := NewRingBuffer()

	// Fill beyond capacity to force wrap-around.
	const extra = 5
	for i := range RingBufferCapacity + extra {
		rb.Push(Row{Seq: uint64(i + 1)})
	}

	if got := rb.Len(); got != RingBufferCapacity {
		t.Fatalf("expected len=%d after overflow, got %d", RingBufferCapacity, got)
	}
	if got := rb.TotalPushed(); got != uint64(RingBufferCapacity+extra) {
		t.Fatalf("expected totalPushed=%d, got %d", RingBufferCapacity+extra, got)
	}

	snap := rb.Snapshot()
	if len(snap) != RingBufferCapacity {
		t.Fatalf("snapshot len = %d, want %d", len(snap), RingBufferCapacity)
	}
	// After filling cap+extra rows the oldest surviving seq should be extra+1.
	wantFirstSeq := uint64(extra + 1)
	if snap[0].Seq != wantFirstSeq {
		t.Fatalf("oldest surviving seq = %d, want %d", snap[0].Seq, wantFirstSeq)
	}
}

// TestRingBufferSnapshotOnEmpty verifies that Snapshot on an empty buffer
// returns an empty (non-nil) slice.
func TestRingBufferSnapshotOnEmpty(t *testing.T) {
	rb := NewRingBuffer()
	snap := rb.Snapshot()
	if snap == nil {
		t.Fatal("expected non-nil snapshot on empty buffer")
	}
	if len(snap) != 0 {
		t.Fatalf("expected empty snapshot, got len=%d", len(snap))
	}
}

// TestRingBufferReset verifies that Reset clears all rows and counters.
func TestRingBufferReset(t *testing.T) {
	rb := NewRingBuffer()
	for i := range 10 {
		rb.Push(Row{Seq: uint64(i + 1)})
	}

	rb.Reset()

	if got := rb.Len(); got != 0 {
		t.Fatalf("expected len=0 after reset, got %d", got)
	}
	if got := rb.TotalPushed(); got != 0 {
		t.Fatalf("expected totalPushed=0 after reset, got %d", got)
	}
	snap := rb.Snapshot()
	if len(snap) != 0 {
		t.Fatalf("expected empty snapshot after reset, got len=%d", len(snap))
	}
}
