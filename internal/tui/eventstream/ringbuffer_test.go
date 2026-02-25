package eventstream

import (
	"sync"
	"testing"
)

func TestRingBufferWrapsAtCapacity(t *testing.T) {
	rb := NewRingBuffer()

	for i := 0; i < ringBufferCapacity+5; i++ {
		rb.Push(StreamEvent{Seq: uint64(i)})
	}

	if got := rb.Len(); got != ringBufferCapacity {
		t.Fatalf("Len() = %d, want %d", got, ringBufferCapacity)
	}
	if got := rb.TotalPushed(); got != uint64(ringBufferCapacity+5) {
		t.Fatalf("TotalPushed() = %d, want %d", got, ringBufferCapacity+5)
	}

	snap := rb.Snapshot()
	if len(snap) != ringBufferCapacity {
		t.Fatalf("len(Snapshot()) = %d, want %d", len(snap), ringBufferCapacity)
	}
	if snap[0].Seq != 5 {
		t.Fatalf("first seq = %d, want 5", snap[0].Seq)
	}
	if snap[len(snap)-1].Seq != uint64(ringBufferCapacity+4) {
		t.Fatalf("last seq = %d, want %d", snap[len(snap)-1].Seq, ringBufferCapacity+4)
	}
}

func TestRingBufferSnapshotOldestFirst(t *testing.T) {
	rb := NewRingBuffer()

	rb.Push(StreamEvent{Seq: 10})
	rb.Push(StreamEvent{Seq: 11})
	rb.Push(StreamEvent{Seq: 12})

	snap := rb.Snapshot()
	if len(snap) != 3 {
		t.Fatalf("len(Snapshot()) = %d, want 3", len(snap))
	}
	if snap[0].Seq != 10 || snap[1].Seq != 11 || snap[2].Seq != 12 {
		t.Fatalf("snapshot order = [%d,%d,%d], want [10,11,12]", snap[0].Seq, snap[1].Seq, snap[2].Seq)
	}
}

func TestRingBufferConcurrentPushAndSnapshot(t *testing.T) {
	rb := NewRingBuffer()
	const pushes = 20000

	var pushWG sync.WaitGroup
	pushWG.Add(1)
	go func() {
		defer pushWG.Done()
		for i := 0; i < pushes; i++ {
			rb.Push(StreamEvent{Seq: uint64(i)})
		}
	}()

	done := make(chan struct{})
	var readWG sync.WaitGroup
	for i := 0; i < 4; i++ {
		readWG.Add(1)
		go func() {
			defer readWG.Done()
			for {
				select {
				case <-done:
					return
				default:
					_ = rb.Snapshot()
					_ = rb.Len()
					_ = rb.TotalPushed()
				}
			}
		}()
	}

	pushWG.Wait()
	close(done)
	readWG.Wait()

	if got := rb.TotalPushed(); got != pushes {
		t.Fatalf("TotalPushed() = %d, want %d", got, pushes)
	}
	if got := rb.Len(); got > ringBufferCapacity {
		t.Fatalf("Len() = %d, want <= %d", got, ringBufferCapacity)
	}
}

func TestRingBufferSnapshotEmpty(t *testing.T) {
	rb := NewRingBuffer()

	snap := rb.Snapshot()
	if snap == nil {
		t.Fatalf("Snapshot() = nil, want empty slice")
	}
	if len(snap) != 0 {
		t.Fatalf("len(Snapshot()) = %d, want 0", len(snap))
	}
}
