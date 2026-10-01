package streamrow

import (
	"math/rand/v2"
	"sync"
	"testing"
)

// scanWarnings counts the warning rows of a snapshot: the reference the
// incrementally kept WarningCount must always equal.
func scanWarnings(rows []Row) int {
	n := 0
	for i := range rows {
		if rows[i].IsWarning {
			n++
		}
	}
	return n
}

// assertWarningCount fails unless WarningCount equals both want and a scan
// of the retained rows.
func assertWarningCount(t *testing.T, rb *RingBuffer, want int, step string) {
	t.Helper()
	got := rb.WarningCount()
	if scanned := scanWarnings(rb.Snapshot()); got != scanned {
		t.Fatalf("%s: WarningCount = %d, scan of the retained rows = %d", step, got, scanned)
	}
	if got != want {
		t.Fatalf("%s: WarningCount = %d, want %d", step, got, want)
	}
}

// TestRingBufferWarningCountInsertAndReset covers the plain cases: an empty
// buffer, normal rows that must not count, warning rows that must, and a
// Reset (the trace restart's stream clear) that drops the count to zero.
func TestRingBufferWarningCountInsertAndReset(t *testing.T) {
	rb := NewRingBuffer()
	assertWarningCount(t, rb, 0, "empty")

	rb.Push(Row{Seq: 1, Syscall: "read"})
	assertWarningCount(t, rb, 0, "normal row")

	rb.Push(NewWarning(2, "first"))
	rb.Push(Row{Seq: 3, Syscall: "write"})
	rb.Push(NewWarning(4, "second"))
	assertWarningCount(t, rb, 2, "mixed rows")

	rb.Reset()
	assertWarningCount(t, rb, 0, "after Reset")

	rb.Push(NewWarning(5, "after reset"))
	assertWarningCount(t, rb, 1, "push after Reset")
}

// TestRingBufferWarningCountFollowsEviction fills the ring so that the
// warning rows are overwritten by a wrap: each eviction of a warning row must
// leave the count, each eviction of a normal row must not touch it.
func TestRingBufferWarningCountFollowsEviction(t *testing.T) {
	rb := NewRingBuffer()
	rb.Push(NewWarning(0, "oldest"))
	rb.Push(Row{Seq: 1})
	rb.Push(NewWarning(2, "second oldest"))
	for seq := uint64(3); seq < RingBufferCapacity; seq++ {
		rb.Push(Row{Seq: seq})
	}
	assertWarningCount(t, rb, 2, "full ring")

	rb.Push(Row{Seq: RingBufferCapacity}) // evicts warning 0
	assertWarningCount(t, rb, 1, "first warning evicted")
	rb.Push(NewWarning(RingBufferCapacity+1, "newer")) // evicts normal row 1
	assertWarningCount(t, rb, 2, "normal row evicted, warning added")
	rb.Push(NewWarning(RingBufferCapacity+2, "newest")) // evicts warning 2
	assertWarningCount(t, rb, 2, "warning evicts warning")

	// A whole lap of normal rows pushes every warning out.
	for i := range RingBufferCapacity {
		rb.Push(Row{Seq: uint64(2*RingBufferCapacity + i)})
	}
	assertWarningCount(t, rb, 0, "a lap of normal rows")
}

// TestRingBufferWarningCountRandomMix drives several laps of a seeded random
// mix of warning and normal rows with occasional Resets and compares the
// count to a scan of the retained rows at checkpoints throughout.
func TestRingBufferWarningCountRandomMix(t *testing.T) {
	rng := rand.New(rand.NewPCG(7, 11))
	rb := NewRingBuffer()
	for i := range 3*RingBufferCapacity + 123 {
		switch r := rng.IntN(1000); {
		case r == 0:
			rb.Reset()
		case r < 300:
			rb.Push(NewWarning(uint64(i), "w"))
		default:
			rb.Push(Row{Seq: uint64(i)})
		}
		if i%997 == 0 {
			assertWarningCount(t, rb, scanWarnings(rb.Snapshot()), "random mix")
		}
	}
	assertWarningCount(t, rb, scanWarnings(rb.Snapshot()), "random mix end")
}

// TestRingBufferWarningCountConcurrentPush pushes from several goroutines
// while a reader polls WarningCount (the UI goroutine's pattern); under
// -race this pins that the count is read and written under the lock, and
// the final count must still be exact.
func TestRingBufferWarningCountConcurrentPush(t *testing.T) {
	rb := NewRingBuffer()
	const writers, perWriter = 4, 3000
	var wg sync.WaitGroup
	done, readerDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			select {
			case <-done:
				return
			default:
				if n := rb.WarningCount(); n < 0 || n > RingBufferCapacity {
					t.Errorf("WarningCount out of range: %d", n)
					return
				}
			}
		}
	}()
	for w := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range perWriter {
				if i%3 == 0 {
					rb.Push(NewWarning(uint64(w*perWriter+i), "w"))
				} else {
					rb.Push(Row{Seq: uint64(w*perWriter + i)})
				}
			}
		}()
	}
	wg.Wait()
	close(done)
	<-readerDone
	assertWarningCount(t, rb, scanWarnings(rb.Snapshot()), "after concurrent pushes")
}
