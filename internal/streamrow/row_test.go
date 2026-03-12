package streamrow

import (
	"sync"
	"testing"
)

func TestSequencerStartsAfterSeed(t *testing.T) {
	seq := NewSequencer(41)
	if got, want := seq.Next(), uint64(42); got != want {
		t.Fatalf("first Next() = %d, want %d", got, want)
	}
	if got, want := seq.Next(), uint64(43); got != want {
		t.Fatalf("second Next() = %d, want %d", got, want)
	}
}

func TestSequencerIsMonotonicUnderConcurrency(t *testing.T) {
	seq := NewSequencer(0)

	const workers = 8
	const perWorker = 64

	got := make(chan uint64, workers*perWorker)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perWorker; j++ {
				got <- seq.Next()
			}
		}()
	}
	wg.Wait()
	close(got)

	seen := make(map[uint64]struct{}, workers*perWorker)
	for n := range got {
		if _, ok := seen[n]; ok {
			t.Fatalf("duplicate sequence number %d", n)
		}
		seen[n] = struct{}{}
	}
	if got, want := len(seen), workers*perWorker; got != want {
		t.Fatalf("unique sequence count = %d, want %d", got, want)
	}
}
