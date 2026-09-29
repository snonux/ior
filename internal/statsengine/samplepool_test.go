package statsengine

import "testing"

func TestSampleBufferPoolReusesAndTrims(t *testing.T) {
	pool := newSampleBufferPool(8)
	if got := pool.acquire(0); got != nil {
		t.Fatalf("acquire(0) = %v, want nil", got)
	}

	bufs := pool.acquire(3)
	if len(bufs) != 3 {
		t.Fatalf("acquire(3) returned %d buffers", len(bufs))
	}
	for _, buf := range bufs {
		if len(buf) != 0 || cap(buf) != 8 {
			t.Fatalf("expected empty buffer with cap 8, got len=%d cap=%d", len(buf), cap(buf))
		}
	}
	first := &bufs[0][:1][0]
	bufs[0] = append(bufs[0], 1, 2, 3)

	// keep=2 trims the pool: only two of the three buffers are retained.
	pool.release(bufs, 2)
	if len(pool.free) != 2 {
		t.Fatalf("expected 2 pooled buffers after trimmed release, got %d", len(pool.free))
	}

	again := pool.acquire(3)
	reused := false
	for _, buf := range again {
		if len(buf) != 0 {
			t.Fatalf("reused buffer not reset to length 0: %v", buf)
		}
		if &buf[:1][0] == first {
			reused = true
		}
	}
	if !reused || len(pool.free) != 0 {
		t.Fatalf("expected pooled buffers to be handed out again (reused=%v, left=%d)", reused, len(pool.free))
	}
}

func TestSampleBufferPoolDropsUndersizedBuffers(t *testing.T) {
	pool := newSampleBufferPool(8)
	pool.release([][]uint64{make([]uint64, 3), nil, make([]uint64, 0, 8)}, 10)
	if len(pool.free) != 1 || cap(pool.free[0]) != 8 {
		t.Fatalf("expected only the full-size buffer to be pooled, got %d buffers", len(pool.free))
	}
}
