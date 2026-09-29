package statsengine

import "testing"

// demandJobs builds percentile jobs whose sample slices have the given lengths.
func demandJobs(lens ...int) []percentileJob {
	jobs := make([]percentileJob, 0, len(lens))
	for _, n := range lens {
		jobs = append(jobs, percentileJob{samples: make([]uint64, n)})
	}
	return jobs
}

func TestSampleBufferPoolAcquireFollowsDemand(t *testing.T) {
	pool := newSampleBufferPool(100)
	if got := pool.acquire(); got != nil {
		t.Fatalf("acquire without demand = %v, want nil", got)
	}

	pool.recordDemand(demandJobs(1, 3, 64, 65, 100, 100))
	bufs := pool.acquire()
	var caps []int
	for _, buf := range bufs {
		if len(buf) != 0 {
			t.Fatalf("acquired buffer not empty: len %d", len(buf))
		}
		caps = append(caps, cap(buf))
	}
	want := []int{1, 4, 64, 100, 100, 100} // pow2 buckets capped at bufCap
	if len(caps) != len(want) {
		t.Fatalf("acquired caps %v, want %v", caps, want)
	}
	for i := range want {
		if caps[i] != want[i] {
			t.Fatalf("acquired caps %v, want %v", caps, want)
		}
	}

	// Released buffers are handed out again instead of reallocated.
	first := &bufs[2][:1][0]
	pool.release(bufs)
	reused := false
	for _, buf := range pool.acquire() {
		if cap(buf) > 0 && &buf[:1][0] == first {
			reused = true
		}
	}
	if !reused {
		t.Fatalf("expected a released buffer to be reused")
	}
}

func TestSampleBufferPoolTrimsToDemand(t *testing.T) {
	tests := []struct {
		name      string
		demand    []int
		release   []int // capacities of released buffers
		wantCount int
		wantCap   int
	}{
		{name: "no demand keeps nothing", demand: nil, release: []int{100, 8}, wantCount: 0, wantCap: 0},
		{name: "one buffer per demand", demand: []int{8, 8}, release: []int{8, 8, 8, 8}, wantCount: 2, wantCap: 16},
		{name: "oversized buffers dropped", demand: []int{4}, release: []int{100}, wantCount: 0, wantCap: 0},
		{name: "undersized buffers dropped", demand: []int{60}, release: []int{60}, wantCount: 0, wantCap: 0},
		{name: "best fit per demand", demand: []int{100, 5}, release: []int{8, 100, 64}, wantCount: 2, wantCap: 108},
		{name: "nil and empty buffers ignored", demand: []int{1}, release: []int{0}, wantCount: 0, wantCap: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pool := newSampleBufferPool(100)
			pool.recordDemand(demandJobs(tc.demand...))
			bufs := make([][]uint64, 0, len(tc.release))
			for _, c := range tc.release {
				bufs = append(bufs, make([]uint64, 0, c))
			}
			pool.release(bufs)
			if len(pool.free) != tc.wantCount || pool.retainedCap() != tc.wantCap {
				t.Fatalf("retained %d buffers / cap %d, want %d / %d", len(pool.free), pool.retainedCap(), tc.wantCount, tc.wantCap)
			}
		})
	}
}

func TestTakeBestFit(t *testing.T) {
	bufs := [][]uint64{make([]uint64, 0, 64), make([]uint64, 3, 8), make([]uint64, 0, 16)}
	buf, ok := takeBestFit(&bufs, 10)
	if !ok || cap(buf) != 16 || len(buf) != 0 || len(bufs) != 2 {
		t.Fatalf("takeBestFit(10) = cap %d len %d ok %v, %d left", cap(buf), len(buf), ok, len(bufs))
	}
	if _, ok := takeBestFit(&bufs, 65); ok || len(bufs) != 2 {
		t.Fatalf("takeBestFit(65) must find nothing and keep the pool")
	}
}
