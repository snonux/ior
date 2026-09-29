package statsengine

import (
	"math/rand/v2"
	"slices"
	"sync"
	"testing"
	"time"

	"ior/internal/types"
)

// fillReservoirs ingests samplesPerID latency samples for each of numIDs
// distinct syscalls into e, with durations spread so percentiles differ.
func fillReservoirs(e *Engine, numIDs, samplesPerID int) []types.TraceId {
	ids := make([]types.TraceId, 0, numIDs)
	for i := 1; i <= numIDs; i++ {
		ids = append(ids, types.TraceId(i))
	}
	for n := 0; n < samplesPerID; n++ {
		for i, id := range ids {
			e.Ingest(newPair(id, uint64((n*7919+i*31)%100_000+1), 1, 0))
		}
	}
	return ids
}

// referencePercentiles computes p50/p95/p99 the straightforward way, by
// sorting a copy of the reservoir, to check the capture/resolve/store split
// against.
func referencePercentiles(samples []uint64) (uint64, uint64, uint64) {
	sorted := slices.Clone(samples)
	slices.Sort(sorted)
	return samplePercentile(sorted, 0.50), samplePercentile(sorted, 0.95), samplePercentile(sorted, 0.99)
}

func TestSyscallSnapshotPercentilesMatchReference(t *testing.T) {
	tests := []struct {
		name    string
		samples int
	}{
		{name: "single sample", samples: 1},
		{name: "small reservoir", samples: 7},
		{name: "partial reservoir", samples: 1_000},
		{name: "full reservoir", samples: syscallReservoirSampleCapDefault},
		{name: "overflowing reservoir", samples: 3 * syscallReservoirSampleCapDefault},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			acc := newSyscallAccumulatorWithConfig(syscallReservoirSampleCapDefault, rand.New(rand.NewPCG(7, 0)))
			for i := 0; i < tc.samples; i++ {
				acc.Add(newPair(types.SYS_ENTER_READ, uint64((i*104729)%50_000+1), 0, 0))
			}
			stats := acc.byID[types.SYS_ENTER_READ]
			wantP50, wantP95, wantP99 := referencePercentiles(stats.samples)
			before := slices.Clone(stats.samples)

			snap := acc.Snapshot(time.Second)
			if len(snap) != 1 {
				t.Fatalf("expected 1 syscall snapshot, got %d", len(snap))
			}
			got := snap[0]
			if got.LatencyP50Ns != wantP50 || got.LatencyP95Ns != wantP95 || got.LatencyP99Ns != wantP99 {
				t.Fatalf("snapshot percentiles = %d/%d/%d, want %d/%d/%d",
					got.LatencyP50Ns, got.LatencyP95Ns, got.LatencyP99Ns, wantP50, wantP95, wantP99)
			}
			if stats.cachedP50 != wantP50 || stats.cachedP95 != wantP95 || stats.cachedP99 != wantP99 {
				t.Fatalf("cached percentiles = %d/%d/%d, want %d/%d/%d",
					stats.cachedP50, stats.cachedP95, stats.cachedP99, wantP50, wantP95, wantP99)
			}
			if stats.lastPercentileVersion != stats.sampleVersion {
				t.Fatalf("cache version = %d, want %d", stats.lastPercentileVersion, stats.sampleVersion)
			}
			if !slices.Equal(stats.samples, before) {
				t.Fatalf("resolving percentiles must not reorder the live reservoir")
			}
		})
	}
}

// TestEngineCaptureDoesNotSortReservoirs is the regression test for the
// engine lock being held while every syscall's 10k-sample reservoir is
// sorted: the capture (the only part of Snapshot that holds e.mu) must leave
// the percentile cache untouched and hand out private, unsorted copies.
func TestEngineCaptureDoesNotSortReservoirs(t *testing.T) {
	engine := NewEngine(DefaultTopN)
	ids := fillReservoirs(engine, 8, 2_000)

	in := engine.captureSnapshotInputs()
	if len(in.syscalls.jobs) != len(ids) {
		t.Fatalf("expected %d percentile jobs, got %d", len(ids), len(in.syscalls.jobs))
	}
	for _, job := range in.syscalls.jobs {
		stats := job.stats
		if stats.lastPercentileVersion != 0 || stats.cachedP50 != 0 {
			t.Fatalf("%s: percentiles were computed during capture (under the lock)", stats.name)
		}
		if &job.samples[0] == &stats.samples[0] {
			t.Fatalf("%s: job samples alias the live reservoir", stats.name)
		}
		if !slices.Equal(job.samples, stats.samples) {
			t.Fatalf("%s: job samples differ from the reservoir", stats.name)
		}
	}

	snap, err := engine.Snapshot()
	if err != nil {
		t.Fatalf("unexpected snapshot error: %v", err)
	}
	for _, s := range snap.Syscalls() {
		stats := engine.syscalls.byID[s.TraceID]
		wantP50, wantP95, wantP99 := referencePercentiles(stats.samples)
		if s.LatencyP50Ns != wantP50 || s.LatencyP95Ns != wantP95 || s.LatencyP99Ns != wantP99 {
			t.Fatalf("%s: percentiles = %d/%d/%d, want %d/%d/%d",
				s.Name, s.LatencyP50Ns, s.LatencyP95Ns, s.LatencyP99Ns, wantP50, wantP95, wantP99)
		}
		if stats.lastPercentileVersion != stats.sampleVersion || stats.cachedP50 != wantP50 {
			t.Fatalf("%s: percentiles were not cached after Snapshot", s.Name)
		}
	}

	// With the cache fresh, the next capture must not copy any reservoir.
	if jobs := engine.captureSnapshotInputs().syscalls.jobs; len(jobs) != 0 {
		t.Fatalf("expected no percentile jobs with a fresh cache, got %d", len(jobs))
	}
}

func TestSyscallCaptureSkipsEmptyReservoir(t *testing.T) {
	acc := newSyscallAccumulator()
	acc.AddAggregate(SyscallAggregate{TraceID: types.SYS_ENTER_READ, Count: 5, TotalLatencyNs: 50, MinLatencyNs: 1, MaxLatencyNs: 20})

	capture := acc.captureInputs()
	if len(capture.jobs) != 0 {
		t.Fatalf("aggregate-only syscall must not produce a percentile job, got %d", len(capture.jobs))
	}
	if len(capture.inputs) != 1 || capture.inputs[0].p50Latency != 0 || capture.inputs[0].p99Latency != 0 {
		t.Fatalf("unexpected inputs for aggregate-only syscall: %+v", capture.inputs)
	}
}

func TestSyscallCaptureNilAccumulator(t *testing.T) {
	var acc *syscallAccumulator
	capture := acc.captureInputs()
	if capture.inputs != nil || capture.jobs != nil {
		t.Fatalf("expected empty capture for nil accumulator, got %+v", capture)
	}
	capture.resolvePercentiles()
	capture.storePercentiles()
}

// TestSyscallStorePercentilesKeepsFresherCache covers the write-back race: a
// job resolved from an older (or the same) sample version must not replace
// percentiles a concurrent Snapshot already cached for that version or later.
func TestSyscallStorePercentilesKeepsFresherCache(t *testing.T) {
	tests := []struct {
		name        string
		jobVersion  uint64
		wantVersion uint64
		wantP50     uint64
	}{
		{name: "older job is dropped", jobVersion: 5, wantVersion: 10, wantP50: 100},
		{name: "same version is dropped", jobVersion: 10, wantVersion: 10, wantP50: 100},
		{name: "newer job is stored", jobVersion: 11, wantVersion: 11, wantP50: 7},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stats := &syscallStats{lastPercentileVersion: 10, cachedP50: 100, cachedP95: 200, cachedP99: 300}
			capture := syscallCapture{jobs: []percentileJob{{stats: stats, version: tc.jobVersion, p50: 7, p95: 8, p99: 9}}}
			capture.storePercentiles()
			if stats.lastPercentileVersion != tc.wantVersion || stats.cachedP50 != tc.wantP50 {
				t.Fatalf("got version=%d p50=%d, want version=%d p50=%d",
					stats.lastPercentileVersion, stats.cachedP50, tc.wantVersion, tc.wantP50)
			}
		})
	}
}

// TestEngineConcurrentIngestSnapshotReset exercises the capture / lock-free
// resolve / locked write-back split under the race detector while ingestion
// and resets run concurrently.
func TestEngineConcurrentIngestSnapshotReset(t *testing.T) {
	engine := NewEngine(DefaultTopN)
	fillReservoirs(engine, 4, 500)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(2)
	go func() {
		defer wg.Done()
		for n := 0; ; n++ {
			select {
			case <-stop:
				return
			default:
			}
			engine.Ingest(newPair(types.TraceId(n%4+1), uint64(n%1000+1), 1, 0))
			if n%5_000 == 4_999 {
				engine.Reset()
			}
		}
	}()
	go func() {
		defer wg.Done()
		defer close(stop)
		for i := 0; i < 50; i++ {
			snap, err := engine.Snapshot()
			if err != nil {
				t.Errorf("unexpected snapshot error: %v", err)
				return
			}
			for _, s := range snap.Syscalls() {
				if s.LatencyP50Ns > s.LatencyP95Ns || s.LatencyP95Ns > s.LatencyP99Ns {
					t.Errorf("%s: percentiles not monotonic: %d/%d/%d", s.Name, s.LatencyP50Ns, s.LatencyP95Ns, s.LatencyP99Ns)
					return
				}
			}
		}
	}()
	wg.Wait()
}
