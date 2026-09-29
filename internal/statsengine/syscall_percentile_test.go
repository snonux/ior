package statsengine

import (
	"fmt"
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

// TestEngineSnapshotCachesPercentilesAcrossStaleSnapshots checks that every
// Snapshot that resolves stale reservoirs writes the fresh percentiles back to
// the cache, also on later rounds when the samples are copied into the
// scratch buffers the previous round handed back.
func TestEngineSnapshotCachesPercentilesAcrossStaleSnapshots(t *testing.T) {
	engine := NewEngine(DefaultTopN)
	ids := fillReservoirs(engine, 6, 3_000)

	for round := 0; round < 3; round++ {
		if round > 0 {
			// Push every syscall past the recompute step with larger latencies
			// so the percentiles really change between rounds.
			for n := 0; n < syscallPercentileRecomputeStepDefault; n++ {
				for _, id := range ids {
					engine.Ingest(newPair(id, uint64(200_000*round+n), 1, 0))
				}
			}
		}
		if _, err := engine.Snapshot(); err != nil {
			t.Fatalf("round %d: unexpected snapshot error: %v", round, err)
		}
		for _, id := range ids {
			stats := engine.syscalls.byID[id]
			wantP50, wantP95, wantP99 := referencePercentiles(stats.samples)
			if stats.lastPercentileVersion != stats.sampleVersion {
				t.Fatalf("round %d, %s: cache version %d, want %d", round, stats.name, stats.lastPercentileVersion, stats.sampleVersion)
			}
			if stats.cachedP50 != wantP50 || stats.cachedP95 != wantP95 || stats.cachedP99 != wantP99 {
				t.Fatalf("round %d, %s: cached %d/%d/%d, want %d/%d/%d", round, stats.name,
					stats.cachedP50, stats.cachedP95, stats.cachedP99, wantP50, wantP95, wantP99)
			}
		}
		// From round 1 on every stale reservoir must be copied into the
		// scratch buffer the previous round handed back.
		for _, id := range ids {
			if stats := engine.syscalls.byID[id]; stats.scratch == nil {
				t.Fatalf("round %d, %s: scratch buffer not handed back", round, stats.name)
			}
		}
	}
}

// TestEngineCaptureReusesScratchAtMixedRates is the regression test for
// allocating reservoir copies under the engine lock: syscalls ingesting at
// different rates go stale on different ticks, and after the first capture
// every stale reservoir must still be copied into its own scratch buffer,
// never into a buffer allocated under the lock.
func TestEngineCaptureReusesScratchAtMixedRates(t *testing.T) {
	engine := NewEngine(DefaultTopN)
	const numIDs, ticks = 24, 40
	ids := fillReservoirs(engine, numIDs, syscallReservoirSampleCapDefault)
	if _, err := engine.Snapshot(); err != nil { // warm-up: allocates scratch
		t.Fatalf("unexpected snapshot error: %v", err)
	}

	misses, jobs := 0, 0
	for tick := 0; tick < ticks; tick++ {
		for i, id := range ids {
			rate := 24 + (i*97)%237 // 24..260 samples per tick
			for n := 0; n < rate; n++ {
				engine.Ingest(newPair(id, uint64((tick*rate+n)%90_000+1), 1, 0))
			}
		}
		in := engine.captureSnapshotInputs()
		misses += in.syscalls.scratchMisses
		jobs += len(in.syscalls.jobs)
		ss, err := buildSubSnapshots(in, time.Second)
		if err != nil {
			t.Fatalf("tick %d: unexpected build error: %v", tick, err)
		}
		engine.storeSyscallPercentiles(ss.syscallJobs)
	}
	if jobs == 0 {
		t.Fatalf("expected stale reservoirs across the ticks")
	}
	if misses != 0 {
		t.Fatalf("%d of %d jobs allocated their buffer under the lock after warm-up", misses, jobs)
	}
	// Retention stays at one buffer per reservoir, no larger than it.
	for _, id := range ids {
		stats := engine.syscalls.byID[id]
		if cap(stats.scratch) > cap(stats.samples) {
			t.Fatalf("%s: scratch cap %d exceeds reservoir cap %d", stats.name, cap(stats.scratch), cap(stats.samples))
		}
	}
}

// TestEngineStoreAfterResetLeavesNewStatsUntouched runs the Snapshot phases
// by hand around a Reset: the write-back of a capture taken before the Reset
// must only touch the discarded accumulator's stats, never the fresh ones.
func TestEngineStoreAfterResetLeavesNewStatsUntouched(t *testing.T) {
	engine := NewEngine(DefaultTopN)
	ids := fillReservoirs(engine, 3, 1_000)

	in := engine.captureSnapshotInputs()
	engine.Reset()
	for _, id := range ids {
		engine.Ingest(newPair(id, 42, 1, 0))
	}
	capture := in.syscalls
	capture.resolvePercentiles()
	engine.storeSyscallPercentiles(capture.jobs)

	for _, id := range ids {
		stats := engine.syscalls.byID[id]
		if stats.lastPercentileVersion != 0 || stats.cachedP50 != 0 || stats.cachedP99 != 0 {
			t.Fatalf("%s: stale write-back touched the post-Reset stats: %+v", stats.name, stats)
		}
	}
	for _, job := range capture.jobs {
		if job.stats.lastPercentileVersion != job.version || job.stats.cachedP50 == 0 {
			t.Fatalf("%s: write-back to the discarded stats did not happen", job.stats.name)
		}
	}

	snap, err := engine.Snapshot()
	if err != nil {
		t.Fatalf("unexpected snapshot error: %v", err)
	}
	for _, s := range snap.Syscalls() {
		if s.LatencyP50Ns != 42 || s.LatencyP99Ns != 42 {
			t.Fatalf("%s: post-Reset percentiles = %d/%d, want 42/42", s.Name, s.LatencyP50Ns, s.LatencyP99Ns)
		}
	}
}

func TestSyscallCaptureUsesScratchBuffers(t *testing.T) {
	tests := []struct {
		name       string
		scratchCap int // -1: no scratch buffer
		wantReused bool
	}{
		{name: "no scratch allocates", scratchCap: -1, wantReused: false},
		{name: "too small scratch allocates", scratchCap: 10, wantReused: false},
		{name: "exact scratch is reused", scratchCap: 50, wantReused: true},
		{name: "larger scratch is reused", scratchCap: 64, wantReused: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			acc := newSyscallAccumulator()
			for i := 0; i < 50; i++ {
				acc.Add(newPair(types.SYS_ENTER_READ, uint64(i+1), 0, 0))
			}
			stats := acc.byID[types.SYS_ENTER_READ]
			if tc.scratchCap >= 0 {
				stats.scratch = make([]uint64, 3, tc.scratchCap)
			}
			old := stats.scratch

			capture := acc.captureInputs()
			if len(capture.jobs) != 1 || stats.scratch != nil {
				t.Fatalf("expected 1 job and the scratch taken, got %d jobs, scratch %v", len(capture.jobs), stats.scratch != nil)
			}
			job := capture.jobs[0]
			if !slices.Equal(job.samples, stats.samples) || &job.samples[0] == &stats.samples[0] {
				t.Fatalf("job samples are not a private copy of the reservoir")
			}
			reused := old != nil && &job.samples[0] == &old[:1][0]
			if reused != tc.wantReused || (capture.scratchMisses == 0) != tc.wantReused {
				t.Fatalf("reused=%v misses=%d, want reused=%v", reused, capture.scratchMisses, tc.wantReused)
			}

			storePercentileJobs(capture.jobs)
			if stats.scratch == nil || len(stats.scratch) != 0 || &stats.scratch[:1][0] != &job.samples[0] {
				t.Fatalf("store must hand the job buffer back as empty scratch")
			}
		})
	}
}

// TestStorePercentileJobsKeepsExistingScratch covers two overlapping
// snapshots: the second store must not replace the buffer the first returned.
func TestStorePercentileJobsKeepsExistingScratch(t *testing.T) {
	stats := &syscallStats{scratch: make([]uint64, 0, 8)}
	kept := &stats.scratch[:1][0]
	storePercentileJobs([]percentileJob{{stats: stats, version: 1, samples: make([]uint64, 4, 8)}})
	if &stats.scratch[:1][0] != kept {
		t.Fatalf("store replaced an existing scratch buffer")
	}
}

// TestNeedsPercentileRecompute pins the recompute batching boundaries.
func TestNeedsPercentileRecompute(t *testing.T) {
	full := make([]uint64, syscallReservoirSampleCapDefault)
	small := make([]uint64, 80)
	tests := []struct {
		name    string
		samples []uint64
		last    uint64
		version uint64
		want    bool
	}{
		{name: "empty reservoir", samples: nil, last: 0, version: 0, want: false},
		{name: "never computed", samples: small, last: 0, version: 80, want: true},
		{name: "cache current", samples: full, last: 20_000, version: 20_000, want: false},
		{name: "full reservoir delta 255", samples: full, last: 20_000, version: 20_255, want: false},
		{name: "full reservoir delta 256", samples: full, last: 20_000, version: 20_256, want: true},
		{name: "small reservoir delta*8 below len", samples: small, last: 80, version: 89, want: false},
		{name: "small reservoir delta*8 equals len", samples: small, last: 80, version: 90, want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stats := &syscallStats{samples: tc.samples, lastPercentileVersion: tc.last, sampleVersion: tc.version}
			if got := stats.needsPercentileRecompute(); got != tc.want {
				t.Fatalf("needsPercentileRecompute() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestNeedsPercentileRecomputeIgnoresRejectedSamples checks that samples the
// full reservoir rejects bump neither sampleVersion nor the recompute trigger.
func TestNeedsPercentileRecomputeIgnoresRejectedSamples(t *testing.T) {
	acc := newSyscallAccumulatorWithConfig(1_000, rand.New(rand.NewPCG(3, 0)))
	for i := 0; i < 1_000; i++ {
		acc.Add(newPair(types.SYS_ENTER_READ, uint64(i+1), 0, 0))
	}
	_ = acc.Snapshot(time.Second)
	stats := acc.byID[types.SYS_ENTER_READ]
	version := stats.sampleVersion

	// With this many samples already seen, each new one replaces a reservoir
	// slot with probability 1000/2^40, i.e. effectively never.
	stats.seenLatencies = 1 << 40
	for i := 0; i < 2*syscallPercentileRecomputeStepDefault; i++ {
		acc.Add(newPair(types.SYS_ENTER_READ, 1_000_000, 0, 0))
	}
	if stats.sampleVersion != version {
		t.Fatalf("rejected samples bumped sampleVersion: %d -> %d", version, stats.sampleVersion)
	}
	if stats.needsPercentileRecompute() {
		t.Fatalf("rejected samples must not trigger a percentile recompute")
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
	storePercentileJobs(capture.jobs)
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
			storePercentileJobs(capture.jobs)
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
				if err := checkPercentileBounds(s); err != "" {
					t.Error(err)
					return
				}
			}
		}
	}()
	wg.Wait()
}

// checkPercentileBounds returns a description of the first violated invariant
// Min <= P50 <= P95 <= P99 <= Max of a non-empty syscall snapshot, or "".
func checkPercentileBounds(s SyscallSnapshot) string {
	if s.Count == 0 {
		return ""
	}
	vals := []uint64{s.LatencyMinNs, s.LatencyP50Ns, s.LatencyP95Ns, s.LatencyP99Ns, s.LatencyMaxNs}
	if !slices.IsSorted(vals) {
		return fmt.Sprintf("%s: want min<=p50<=p95<=p99<=max, got %v", s.Name, vals)
	}
	return ""
}
