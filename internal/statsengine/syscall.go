package statsengine

import (
	"cmp"
	"math/rand/v2"
	"slices"
	"time"

	"ior/internal/event"
	"ior/internal/types"
)

const syscallReservoirSampleCapDefault = 10_000
const syscallPercentileRecomputeStepDefault = 256

type syscallAccumulator struct {
	byID      map[types.TraceId]*syscallStats
	sampleCap int
	rng       *rand.Rand
}

type syscallStats struct {
	traceID types.TraceId
	name    string

	count        uint64
	errorCount   uint64
	totalBytes   uint64
	totalLatency uint64
	minLatency   uint64
	maxLatency   uint64

	seenLatencies uint64
	samples       []uint64

	sampleVersion         uint64
	lastPercentileVersion uint64
	cachedP50             uint64
	cachedP95             uint64
	cachedP99             uint64
}

// percentileJob carries a private copy of one syscall's latency reservoir from
// snapshot capture (which runs under the engine lock) to the lock-free
// percentile computation, and from there back to the cached values in stats.
// Sorting a full 10k-sample reservoir costs ~0.5ms, so doing it for every
// active syscall under the lock used to stall Engine.Ingest for tens of ms per
// refresh. Under the lock only an 80KB copy per stale reservoir remains, into
// a buffer the caller acquired beforehand (see sampleBufferPool) so that the
// lock is not also held across allocation and GC assists.
type percentileJob struct {
	stats    *syscallStats
	version  uint64   // stats.sampleVersion at the time samples was copied
	samples  []uint64 // private copy, sorted in place outside the lock
	inputIdx int      // index of the matching entry in syscallCapture.inputs
	p50      uint64
	p95      uint64
	p99      uint64
}

// syscallCapture is the syscall part of a snapshot capture: per-syscall
// inputs (percentiles pre-filled from the cache), the percentile jobs for
// reservoirs whose cached percentiles are stale, and the scratch buffers the
// capture was given but did not need.
type syscallCapture struct {
	inputs []syscallSnapshotInput
	jobs   []percentileJob
	spare  [][]uint64
}

type syscallSnapshotInput struct {
	traceID      types.TraceId
	name         string
	count        uint64
	errorCount   uint64
	totalBytes   uint64
	totalLatency uint64
	minLatency   uint64
	maxLatency   uint64
	p50Latency   uint64
	p95Latency   uint64
	p99Latency   uint64
}

func newSyscallAccumulator() *syscallAccumulator {
	return newSyscallAccumulatorWithConfig(syscallReservoirSampleCapDefault, nil)
}

// newSyscallAccumulatorWithConfig creates a syscall accumulator with the given
// sample capacity and optional RNG. A nil rng uses the auto-seeded default.
func newSyscallAccumulatorWithConfig(sampleCap int, rng *rand.Rand) *syscallAccumulator {
	if sampleCap <= 0 {
		sampleCap = syscallReservoirSampleCapDefault
	}
	if rng == nil {
		rng = rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64()))
	}

	return &syscallAccumulator{
		byID:      make(map[types.TraceId]*syscallStats),
		sampleCap: sampleCap,
		rng:       rng,
	}
}

func (a *syscallAccumulator) Add(pair *event.Pair) {
	if a == nil || pair == nil || pair.EnterEv == nil {
		return
	}

	traceID := pair.EnterEv.GetTraceId()
	stats := a.byID[traceID]
	if stats == nil {
		stats = &syscallStats{traceID: traceID, name: traceID.Name()}
		a.byID[traceID] = stats
	}

	stats.count++
	stats.totalBytes += pair.Bytes
	stats.totalLatency += pair.Duration
	stats.updateMinMax(pair.Duration)
	stats.addSample(pair.Duration, a.sampleCap, a.rng)

	// Any ret-carrying exit event counts here, including the kind-specific
	// exits (accept/accept4, pipe/pipe2, socketpair, eventfd/pidfd).
	if retEv, ok := pair.ExitEv.(event.RetCarrier); ok && event.IsErrnoRet(retEv.GetRet()) {
		stats.errorCount++
	}
}

func (a *syscallAccumulator) AddAggregate(row SyscallAggregate) {
	if a == nil || row.TraceID == 0 || row.Count == 0 {
		return
	}

	stats := a.byID[row.TraceID]
	if stats == nil {
		stats = &syscallStats{traceID: row.TraceID, name: row.TraceID.Name()}
		a.byID[row.TraceID] = stats
	}

	prevCount := stats.count
	stats.count += row.Count
	stats.errorCount += row.Errors
	stats.totalLatency += row.TotalLatencyNs
	if prevCount == 0 || row.MinLatencyNs < stats.minLatency {
		stats.minLatency = row.MinLatencyNs
	}
	if row.MaxLatencyNs > stats.maxLatency {
		stats.maxLatency = row.MaxLatencyNs
	}
}

// Snapshot returns a slice of SyscallSnapshots for all tracked syscalls.
// It panics on build error, which should never happen for a valid accumulator.
// The accumulator is not safe for concurrent use on its own, so capture,
// percentile computation and write-back simply run back to back here; Engine
// splits them to keep the sort out of its lock.
func (a *syscallAccumulator) Snapshot(elapsed time.Duration) []SyscallSnapshot {
	if a == nil {
		return nil
	}

	capture := a.captureInputs(nil)
	capture.resolvePercentiles()
	storePercentileJobs(capture.jobs)
	snap, err := buildSyscallSnapshots(capture.inputs, elapsed)
	if err != nil {
		panic("buildSyscallSnapshots: " + err.Error())
	}
	return snap
}

// captureInputs copies the per-syscall counters and, for every reservoir whose
// cached percentiles are stale, a private copy of its samples. It must run
// under the lock guarding the accumulator but performs no sorting. Samples are
// copied into the best-fitting scratch buffer (empty, pre-allocated outside
// the lock); only when no scratch buffer is large enough, e.g. for reservoirs
// that went stale or grew since the caller sized it, does it allocate. Unused
// scratch buffers are returned in spare.
// The returned inputs carry the cached percentiles; resolvePercentiles
// overwrites the stale ones.
func (a *syscallAccumulator) captureInputs(scratch [][]uint64) syscallCapture {
	if a == nil {
		return syscallCapture{spare: scratch}
	}

	capture := syscallCapture{inputs: make([]syscallSnapshotInput, 0, len(a.byID))}
	for _, stats := range a.byID {
		if stats.needsPercentileRecompute() {
			// Best fit, so a small reservoir does not take the buffer a full
			// one needs; with no fitting buffer, append allocates exactly.
			buf, _ := takeBestFit(&scratch, len(stats.samples))
			capture.jobs = append(capture.jobs, percentileJob{
				stats:    stats,
				version:  stats.sampleVersion,
				samples:  append(buf[:0], stats.samples...),
				inputIdx: len(capture.inputs),
			})
		}
		capture.inputs = append(capture.inputs, stats.snapshotInput())
	}
	capture.spare = scratch
	return capture
}

// resolvePercentiles computes each job's percentiles from its private sample
// copy (reordering it in place) and fills them in both on the job (for
// storePercentileJobs) and on the matching input. It touches no accumulator
// state, so callers run it without holding any lock.
func (c *syscallCapture) resolvePercentiles() {
	for i := range c.jobs {
		job := &c.jobs[i]
		job.p50, job.p95, job.p99 = latencyPercentiles(job.samples)

		in := &c.inputs[job.inputIdx]
		in.p50Latency, in.p95Latency, in.p99Latency = job.p50, job.p95, job.p99
	}
}

// storePercentileJobs writes resolved percentiles back into the per-syscall
// cache so later snapshots can reuse them. It must run under the lock guarding
// the accumulator. A job is dropped when the cache already holds percentiles
// for the same or a newer sample version (a concurrent Snapshot got there
// first), so an older result never replaces a fresher one.
func storePercentileJobs(jobs []percentileJob) {
	for i := range jobs {
		job := &jobs[i]
		stats := job.stats
		if stats.lastPercentileVersion >= job.version {
			continue
		}
		stats.cachedP50, stats.cachedP95, stats.cachedP99 = job.p50, job.p95, job.p99
		stats.lastPercentileVersion = job.version
	}
}

// jobSampleBuffers returns the sample buffers owned by jobs so the caller can
// recycle them once the jobs are resolved and stored.
func jobSampleBuffers(jobs []percentileJob) [][]uint64 {
	bufs := make([][]uint64, 0, len(jobs))
	for i := range jobs {
		bufs = append(bufs, jobs[i].samples)
	}
	return bufs
}

// buildSyscallSnapshots converts raw syscall accumulator inputs into sorted
// SyscallSnapshot slices. The error return is reserved for future validation;
// currently this function always succeeds.
func buildSyscallSnapshots(inputs []syscallSnapshotInput, elapsed time.Duration) ([]SyscallSnapshot, error) {
	rateDiv := elapsed.Seconds()
	result := make([]SyscallSnapshot, 0, len(inputs))
	for _, in := range inputs {
		result = append(result, in.toSnapshot(rateDiv))
	}
	slices.SortFunc(result, func(a, b SyscallSnapshot) int {
		if a.Count != b.Count {
			return cmp.Compare(b.Count, a.Count)
		}
		return cmp.Compare(a.Name, b.Name)
	})
	return result, nil
}

func (s *syscallStats) updateMinMax(duration uint64) {
	if s.count == 1 || duration < s.minLatency {
		s.minLatency = duration
	}
	if duration > s.maxLatency {
		s.maxLatency = duration
	}
}

func (s *syscallStats) addSample(duration uint64, cap int, rng *rand.Rand) {
	s.seenLatencies++
	if len(s.samples) < cap {
		s.samples = append(s.samples, duration)
		s.sampleVersion++
		return
	}

	idx := rng.IntN(int(s.seenLatencies))
	if idx >= cap {
		return
	}
	s.samples[idx] = duration
	s.sampleVersion++
}

// needsPercentileRecompute reports whether the cached percentiles must be
// recomputed from the samples. An empty reservoir (e.g. a syscall only seen
// through AddAggregate) never needs a job: its cached zero percentiles are
// already correct. Otherwise the first computation always happens, later ones
// are batched by percentilesStale.
func (s *syscallStats) needsPercentileRecompute() bool {
	if s.lastPercentileVersion == s.sampleVersion || len(s.samples) == 0 {
		return false
	}
	return s.lastPercentileVersion == 0 || s.percentilesStale()
}

// snapshotInput copies the counters and the cached percentiles of s.
func (s *syscallStats) snapshotInput() syscallSnapshotInput {
	return syscallSnapshotInput{
		traceID:      s.traceID,
		name:         s.name,
		count:        s.count,
		errorCount:   s.errorCount,
		totalBytes:   s.totalBytes,
		totalLatency: s.totalLatency,
		minLatency:   s.minLatency,
		maxLatency:   s.maxLatency,
		p50Latency:   s.cachedP50,
		p95Latency:   s.cachedP95,
		p99Latency:   s.cachedP99,
	}
}

// percentilesStale reports whether enough new samples arrived since the last
// percentile computation. Recomputes are batched by a fixed step for large
// reservoirs, but a small reservoir is recomputed once the new samples are a
// noticeable fraction of it; otherwise a rarely called syscall would keep its
// first-snapshot percentiles until it collected another full step of samples.
func (s *syscallStats) percentilesStale() bool {
	delta := s.sampleVersion - s.lastPercentileVersion
	if delta >= syscallPercentileRecomputeStepDefault {
		return true
	}
	return delta*8 >= uint64(len(s.samples))
}

func (s syscallSnapshotInput) toSnapshot(rateDiv float64) SyscallSnapshot {
	return SyscallSnapshot{
		TraceID:        s.traceID,
		Name:           s.name,
		Count:          s.count,
		RatePerSec:     safeRate(s.count, rateDiv),
		Errors:         s.errorCount,
		Bytes:          s.totalBytes,
		LatencyMinNs:   s.minLatency,
		LatencyMaxNs:   s.maxLatency,
		LatencyMeanNs:  float64(s.totalLatency) / float64(maxU64(s.count, 1)),
		TotalLatencyNs: s.totalLatency,
		LatencyP50Ns:   s.p50Latency,
		LatencyP95Ns:   s.p95Latency,
		LatencyP99Ns:   s.p99Latency,
	}
}

func safeRate(count uint64, elapsedSeconds float64) float64 {
	if elapsedSeconds <= 0 {
		return 0
	}
	return float64(count) / elapsedSeconds
}

func maxU64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}
