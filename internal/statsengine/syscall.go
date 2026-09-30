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
	// untimedCount is the part of count that carries no latency (see
	// SyscallAggregate.UntimedCount); the mean divides by the timed rest.
	untimedCount uint64
	// hasTimed records whether min/max hold a real latency yet. A flag, not
	// count - untimedCount == 1: untimed counts are an estimate the consumer
	// may book one too high after a torn per-CPU read, and an off-by-one
	// there must not let a later sample overwrite a smaller minimum.
	hasTimed bool

	seenLatencies uint64
	samples       []uint64
	// scratch is a reusable buffer the snapshot capture copies samples into
	// (under the engine lock) so that it neither allocates under the lock
	// nor reorders the live reservoir. A capture takes it (leaving nil) and
	// storePercentileJobs hands it back. At most one buffer per reservoir is
	// retained, and it is freed together with the stats on Reset.
	scratch []uint64

	sampleVersion         uint64
	lastPercentileVersion uint64
	cachedP50             uint64
	cachedP95             uint64
	cachedP99             uint64
}

// percentileJob carries a private copy of one syscall's latency reservoir from
// snapshot capture (which runs under the engine lock) to the lock-free
// percentile computation, and from there back to the cached values in stats.
// Selecting the percentiles from a full 10k-sample reservoir costs ~0.16ms
// (~0.5ms with a full sort), so doing it for every active syscall under the
// engine lock used to stall Engine.Ingest for tens of ms per refresh. Under
// the lock only a copy per stale reservoir (80KB when full) remains, into the
// stats' reusable scratch buffer, so the lock is normally not also held across
// allocation and GC assists.
type percentileJob struct {
	stats    *syscallStats
	version  uint64   // stats.sampleVersion at the time samples was copied
	samples  []uint64 // private copy, reordered in place by latencyPercentiles outside the lock
	inputIdx int      // index of the matching entry in syscallCapture.inputs
	p50      uint64
	p95      uint64
	p99      uint64
}

// syscallCapture is the syscall part of a snapshot capture: per-syscall
// inputs (percentiles pre-filled from the cache) and the percentile jobs for
// reservoirs whose cached percentiles are stale. scratchMisses counts the jobs
// whose buffer had to be allocated under the lock because the stats' scratch
// buffer was missing (first capture, or held by a concurrent Snapshot) or too
// small (the reservoir grew).
type syscallCapture struct {
	inputs        []syscallSnapshotInput
	jobs          []percentileJob
	scratchMisses int
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
	untimedCount uint64
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
	if retEv, ok := pair.ExitEv.(event.RetCarrier); ok && event.IsErrorRet(retEv.GetRet()) {
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

	// Only a row with timed invocations has latency extrema; a row of
	// untimed counts carries min = max = 0, which must neither seed nor lower
	// the minimum. Likewise the minimum is seeded by the first *timed*
	// invocation, not by the first counted one.
	stats.count += row.Count
	stats.untimedCount += row.Count - row.timedCount()
	stats.errorCount += row.Errors
	stats.totalLatency += row.TotalLatencyNs
	if row.timedCount() == 0 {
		return
	}
	if !stats.hasTimed || row.MinLatencyNs < stats.minLatency {
		stats.minLatency = row.MinLatencyNs
	}
	if row.MaxLatencyNs > stats.maxLatency {
		stats.maxLatency = row.MaxLatencyNs
	}
	stats.hasTimed = true
}

// Snapshot returns a slice of SyscallSnapshots for all tracked syscalls.
// It panics on build error, which should never happen for a valid accumulator.
// The accumulator is not safe for concurrent use on its own, so capture,
// percentile computation and write-back simply run back to back here; Engine
// splits them to keep the percentile selection out of its lock.
func (a *syscallAccumulator) Snapshot(elapsed time.Duration) []SyscallSnapshot {
	if a == nil {
		return nil
	}

	capture := a.captureInputs()
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
// under the lock guarding the accumulator but computes no percentiles, and after
// the first capture it normally does not allocate either: samples are copied
// into the stats' own scratch buffer (see takeScratch). The returned inputs
// carry the cached percentiles; resolvePercentiles overwrites the stale ones.
func (a *syscallAccumulator) captureInputs() syscallCapture {
	if a == nil {
		return syscallCapture{}
	}

	capture := syscallCapture{inputs: make([]syscallSnapshotInput, 0, len(a.byID))}
	for _, stats := range a.byID {
		if stats.needsPercentileRecompute() {
			buf, reused := stats.takeScratch()
			if !reused {
				capture.scratchMisses++
			}
			capture.jobs = append(capture.jobs, percentileJob{
				stats:    stats,
				version:  stats.sampleVersion,
				samples:  append(buf, stats.samples...),
				inputIdx: len(capture.inputs),
			})
		}
		capture.inputs = append(capture.inputs, stats.snapshotInput())
	}
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
// cache so later snapshots can reuse them, and hands each job's sample buffer
// back as the stats' scratch buffer. It must run under the lock guarding the
// accumulator, after the job's samples are no longer used. A job's
// percentiles are dropped when the cache already holds percentiles for the
// same or a newer sample version (a concurrent Snapshot got there first), so
// an older result never replaces a fresher one; likewise a buffer is dropped
// when a concurrent Snapshot already returned one.
func storePercentileJobs(jobs []percentileJob) {
	for i := range jobs {
		job := &jobs[i]
		stats := job.stats
		if stats.scratch == nil {
			stats.scratch = job.samples[:0]
		}
		if stats.lastPercentileVersion >= job.version {
			continue
		}
		stats.cachedP50, stats.cachedP95, stats.cachedP99 = job.p50, job.p95, job.p99
		stats.lastPercentileVersion = job.version
	}
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

// updateMinMax folds one timed invocation into the latency extrema; the
// first timed one seeds the minimum.
func (s *syscallStats) updateMinMax(duration uint64) {
	if !s.hasTimed || duration < s.minLatency {
		s.minLatency = duration
	}
	s.hasTimed = true
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

// takeScratch removes the stats' scratch buffer and returns it emptied, with
// room for the whole reservoir. If the buffer is missing (first capture, or a
// concurrent Snapshot still holds it) or too small (the reservoir grew), it
// allocates one matching the reservoir's capacity and reports reused=false.
// Must run under the lock guarding the stats.
func (s *syscallStats) takeScratch() (buf []uint64, reused bool) {
	buf, s.scratch = s.scratch, nil
	if cap(buf) >= len(s.samples) && buf != nil {
		return buf[:0], true
	}
	return make([]uint64, 0, cap(s.samples)), false
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
		untimedCount: s.untimedCount,
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
		LatencyMeanNs:  float64(s.totalLatency) / float64(maxU64(timedCount(s.count, s.untimedCount), 1)),
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

// timedCount returns the part of count that carries a latency, i.e. the
// denominator of a latency mean. Untimed invocations add to count but not to
// total latency (see SyscallAggregate.UntimedCount); dividing by the full
// count would understate the mean exactly when the kernel falls back to them.
func timedCount(count, untimed uint64) uint64 {
	if untimed >= count {
		return 0
	}
	return count - untimed
}

func maxU64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}
