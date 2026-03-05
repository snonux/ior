package statsengine

import (
	"math"
	"math/rand"
	"sort"
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
	return newSyscallAccumulatorWithConfig(syscallReservoirSampleCapDefault, rand.New(rand.NewSource(time.Now().UnixNano())))
}

func newSyscallAccumulatorWithConfig(sampleCap int, rng *rand.Rand) *syscallAccumulator {
	if sampleCap <= 0 {
		sampleCap = syscallReservoirSampleCapDefault
	}
	if rng == nil {
		rng = rand.New(rand.NewSource(time.Now().UnixNano()))
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

	if retEv, ok := pair.ExitEv.(*types.RetEvent); ok && retEv.Ret < 0 {
		stats.errorCount++
	}
}

func (a *syscallAccumulator) Snapshot(elapsed time.Duration) []SyscallSnapshot {
	if a == nil {
		return nil
	}

	return buildSyscallSnapshots(a.snapshotInputs(), elapsed)
}

func (a *syscallAccumulator) snapshotInputs() []syscallSnapshotInput {
	if a == nil {
		return nil
	}

	inputs := make([]syscallSnapshotInput, 0, len(a.byID))
	for _, stats := range a.byID {
		stats.ensurePercentiles()
		inputs = append(inputs, syscallSnapshotInput{
			traceID:      stats.traceID,
			name:         stats.name,
			count:        stats.count,
			errorCount:   stats.errorCount,
			totalBytes:   stats.totalBytes,
			totalLatency: stats.totalLatency,
			minLatency:   stats.minLatency,
			maxLatency:   stats.maxLatency,
			p50Latency:   stats.cachedP50,
			p95Latency:   stats.cachedP95,
			p99Latency:   stats.cachedP99,
		})
	}
	return inputs
}

func buildSyscallSnapshots(inputs []syscallSnapshotInput, elapsed time.Duration) []SyscallSnapshot {
	rateDiv := elapsed.Seconds()
	result := make([]SyscallSnapshot, 0, len(inputs))
	for _, in := range inputs {
		result = append(result, in.toSnapshot(rateDiv))
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Count != result[j].Count {
			return result[i].Count > result[j].Count
		}
		return result[i].Name < result[j].Name
	})
	return result
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

	idx := rng.Int63n(int64(s.seenLatencies))
	if idx >= int64(cap) {
		return
	}
	s.samples[idx] = duration
	s.sampleVersion++
}

func (s *syscallStats) ensurePercentiles() {
	if s.lastPercentileVersion == s.sampleVersion {
		return
	}
	if s.lastPercentileVersion != 0 && s.sampleVersion-s.lastPercentileVersion < syscallPercentileRecomputeStepDefault {
		return
	}
	if len(s.samples) == 0 {
		s.cachedP50, s.cachedP95, s.cachedP99 = 0, 0, 0
		s.lastPercentileVersion = s.sampleVersion
		return
	}

	sorted := append([]uint64(nil), s.samples...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	s.cachedP50 = samplePercentile(sorted, 0.50)
	s.cachedP95 = samplePercentile(sorted, 0.95)
	s.cachedP99 = samplePercentile(sorted, 0.99)
	s.lastPercentileVersion = s.sampleVersion
}

func (s syscallSnapshotInput) toSnapshot(rateDiv float64) SyscallSnapshot {
	return SyscallSnapshot{
		TraceID:       s.traceID,
		Name:          s.name,
		Count:         s.count,
		RatePerSec:    safeRate(s.count, rateDiv),
		Errors:        s.errorCount,
		Bytes:         s.totalBytes,
		LatencyMinNs:  s.minLatency,
		LatencyMaxNs:  s.maxLatency,
		LatencyMeanNs: float64(s.totalLatency) / float64(maxU64(s.count, 1)),
		LatencyP50Ns:  s.p50Latency,
		LatencyP95Ns:  s.p95Latency,
		LatencyP99Ns:  s.p99Latency,
	}
}

func samplePercentile(sorted []uint64, p float64) uint64 {
	if len(sorted) == 0 {
		return 0
	}
	if p <= 0 {
		return sorted[0]
	}
	if p >= 1 {
		return sorted[len(sorted)-1]
	}

	rank := int(math.Ceil(p*float64(len(sorted)))) - 1
	if rank < 0 {
		rank = 0
	}
	if rank >= len(sorted) {
		rank = len(sorted) - 1
	}
	return sorted[rank]
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
