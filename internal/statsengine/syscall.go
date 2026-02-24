package statsengine

import (
	"ior/internal/event"
	"ior/internal/types"
	"math"
	"math/rand"
	"sort"
	"time"
)

const syscallReservoirSampleCapDefault = 10_000

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
}

type syscallSnapshotInput struct {
	traceID       types.TraceId
	name          string
	count         uint64
	errorCount    uint64
	totalBytes    uint64
	totalLatency  uint64
	minLatency    uint64
	maxLatency    uint64
	sortedSamples []uint64
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
		sorted := append([]uint64(nil), stats.samples...)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
		inputs = append(inputs, syscallSnapshotInput{
			traceID:       stats.traceID,
			name:          stats.name,
			count:         stats.count,
			errorCount:    stats.errorCount,
			totalBytes:    stats.totalBytes,
			totalLatency:  stats.totalLatency,
			minLatency:    stats.minLatency,
			maxLatency:    stats.maxLatency,
			sortedSamples: sorted,
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
		return
	}

	idx := rng.Int63n(int64(s.seenLatencies))
	if idx >= int64(cap) {
		return
	}
	s.samples[idx] = duration
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
		LatencyP50Ns:  samplePercentile(s.sortedSamples, 0.50),
		LatencyP95Ns:  samplePercentile(s.sortedSamples, 0.95),
		LatencyP99Ns:  samplePercentile(s.sortedSamples, 0.99),
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
