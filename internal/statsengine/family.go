package statsengine

import (
	"cmp"
	"slices"
	"time"

	"ior/internal/event"
	"ior/internal/types"
)

type familyAccumulator struct {
	byFamily map[types.SyscallFamily]*familyStats
}

type familyStats struct {
	family       types.SyscallFamily
	count        uint64
	errorCount   uint64
	totalBytes   uint64
	totalLatency uint64
	minLatency   uint64
	maxLatency   uint64
}

type familySnapshotInput struct {
	family       types.SyscallFamily
	count        uint64
	errorCount   uint64
	totalBytes   uint64
	totalLatency uint64
	minLatency   uint64
	maxLatency   uint64
}

func newFamilyAccumulator() *familyAccumulator {
	return &familyAccumulator{byFamily: make(map[types.SyscallFamily]*familyStats)}
}

func (a *familyAccumulator) Add(pair *event.Pair) {
	if a == nil || pair == nil || pair.EnterEv == nil {
		return
	}

	family := pair.EnterEv.GetTraceId().Family()
	stats := a.byFamily[family]
	if stats == nil {
		stats = &familyStats{family: family}
		a.byFamily[family] = stats
	}

	stats.count++
	stats.totalBytes += pair.Bytes
	stats.totalLatency += pair.Duration
	stats.updateMinMax(pair.Duration)

	if retEv, ok := pair.ExitEv.(*types.RetEvent); ok && retEv.Ret < 0 {
		stats.errorCount++
	}
}

func (a *familyAccumulator) snapshotInputs() []familySnapshotInput {
	if a == nil {
		return nil
	}

	inputs := make([]familySnapshotInput, 0, len(a.byFamily))
	for _, stats := range a.byFamily {
		inputs = append(inputs, familySnapshotInput{
			family:       stats.family,
			count:        stats.count,
			errorCount:   stats.errorCount,
			totalBytes:   stats.totalBytes,
			totalLatency: stats.totalLatency,
			minLatency:   stats.minLatency,
			maxLatency:   stats.maxLatency,
		})
	}
	return inputs
}

func buildFamilySnapshots(inputs []familySnapshotInput, elapsed time.Duration) ([]FamilySnapshot, error) {
	rateDiv := elapsed.Seconds()
	result := make([]FamilySnapshot, 0, len(inputs))
	for _, in := range inputs {
		result = append(result, in.toSnapshot(rateDiv))
	}
	slices.SortFunc(result, compareFamilyDefault)
	return result, nil
}

func (s *familyStats) updateMinMax(duration uint64) {
	if s.count == 1 || duration < s.minLatency {
		s.minLatency = duration
	}
	if duration > s.maxLatency {
		s.maxLatency = duration
	}
}

func (s familySnapshotInput) toSnapshot(rateDiv float64) FamilySnapshot {
	return FamilySnapshot{
		Family:         s.family,
		Name:           string(s.family),
		Count:          s.count,
		RatePerSec:     safeRate(s.count, rateDiv),
		Errors:         s.errorCount,
		Bytes:          s.totalBytes,
		LatencyMinNs:   s.minLatency,
		LatencyMaxNs:   s.maxLatency,
		LatencyMeanNs:  float64(s.totalLatency) / float64(maxU64(s.count, 1)),
		TotalLatencyNs: s.totalLatency,
	}
}

func compareFamilyDefault(left, right FamilySnapshot) int {
	if left.Count != right.Count {
		return cmp.Compare(right.Count, left.Count)
	}
	return cmp.Compare(types.SyscallFamilyRank(left.Family), types.SyscallFamilyRank(right.Family))
}
