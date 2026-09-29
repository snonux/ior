package statsengine

const histogramBucketCount = 8

type histogram struct {
	counts [histogramBucketCount]uint64
	total  uint64
}

type histogramSnapshotInput struct {
	counts [histogramBucketCount]uint64
	total  uint64
}

var histogramBoundariesNs = [histogramBucketCount - 1]uint64{
	1_000,
	10_000,
	100_000,
	1_000_000,
	10_000_000,
	100_000_000,
	1_000_000_000,
}

var histogramLabels = [histogramBucketCount]string{
	"[0,1us)",
	"[1us,10us)",
	"[10us,100us)",
	"[100us,1ms)",
	"[1ms,10ms)",
	"[10ms,100ms)",
	"[100ms,1s)",
	"[1s,+inf)",
}

func newHistogram() *histogram {
	return &histogram{}
}

func (h *histogram) Increment(durationNs uint64) {
	if h == nil {
		return
	}

	idx := histogramBucketIndex(durationNs)
	h.counts[idx]++
	h.total++
}

func (h *histogram) AddBucketCounts(counts [histogramBucketCount]uint64) {
	if h == nil {
		return
	}
	for i, count := range counts {
		h.counts[i] += count
		h.total += count
	}
}

// Snapshot returns a HistogramSnapshot of the current histogram state.
// It panics on build error, which should never happen for a valid histogram.
func (h *histogram) Snapshot() HistogramSnapshot {
	if h == nil {
		return NewHistogramSnapshot(0, nil)
	}

	snap, err := buildHistogramSnapshot(h.snapshotInputs())
	if err != nil {
		panic("buildHistogramSnapshot: " + err.Error())
	}
	return snap
}

func (h *histogram) snapshotInputs() histogramSnapshotInput {
	if h == nil {
		return histogramSnapshotInput{}
	}
	return histogramSnapshotInput{
		counts: h.counts,
		total:  h.total,
	}
}

// buildHistogramSnapshot converts a histogramSnapshotInput into a
// HistogramSnapshot. The error return is reserved for future validation;
// currently this function always succeeds.
func buildHistogramSnapshot(in histogramSnapshotInput) (HistogramSnapshot, error) {
	buckets := make([]HistogramBucketSnapshot, 0, histogramBucketCount)
	for i := 0; i < histogramBucketCount; i++ {
		lower, upper := histogramBucketRange(i)
		buckets = append(buckets, HistogramBucketSnapshot{
			Label:   histogramLabels[i],
			LowerNs: lower,
			UpperNs: upper,
			Count:   in.counts[i],
		})
	}

	return NewHistogramSnapshot(in.total, buckets), nil
}

func histogramBucketIndex(durationNs uint64) int {
	for i, upper := range histogramBoundariesNs {
		if durationNs < upper {
			return i
		}
	}
	return histogramBucketCount - 1
}

func histogramBucketRange(i int) (lower uint64, upper uint64) {
	if i == 0 {
		return 0, histogramBoundariesNs[0]
	}
	if i == histogramBucketCount-1 {
		return histogramBoundariesNs[i-1], 0
	}
	return histogramBoundariesNs[i-1], histogramBoundariesNs[i]
}
