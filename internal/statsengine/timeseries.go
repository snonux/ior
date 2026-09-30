package statsengine

import "time"

const (
	timeSeriesSlotsDefault = 120
)

var timeSeriesSlotWidthDefault = 500 * time.Millisecond

// timeSeriesSlot accumulates the samples of one time bucket. weight is the
// number of samples behind sum; it is fractional because AddSpread splits a
// batch across the slots its interval overlaps.
type timeSeriesSlot struct {
	key    int64
	sum    float64
	weight float64
}

// ringTimeSeries stores fixed-width time buckets in a circular buffer; each
// bucket reports the (weighted) mean of the samples that fell into it.
type ringTimeSeries struct {
	slots    []timeSeriesSlot
	slotSize time.Duration
	lastKey  int64
	hasData  bool
}

func newRingTimeSeries() *ringTimeSeries {
	return newRingTimeSeriesWithConfig(timeSeriesSlotWidthDefault, timeSeriesSlotsDefault)
}

func newRingTimeSeriesWithConfig(slotSize time.Duration, slots int) *ringTimeSeries {
	if slotSize <= 0 {
		slotSize = timeSeriesSlotWidthDefault
	}
	if slots <= 0 {
		slots = timeSeriesSlotsDefault
	}

	return &ringTimeSeries{
		slots:    make([]timeSeriesSlot, slots),
		slotSize: slotSize,
	}
}

// Add records one sample of value at t.
func (r *ringTimeSeries) Add(value float64, t time.Time) {
	if r == nil {
		return
	}
	r.addWeighted(value, 1, r.slotKey(t))
}

// AddSpread records a pre-aggregated batch of count samples summing to sum
// that accrued over [from, to), such as one kernel aggregate drain. The batch
// is split across the slots the interval overlaps, each receiving the share
// of sum and count proportional to its overlap, so:
//   - it weighs count samples, as many as the per-event samples it stands
//     for, instead of one sample next to them;
//   - a drain interval longer than a slot fills every slot it covers with
//     the batch mean, instead of piling onto one slot and leaving the others
//     empty (a comb of spikes and zeros that fakes trends).
//
// Shares falling before the series window are dropped like any too-old
// sample. An empty interval (to not after from) records the whole batch in
// to's slot, and a zero count carries no sample and is ignored, so it can
// neither create a slot nor advance the window.
func (r *ringTimeSeries) AddSpread(sum float64, count uint64, from, to time.Time) {
	if r == nil || count == 0 {
		return
	}
	if !to.After(from) {
		r.addWeighted(sum, float64(count), r.slotKey(to))
		return
	}

	total := float64(to.Sub(from))
	// Only the last len(slots) slots can be kept; skip iterating older ones.
	start := from
	if windowStart := to.Add(-r.slotSize * time.Duration(len(r.slots))); windowStart.After(start) {
		start = windowStart
	}
	for key := r.slotKey(start); key <= r.slotKey(to); key++ {
		overlap := r.overlap(key, start, to)
		if overlap <= 0 {
			continue
		}
		frac := float64(overlap) / total
		r.addWeighted(sum*frac, float64(count)*frac, key)
	}
}

// Values returns the window ending at the most recent slot that has data.
func (r *ringTimeSeries) Values() []float64 {
	return r.ValuesAt(time.Time{})
}

// ValuesAt returns the window ending at now (or at the most recent slot with
// data, whichever is later), so idle periods scroll in as zero-valued slots
// instead of freezing the series at the last event. A zero now is ignored.
func (r *ringTimeSeries) ValuesAt(now time.Time) []float64 {
	if r == nil {
		return nil
	}

	result := make([]float64, len(r.slots))
	if !r.hasData {
		return result
	}

	end := r.lastKey
	if !now.IsZero() {
		end = max(end, r.slotKey(now))
	}
	start := end - int64(len(r.slots)-1)
	for i := range result {
		key := start + int64(i)
		idx := r.slotIndex(key)
		slot := r.slots[idx]
		if slot.key != key || slot.weight == 0 {
			continue
		}
		result[i] = slot.sum / slot.weight
	}

	return result
}

// addWeighted adds sum and weight to the slot with key, advancing the window
// when key is newer than every slot so far.
func (r *ringTimeSeries) addWeighted(sum, weight float64, key int64) {
	if r.isTooOld(key) {
		return
	}
	if !r.hasData || key > r.lastKey {
		r.lastKey = key
		r.hasData = true
	}

	idx := r.slotIndex(key)
	r.resetSlotIfNeeded(idx, key)
	r.slots[idx].sum += sum
	r.slots[idx].weight += weight
}

// overlap returns how much of [from, to) falls into the slot with key.
func (r *ringTimeSeries) overlap(key int64, from, to time.Time) time.Duration {
	slotStart := time.Unix(0, key*r.slotSize.Nanoseconds())
	slotEnd := slotStart.Add(r.slotSize)
	if from.After(slotStart) {
		slotStart = from
	}
	if to.Before(slotEnd) {
		slotEnd = to
	}
	return slotEnd.Sub(slotStart)
}

func (r *ringTimeSeries) slotKey(t time.Time) int64 {
	return t.UnixNano() / r.slotSize.Nanoseconds()
}

func (r *ringTimeSeries) isTooOld(key int64) bool {
	if !r.hasData {
		return false
	}
	minKey := r.lastKey - int64(len(r.slots)-1)
	return key < minKey
}

func (r *ringTimeSeries) slotIndex(key int64) int {
	i := int(key % int64(len(r.slots)))
	if i < 0 {
		i += len(r.slots)
	}
	return i
}

func (r *ringTimeSeries) resetSlotIfNeeded(idx int, key int64) {
	if r.slots[idx].key == key {
		return
	}
	r.slots[idx] = timeSeriesSlot{key: key}
}
