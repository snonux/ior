package statsengine

import "time"

const (
	timeSeriesSlotsDefault = 120
)

var timeSeriesSlotWidthDefault = 500 * time.Millisecond

type timeSeriesSlot struct {
	key   int64
	sum   float64
	count uint64
}

// ringTimeSeries stores fixed-width time buckets in a circular buffer.
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

// Add records one sample of value at t; the slot reports the mean of all
// samples that fell into it.
func (r *ringTimeSeries) Add(value float64, t time.Time) {
	r.AddWeighted(value, 1, t)
}

// AddWeighted records count samples at t whose values sum to sum, so a
// pre-aggregated batch (e.g. one kernel aggregate drain covering a million
// syscalls) weighs as much in its slot's mean as the individual samples it
// stands for, instead of counting as a single sample next to per-event ones.
// A zero count carries no sample and is ignored, so it can neither create a
// slot nor advance the window.
func (r *ringTimeSeries) AddWeighted(sum float64, count uint64, t time.Time) {
	if r == nil || count == 0 {
		return
	}

	key := r.slotKey(t)
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
	r.slots[idx].count += count
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
		if slot.key != key || slot.count == 0 {
			continue
		}
		result[i] = slot.sum / float64(slot.count)
	}

	return result
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
