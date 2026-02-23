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

func (r *ringTimeSeries) Add(value float64, t time.Time) {
	if r == nil {
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
	r.slots[idx].sum += value
	r.slots[idx].count++
}

func (r *ringTimeSeries) Values() []float64 {
	if r == nil {
		return nil
	}

	result := make([]float64, len(r.slots))
	if !r.hasData {
		return result
	}

	start := r.lastKey - int64(len(r.slots)-1)
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
