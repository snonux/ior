package statsengine

import (
	"math"
	"reflect"
	"testing"
	"time"
)

func TestRingTimeSeriesAveragesWithinSlot(t *testing.T) {
	r := newRingTimeSeriesWithConfig(time.Second, 4)
	base := time.Unix(0, 0)

	r.Add(10, base)
	r.Add(20, base.Add(400*time.Millisecond))

	got := r.Values()
	want := []float64{0, 0, 0, 15}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected values: got %v want %v", got, want)
	}
}

func TestRingTimeSeriesWrapAround(t *testing.T) {
	r := newRingTimeSeriesWithConfig(time.Second, 4)
	base := time.Unix(0, 0)

	for i := 0; i < 6; i++ {
		r.Add(float64(i+1), base.Add(time.Duration(i)*time.Second))
	}

	got := r.Values()
	want := []float64{3, 4, 5, 6}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected wrap-around values: got %v want %v", got, want)
	}
}

func TestRingTimeSeriesGapHandling(t *testing.T) {
	r := newRingTimeSeriesWithConfig(time.Second, 4)
	base := time.Unix(0, 0)

	r.Add(10, base)
	r.Add(40, base.Add(3*time.Second))

	got := r.Values()
	want := []float64{10, 0, 0, 40}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected gap values: got %v want %v", got, want)
	}
}

func TestRingTimeSeriesIgnoresTooOldSamples(t *testing.T) {
	r := newRingTimeSeriesWithConfig(time.Second, 4)
	base := time.Unix(0, 0)

	r.Add(1, base)
	r.Add(5, base.Add(5*time.Second))
	r.Add(99, base)

	got := r.Values()
	want := []float64{0, 0, 0, 5}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected values with old sample: got %v want %v", got, want)
	}
}

func TestRingTimeSeriesValuesAtScrollsThroughIdlePeriod(t *testing.T) {
	r := newRingTimeSeriesWithConfig(time.Second, 4)
	base := time.Unix(100, 0)

	r.Add(5, base)
	r.Add(7, base.Add(time.Second))

	got := r.ValuesAt(base.Add(3 * time.Second))
	want := []float64{5, 7, 0, 0}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected values: got %v want %v", got, want)
	}
}

// A batch counts as count samples in its slot's mean: one batch of 3 samples
// summing to 300 next to a single sample of 10 gives (300+10)/4, not the
// unweighted (100+10)/2.
func TestRingTimeSeriesAddSpreadWeighsBatchByCount(t *testing.T) {
	base := time.Unix(100, 0)
	r := newRingTimeSeriesWithConfig(time.Second, 4)
	r.AddSpread(300, 3, base, base) // empty interval: all in base's slot
	r.Add(10, base)

	got := r.Values()
	if last := got[len(got)-1]; last != 77.5 {
		t.Fatalf("slot mean = %v, want 77.5", last)
	}
}

// A batch covering several slots fills each with the batch mean and splits
// its weight by overlap: 1s of 40ns calls over 500ms slots puts half the
// weight in each, so a 100ns pair in the last slot moves its mean to
// (20*40+100)/21 while the first slot keeps 40.
func TestRingTimeSeriesAddSpreadSplitsAcrossSlots(t *testing.T) {
	base := time.Unix(100, 0)
	r := newRingTimeSeriesWithConfig(500*time.Millisecond, 4)
	r.AddSpread(40*40, 40, base, base.Add(time.Second))
	r.Add(100, base.Add(700*time.Millisecond))

	got := r.ValuesAt(base.Add(999 * time.Millisecond))
	want := []float64{0, 0, 40, (20*40 + 100) / 21.0}
	for i := range want {
		if math.Abs(got[i]-want[i]) > 1e-9 {
			t.Fatalf("values = %v, want %v", got, want)
		}
	}
}

// A partial overlap gets its proportional share: [250ms, 1s) over 500ms
// slots is 1/3 in the first slot and 2/3 in the second.
func TestRingTimeSeriesAddSpreadPartialOverlap(t *testing.T) {
	base := time.Unix(100, 0)
	r := newRingTimeSeriesWithConfig(500*time.Millisecond, 4)
	r.AddSpread(30, 3, base.Add(250*time.Millisecond), base.Add(time.Second))

	first, second := r.slots[r.slotIndex(r.slotKey(base))], r.slots[r.slotIndex(r.slotKey(base.Add(500*time.Millisecond)))]
	if math.Abs(first.weight-1) > 1e-9 || math.Abs(second.weight-2) > 1e-9 {
		t.Fatalf("weights = %v/%v, want 1/2", first.weight, second.weight)
	}
	if math.Abs(first.sum-10) > 1e-9 || math.Abs(second.sum-20) > 1e-9 {
		t.Fatalf("sums = %v/%v, want 10/20", first.sum, second.sum)
	}
}

// An interval reaching far back only touches the slots still in the window;
// the older share is dropped and every kept slot shows the batch mean.
func TestRingTimeSeriesAddSpreadClampsToWindow(t *testing.T) {
	base := time.Unix(1_000, 0)
	r := newRingTimeSeriesWithConfig(time.Second, 4)
	r.AddSpread(7*1_000, 1_000, base.Add(-time.Hour), base)

	for _, v := range r.ValuesAt(base.Add(-time.Nanosecond)) {
		if math.Abs(v-7) > 1e-9 {
			t.Fatalf("values = %v, want all 7", r.Values())
		}
	}
}

// A zero-count batch carries no sample: it must neither create a slot (whose
// 0/0 mean would be reported) nor advance the window past older data.
func TestRingTimeSeriesAddSpreadIgnoresZeroCount(t *testing.T) {
	base := time.Unix(100, 0)
	r := newRingTimeSeriesWithConfig(time.Second, 4)
	r.AddSpread(50, 0, base, base.Add(time.Second))
	if r.hasData {
		t.Fatal("zero-count batch on an empty series marked it as having data")
	}

	r.Add(8, base)
	r.AddSpread(1_000, 0, base, base.Add(10*time.Second))
	got := r.Values()
	if last := got[len(got)-1]; last != 8 {
		t.Fatalf("values = %v, want last point 8 (window not advanced)", got)
	}
}

// A reversed interval (clock stepped back) records the batch in to's slot.
func TestRingTimeSeriesAddSpreadReversedInterval(t *testing.T) {
	base := time.Unix(100, 0)
	r := newRingTimeSeriesWithConfig(time.Second, 4)
	r.AddSpread(20, 2, base.Add(5*time.Second), base)

	got := r.Values()
	if last := got[len(got)-1]; last != 10 || r.lastKey != r.slotKey(base) {
		t.Fatalf("values = %v lastKey = %d, want last point 10 in base's slot", got, r.lastKey)
	}
}

func TestRingTimeSeriesNilReceiver(t *testing.T) {
	var r *ringTimeSeries
	r.Add(1, time.Unix(1, 0))                           // must not panic
	r.AddSpread(1, 1, time.Unix(0, 0), time.Unix(1, 0)) // must not panic
}
