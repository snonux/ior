package statsengine

import (
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

// A weighted batch counts as count samples in its slot's mean: one batch of
// 3 samples summing to 300 next to a single sample of 10 gives (300+10)/4,
// not the unweighted (100+10)/2.
func TestRingTimeSeriesAddWeightedWeighsBatchByCount(t *testing.T) {
	base := time.Unix(100, 0)
	r := newRingTimeSeriesWithConfig(time.Second, 4)
	r.AddWeighted(300, 3, base)
	r.Add(10, base)

	got := r.Values()
	if last := got[len(got)-1]; last != 77.5 {
		t.Fatalf("slot mean = %v, want 77.5", last)
	}
}

// A zero-count batch carries no sample: it must neither create a slot (whose
// 0/0 mean would be reported) nor advance the window past older data.
func TestRingTimeSeriesAddWeightedIgnoresZeroCount(t *testing.T) {
	base := time.Unix(100, 0)
	r := newRingTimeSeriesWithConfig(time.Second, 4)
	r.AddWeighted(50, 0, base)
	if r.hasData {
		t.Fatal("zero-count batch on an empty series marked it as having data")
	}

	r.Add(8, base)
	r.AddWeighted(1_000, 0, base.Add(10*time.Second))
	got := r.Values()
	if last := got[len(got)-1]; last != 8 {
		t.Fatalf("values = %v, want last point 8 (window not advanced)", got)
	}
}

func TestRingTimeSeriesAddWeightedNilReceiver(t *testing.T) {
	var r *ringTimeSeries
	r.AddWeighted(1, 1, time.Unix(1, 0)) // must not panic
}
