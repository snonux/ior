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
