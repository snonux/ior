package flamegraph

import "testing"

func TestFrameCoordToTargetRowKeepsUniformBarMapping(t *testing.T) {
	frames := []tuiFrame{
		{Name: "root", Row: 0, Col: 0, Width: 20, Path: "root"},
		{Name: "a", Row: 1, Col: 0, Width: 20, Path: "root" + pathSeparator + "a"},
		{Name: "b", Row: 2, Col: 0, Width: 20, Path: "root" + pathSeparator + "a" + pathSeparator + "b"},
		{Name: "leaf", Row: 3, Col: 0, Width: 20, Path: "root" + pathSeparator + "a" + pathSeparator + "b" + pathSeparator + "leaf"},
	}
	availableRows := 8
	params := computeRenderParamsForAvailableRows(frames, availableRows, false)
	want := []int{3, 3, 2, 2, 1, 1, 0, 0}
	for dataRow, expected := range want {
		if got := frameCoordToTargetRow(dataRow, params); got != expected {
			t.Fatalf("dataRow=%d: got row=%d want=%d", dataRow, got, expected)
		}
	}
}

func TestFrameCoordToTargetRowHeightMetricMapsExpandedLeafBand(t *testing.T) {
	frames := []tuiFrame{
		{Name: "root", Row: 0, Col: 0, Width: 20, Path: "root"},
		{Name: "leaf", Row: 1, Col: 0, Width: 20, Path: "root" + pathSeparator + "leaf", HeightTotal: 100},
	}
	availableRows := 6
	params := computeRenderParamsForAvailableRows(frames, availableRows, true)
	want := []int{1, 1, 1, 1, 1, 0}
	for dataRow, expected := range want {
		if got := frameCoordToTargetRow(dataRow, params); got != expected {
			t.Fatalf("dataRow=%d: got row=%d want=%d", dataRow, got, expected)
		}
	}
}

func TestFrameIndexAtHeightMetricMapsClicksInExpandedLeafBand(t *testing.T) {
	frames := []tuiFrame{
		{Name: "root", Row: 0, Col: 0, Width: 20, Path: "root"},
		{Name: "leaf", Row: 1, Col: 0, Width: 20, Path: "root" + pathSeparator + "leaf", HeightTotal: 100},
	}
	for y := 1; y <= 5; y++ {
		if got := frameIndexAt(frames, 10, y, 20, 9, false, true); got != 1 {
			t.Fatalf("y=%d: expected leaf frame index 1, got %d", y, got)
		}
	}
	if got := frameIndexAt(frames, 10, 6, 20, 9, false, true); got != 0 {
		t.Fatalf("y=6: expected root frame index 0, got %d", got)
	}
}
