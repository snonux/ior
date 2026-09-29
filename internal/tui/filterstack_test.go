package tui

import (
	"testing"

	"ior/internal/globalfilter"
	"ior/internal/globalfilter/presenter"
)

// TestGlobalFilterActionLabelUsesPresenterTokens checks the derived label of
// every dimension, set and cleared, against the presenter's canonical token.
func TestGlobalFilterActionLabelUsesPresenterTokens(t *testing.T) {
	set := globalfilter.Filter{
		Syscall:   &globalfilter.StringFilter{Pattern: "read"},
		Family:    &globalfilter.StringFilter{Pattern: "FS"},
		Comm:      &globalfilter.StringFilter{Pattern: "a b~c"},
		File:      &globalfilter.StringFilter{Pattern: "/tmp/x y"},
		PID:       &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: 1},
		TID:       &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: 2},
		FD:        &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: -1},
		LatencyNs: &globalfilter.NumericFilter{Op: globalfilter.OpGte, Value: 1234},
		GapNs:     &globalfilter.NumericFilter{Op: globalfilter.OpGte, Value: 0},
		Bytes:     &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: 0},
		RetVal:    &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: -2},
	}
	for _, d := range presenter.Dimensions() {
		t.Run(d.Name(), func(t *testing.T) {
			only := onlyDimension(set, d)
			want := presenter.DimensionSummary(set, d)
			if want == "" {
				t.Fatalf("test filter leaves %s unset", d.Name())
			}
			if got := globalFilterActionLabel(globalfilter.Filter{}, only, ""); got != want {
				t.Fatalf("set label = %q, want presenter token %q", got, want)
			}
			if got := globalFilterActionLabel(only, globalfilter.Filter{}, ""); got != "clear "+d.Name() {
				t.Fatalf("clear label = %q, want %q", got, "clear "+d.Name())
			}
		})
	}
}

// onlyDimension returns a filter carrying just src's constraint on d.
func onlyDimension(src globalfilter.Filter, d presenter.Dimension) globalfilter.Filter {
	var out globalfilter.Filter
	switch d {
	case presenter.DimSyscall:
		out.Syscall = src.Syscall
	case presenter.DimFamily:
		out.Family = src.Family
	case presenter.DimComm:
		out.Comm = src.Comm
	case presenter.DimFile:
		out.File = src.File
	case presenter.DimPID:
		out.PID = src.PID
	case presenter.DimTID:
		out.TID = src.TID
	case presenter.DimFD:
		out.FD = src.FD
	case presenter.DimLatency:
		out.LatencyNs = src.LatencyNs
	case presenter.DimGap:
		out.GapNs = src.GapNs
	case presenter.DimBytes:
		out.Bytes = src.Bytes
	case presenter.DimRet:
		out.RetVal = src.RetVal
	}
	return out.Clone()
}

func TestGlobalFilterActionLabelEdgeCases(t *testing.T) {
	pid := func(v int64) *globalfilter.NumericFilter {
		return &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: v}
	}
	comm := func(p string) *globalfilter.StringFilter { return &globalfilter.StringFilter{Pattern: p} }
	tests := []struct {
		name       string
		prev, next globalfilter.Filter
		action     string
		want       string
	}{
		{"explicit action wins", globalfilter.Filter{}, globalfilter.Filter{PID: pid(1)}, "custom", "custom"},
		{"blank action derives", globalfilter.Filter{}, globalfilter.Filter{PID: pid(1)}, "  ", "pid=1"},
		{"changed value", globalfilter.Filter{PID: pid(1)}, globalfilter.Filter{PID: pid(2)}, "", "pid=2"},
		{"changed op", globalfilter.Filter{PID: pid(1)}, globalfilter.Filter{PID: &globalfilter.NumericFilter{Op: globalfilter.OpNeq, Value: 1}}, "", "pid!=1"},
		{"padding only is no change", globalfilter.Filter{Comm: comm("sh")}, globalfilter.Filter{Comm: comm(" sh "), PID: pid(3)}, "", "pid=3"},
		{"blank pattern clears", globalfilter.Filter{Comm: comm("sh")}, globalfilter.Filter{Comm: comm("  ")}, "", "clear comm"},
		{"errors toggled on", globalfilter.Filter{}, globalfilter.Filter{ErrorsOnly: true, Comm: comm("x")}, "", "errors comm~x"},
		{"errors toggled off", globalfilter.Filter{ErrorsOnly: true}, globalfilter.Filter{}, "", "clear errors"},
		{"no token change falls back to summary", globalfilter.Filter{}, globalfilter.Filter{Comm: comm(" ")}, "", "all"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := globalFilterActionLabel(tt.prev, tt.next, tt.action); got != tt.want {
				t.Fatalf("globalFilterActionLabel() = %q, want %q", got, tt.want)
			}
		})
	}
}
