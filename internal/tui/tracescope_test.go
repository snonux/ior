package tui

import (
	"testing"

	"ior/internal/globalfilter"
)

// TestKernelScopeCovers pins which filter changes a running session can take
// in place: its PID/TID scope is loaded into BPF at start, so only a filter
// that keeps a scoped dimension on the same ID is covered.
func TestKernelScopeCovers(t *testing.T) {
	pid := func(v int64) globalfilter.Filter {
		return globalfilter.Filter{PID: globalfilter.NewEqFilter(v)}
	}
	cases := []struct {
		name    string
		session globalfilter.Filter
		next    globalfilter.Filter
		want    bool
	}{
		{"unscoped narrows to a pid", globalfilter.Filter{}, pid(4242), true},
		{"same pid", pid(4242), pid(4242), true},
		{"other pid", pid(4242), pid(5678), false},
		{"pid cleared", pid(4242), globalfilter.Filter{}, false},
		{"pid to non-equality", pid(4242), globalfilter.Filter{PID: &globalfilter.NumericFilter{Op: globalfilter.OpNeq, Value: 1}}, false},
	}
	for _, tc := range cases {
		lifecycle := traceLifecycle{scope: kernelScopeOf(tc.session)}
		if got := lifecycle.scopeCovers(tc.next); got != tc.want {
			t.Errorf("%s: scopeCovers = %v, want %v", tc.name, got, tc.want)
		}
	}
}
