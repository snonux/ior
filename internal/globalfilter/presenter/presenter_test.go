package presenter_test

import (
	"strings"
	"testing"

	"ior/internal/globalfilter"
	"ior/internal/globalfilter/presenter"
)

func TestCompareOpSymbolCoversAllOps(t *testing.T) {
	for _, tc := range []struct {
		name string
		op   globalfilter.CompareOp
		want string
	}{
		{name: "eq", op: globalfilter.OpEq, want: "="},
		{name: "neq", op: globalfilter.OpNeq, want: "!="},
		{name: "gt", op: globalfilter.OpGt, want: ">"},
		{name: "gte", op: globalfilter.OpGte, want: ">="},
		{name: "lt", op: globalfilter.OpLt, want: "<"},
		{name: "lte", op: globalfilter.OpLte, want: "<="},
		{name: "unknown", op: globalfilter.CompareOp(99), want: "?"},
	} {
		if got := presenter.CompareOpSymbol(tc.op); got != tc.want {
			t.Fatalf("%s: CompareOpSymbol() = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestAppendStringSummarySkipsEmptyAndNilFilters(t *testing.T) {
	parts := []string{}
	parts = presenter.AppendStringSummary(parts, "syscall", nil)
	if len(parts) != 0 {
		t.Fatalf("nil filter should not append")
	}
	parts = presenter.AppendStringSummary(parts, "syscall", &globalfilter.StringFilter{Pattern: "  "})
	if len(parts) != 0 {
		t.Fatalf("blank pattern should not append")
	}
	parts = presenter.AppendStringSummary(parts, "syscall", &globalfilter.StringFilter{Pattern: "read"})
	if len(parts) != 1 || parts[0] != "syscall~read" {
		t.Fatalf("expected syscall~read, got %v", parts)
	}
}

func TestAppendNumericSummaryFormatsDurationsAndIntegers(t *testing.T) {
	parts := []string{}
	nf := &globalfilter.NumericFilter{Op: globalfilter.OpGt, Value: 1_000_000}
	parts = presenter.AppendNumericSummary(parts, "latency", nf, true)
	if len(parts) != 1 || parts[0] != "latency>1ms" {
		t.Fatalf("expected latency>1ms, got %v", parts)
	}

	parts = []string{}
	nf = &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: 42}
	parts = presenter.AppendNumericSummary(parts, "pid", nf, false)
	if len(parts) != 1 || parts[0] != "pid=42" {
		t.Fatalf("expected pid=42, got %v", parts)
	}
}

func TestFilterSummaryReturnsAllForZeroFilter(t *testing.T) {
	if got := presenter.FilterSummary(globalfilter.Filter{}); got != "all" {
		t.Fatalf("FilterSummary(zero) = %q, want \"all\"", got)
	}
}

func TestFilterSummaryIncludesAllActivePredicates(t *testing.T) {
	f := globalfilter.Filter{
		ErrorsOnly: true,
		Syscall:    &globalfilter.StringFilter{Pattern: "read"},
		Comm:       &globalfilter.StringFilter{Pattern: "nginx"},
		PID:        &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: 1234},
		LatencyNs:  &globalfilter.NumericFilter{Op: globalfilter.OpGt, Value: 1_000_000},
	}
	got := presenter.FilterSummary(f)
	for _, want := range []string{"errors", "syscall~read", "comm~nginx", "pid=1234", "latency>1ms"} {
		if !strings.Contains(got, want) {
			t.Fatalf("FilterSummary() = %q, missing %q", got, want)
		}
	}
}

// allDimensionsFilter sets every dimension so each DimensionSummary token is
// non-empty.
func allDimensionsFilter() globalfilter.Filter {
	return globalfilter.Filter{
		Syscall:   &globalfilter.StringFilter{Pattern: "read"},
		Family:    &globalfilter.StringFilter{Pattern: "FS"},
		Comm:      &globalfilter.StringFilter{Pattern: "nginx"},
		File:      &globalfilter.StringFilter{Pattern: "/tmp/x"},
		PID:       &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: 1},
		TID:       &globalfilter.NumericFilter{Op: globalfilter.OpNeq, Value: 2},
		FD:        &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: -1},
		LatencyNs: &globalfilter.NumericFilter{Op: globalfilter.OpGte, Value: 1500},
		GapNs:     &globalfilter.NumericFilter{Op: globalfilter.OpLt, Value: 0},
		Bytes:     &globalfilter.NumericFilter{Op: globalfilter.OpLte, Value: 64},
		RetVal:    &globalfilter.NumericFilter{Op: globalfilter.OpGt, Value: -2},
	}
}

func TestDimensionSummaryCoversEveryDimension(t *testing.T) {
	f := allDimensionsFilter()
	want := map[presenter.Dimension]string{
		presenter.DimSyscall: "syscall~read",
		presenter.DimFamily:  "family~FS",
		presenter.DimComm:    "comm~nginx",
		presenter.DimFile:    "file~/tmp/x",
		presenter.DimPID:     "pid=1",
		presenter.DimTID:     "tid!=2",
		presenter.DimFD:      "fd=-1",
		presenter.DimLatency: "latency>=1.5µs",
		presenter.DimGap:     "gap<0s",
		presenter.DimBytes:   "bytes<=64",
		presenter.DimRet:     "ret>-2",
	}
	dims := presenter.Dimensions()
	if len(dims) != len(want) {
		t.Fatalf("Dimensions() has %d entries, want %d", len(dims), len(want))
	}
	for _, d := range dims {
		if got := presenter.DimensionSummary(f, d); got != want[d] {
			t.Fatalf("DimensionSummary(%s) = %q, want %q", d.Name(), got, want[d])
		}
	}
	// FilterSummary is the dimension tokens in canonical order.
	joined := strings.Join([]string{
		"syscall~read", "family~FS", "comm~nginx", "file~/tmp/x", "pid=1", "tid!=2",
		"fd=-1", "latency>=1.5µs", "gap<0s", "bytes<=64", "ret>-2",
	}, " ")
	if got := presenter.FilterSummary(f); got != joined {
		t.Fatalf("FilterSummary() = %q, want %q", got, joined)
	}
}

func TestDimensionSummaryEmptyAndSpecialValues(t *testing.T) {
	for _, d := range presenter.Dimensions() {
		if got := presenter.DimensionSummary(globalfilter.Filter{}, d); got != "" {
			t.Fatalf("DimensionSummary(zero, %s) = %q, want empty", d.Name(), got)
		}
	}
	blank := globalfilter.Filter{Comm: &globalfilter.StringFilter{Pattern: " \t "}}
	if got := presenter.DimensionSummary(blank, presenter.DimComm); got != "" {
		t.Fatalf("blank comm pattern should have no token, got %q", got)
	}
	special := globalfilter.Filter{File: &globalfilter.StringFilter{Pattern: "  ^/a b~c=d$ "}}
	if got := presenter.DimensionSummary(special, presenter.DimFile); got != "file~^/a b~c=d$" {
		t.Fatalf("special file pattern token = %q", got)
	}
	unknown := presenter.Dimension(99)
	if got := presenter.DimensionSummary(allDimensionsFilter(), unknown); got != "" {
		t.Fatalf("unknown dimension token = %q, want empty", got)
	}
	if got := unknown.Name(); got != "?" {
		t.Fatalf("unknown dimension name = %q, want ?", got)
	}
}
