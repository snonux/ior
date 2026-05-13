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
