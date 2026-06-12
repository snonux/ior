// External test package so that presenter and parser sub-packages can be
// imported without creating an import cycle with globalfilter itself.
package globalfilter_test

import (
	"strings"
	"testing"

	"ior/internal/globalfilter"
	"ior/internal/globalfilter/parser"
	"ior/internal/globalfilter/presenter"
)

func TestFilterSummaryViaPresenter(t *testing.T) {
	filter := globalfilter.Filter{
		ErrorsOnly: true,
		Syscall:    &globalfilter.StringFilter{Pattern: "read"},
		Family:     &globalfilter.StringFilter{Pattern: "Polling"},
		PID:        &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: 1234},
		LatencyNs:  &globalfilter.NumericFilter{Op: globalfilter.OpGt, Value: 1_000_000},
	}
	got := presenter.FilterSummary(filter)
	for _, want := range []string{"errors", "syscall~read", "family~Polling", "pid=1234", "latency>1ms"} {
		if !strings.Contains(got, want) {
			t.Fatalf("FilterSummary() = %q, missing %q", got, want)
		}
	}

	// Zero-value filter should produce "all".
	if got := presenter.FilterSummary(globalfilter.Filter{}); got != "all" {
		t.Fatalf("FilterSummary(zero) = %q, want \"all\"", got)
	}
}

func TestParseDurationNsViaParser(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int64
	}{
		{in: "1ms", want: 1_000_000},
		{in: "10us", want: 10_000},
		{in: "500ns", want: 500},
		{in: "42", want: 42},
	} {
		gotNs, err := parser.ParseDurationNs(tc.in)
		if err != nil {
			t.Fatalf("ParseDurationNs(%q) err = %v", tc.in, err)
		}
		if gotNs != tc.want {
			t.Fatalf("ParseDurationNs(%q) = %d, want %d", tc.in, gotNs, tc.want)
		}
	}
	if _, err := parser.ParseDurationNs("garbage"); err == nil {
		t.Fatalf("ParseDurationNs(garbage) expected error")
	}
}

func TestCompareOpSymbolViaPresenter(t *testing.T) {
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
			t.Fatalf("%s: CompareOpSymbol(%v) = %q, want %q", tc.name, tc.op, got, tc.want)
		}
	}
}
