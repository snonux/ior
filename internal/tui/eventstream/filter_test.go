package eventstream

import (
	"strings"
	"testing"
)

func sampleEvent() StreamEvent {
	return StreamEvent{
		Seq:        7,
		TimeNs:     999,
		Syscall:    "read",
		Comm:       "nginx",
		PID:        1234,
		TID:        1235,
		FileName:   "/var/log/access.log",
		DurationNs: 1500000,
		GapNs:      12000,
		Bytes:      4096,
		RetVal:     -1,
		IsError:    true,
	}
}

func TestFilterZeroValueMatchesAll(t *testing.T) {
	ev := sampleEvent()
	f := Filter{}
	if !f.Matches(&ev) {
		t.Fatalf("zero-value filter should match all events")
	}
	if f.IsActive() {
		t.Fatalf("zero-value filter should be inactive")
	}
	if got := f.Summary(); got != "all" {
		t.Fatalf("Summary() = %q, want all", got)
	}
}

func TestFilterStringDimensions(t *testing.T) {
	ev := sampleEvent()
	cases := []struct {
		name   string
		filter Filter
		want   bool
	}{
		{name: "syscall match", filter: Filter{Syscall: &StringFilter{Pattern: "ea"}}, want: true},
		{name: "comm match case-insensitive", filter: Filter{Comm: &StringFilter{Pattern: "NGI"}}, want: true},
		{name: "file match", filter: Filter{File: &StringFilter{Pattern: "access"}}, want: true},
		{name: "syscall mismatch", filter: Filter{Syscall: &StringFilter{Pattern: "write"}}, want: false},
	}
	for _, tc := range cases {
		if got := tc.filter.Matches(&ev); got != tc.want {
			t.Fatalf("%s: Matches() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestFilterStringDimensionsSupportAnchors(t *testing.T) {
	ev := sampleEvent()
	if !(Filter{Syscall: &StringFilter{Pattern: "^read$"}}).Matches(&ev) {
		t.Fatalf("expected ^read$ to exactly match read")
	}
	ev.Syscall = "readlink"
	if (Filter{Syscall: &StringFilter{Pattern: "^read$"}}).Matches(&ev) {
		t.Fatalf("expected ^read$ not to match readlink")
	}
	if !(Filter{Syscall: &StringFilter{Pattern: "^read"}}).Matches(&ev) {
		t.Fatalf("expected ^read to match readlink")
	}
	if !(Filter{Syscall: &StringFilter{Pattern: "link$"}}).Matches(&ev) {
		t.Fatalf("expected link$ to match readlink")
	}
}

func TestFilterNumericDimensions(t *testing.T) {
	ev := sampleEvent()
	cases := []struct {
		name   string
		filter Filter
		want   bool
	}{
		{name: "pid eq", filter: Filter{PID: &NumericFilter{Op: OpEq, Value: 1234}}, want: true},
		{name: "tid neq", filter: Filter{TID: &NumericFilter{Op: OpNeq, Value: 1}}, want: true},
		{name: "latency gt", filter: Filter{LatencyNs: &NumericFilter{Op: OpGt, Value: 1000000}}, want: true},
		{name: "gap lte", filter: Filter{GapNs: &NumericFilter{Op: OpLte, Value: 12000}}, want: true},
		{name: "bytes lt", filter: Filter{Bytes: &NumericFilter{Op: OpLt, Value: 8192}}, want: true},
		{name: "ret gte", filter: Filter{RetVal: &NumericFilter{Op: OpGte, Value: -1}}, want: true},
		{name: "pid mismatch", filter: Filter{PID: &NumericFilter{Op: OpEq, Value: 22}}, want: false},
	}
	for _, tc := range cases {
		if got := tc.filter.Matches(&ev); got != tc.want {
			t.Fatalf("%s: Matches() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestFilterErrorsOnlyAndCombined(t *testing.T) {
	ev := sampleEvent()

	f := Filter{
		ErrorsOnly: true,
		Syscall:    &StringFilter{Pattern: "read"},
		PID:        &NumericFilter{Op: OpEq, Value: 1234},
		LatencyNs:  &NumericFilter{Op: OpGt, Value: 1000000},
	}
	if !f.Matches(&ev) {
		t.Fatalf("combined filter should match")
	}

	ev.IsError = false
	if f.Matches(&ev) {
		t.Fatalf("errors-only filter should reject non-error events")
	}
}

func TestFilterSummaryIncludesActivePredicates(t *testing.T) {
	f := Filter{
		ErrorsOnly: true,
		Syscall:    &StringFilter{Pattern: "read"},
		PID:        &NumericFilter{Op: OpEq, Value: 1234},
		LatencyNs:  &NumericFilter{Op: OpGt, Value: 1000000},
	}
	got := f.Summary()
	for _, wantPart := range []string{"errors", "syscall~read", "pid=1234", "latency>1ms"} {
		if !strings.Contains(got, wantPart) {
			t.Fatalf("Summary() = %q, missing %q", got, wantPart)
		}
	}
	if !f.IsActive() {
		t.Fatalf("filter with predicates should be active")
	}
}

func TestParseDurationNs(t *testing.T) {
	cases := []struct {
		in   string
		want int64
	}{
		{in: "1ms", want: 1000000},
		{in: "10us", want: 10000},
		{in: "500ns", want: 500},
		{in: "42", want: 42},
	}
	for _, tc := range cases {
		got, err := ParseDurationNs(tc.in)
		if err != nil {
			t.Fatalf("ParseDurationNs(%q) err = %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("ParseDurationNs(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}

	if _, err := ParseDurationNs("garbage"); err == nil {
		t.Fatalf("ParseDurationNs(garbage) expected error")
	}
}
