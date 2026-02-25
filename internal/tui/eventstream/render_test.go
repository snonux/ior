package eventstream

import (
	"strings"
	"testing"
)

func TestRenderStatusAndFilterLines(t *testing.T) {
	events := []StreamEvent{{Syscall: "read", Comm: "nginx", PID: 1, TID: 2, DurationNs: 1200, GapNs: 300, Bytes: 64, FileName: "/tmp/a", RetVal: 64}}
	f := Filter{Syscall: &StringFilter{Pattern: "read"}, PID: &NumericFilter{Op: OpEq, Value: 1}}
	out := RenderStreamTable(120, false, 100, 1, 100, 10000, f, events)

	for _, want := range []string{"LIVE", "total:100", "filtered:1", "buffer:100/10000", "Filter:", "syscall~read", "pid=1"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q\n%s", want, out)
		}
	}
}

func TestRenderPausedAndErrorRow(t *testing.T) {
	events := []StreamEvent{{Syscall: "write", Comm: "worker", PID: 1, TID: 2, DurationNs: 1000000, GapNs: 5000, Bytes: 32, FileName: "/tmp/b", RetVal: -1, IsError: true}}
	out := RenderStreamTable(120, true, 10, 1, 10, 10000, Filter{}, events)

	if !strings.Contains(out, "PAUSED") {
		t.Fatalf("expected PAUSED indicator\n%s", out)
	}
	if !strings.Contains(out, "-1") {
		t.Fatalf("expected return value in row\n%s", out)
	}
	if !strings.Contains(out, "worker") || !strings.Contains(out, "write") {
		t.Fatalf("expected event row in output\n%s", out)
	}
}

func TestRenderHeaderAndTruncate(t *testing.T) {
	events := []StreamEvent{{
		Syscall:    "very_long_syscall_name",
		Comm:       "very-long-command-name",
		PID:        1,
		TID:        2,
		DurationNs: 2_000_000,
		GapNs:      100,
		Bytes:      4096,
		FileName:   "/very/long/path/that/should/be/truncated/for/narrow/views/file.log",
		RetVal:     1,
	}}
	out := RenderStreamTable(80, false, 1, 1, 1, 10000, Filter{}, events)

	for _, col := range []string{"Gap", "Latency", "Comm", "PID.TID", "Syscall", "Ret", "Bytes", "File"} {
		if !strings.Contains(out, col) {
			t.Fatalf("missing column %q\n%s", col, out)
		}
	}
	if !strings.Contains(out, "...") {
		t.Fatalf("expected truncated field with ellipsis\n%s", out)
	}
}

func TestFormatDurationNs(t *testing.T) {
	cases := []struct {
		in   uint64
		want string
	}{
		{in: 999, want: "999ns"},
		{in: 1500, want: "1.5us"},
		{in: 2_000_000, want: "2.0ms"},
	}
	for _, tc := range cases {
		if got := formatDurationNs(tc.in); got != tc.want {
			t.Fatalf("formatDurationNs(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
