package sampling

import (
	"encoding/json"
	"strings"
	"testing"
)

func sampled() Summary {
	// Deliberately unsorted: New must order them.
	return New([]Entry{
		{Syscall: "write", Rate: 0, Traced: 0, Counted: 70},
		{Syscall: "read", Rate: 10, Traced: 110, Counted: 890},
	}, "")
}

func TestNewSortsEntriesBySyscall(t *testing.T) {
	got := sampled()
	if got.Entries[0].Syscall != "read" || got.Entries[1].Syscall != "write" {
		t.Fatalf("entries = %+v, want read before write", got.Entries)
	}
}

func TestZeroSummaryIsNotSampled(t *testing.T) {
	var s Summary
	if s.Active() || s.TotalsKnown() {
		t.Fatalf("zero Summary: Active=%v TotalsKnown=%v, want both false", s.Active(), s.TotalsKnown())
	}
	if s.Rates() != "" || s.Totals() != "" || s.Lines() != nil {
		t.Fatalf("zero Summary renders %q / %q / %v, want nothing", s.Rates(), s.Totals(), s.Lines())
	}
}

func TestEntryTotalIsTracedPlusCounted(t *testing.T) {
	if got := (Entry{Traced: 110, Counted: 890}).Total(); got != 1000 {
		t.Fatalf("Total() = %d, want 1000", got)
	}
}

func TestRatesUsesTheSamplingFlagNotation(t *testing.T) {
	if got := sampled().Rates(); got != "read=10,write=0" {
		t.Fatalf("Rates() = %q, want read=10,write=0", got)
	}
}

func TestTotalsIsJSONWithExactCounts(t *testing.T) {
	var got []map[string]any
	if err := json.Unmarshal([]byte(sampled().Totals()), &got); err != nil {
		t.Fatalf("Totals() is not JSON: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("Totals() has %d entries, want 2", len(got))
	}
	read := got[0]
	want := map[string]float64{"rate": 10, "traced": 110, "counted_only": 890, "total": 1000}
	for key, w := range want {
		if read[key] != w {
			t.Fatalf("read %s = %v, want %v", key, read[key], w)
		}
	}
	if read["syscall"] != "read" {
		t.Fatalf("first entry syscall = %v, want read", read["syscall"])
	}
}

// When the counts are not trustworthy they must not be rendered as numbers:
// a wrong total is worse than none.
func TestTotalsAreUnavailableNotGuessed(t *testing.T) {
	s := New([]Entry{{Syscall: "read", Rate: 10, Traced: 110}}, "filter")
	if s.TotalsKnown() {
		t.Fatal("TotalsKnown() = true with a reason given")
	}
	if got := s.Totals(); got != "unavailable" {
		t.Fatalf("Totals() = %q, want unavailable", got)
	}
	if got := s.Rates(); got != "read=10" {
		t.Fatalf("Rates() = %q, want the rates regardless, read=10", got)
	}
	lines := s.Lines()
	if len(lines) != 1 || !strings.Contains(lines[0], "unavailable") || !strings.Contains(lines[0], "filter") ||
		!strings.Contains(lines[0], "read 1-in-10") || strings.Contains(lines[0], "110") {
		t.Fatalf("Lines() = %q, want one line naming the rate and the reason but no count", lines)
	}
}

func TestLinesReportExactTotalsPerSyscall(t *testing.T) {
	lines := sampled().Lines()
	if len(lines) != 3 {
		t.Fatalf("Lines() = %q, want a headline and two syscalls", lines)
	}
	if want := "read: 1000 calls (1-in-10: 110 traced, 890 counted only)"; !strings.Contains(lines[1], want) {
		t.Fatalf("line = %q, want it to contain %q", lines[1], want)
	}
	if want := "write: 70 calls (aggregate-only: 0 traced, 70 counted only)"; !strings.Contains(lines[2], want) {
		t.Fatalf("line = %q, want it to contain %q", lines[2], want)
	}
}
