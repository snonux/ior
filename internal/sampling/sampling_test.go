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

// fsFamily is what a run with -syscall-sampling-families FS=10 looks like to
// New: one entry per attached syscall of the family, only two of them invoked.
func fsFamily() Summary {
	entries := []Entry{
		{Syscall: "openat", Rate: 10, Family: "FS", Traced: 3, Counted: 27},
		{Syscall: "read", Rate: 10, Family: "FS", Traced: 10, Counted: 90},
	}
	for _, name := range []string{"close", "fsync", "lseek", "write"} {
		entries = append(entries, Entry{Syscall: name, Rate: 10, Family: "FS"})
	}
	return New(entries, "")
}

// A family rate is reported once; the syscalls of the family that were never
// invoked do not each get an entry, a rate, a line or a JSON element.
func TestFamilyRateIsReportedOnceAndIdleSyscallsAreDropped(t *testing.T) {
	s := fsFamily()
	if len(s.Families) != 1 || s.Families[0] != (FamilyRate{Family: "FS", Rate: 10}) {
		t.Fatalf("Families = %+v, want FS at 10 once", s.Families)
	}
	if len(s.Entries) != 2 {
		t.Fatalf("Entries = %+v, want only the two invoked syscalls", s.Entries)
	}
	if got := s.Rates(); got != "FS=10" {
		t.Fatalf("Rates() = %q, want FS=10 and no per-syscall pairs", got)
	}
	var totals []map[string]any
	if err := json.Unmarshal([]byte(s.Totals()), &totals); err != nil || len(totals) != 2 {
		t.Fatalf("Totals() = %q, %v; want JSON with two elements", s.Totals(), err)
	}
	lines := s.Lines()
	if len(lines) != 3 || !strings.Contains(lines[0], "(FS 1-in-10)") {
		t.Fatalf("Lines() = %q, want a headline naming FS once plus two syscall lines", lines)
	}
	for _, idle := range []string{"close", "fsync", "lseek", "write"} {
		if strings.Contains(strings.Join(lines, "\n"), idle) || strings.Contains(s.Totals(), idle) {
			t.Fatalf("idle syscall %s is reported: %q %q", idle, lines, s.Totals())
		}
	}
}

// A syscall with a rate of its own stays visible next to the family, even
// when nothing was counted for it: it is what the user asked for explicitly.
func TestExplicitRateStaysNextToTheFamilyRate(t *testing.T) {
	s := New([]Entry{
		{Syscall: "read", Rate: 10, Family: "FS", Traced: 1, Counted: 9},
		{Syscall: "write", Rate: 5},
	}, "")
	if got := s.Rates(); got != "FS=10,write=5" {
		t.Fatalf("Rates() = %q, want FS=10,write=5", got)
	}
	if got := s.describeRates(); got != "FS 1-in-10, write 1-in-5" {
		t.Fatalf("describeRates() = %q", got)
	}
	// The silent write entry is in Rates but has no line and no JSON element.
	if lines := s.Lines(); len(lines) != 2 || strings.Contains(lines[1], "write") {
		t.Fatalf("Lines() = %q, want a headline and the read line only", lines)
	}
}

func TestFamilyOnlySummaryIsActiveWithoutEntries(t *testing.T) {
	s := New([]Entry{{Syscall: "read", Rate: 10, Family: "FS"}}, "the run has not finished")
	if !s.Active() || len(s.Entries) != 0 || s.Rates() != "FS=10" {
		t.Fatalf("summary = %+v, want active with the rate FS=10 and no entries", s)
	}
}

// Ring-buffer drops make the counts a lower bound: the numbers are kept but
// every rendering says "at least", and the JSON carries lower_bound on each
// element so a query over the footer cannot mistake them for exact totals.
func TestLowerBoundIsLabelledEverywhere(t *testing.T) {
	s := sampled().AtLeast()
	if !s.TotalsKnown() {
		t.Fatal("a lower bound still has totals")
	}
	var got []map[string]any
	if err := json.Unmarshal([]byte(s.Totals()), &got); err != nil {
		t.Fatalf("Totals() is not JSON: %v", err)
	}
	for _, e := range got {
		if e["lower_bound"] != true {
			t.Fatalf("element %v lacks lower_bound:true", e)
		}
	}
	lines := strings.Join(s.Lines(), "\n")
	if strings.Contains(lines, "exact kernel totals") || !strings.Contains(lines, "lower bounds") ||
		!strings.Contains(lines, "read: at least 1000 calls") {
		t.Fatalf("Lines() = %q, want lower-bound wording with the numbers kept", lines)
	}
}

// Exact totals carry no lower_bound key at all, so the documented shape of the
// common case does not change.
func TestExactTotalsHaveNoLowerBoundKey(t *testing.T) {
	if strings.Contains(sampled().Totals(), "lower_bound") {
		t.Fatalf("Totals() = %s, want no lower_bound key", sampled().Totals())
	}
}
