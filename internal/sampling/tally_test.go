package sampling

import (
	"strings"
	"sync"
	"testing"
)

func tallyEntries() []Entry {
	return []Entry{
		{Syscall: "read", Rate: 10},
		{Syscall: "futex", Rate: 0},
		{Syscall: "openat", Rate: 4, Family: "FS"},
		{Syscall: "stat", Rate: 4, Family: "FS"},
	}
}

func TestNewTallyOfNothingSampledIsNil(t *testing.T) {
	if got := NewTally(nil, nil); got != nil {
		t.Fatalf("NewTally(nil) = %v, want nil", got)
	}
	// The nil tally is the "nothing sampled" one: every call is safe and it
	// renders as the zero Summary, so the recording stays unmarked.
	var none *Tally
	none.CountTraced("read")
	none.CountUntraced("read", 3)
	none.MarkLowerBound()
	none.MarkUnavailable("x")
	if none.Plan().Active() || none.Summary().Active() {
		t.Fatal("nil tally renders an active summary, want the zero Summary")
	}
}

// The tally adds rows and kernel-only counts per syscall into the totals the
// footer stores, ignores syscalls it does not sample, and renders family rates
// once.
func TestTallyTotalsAreRowsPlusKernelCounts(t *testing.T) {
	tally := NewTally(tallyEntries(), nil)
	for range 3 {
		tally.CountTraced("read")
	}
	tally.CountTraced("write") // not sampled: no entry
	tally.CountUntraced("read", 27)
	tally.CountUntraced("futex", 500)
	tally.CountUntraced("openat", 9)
	tally.CountUntraced("write", 99)

	got := tally.Summary()
	if rates := got.Rates(); rates != "FS=4,futex=0,read=10" {
		t.Fatalf("Rates() = %q, want FS=4,futex=0,read=10", rates)
	}
	want := `[{"syscall":"futex","rate":0,"traced":0,"counted_only":500,"total":500},` +
		`{"syscall":"openat","rate":4,"traced":0,"counted_only":9,"total":9},` +
		`{"syscall":"read","rate":10,"traced":3,"counted_only":27,"total":30}]`
	if totals := got.Totals(); totals != want {
		t.Fatalf("Totals() = %s\nwant      %s", totals, want)
	}
}

// Plan announces only what is attached when the recording starts, but a
// sampled syscall attached later is still counted and reported once invoked.
func TestTallyPlanIsTheAttachedRatesAndLateProbesStillCount(t *testing.T) {
	attached := func(syscall string) bool { return syscall != "futex" }
	tally := NewTally(tallyEntries(), attached)
	if got := tally.Plan().Rates(); got != "FS=4,read=10" {
		t.Fatalf("Plan().Rates() = %q, want FS=4,read=10 (futex not attached)", got)
	}
	if got := tally.Summary().Totals(); got != "[]" {
		t.Fatalf("Totals() before any count = %q, want []", got)
	}
	tally.CountUntraced("futex", 5)
	if got := tally.Summary().Totals(); !strings.Contains(got, `"syscall":"futex","rate":0`) {
		t.Fatalf("Totals() = %s, want the late-attached futex with its rate", got)
	}
}

func TestTallyMarksLowerBoundAndKeepsTheFirstUnavailableReason(t *testing.T) {
	tally := NewTally(tallyEntries(), nil)
	tally.CountTraced("read")
	tally.MarkLowerBound()
	if got := tally.Summary(); !got.LowerBound || !strings.Contains(got.Totals(), `"lower_bound":true`) {
		t.Fatalf("summary = %+v, want a lower bound", got)
	}
	tally.MarkUnavailable("")
	tally.MarkUnavailable("first")
	tally.MarkUnavailable("second")
	if got := tally.Summary(); got.Unavailable != "first" || got.Totals() != "unavailable" {
		t.Fatalf("Unavailable = %q, Totals = %q; want first / unavailable", got.Unavailable, got.Totals())
	}
}

// The recorder goroutine counts rows while the drain loop adds kernel counts.
func TestTallyIsSafeForConcurrentUse(t *testing.T) {
	tally := NewTally(tallyEntries(), nil)
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 1000 {
				tally.CountTraced("read")
				tally.CountUntraced("read", 1)
			}
		})
	}
	wg.Wait()
	if got := tally.Summary().Entries; len(got) == 0 || got[len(got)-1].Total() != 8000 {
		t.Fatalf("entries = %+v, want read total 8000", got)
	}
}
