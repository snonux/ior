// Package sampling describes which syscalls a run sampled and what their true
// totals were, so every raw-mode output (-plain, -flamegraph, headless
// -parquet) can say that its rows are a sample instead of passing for the whole
// population.
//
// A syscall with sampling rate N > 1 writes roughly 1 in N invocations as
// output rows, and a syscall at rate 0 (aggregate-only) writes none. The kernel
// counts every invocation it does not emit in syscall_aggregate_map, so the
// exact population is the rows that exist plus that aggregate count (see
// "Sampled counts are exact, not scaled" in AGENTS.md). Summary carries both
// halves per syscall; the formats that persist it (the Parquet footer and the
// .ior.zst header) store it verbatim.
package sampling

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// Entry is one sampled syscall of a run.
type Entry struct {
	// Syscall is the syscall name ("read").
	Syscall string
	// Rate is the effective sampling rate: 0 means aggregate-only (no output
	// rows at all), N > 1 means roughly 1 invocation in N became a row. A
	// syscall traced in full (rate 1) is not sampled and has no Entry.
	Rate uint32
	// Family names the syscall family whose -syscall-sampling-families rate
	// this syscall runs at ("FS"), or is empty when the rate is the syscall's
	// own. A family rate covers dozens of syscalls; New reports it once (see
	// Summary.Families) instead of repeating it per syscall.
	Family string
	// Traced is the number of invocations written as output rows.
	Traced uint64
	// Counted is the number of invocations that only the kernel's aggregate
	// counter saw; no row exists for them. Meaningful only when the Summary's
	// Unavailable is empty.
	Counted uint64
}

// Total is the exact number of invocations of the syscall.
func (e Entry) Total() uint64 { return e.Traced + e.Counted }

// FamilyRate is the sampling rate a whole syscall family runs at.
type FamilyRate struct {
	Family string
	Rate   uint32
}

// Summary is the sampling outcome of one run. The zero value means "nothing
// was sampled": every syscall was traced in full.
//
// A family rate is kept compact: the family appears once in Families, and only
// its syscalls that were actually invoked get an Entry (a family such as FS
// covers over a hundred syscalls of which a run typically uses a handful).
// Entries with a syscall's own rate are kept even when nothing was counted.
type Summary struct {
	// Families lists the family-wide rates in effect, sorted by family.
	Families []FamilyRate
	// Entries lists the sampled syscalls sorted by name: those with a rate
	// of their own, and those of a sampled family that have a nonzero total.
	Entries []Entry
	// LowerBound is true when Traced and Counted are not exact but only a
	// lower bound: rows were lost after they were emitted, either because the
	// kernel dropped events (the ring buffer was full) or because records
	// still buffered at stop were discarded undecoded. Such a row is one the
	// kernel did not count in the aggregate either and that never reached the
	// output. It is also true when the kernel skipped probe runs, which may
	// have been a traced task's and are in neither count then. The true
	// totals are at least the ones stored. Meaningful only when
	// Unavailable is empty.
	LowerBound bool
	// Unavailable is empty when Traced and Counted are the run's exact
	// counts, and otherwise says why they are not (for example a filter the
	// kernel counters cannot honour, or a failed read of them). The rates are
	// known either way; only the totals are then missing.
	Unavailable string
}

// New builds a Summary from one entry per sampled syscall. It sorts them by
// syscall name so every rendering of it is deterministic, and folds the
// entries that run at a family rate into Families, dropping those that saw no
// invocation at all (see Summary).
func New(entries []Entry, unavailable string) Summary {
	families := make(map[string]uint32)
	kept := make([]Entry, 0, len(entries))
	for _, e := range entries {
		if e.Family == "" {
			kept = append(kept, e)
			continue
		}
		families[e.Family] = e.Rate
		if e.Total() > 0 {
			kept = append(kept, e)
		}
	}
	slices.SortFunc(kept, func(a, b Entry) int { return strings.Compare(a.Syscall, b.Syscall) })
	s := Summary{Entries: kept, Unavailable: unavailable}
	for family, rate := range families {
		s.Families = append(s.Families, FamilyRate{Family: family, Rate: rate})
	}
	slices.SortFunc(s.Families, func(a, b FamilyRate) int { return strings.Compare(a.Family, b.Family) })
	return s
}

// AtLeast returns s with its totals marked as a lower bound (Summary.LowerBound).
func (s Summary) AtLeast() Summary {
	s.LowerBound = true
	return s
}

// Active reports whether any syscall was sampled.
func (s Summary) Active() bool { return len(s.Entries) > 0 || len(s.Families) > 0 }

// TotalsKnown reports whether the per-syscall counts are exact.
func (s Summary) TotalsKnown() bool { return s.Active() && s.Unavailable == "" }

// RateString renders one rate the way a user would say it.
func RateString(rate uint32) string {
	if rate == 0 {
		return "aggregate-only"
	}
	return fmt.Sprintf("1-in-%d", rate)
}

// Rates renders the effective rates in the notation of the sampling flags:
// the family-wide ones ("FS=10", as -syscall-sampling-families takes them)
// first, then the syscalls with a rate of their own ("read=10,write=0", as
// -syscall-sampling-syscalls takes them), each sorted; "" when nothing was
// sampled. Family names are upper case and syscall names lower case, so the
// two kinds cannot be confused.
func (s Summary) Rates() string {
	return strings.Join(s.rateParts("=", func(rate uint32) string { return fmt.Sprint(rate) }), ",")
}

// rateParts renders each rate as name<sep>value, families first; the syscalls
// of a sampled family are covered by the family's part and get none of their own.
func (s Summary) rateParts(sep string, value func(uint32) string) []string {
	parts := make([]string, 0, len(s.Families)+len(s.Entries))
	for _, f := range s.Families {
		parts = append(parts, f.Family+sep+value(f.Rate))
	}
	for _, e := range s.Entries {
		if e.Family == "" {
			parts = append(parts, e.Syscall+sep+value(e.Rate))
		}
	}
	return parts
}

// totalsEntry is the stable JSON shape of one entry in Totals.
type totalsEntry struct {
	Syscall string `json:"syscall"`
	Rate    uint32 `json:"rate"`
	Traced  uint64 `json:"traced"`
	Counted uint64 `json:"counted_only"`
	Total   uint64 `json:"total"`
	// LowerBound is set (and only then present) when the counts are a lower
	// bound: see Summary.LowerBound.
	LowerBound bool `json:"lower_bound,omitempty"`
}

// Totals renders the exact per-syscall counts as a JSON array
// ([{"syscall":"read","rate":10,"traced":110,"counted_only":890,"total":1000}]),
// or as the word "unavailable" when they are not known. Only syscalls that were
// invoked appear. When the counts are only a lower bound every element also
// carries "lower_bound":true. "" when nothing was sampled. The JSON shape is
// part of the Parquet footer contract documented in docs/parquet-querying.md.
func (s Summary) Totals() string {
	if !s.Active() {
		return ""
	}
	if !s.TotalsKnown() {
		return "unavailable"
	}
	out := make([]totalsEntry, 0, len(s.Entries))
	for _, e := range s.Entries {
		if e.Total() > 0 {
			out = append(out, totalsEntry{e.Syscall, e.Rate, e.Traced, e.Counted, e.Total(), s.LowerBound})
		}
	}
	// Marshalling plain integers and strings cannot fail.
	data, _ := json.Marshal(out)
	return string(data)
}

// Lines renders the summary for people (stderr, `ior collapsed`): a headline
// naming the rates, then one line per sampled syscall that was invoked. Nil
// when nothing was sampled.
func (s Summary) Lines() []string {
	if !s.Active() {
		return nil
	}
	rates := s.describeRates()
	if !s.TotalsKnown() {
		return []string{fmt.Sprintf("sampled syscalls (%s): rows are a sample; exact totals unavailable (%s)",
			rates, s.Unavailable)}
	}
	headline := fmt.Sprintf("sampled syscalls (%s): rows are a sample; the counts below are exact kernel totals", rates)
	calls := "%d calls"
	if s.LowerBound {
		headline = fmt.Sprintf("sampled syscalls (%s): rows are a sample and some events were lost (ring buffer drops or records discarded at stop); "+
			"the counts below are lower bounds, the true totals are higher", rates)
		calls = "at least %d calls"
	}
	lines := []string{headline}
	for _, e := range s.Entries {
		if e.Total() == 0 {
			continue
		}
		lines = append(lines, fmt.Sprintf("  %s: "+calls+" (%s: %d traced, %d counted only)",
			e.Syscall, e.Total(), RateString(e.Rate), e.Traced, e.Counted))
	}
	return lines
}

// describeRates is Rates with the words of RateString: "FS 1-in-10, write aggregate-only".
func (s Summary) describeRates() string {
	return strings.Join(s.rateParts(" ", RateString), ", ")
}
