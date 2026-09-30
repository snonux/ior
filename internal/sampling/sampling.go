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
	// Traced is the number of invocations written as output rows.
	Traced uint64
	// Counted is the number of invocations that only the kernel's aggregate
	// counter saw; no row exists for them. Meaningful only when the Summary's
	// Unavailable is empty.
	Counted uint64
}

// Total is the exact number of invocations of the syscall.
func (e Entry) Total() uint64 { return e.Traced + e.Counted }

// Summary is the sampling outcome of one run. The zero value means "nothing
// was sampled": every syscall was traced in full.
type Summary struct {
	// Entries lists the sampled syscalls sorted by name.
	Entries []Entry
	// Unavailable is empty when Traced and Counted are the run's exact
	// counts, and otherwise says why they are not (for example a filter the
	// kernel counters cannot honour, or a failed read of them). The rates are
	// known either way; only the totals are then missing.
	Unavailable string
}

// New builds a Summary from entries, sorting them by syscall name so every
// rendering of it is deterministic.
func New(entries []Entry, unavailable string) Summary {
	sorted := slices.Clone(entries)
	slices.SortFunc(sorted, func(a, b Entry) int { return strings.Compare(a.Syscall, b.Syscall) })
	return Summary{Entries: sorted, Unavailable: unavailable}
}

// Active reports whether any syscall was sampled.
func (s Summary) Active() bool { return len(s.Entries) > 0 }

// TotalsKnown reports whether the per-syscall counts are exact.
func (s Summary) TotalsKnown() bool { return s.Active() && s.Unavailable == "" }

// RateString renders one rate the way a user would say it.
func RateString(rate uint32) string {
	if rate == 0 {
		return "aggregate-only"
	}
	return fmt.Sprintf("1-in-%d", rate)
}

// Rates renders the effective rates as "read=10,write=0" (the notation of
// -syscall-sampling-syscalls), sorted by syscall; "" when nothing was sampled.
func (s Summary) Rates() string {
	parts := make([]string, 0, len(s.Entries))
	for _, e := range s.Entries {
		parts = append(parts, fmt.Sprintf("%s=%d", e.Syscall, e.Rate))
	}
	return strings.Join(parts, ",")
}

// totalsEntry is the stable JSON shape of one entry in Totals.
type totalsEntry struct {
	Syscall string `json:"syscall"`
	Rate    uint32 `json:"rate"`
	Traced  uint64 `json:"traced"`
	Counted uint64 `json:"counted_only"`
	Total   uint64 `json:"total"`
}

// Totals renders the exact per-syscall counts as a JSON array
// ([{"syscall":"read","rate":10,"traced":110,"counted_only":890,"total":1000}]),
// or as the word "unavailable" when they are not known. "" when nothing was
// sampled. The JSON shape is part of the Parquet footer contract documented in
// docs/parquet-querying.md.
func (s Summary) Totals() string {
	if !s.Active() {
		return ""
	}
	if !s.TotalsKnown() {
		return "unavailable"
	}
	out := make([]totalsEntry, 0, len(s.Entries))
	for _, e := range s.Entries {
		out = append(out, totalsEntry{e.Syscall, e.Rate, e.Traced, e.Counted, e.Total()})
	}
	// Marshalling plain integers and strings cannot fail.
	data, _ := json.Marshal(out)
	return string(data)
}

// Lines renders the summary for people (stderr, `ior collapsed`): a headline
// followed by one line per sampled syscall. Nil when nothing was sampled.
func (s Summary) Lines() []string {
	if !s.Active() {
		return nil
	}
	if !s.TotalsKnown() {
		return []string{fmt.Sprintf("sampled syscalls: %s - rows are a sample; exact totals unavailable (%s)",
			s.describeRates(), s.Unavailable)}
	}
	lines := []string{"sampled syscalls: rows are a sample; the counts below are exact kernel totals"}
	for _, e := range s.Entries {
		lines = append(lines, fmt.Sprintf("  %s: %d calls (%s: %d traced, %d counted only)",
			e.Syscall, e.Total(), RateString(e.Rate), e.Traced, e.Counted))
	}
	return lines
}

// describeRates is Rates with the words of RateString: "read 1-in-10, write aggregate-only".
func (s Summary) describeRates() string {
	parts := make([]string, 0, len(s.Entries))
	for _, e := range s.Entries {
		parts = append(parts, e.Syscall+" "+RateString(e.Rate))
	}
	return strings.Join(parts, ", ")
}
