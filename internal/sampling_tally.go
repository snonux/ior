package internal

import (
	"fmt"
	"sync"
	"sync/atomic"

	"ior/internal/flags"
	"ior/internal/sampling"
	"ior/internal/statsengine"
	"ior/internal/types"
)

// rawModeSamplingRates returns the effective sampling rate of every syscall a
// raw output mode (-plain, -flamegraph, headless -parquet) samples: the trace
// IDs whose rate is not 1. It is nil outside raw modes - the TUI has its own
// aggregate sink (the stats engine) and shows the merged counts itself - and
// in a raw mode that samples nothing, which is every run that does not pass an
// explicit rate: the built-in aggregate-only defaults are promoted to 1 there
// (see flags.resolveDefaultSyscallSamplingRates), so such a run neither needs
// the kernel aggregate map nor carries a sampling marker.
//
// The rates cover every syscall the configuration names, attached or not. The
// ones that never attached cannot be told apart here, before the probes are
// up; eventLoop.restrictSamplingToActive drops them once they are known.
func rawModeSamplingRates(cfg flags.Config) map[types.TraceId]uint32 {
	if !cfg.IsRawOutputMode() {
		return nil
	}
	return sampledSyscallRates(cfg)
}

// sampledSyscallRates returns the effective rate of every syscall cfg samples
// (rate other than 1, as loaded into the BPF sampling map), or nil when it
// samples none. Shared by the raw modes and the TUI recordings
// (tuiSampledSyscalls), so both report exactly what the kernel applies.
func sampledSyscallRates(cfg flags.Config) map[types.TraceId]uint32 {
	rates := make(map[types.TraceId]uint32)
	for traceID, rate := range buildSyscallSamplingRates(cfg) {
		if rate != 1 {
			rates[traceID] = rate
		}
	}
	if len(rates) == 0 {
		return nil
	}
	return rates
}

// rawModeSamplingFamilyRates returns the -syscall-sampling-families rates of a
// raw output mode that samples (as effective rates: a family's 0 is promoted to
// 1 there, see promoteFamilyZeroForRawOutput), excluding the rate 1. They are
// what lets the report say "FS=10" once instead of naming every syscall of the
// family. Nil when nothing is sampled.
func rawModeSamplingFamilyRates(cfg flags.Config) map[types.SyscallFamily]uint32 {
	if !cfg.IsRawOutputMode() {
		return nil
	}
	return sampledFamilyRates(cfg)
}

// sampledFamilyRates returns cfg's effective -syscall-sampling-families rates
// other than 1 (promoteFamilyZeroForRawOutput only changes a raw mode's 0).
func sampledFamilyRates(cfg flags.Config) map[types.SyscallFamily]uint32 {
	rates := make(map[types.SyscallFamily]uint32)
	for family, rate := range cfg.SyscallFamilySamplingRates {
		if rate = promoteFamilyZeroForRawOutput(cfg, rate); rate != 1 {
			rates[family] = rate
		}
	}
	return rates
}

// samplingTally keeps the exact per-syscall population of a raw-mode run that
// samples. Its two halves come from disjoint sources, which is what makes their
// sum exact (ior_on_syscall_exit in internal/c/filter.c updates the kernel
// aggregate only for invocations it does not emit):
//
//   - traced: invocations that reached the output as a row, counted by the
//     event loop where it emits them (countTraced);
//   - counted: invocations only the kernel aggregate saw, merged in by the
//     aggregate drain loop, to which the tally is wired as the sink
//     (IngestSyscallAggregates). The drain loop's stop takes a last drain, so
//     the tally is complete once the event loop has returned.
//
// It is the raw-mode counterpart of the stats engine, which does this job for
// the TUI.
type samplingTally struct {
	// rates holds the sampled syscalls and their effective rates. Only
	// restrict changes it, before the event loop starts.
	rates map[types.TraceId]uint32
	// familyRates are the family-wide rates; a syscall whose effective rate
	// equals its family's runs at the family rate and is reported as such.
	familyRates map[types.SyscallFamily]uint32

	// traced is written by the event-loop goroutine only and read after the
	// loop returned, so it needs no lock.
	traced map[types.TraceId]uint64

	mu      sync.Mutex
	counted map[types.TraceId]uint64

	// drainFailed is true while the most recent drain failed. The map is
	// cumulative, so a later successful drain catches up; but a last drain
	// that failed leaves the final counts short.
	drainFailed atomic.Bool
}

func newSamplingTally(rates map[types.TraceId]uint32, familyRates map[types.SyscallFamily]uint32) *samplingTally {
	return &samplingTally{
		rates:       rates,
		familyRates: familyRates,
		traced:      make(map[types.TraceId]uint64, len(rates)),
		counted:     make(map[types.TraceId]uint64, len(rates)),
	}
}

// restrict drops every syscall for which active is false, so the report names
// only syscalls whose probes are attached. A syscall whose probe never attached
// was not traced at all; "0 calls" under "exact kernel totals" for it would be
// a claim about something nobody measured. Call it before the event loop runs.
func (t *samplingTally) restrict(active func(types.TraceId) bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for traceID := range t.rates {
		if !active(traceID) {
			delete(t.rates, traceID)
		}
	}
}

// countTraced records that an invocation of traceID was written as an output
// row. Event-loop goroutine only. IDs that are not sampled are ignored.
func (t *samplingTally) countTraced(traceID types.TraceId) {
	if _, ok := t.rates[traceID]; ok {
		t.traced[traceID]++
	}
}

// IngestSyscallAggregates implements syscallAggregateSink: it adds the
// invocations the kernel counted without emitting them. The rows are deltas
// since the previous drain (see syscallAggregateConsumer.drainRow).
func (t *samplingTally) IngestSyscallAggregates(rows []statsengine.SyscallAggregate) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, row := range rows {
		if _, ok := t.rates[row.TraceID]; ok {
			t.counted[row.TraceID] += row.Count
		}
	}
}

// summary renders the tally. unavailable, when non-empty, says why the counts
// cannot be trusted; the rates are reported regardless. Call it only after the
// event loop has returned.
func (t *samplingTally) summary(unavailable string) sampling.Summary {
	t.mu.Lock()
	defer t.mu.Unlock()
	entries := make([]sampling.Entry, 0, len(t.rates))
	for traceID, rate := range t.rates {
		entry := samplingEntry(traceID, rate, t.familyRates)
		entry.Traced, entry.Counted = t.traced[traceID], t.counted[traceID]
		entries = append(entries, entry)
	}
	return sampling.New(entries, unavailable)
}

// samplingEntry describes one sampled syscall, without counts. Its Family is
// set when the syscall runs at its family's -syscall-sampling-families rate,
// which lets sampling.New report that rate once for the whole family.
func samplingEntry(traceID types.TraceId, rate uint32, familyRates map[types.SyscallFamily]uint32) sampling.Entry {
	entry := sampling.Entry{Syscall: traceID.Name(), Rate: rate}
	if familyRate, ok := familyRates[traceID.Family()]; ok && familyRate == rate {
		entry.Family = string(traceID.Family())
	}
	return entry
}

// restrictSamplingToActive limits the sampling report to the syscalls whose
// probes are attached (isActive, normally probemanager.Manager.IsActive). A run
// that samples read=10,write=10,futex=0 but traces only read and openat has no
// write or futex counts to report. Call it once the probes are attached and
// before the loop runs.
func (e *eventLoop) restrictSamplingToActive(isActive func(syscall string) bool) {
	if e.samplingTally == nil {
		return
	}
	e.samplingTally.restrict(func(id types.TraceId) bool { return isActive(id.Name()) })
}

// samplingPlan is the summary as known before the run: the rates, no counts.
// Nothing sampled yields the zero Summary.
func (e *eventLoop) samplingPlan() sampling.Summary {
	if e.samplingTally == nil {
		return sampling.Summary{}
	}
	return e.samplingTally.summary("the run has not finished")
}

// samplingResult is the run's sampling outcome. Call it after run returned;
// the counts are then final. Nothing sampled yields the zero Summary.
//
// The kernel aggregate is keyed by syscall only, so a filter on anything else
// (comm, path, latency, ...) cannot be applied to it: the drainer then ingests
// nothing (aggregateIngestAllowedForFilter), and the exact totals are reported
// as unavailable rather than as a count that ignores the filter. A drain that
// failed at the end leaves the counts short for the same reason.
//
// Lost rows do not make the counts unavailable, but inexact: a row that was
// emitted and never decoded is in neither the traced count nor the kernel
// aggregate (which only sees invocations that were not emitted). The counts are
// then a lower bound and are marked as one. Three kinds of loss qualify: a
// ring-buffer drop (the row never reached the loop), a record discarded at
// stop (it reached rawCh but the stop-time drain could not decode it, see
// drainBacklogAtStop), and a record left in the kernel ring buffer at stop
// (emitted, never decoded: a lagging consumer, tasks us2 and f23). None of
// the three counts can say which syscalls lost rows, so any loss, or a drop
// counter that could not be read, marks all of them.
//
// A program run the kernel skipped marks them as well (task 723). The
// kernel's aggregate is counted by the same program as the row, so a skipped
// run of a traced task is in neither count. The skip counter covers every
// task on the host (skippedRunCounter), so under a -pid/-tid filter the
// totals may in fact be exact; nothing tells the two cases apart, and "at
// least" is the claim that holds in both.
func (e *eventLoop) samplingResult() sampling.Summary {
	t := e.samplingTally
	if t == nil {
		return sampling.Summary{}
	}
	filter := e.Filter()
	scope := kernelProcessScope{pid: e.cfg.pidFilter, tid: e.cfg.tidFilter}
	switch {
	case !aggregateIngestAllowedForFilter(&filter, scope):
		return t.summary(withheldByFilter)
	case t.drainFailed.Load():
		return t.summary("reading the kernel counters failed")
	}
	summary := t.summary("")
	// numDiscardedAtStop and numLeftInKernelRing are written by the event-loop
	// goroutine only and are final here: the caller runs after run returned.
	if e.kernelLossPossible() || e.numDiscardedAtStop > 0 || e.numLeftInKernelRing > 0 {
		return summary.AtLeast()
	}
	return summary
}

// kernelLossPossible reports whether the run may have lost a record in the
// kernel: a counted ring-buffer drop, a skipped program run, or a counter of
// either that could not be read last time.
func (e *eventLoop) kernelLossPossible() bool {
	return e.numRingbufDrops.Load() > 0 || e.ringbufDropReadFailed.Load() ||
		e.numSkippedRuns.Load() > 0 || e.skippedRunReadFailed.Load()
}

// announceSampling tells the user at startup that the output of this run is a
// sample, in the raw modes where nothing on the screen would say so. The exact
// totals follow in the end-of-run statistics.
func (e *eventLoop) announceSampling() {
	plan := e.samplingPlan()
	if !plan.Active() {
		return
	}
	e.notifyStatus(fmt.Sprintf("Sampling active (%s): output rows are a sample of these syscalls; exact totals are reported at the end",
		plan.Rates()))
}

// samplingStatLines renders the sampling block of the end-of-run statistics,
// or "" for a run that sampled nothing.
func (e *eventLoop) samplingStatLines() string {
	result := e.samplingResult()
	lines := result.Lines()
	if len(lines) == 0 {
		return ""
	}
	out := ""
	for _, line := range lines {
		out += "\t" + line + "\n"
	}
	if result.TotalsKnown() {
		atLeast := ""
		if result.LowerBound {
			atLeast = "at least "
		}
		out += fmt.Sprintf("\tsyscalls including kernel-counted only: %s%d\n", atLeast, e.numSyscallsAfterFilter+sumCounted(result))
	}
	return out
}

// sumCounted is the number of invocations that have no output row.
func sumCounted(s sampling.Summary) uint {
	var n uint64
	for _, e := range s.Entries {
		n += e.Counted
	}
	return uint(n)
}

// initSamplingTally starts the exact tally of a raw-mode run that samples and
// makes it the aggregate sink, so the drain loop (startAggregateDrainLoop) runs
// and merges the kernel counts of the invocations that were not emitted. No
// rates, no tally: a run that samples nothing pays for no drain loop.
func (e *eventLoop) initSamplingTally(rates map[types.TraceId]uint32, familyRates map[types.SyscallFamily]uint32) {
	if len(rates) == 0 {
		return
	}
	e.samplingTally = newSamplingTally(rates, familyRates)
	e.SetAggregateSink(e.samplingTally)
}
