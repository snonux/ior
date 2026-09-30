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
func rawModeSamplingRates(cfg flags.Config) map[types.TraceId]uint32 {
	if !cfg.IsRawOutputMode() {
		return nil
	}
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
	rates map[types.TraceId]uint32

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

func newSamplingTally(rates map[types.TraceId]uint32) *samplingTally {
	return &samplingTally{
		rates:   rates,
		traced:  make(map[types.TraceId]uint64, len(rates)),
		counted: make(map[types.TraceId]uint64, len(rates)),
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
		entries = append(entries, sampling.Entry{
			Syscall: traceID.Name(),
			Rate:    rate,
			Traced:  t.traced[traceID],
			Counted: t.counted[traceID],
		})
	}
	return sampling.New(entries, unavailable)
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
func (e *eventLoop) samplingResult() sampling.Summary {
	t := e.samplingTally
	if t == nil {
		return sampling.Summary{}
	}
	filter := e.Filter()
	scope := kernelProcessScope{pid: e.cfg.pidFilter, tid: e.cfg.tidFilter}
	switch {
	case !aggregateIngestAllowedForFilter(&filter, scope):
		return t.summary("the active filter cannot be applied to the kernel counters")
	case t.drainFailed.Load():
		return t.summary("reading the kernel counters failed")
	}
	return t.summary("")
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
		out += fmt.Sprintf("\tsyscalls including kernel-counted only: %d\n", e.numSyscallsAfterFilter+sumCounted(result))
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
func (e *eventLoop) initSamplingTally(rates map[types.TraceId]uint32) {
	if len(rates) == 0 {
		return
	}
	e.samplingTally = newSamplingTally(rates)
	e.SetAggregateSink(e.samplingTally)
}
