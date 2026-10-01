package internal

import (
	"slices"
	"strings"

	"ior/internal/flags"
	"ior/internal/runtime"
	"ior/internal/sampling"
)

// The trace-core side of marking a TUI Parquet recording (the R key) as
// sampled, the TUI counterpart of the raw modes' samplingTally (task qs2).
//
// The dashboard's stats engine cannot provide a recording's totals: it is
// reset by the auto-reset timer (every 30s by default), the r key and every
// live filter swap, and replaced by each trace restart, while a recording
// spans all of these. So the recording keeps its own tally
// (parquet.StartOptions.SamplingTally), fed from the same two disjoint sources
// the engine and the raw-mode tally use:
//
//   - traced: the rows the recorder writes, counted by the recorder itself;
//   - counted: the kernel aggregate rows the drain loop ingests, forwarded
//     here to the active recording (runtime.RecordingSamplingCounter, through
//     the session-gated recorder view, so a retired session reports nothing).
//
// The TUI flushes the drain loop at the recording's start and stop and before
// a session retires (runtime.RecordingSampling.FlushAggregates), so a
// recording's kernel counts are its own window's, not up to one drain period
// off at either end.

// recordingSamplingSource is one TUI session's runtime.RecordingSampling.
type recordingSamplingSource struct {
	entries []sampling.Entry
	el      *eventLoop
}

var _ runtime.RecordingSampling = recordingSamplingSource{}

// SampledSyscalls returns a copy of the session's sampled syscalls.
func (s recordingSamplingSource) SampledSyscalls() []sampling.Entry {
	return slices.Clone(s.entries)
}

// FlushAggregates drains the session's kernel aggregate map now.
func (s recordingSamplingSource) FlushAggregates() {
	s.el.flushAggregates()
}

// tuiSampledSyscalls lists every syscall a TUI session samples, with its
// effective rate and family attribution, sorted by name; nil when it samples
// none. In the TUI the built-in aggregate-only defaults (futex*,
// clock_gettime, ...) stay at 0, so a default TUI session always samples
// those; a family's 0 is not promoted either (that only happens in raw modes).
func tuiSampledSyscalls(cfg flags.Config) []sampling.Entry {
	rates := sampledSyscallRates(cfg)
	if len(rates) == 0 {
		return nil
	}
	familyRates := sampledFamilyRates(cfg)
	entries := make([]sampling.Entry, 0, len(rates))
	for traceID, rate := range rates {
		entries = append(entries, samplingEntry(traceID, rate, familyRates))
	}
	slices.SortFunc(entries, func(a, b sampling.Entry) int { return strings.Compare(a.Syscall, b.Syscall) })
	return entries
}

// flushAggregates drains the kernel aggregate map now through the running
// drainer (aggregateDrainer.Flush), or does nothing while no drain loop runs.
func (e *eventLoop) flushAggregates() {
	if d := e.aggregateDrainer.Load(); d != nil {
		d.Flush()
	}
}

// SetRecordingSamplingCounter wires the receiver of the kernel counts and
// loss signals a TUI recording's sampling totals need. Call it before the
// loop runs.
func (e *eventLoop) SetRecordingSamplingCounter(counter runtime.RecordingSamplingCounter) {
	e.recordingCounter = counter
}

// forwardAggregatesToRecording hands one drain result to the active
// recording: the ingested rows as kernel-only counts (the very rows the stats
// engine gets, so the live filter applies to both alike), a failed drain or
// counts the filter withheld as the reason its totals are unavailable. A
// failed drain is not caught up later as far as the recording is concerned:
// the next successful drain's delta could straddle the recording's start.
func (e *eventLoop) forwardAggregatesToRecording(result aggregateDrainResult) {
	counter := e.recordingCounter
	if counter == nil {
		return
	}
	if result.warning != "" {
		counter.MarkSamplingUnavailable("reading the kernel counters failed")
		return
	}
	if result.withheld != "" {
		counter.MarkSamplingUnavailable(result.withheld)
	}
	for _, row := range result.rows {
		counter.CountKernelOnly(row.TraceID.Name(), row.Count)
	}
}

// markRecordingLowerBound tells the active recording that events were lost
// (or that the drop counter could not be read): its totals become a lower
// bound, as the raw modes' do (samplingResult).
func (e *eventLoop) markRecordingLowerBound() {
	if e.recordingCounter != nil {
		e.recordingCounter.MarkSamplingLowerBound()
	}
}

// wireRecordingSampling connects a TUI session's event loop to the TUI's
// Parquet recordings: the loop reports kernel counts and losses to the
// session-gated recorder (rt.samplingCounter), and the session publishes its
// sampled syscalls and drain flush to the TUI, which needs them when the user
// starts and stops a recording. A publisher without that capability (fakes,
// the test-flames modes) gets nothing published.
func wireRecordingSampling(cfg flags.Config, el *eventLoop, rt *tuiRuntime, publisher runtime.RuntimePublisher) {
	el.SetRecordingSamplingCounter(rt.samplingCounter)
	if p, ok := publisher.(runtime.RecordingSamplingPublisher); ok {
		p.SetRecordingSampling(recordingSamplingSource{entries: tuiSampledSyscalls(cfg), el: el})
	}
}
