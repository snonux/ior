package flamegraph

import (
	"ior/internal/event"
	"ior/internal/sampling"
)

// Recorder aggregates event pairs and writes them to the legacy .ior.zst format.
// Integration tests still use this artifact to assert trace output end-to-end.
// It holds at most DefaultMaxRecordKeys distinct records in memory; events of
// further new keys are folded into "[other]" records with exact totals and
// reported on stderr (recordcap.go, task uq2).
type Recorder struct {
	name string
	// layout is the time.Format layout of the timestamp in the output name;
	// Prepare downgrades it when the filesystem rejects ':'.
	layout string
	data   iorData
}

// NewRecorder creates a recorder for one trace run.
func NewRecorder(name string) *Recorder {
	data := newIorData()
	data.maxKeys = DefaultMaxRecordKeys // bound the memory of long, churny runs (task uq2)
	return &Recorder{
		name:   name,
		layout: timestampLayout,
		data:   data,
	}
}

// AddPair folds one traced syscall pair into the aggregated output.
func (r *Recorder) AddPair(pair *event.Pair) {
	if r == nil || pair == nil {
		return
	}
	before := r.data.foldedEvents
	r.data.addEventPair(pair)
	if before == 0 && r.data.foldedEvents > 0 {
		// First fold: warn now, not at Write, which may be 900s away.
		r.announceFold(statusOut)
	}
}

// SetSampling records the run's sampling outcome, which Write stores in the
// recording's header: a run that sampled wrote only some of the invocations of
// the sampled syscalls as records, and the header is what says so and keeps the
// exact totals. Call it once the trace has finished, before Write. The zero
// Summary (nothing sampled) leaves the recording a plain version 1 file.
func (r *Recorder) SetSampling(summary sampling.Summary) {
	if r == nil {
		return
	}
	r.data.sampling = summary
}

// Write persists the aggregated trace output to a .ior.zst file.
func (r *Recorder) Write() error {
	if r == nil {
		return nil
	}
	if err := r.data.serializeToFile(r.name, r.layout); err != nil {
		return err
	}
	r.reportFolds(statusOut)
	return nil
}
