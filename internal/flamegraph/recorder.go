package flamegraph

import (
	"ior/internal/event"
	"ior/internal/sampling"
)

// Recorder aggregates event pairs and writes them to the legacy .ior.zst format.
// Integration tests still use this artifact to assert trace output end-to-end.
// It holds at most its cap of distinct records in memory (DefaultMaxRecordKeys
// unless -flamegraph-max-keys chose another, plus a stage-1 headroom and the
// "[other]" records); events of further new keys are folded into pid-less and
// then "[other]" records with exact totals and reported on stderr
// (recordcap.go, task uq2).
type Recorder struct {
	name string
	// layout is the time.Format layout of the timestamp in the output name;
	// Prepare downgrades it when the filesystem rejects ':'.
	layout string
	data   iorData
}

// NewRecorder creates a recorder for one trace run with the default cap of
// DefaultMaxRecordKeys distinct records.
func NewRecorder(name string) *Recorder {
	return NewRecorderWithMaxKeys(name, DefaultMaxRecordKeys)
}

// NewRecorderWithMaxKeys creates a recorder for one trace run that stores up
// to maxKeys distinct records exactly before it starts to fold (task rs2: the
// -flamegraph-max-keys flag). The flags package bounds the value to
// [1, MaxRecordKeysLimit]; a maxKeys <= 0 from any other caller falls back to
// DefaultMaxRecordKeys instead of meaning "unbounded" as it does inside
// iorData, because a live recorder must never grow without bound (task uq2).
func NewRecorderWithMaxKeys(name string, maxKeys int) *Recorder {
	if maxKeys <= 0 {
		maxKeys = DefaultMaxRecordKeys
	}
	data := newIorData()
	data.maxKeys = maxKeys // bound the memory of long, churny runs (task uq2)
	return &Recorder{
		name:   name,
		layout: timestampLayout,
		data:   data,
	}
}

// MaxKeys returns the recorder's cap on distinct exactly stored records.
func (r *Recorder) MaxKeys() int {
	return r.data.maxKeys
}

// AddPair folds one traced syscall pair into the aggregated output.
func (r *Recorder) AddPair(pair *event.Pair) {
	if r == nil || pair == nil {
		return
	}
	before := r.data.folds
	r.data.addEventPair(pair)
	// First fold of a stage: warn now, not at Write, which may be 900s away.
	r.announceNewFolds(statusOut, before)
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
