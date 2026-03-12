package flamegraph

import "ior/internal/event"

// Recorder aggregates event pairs and writes them to the legacy .ior.zst format.
// Integration tests still use this artifact to assert trace output end-to-end.
type Recorder struct {
	name string
	data iorData
}

// NewRecorder creates a recorder for one trace run.
func NewRecorder(name string) *Recorder {
	return &Recorder{
		name: name,
		data: newIorData(),
	}
}

// AddPair folds one traced syscall pair into the aggregated output.
func (r *Recorder) AddPair(pair *event.Pair) {
	if r == nil || pair == nil {
		return
	}
	r.data.addEventPair(pair)
}

// Write persists the aggregated trace output to a .ior.zst file.
func (r *Recorder) Write() error {
	if r == nil {
		return nil
	}
	return r.data.serializeToFile(r.name)
}
