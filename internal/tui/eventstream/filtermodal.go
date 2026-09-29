package eventstream

import tracefilter "ior/internal/tui/tracefilter"

// FilterModal is the stream tab's name for the shared filter modal, so its
// signatures need no extra import of the tracefilter package.
type FilterModal = tracefilter.Model

// NewFilterModal constructs the shared filter modal.
func NewFilterModal() FilterModal {
	return tracefilter.NewModel()
}
