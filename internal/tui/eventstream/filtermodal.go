package eventstream

import tracefilter "ior/internal/tui/tracefilter"

type FilterModal = tracefilter.Model

func NewFilterModal() FilterModal {
	return tracefilter.NewModel()
}
