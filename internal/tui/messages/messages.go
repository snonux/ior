package messages

import (
	"ior/internal/globalfilter"
	"ior/internal/statsengine"
)

// PidSelectedMsg is emitted when the user selects a PID from the process table.
type PidSelectedMsg struct {
	Pid int
}

// TidSelectedMsg is emitted when the user selects a TID from the thread table.
type TidSelectedMsg struct {
	Pid int
	Tid int
}

// StatsTickMsg carries a fresh immutable snapshot from the stats engine.
type StatsTickMsg struct {
	Snap *statsengine.Snapshot
}

// ExportRequestMsg requests an export of the current UI state.
type ExportRequestMsg struct{}

// GlobalFilterRequestedMsg requests applying a new shared TUI filter.
type GlobalFilterRequestedMsg struct {
	Filter globalfilter.Filter
	Action string
}

// GlobalFilterUndoRequestedMsg requests popping the latest shared filter layer.
type GlobalFilterUndoRequestedMsg struct{}

// TracingStartedMsg signals that tracing started successfully.
type TracingStartedMsg struct{}

// TracingErrorMsg reports an error while starting or running tracing.
type TracingErrorMsg struct {
	Err error
}
