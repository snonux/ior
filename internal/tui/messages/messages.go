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
//
// The two nil-snapshot cases are distinct: Err == nil with Snap == nil means
// no stats source is wired (the dashboard shows no data), while Err != nil
// means building the snapshot failed; Snap is then nil and receivers keep
// their last good snapshot rather than blanking the view on a transient
// failure.
type StatsTickMsg struct {
	Snap *statsengine.Snapshot
	// Err is non-nil when snapshot construction failed.
	Err error
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

// OpenEditorRequestedMsg requests opening Path (a stream export) in the
// user's external editor. The stream tab emits it; the dashboard runs the
// editor process.
type OpenEditorRequestedMsg struct {
	Path string
}

// TracingStartedMsg signals that tracing started successfully.
type TracingStartedMsg struct{}

// TracingErrorMsg reports an error while starting or running tracing.
type TracingErrorMsg struct {
	Err error
}
