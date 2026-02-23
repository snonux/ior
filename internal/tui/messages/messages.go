package messages

import "ior/internal/statsengine"

// PidSelectedMsg is emitted when the user selects a PID from the process table.
type PidSelectedMsg struct {
	Pid int
}

// StatsTickMsg carries a fresh immutable snapshot from the stats engine.
type StatsTickMsg struct {
	Snap *statsengine.Snapshot
}

// ExportRequestMsg requests an export of the current UI state.
type ExportRequestMsg struct{}

// TracingStartedMsg signals that tracing started successfully.
type TracingStartedMsg struct{}

// TracingErrorMsg reports an error while starting or running tracing.
type TracingErrorMsg struct {
	Err error
}
