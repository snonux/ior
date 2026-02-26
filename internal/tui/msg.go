package tui

import "ior/internal/tui/messages"

// PidSelectedMsg is emitted when the user selects a PID from the process table.
type PidSelectedMsg = messages.PidSelectedMsg

// TidSelectedMsg is emitted when the user selects a TID from the thread table.
type TidSelectedMsg = messages.TidSelectedMsg

// StatsTickMsg carries a fresh immutable snapshot from the stats engine.
type StatsTickMsg = messages.StatsTickMsg

// ExportRequestMsg requests an export of the current UI state.
type ExportRequestMsg = messages.ExportRequestMsg

// TracingStartedMsg signals that tracing started successfully.
type TracingStartedMsg = messages.TracingStartedMsg

// TracingErrorMsg reports an error while starting or running tracing.
type TracingErrorMsg = messages.TracingErrorMsg
