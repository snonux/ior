// Package runtime defines the shared interface contract between the core tracing
// engine (internal) and the TUI layer (internal/tui). By placing these
// interfaces in a neutral sub-package, neither layer imports the other; instead
// both depend on runtime.
package runtime

import (
	"context"

	"ior/internal/flamegraph"
	"ior/internal/globalfilter"
	"ior/internal/parquet"
	"ior/internal/probemanager"
	"ior/internal/statsengine"
	"ior/internal/streamrow"
)

// TraceStarter starts tracing and returns when startup succeeds or fails.
// Long-lived tracing work must continue in background goroutines.
type TraceStarter func(context.Context) error

// StreamSource is the minimal stream-buffer contract needed by the tracing
// engine and the TUI stream view. It mirrors eventstream.Source but is defined
// here so the core package need not import internal/tui/eventstream.
type StreamSource interface {
	Len() int
	Snapshot() []streamrow.Row
}

// EventSink is the write side of the stream buffer: the tracing engine pushes
// events, the TUI reads them via StreamSource. Embedding StreamSource keeps the
// two sides co-located while allowing callers to hold only the read interface.
type EventSink interface {
	StreamSource
	Push(streamrow.Row)
}

// SnapshotSource provides statsengine snapshots for the TUI dashboard.
// The core tracing engine passes a *statsengine.Engine; the TUI stores it
// behind this interface so the dashboard can retrieve live snapshots.
type SnapshotSource interface {
	Snapshot() *statsengine.Snapshot
}

// LiveTrieSource is the minimal flamegraph-trie contract needed by the tracing
// engine and the flamegraph TUI model. It mirrors the interface defined in
// internal/tui/flamegraph but lives here so the core package need not import
// that TUI sub-package. Both interfaces are satisfied by *flamegraph.LiveTrie.
type LiveTrieSource interface {
	Fields() []string
	CountField() string
	Reconfigure([]string) error
	SetCountField(string) error
	Reset()
	Version() uint64
	SnapshotJSON() ([]byte, uint64)
	SnapshotTree() (*flamegraph.SnapshotNode, uint64)
}

// ProbeManager exposes runtime probe controls to the TUI probes modal.
// *probemanager.Manager implements this interface.
type ProbeManager interface {
	States() []probemanager.ProbeState
	Toggle(syscall string) error
	ActiveCount() (int, int)
}

// RuntimePublisher is the write side of the TUI runtime contract.
// A trace starter calls these methods to inject live data into the active TUI.
type RuntimePublisher interface {
	// SetDashboardSnapshotSource wires the stats engine into the dashboard.
	SetDashboardSnapshotSource(source SnapshotSource)
	// SetEventStreamSource wires the stream buffer into the TUI stream view.
	SetEventStreamSource(source StreamSource)
	// SetLiveTrie wires the live flamegraph trie into the TUI flamegraph view.
	SetLiveTrie(liveTrie LiveTrieSource)
	// SetProbeManager wires the BPF probe manager into the TUI probes modal.
	SetProbeManager(manager ProbeManager)
	// SetLiveFilterSetter registers (or, with nil, unregisters) a callback that
	// applies a new global filter to the running trace pipeline in-place without
	// restarting BPF probes. The trace starter passes its eventloop's SetFilter;
	// the TUI calls it on every filter change.
	SetLiveFilterSetter(setter func(globalfilter.Filter))
}

// RuntimeState is the read side of the TUI runtime contract.
// A trace starter calls these methods to obtain persistent state owned by the TUI.
type RuntimeState interface {
	// StreamBuffer returns the TUI-owned ring buffer used for stream events.
	StreamBuffer() StreamSource
	// Recorder returns the parquet recorder for optional stream recording.
	Recorder() *parquet.Recorder
	// StreamSequencer returns the shared monotonic sequence counter for stream rows.
	StreamSequencer() *streamrow.Sequencer
	// FilterEpoch returns the current filter epoch used for parquet recording.
	FilterEpoch() uint64
}

// TraceRuntimeBindings composes RuntimePublisher and RuntimeState so a trace
// starter can both inject live data and read persistent TUI-owned state.
type TraceRuntimeBindings interface {
	RuntimePublisher
	RuntimeState
}

// --- context key types and helpers ---

// runtimeBindingsKey is an unexported context key for runtime bindings.
type runtimeBindingsKey struct{}

// traceFiltersKey is an unexported context key for trace filter values.
type traceFiltersKey struct{}

// traceFilters wraps a cloned filter stored on the context by the TUI model.
type traceFilters struct {
	filter globalfilter.Filter
}

// ContextWithRuntimeBindings stores trace runtime bindings on the context so
// a trace starter can retrieve them via RuntimeBindingsFromContext.
func ContextWithRuntimeBindings(ctx context.Context, bindings TraceRuntimeBindings) context.Context {
	return context.WithValue(ctx, runtimeBindingsKey{}, bindings)
}

// RuntimeBindingsFromContext returns the full TraceRuntimeBindings when the
// context was created by the TUI. Use RuntimePublisherFromContext when only
// write access is needed.
func RuntimeBindingsFromContext(ctx context.Context) (TraceRuntimeBindings, bool) {
	bindings, ok := ctx.Value(runtimeBindingsKey{}).(TraceRuntimeBindings)
	if !ok || bindings == nil {
		return nil, false
	}
	return bindings, true
}

// RuntimePublisherFromContext returns only the RuntimePublisher side of the TUI
// bindings. Use this when the caller only injects data and does not need to
// read persistent TUI state.
func RuntimePublisherFromContext(ctx context.Context) (RuntimePublisher, bool) {
	bindings, ok := ctx.Value(runtimeBindingsKey{}).(RuntimePublisher)
	if !ok || bindings == nil {
		return nil, false
	}
	return bindings, true
}

// ContextWithTraceFilters stores the active trace filters on the context so
// a trace starter can retrieve them via TraceFiltersFromContext.
func ContextWithTraceFilters(ctx context.Context, filter globalfilter.Filter) context.Context {
	filters := traceFilters{filter: filter.Clone()}
	return context.WithValue(ctx, traceFiltersKey{}, filters)
}

// TraceFiltersFromContext returns the active trace filters when provided by the TUI model.
func TraceFiltersFromContext(ctx context.Context) (globalfilter.Filter, bool) {
	filters, ok := ctx.Value(traceFiltersKey{}).(traceFilters)
	if !ok {
		return globalfilter.Filter{}, false
	}
	return filters.filter.Clone(), true
}
