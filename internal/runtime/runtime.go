// Package runtime defines the shared interface contract between the core tracing
// engine (internal) and the TUI layer (internal/tui). By placing these
// interfaces in a neutral sub-package, neither layer imports the other; instead
// both depend on runtime.
package runtime

import (
	"context"
	"sync"

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

// TraceShutdownPhase identifies the currently observable phase of a trace
// session's shutdown. Stopping is indeterminate: the event loop and its
// workers are draining. Detaching is determinate because the probe manager
// knows exactly how many active syscall probe pairs it must release.
type TraceShutdownPhase uint8

const (
	TraceShutdownStopping TraceShutdownPhase = iota
	TraceShutdownDetaching
	TraceShutdownReleasing
	TraceShutdownComplete
)

// TraceShutdownProgress is one immutable shutdown-progress update.
// Completed and Total count active syscall probe pairs, not individual enter
// and exit links.
type TraceShutdownProgress struct {
	Phase     TraceShutdownPhase
	Completed int
	Total     int
}

// TraceShutdownReporter carries progress for exactly one trace session. Its
// single-slot channel keeps the latest update, so a trace restart that nobody
// waits on cannot block teardown and a slow renderer cannot backpressure BPF
// detach. A reporter is never reused across sessions.
type TraceShutdownReporter struct {
	mu        sync.Mutex
	updates   chan TraceShutdownProgress
	claimed   bool
	completed bool
}

// NewTraceShutdownReporter creates a per-session shutdown reporter.
func NewTraceShutdownReporter() *TraceShutdownReporter {
	return &TraceShutdownReporter{updates: make(chan TraceShutdownProgress, 1)}
}

// Updates returns the latest-value progress stream for this session.
func (r *TraceShutdownReporter) Updates() <-chan TraceShutdownProgress {
	if r == nil {
		return nil
	}
	return r.updates
}

// Claim transfers completion ownership from the generic TUI starter command
// to a starter that keeps long-lived trace work in a background goroutine.
// It returns false when completion or another claim already won the ownership
// transition, so a late starter cannot begin work after the TUI has already
// observed that session as complete.
func (r *TraceShutdownReporter) Claim() bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.claimed || r.completed {
		return false
	}
	r.claimed = true
	return true
}

// Publish records progress unless this session has already completed.
func (r *TraceShutdownReporter) Publish(progress TraceShutdownProgress) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.publishLocked(progress)
}

func (r *TraceShutdownReporter) publishLocked(progress TraceShutdownProgress) {
	if r.completed {
		return
	}
	if progress.Phase == TraceShutdownComplete {
		r.completed = true
	}
	select {
	case r.updates <- progress:
		return
	default:
	}
	// Keep only the freshest progress. Publish has a single producer per
	// session, while the TUI is the sole consumer.
	select {
	case <-r.updates:
	default:
	}
	r.updates <- progress
}

// Complete publishes the terminal update for this session.
func (r *TraceShutdownReporter) Complete() {
	r.Publish(TraceShutdownProgress{Phase: TraceShutdownComplete})
}

// CompleteUnlessClaimed completes synchronous/no-op starters. A real trace
// starter claims the reporter before returning its startup result, then owns
// completion until its background run and deferred cleanup have both ended.
func (r *TraceShutdownReporter) CompleteUnlessClaimed() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.claimed || r.completed {
		return
	}
	r.publishLocked(TraceShutdownProgress{Phase: TraceShutdownComplete})
}

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

// Sequencer is the one-method stream-row sequencing contract the tracing
// core needs: a monotonically increasing row number. It exists so the core's
// wiring (and its tests) can depend on the behaviour rather than on
// *streamrow.Sequencer, whose other surface is a construction-time detail.
// *streamrow.Sequencer satisfies it.
type Sequencer interface {
	// Next returns the next strictly increasing sequence number.
	Next() uint64
}

// RowRecorder is the one-method write side of the parquet recorder that the
// tracing core needs: appending one stream row, stamped with the filter epoch
// it was captured under. Keeping the core seam at exactly this method means
// core wiring can be tested against a fake, and parquet signature changes
// cannot ripple through this contract unnoticed.
// *parquet.Recorder satisfies it.
type RowRecorder interface {
	Record(row streamrow.Row, filterEpoch uint64) error
}

// RecordingController is the full recorder surface the TUI needs on top of
// row recording: opening and closing recordings and polling their status.
// Declaring it here (rather than handing the TUI *parquet.Recorder) keeps the
// neutral contract a contract - the concrete recorder stays an
// implementation detail of the bindings that construct it.
// *parquet.Recorder satisfies it.
type RecordingController interface {
	RowRecorder
	// Start opens a new recording at path with the given options.
	Start(path string, options parquet.StartOptions) error
	// Stop closes the active recording. When no recording is active it
	// reports the last session's terminal state instead of starting one.
	Stop() error
	// Status reports the recording's state, including queue-overflow drops.
	Status() parquet.Status
}

// Compile-time assertions that the concrete types the runtime bindings
// construct satisfy the contract; drift surfaces here instead of at the
// bindings' call sites.
var (
	_ RowRecorder         = (*parquet.Recorder)(nil)
	_ RecordingController = (*parquet.Recorder)(nil)
	_ Sequencer           = (*streamrow.Sequencer)(nil)
)

// SnapshotSource provides statsengine snapshots for the TUI dashboard.
// The core tracing engine passes a *statsengine.Engine; the TUI stores it
// behind this interface so the dashboard can retrieve live snapshots.
// Snapshot returns (nil, nil) when the engine is nil. A non-nil error
// indicates that snapshot construction failed and the result must be discarded.
// This is the read side of the stats engine; the write side is
// statsengine.Accumulator.
type SnapshotSource interface {
	Snapshot() (*statsengine.Snapshot, error)
}

// EventIngester is the write-only, event-feeding side of the stats engine,
// as needed by the trace event loop. It is an alias for the statsengine.Accumulator
// contract so callers in the runtime layer can reference a single type without
// importing statsengine directly. Callers that only push events should hold an
// EventIngester; callers that only read statistics should hold a SnapshotSource.
// *statsengine.Engine satisfies both interfaces.
type EventIngester = statsengine.Accumulator

// Snapshotter is the read-only subset of the trie contract used by consumers
// that only need to poll the version and retrieve snapshot data. It mirrors the
// Snapshotter interface in internal/tui/flamegraph but lives here so the core
// package need not import that TUI sub-package.
// *flamegraph.LiveTrie satisfies this interface.
type Snapshotter interface {
	// Version returns the monotonically-increasing snapshot generation counter.
	Version() uint64
	// SnapshotJSON serialises the current trie to JSON for external consumers.
	SnapshotJSON() ([]byte, uint64)
	// SnapshotTree returns a ready-to-render snapshot tree without a JSON round-trip.
	SnapshotTree() (*flamegraph.SnapshotNode, uint64)
}

// Configurator is the write/mutating subset of the trie contract used by
// consumers that need to change field layout, metric, or reset the baseline.
// It mirrors the Configurator interface in internal/tui/flamegraph but lives
// here so the core package need not import that TUI sub-package.
// *flamegraph.LiveTrie satisfies this interface.
type Configurator interface {
	// Fields returns the current ordered list of grouping fields.
	Fields() []string
	// CountField returns the active aggregation metric name.
	CountField() string
	// HeightField returns the active frame-height metric (e.g. "bytes", "duration").
	HeightField() string
	// Reconfigure replaces the grouping fields and resets accumulated data.
	Reconfigure([]string) error
	// SetCountField changes the active aggregation metric and starts a fresh baseline.
	SetCountField(string) error
	// SetHeightField changes the frame-height metric and starts a fresh baseline.
	SetHeightField(string) error
	// Reset clears all accumulated data, starting a new baseline.
	Reset()
}

// LiveTrieSource is the full flamegraph-trie contract needed by the tracing
// engine and the flamegraph TUI model. It embeds Snapshotter (read-only
// snapshot access) and Configurator (mutating operations) so each can be used
// independently where a narrower interface suffices. Both interfaces are
// satisfied by *flamegraph.LiveTrie.
type LiveTrieSource interface {
	Snapshotter
	Configurator
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
	// SetLiveFilterSetter registers a callback that applies a new global filter
	// to the running trace pipeline in-place without restarting BPF probes. The
	// returned function unregisters this callback only if a newer trace session
	// has not replaced it. The trace starter passes its eventloop's SetFilter;
	// the TUI calls it on every filter change.
	SetLiveFilterSetter(setter func(globalfilter.Filter)) func()
}

// RuntimeState is the read side of the TUI runtime contract.
// A trace starter calls these methods to obtain persistent state owned by the TUI.
type RuntimeState interface {
	// StreamBuffer returns the TUI-owned ring buffer used for stream events.
	// The sink (not the read-only StreamSource) is returned because the
	// tracing engine pushes events into it; the TUI reads through the
	// publisher's SetEventStreamSource wiring instead.
	StreamBuffer() EventSink
	// Recorder returns the parquet recorder for optional stream recording.
	// The controller surface (record + start/stop/status) is returned because
	// the TUI drives recording state; the core records rows through the
	// embedded RowRecorder seam.
	Recorder() RecordingController
	// StreamSequencer returns the shared monotonic sequence counter for stream rows.
	StreamSequencer() Sequencer
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

// traceShutdownReporterKey is private so only helpers in this package can
// install or retrieve the per-session reporter.
type traceShutdownReporterKey struct{}

// traceFilters wraps a cloned filter stored on the context by the TUI model.
type traceFilters struct {
	filter globalfilter.Filter
}

// ContextWithRuntimeBindings stores trace runtime bindings on the context so
// a trace starter can retrieve them via RuntimeBindingsFromContext.
func ContextWithRuntimeBindings(ctx context.Context, bindings TraceRuntimeBindings) context.Context {
	return context.WithValue(ctx, runtimeBindingsKey{}, bindings)
}

// ContextWithTraceShutdownReporter stores one trace session's shutdown
// reporter on ctx.
func ContextWithTraceShutdownReporter(ctx context.Context, reporter *TraceShutdownReporter) context.Context {
	return context.WithValue(ctx, traceShutdownReporterKey{}, reporter)
}

// TraceShutdownReporterFromContext returns the current session's reporter.
func TraceShutdownReporterFromContext(ctx context.Context) (*TraceShutdownReporter, bool) {
	reporter, ok := ctx.Value(traceShutdownReporterKey{}).(*TraceShutdownReporter)
	if !ok || reporter == nil {
		return nil, false
	}
	return reporter, true
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

// --- compile-time interface satisfaction assertions ---
//
// These blank-identifier assignments cause a build error if any concrete type
// drifts out of sync with the interface it claims to satisfy. They are grouped
// here because the runtime package already imports every relevant package
// (*flamegraph.LiveTrie, *probemanager.Manager, *statsengine.Engine, and
// *streamrow.RingBuffer), keeping the assertions co-located with the interface
// definitions without introducing new import cycles.

var (
	// *flamegraph.LiveTrie must satisfy both the read-only and mutating sides of
	// the trie contract as well as the combined LiveTrieSource interface.
	_ Snapshotter    = (*flamegraph.LiveTrie)(nil)
	_ Configurator   = (*flamegraph.LiveTrie)(nil)
	_ LiveTrieSource = (*flamegraph.LiveTrie)(nil)

	// *probemanager.Manager must satisfy the probe-control surface exposed to the TUI.
	_ ProbeManager = (*probemanager.Manager)(nil)

	// *statsengine.Engine must satisfy both the snapshot-source contract (read
	// side) and the event-ingestion contract (write side). These interfaces
	// represent the two distinct responsibilities of the engine.
	_ SnapshotSource = (*statsengine.Engine)(nil)
	_ EventIngester  = (*statsengine.Engine)(nil)

	// *streamrow.RingBuffer must satisfy the full event-sink contract (read +
	// write sides), which is a superset of StreamSource.
	_ EventSink = (*streamrow.RingBuffer)(nil)
)
