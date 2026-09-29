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
//
// ctx carries only cancellation: cancelling it stops the session. Everything
// else a session needs from its caller arrives explicitly in the TraceRequest,
// so a starter's dependencies are visible in its signature rather than
// discovered through context values that silently read as "absent" when a
// caller forgets to set them.
type TraceStarter func(context.Context, TraceRequest) error

// TraceRequest is what the caller of a TraceStarter hands one trace session.
// The zero value is valid and means a session with no TUI attached: nothing
// is published, the starter's configured filter is kept, and no shutdown
// progress is reported.
type TraceRequest struct {
	// Bindings is the TUI's runtime surface: the starter publishes the
	// session's live components through it and reuses the TUI-owned
	// persistent state it exposes. Nil means no TUI is attached, so the
	// session publishes nothing.
	Bindings TraceRuntimeBindings
	// Filter is the trace filter the session starts with. It replaces the
	// starter's configured global filter and derives the PID/TID scope from
	// it. Nil keeps the starter's configured filter and scope unchanged,
	// which is not the same as an empty filter: an empty filter clears the
	// PID/TID scope. The starter clones it before use, so the caller may keep
	// mutating its own copy.
	Filter *globalfilter.Filter
	// ShutdownReporter receives this session's shutdown progress. A starter
	// that keeps tracing in the background claims it and owns its completion.
	// Nil means nobody waits for the session's teardown.
	ShutdownReporter *TraceShutdownReporter
}

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

// RowRecorder is the write side of the parquet recorder that the tracing
// core needs: appending one stream row, stamped with the filter epoch it was
// captured under, and claiming a dead recording's failure so it is reported
// exactly once. Keeping the core seam this narrow means core wiring can be
// tested against a fake, and parquet signature changes cannot ripple through
// this contract unnoticed.
// *parquet.Recorder satisfies it.
type RowRecorder interface {
	Record(row streamrow.Row, filterEpoch uint64) error
	// TakeFailure returns the error the last recording died with, once per
	// failure, and nil when there is nothing (new) to report - including a
	// failure the recorder already returned from Stop.
	TakeFailure() error
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
	// reports the last session's failure instead, unless that failure was
	// already reported (via TakeFailure or an earlier Stop).
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

// ResettableSnapshotSource is the dashboard's stats-source contract: the read
// side (SnapshotSource) plus Reset, which clears accumulated statistics and
// restarts the series baselines. The dashboard resets its source on a baseline
// reset (the refresh key and auto-reset ticks), after a probe toggle and after
// an in-place filter swap, so Reset is part of the contract rather than an
// optional capability discovered by type assertion — a source that cannot
// reset must not be wireable into the dashboard, instead of silently ignoring
// those resets.
// *statsengine.Engine satisfies this interface.
type ResettableSnapshotSource interface {
	SnapshotSource
	// Reset clears all accumulated stats and restarts series baselines.
	Reset()
}

// EventIngester is the write-only, event-feeding side of the stats engine,
// as needed by the trace event loop. It is an alias for the statsengine.Accumulator
// contract so callers in the runtime layer can reference a single type without
// importing statsengine directly. Callers that only push events should hold an
// EventIngester; callers that only read statistics should hold a SnapshotSource.
// *statsengine.Engine satisfies both interfaces.
type EventIngester = statsengine.Accumulator

// LiveTrieSource is the live flamegraph-trie contract the trace starter
// publishes to the TUI through RuntimePublisher.SetLiveTrie. It is an alias for
// flamegraph.LiveTrieSource, the single definition shared with the flamegraph
// TUI model, so the runtime contract names it without redeclaring it.
// *flamegraph.LiveTrie satisfies it (asserted in package flamegraph).
type LiveTrieSource = flamegraph.LiveTrieSource

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
	// The source must be resettable because the dashboard restarts its
	// baseline on user resets and probe toggles.
	SetDashboardSnapshotSource(source ResettableSnapshotSource)
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

// --- compile-time interface satisfaction assertions ---
//
// These blank-identifier assignments cause a build error if any concrete type
// drifts out of sync with the interface it claims to satisfy. They are grouped
// here because the runtime package already imports every relevant package
// (*probemanager.Manager, *statsengine.Engine, and *streamrow.RingBuffer),
// keeping the assertions co-located with the interface definitions without
// introducing new import cycles. LiveTrieSource is an alias, so its assertion
// lives with its definition in package flamegraph.

var (
	// *probemanager.Manager must satisfy the probe-control surface exposed to the TUI.
	_ ProbeManager = (*probemanager.Manager)(nil)

	// *statsengine.Engine must satisfy both the snapshot-source contract (read
	// side) and the event-ingestion contract (write side). These interfaces
	// represent the two distinct responsibilities of the engine.
	_ SnapshotSource           = (*statsengine.Engine)(nil)
	_ ResettableSnapshotSource = (*statsengine.Engine)(nil)
	_ EventIngester            = (*statsengine.Engine)(nil)

	// *streamrow.RingBuffer must satisfy the full event-sink contract (read +
	// write sides), which is a superset of StreamSource.
	_ EventSink = (*streamrow.RingBuffer)(nil)
)
