package tui

import (
	"context"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"ior/internal/flags"
	"ior/internal/globalfilter"
	"ior/internal/parquet"
	"ior/internal/runtime"
	"ior/internal/statsengine"
	common "ior/internal/tui/common"
	dashboardui "ior/internal/tui/dashboard"
	"ior/internal/tui/eventstream"
	tuiexport "ior/internal/tui/export"
	"ior/internal/tui/messages"
	"ior/internal/tui/pidpicker"
	"ior/internal/tui/probes"
	tracefilterui "ior/internal/tui/tracefilter"

	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/spinner"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

// Screen identifies the currently active TUI screen.
type Screen int

const (
	// ScreenPIDPicker is the PID selection screen.
	ScreenPIDPicker Screen = iota
	// ScreenDashboard is the runtime dashboard screen.
	ScreenDashboard
)

// TraceStarter starts tracing and returns when startup succeeds or fails.
// It is a type alias for runtime.TraceStarter so TUI callers need not import
// the runtime package directly.
// Long-lived tracing work should continue in background goroutines.
type TraceStarter = runtime.TraceStarter

// SnapshotSource provides dashboard snapshots for TUI rendering.
// It is a type alias for runtime.SnapshotSource.
type SnapshotSource = runtime.SnapshotSource

// ProbeManager exposes runtime probe controls to TUI layers.
// It is a type alias for runtime.ProbeManager.
type ProbeManager = runtime.ProbeManager

// RuntimePublisher is the write side of the TUI runtime contract.
// It is a type alias for runtime.RuntimePublisher; the runtime package owns
// the canonical definition so the core tracing layer can depend on it without
// importing internal/tui.
type RuntimePublisher = runtime.RuntimePublisher

// RuntimeState is the read side of the TUI runtime contract.
// It is a type alias for runtime.RuntimeState.
type RuntimeState = runtime.RuntimeState

// TraceRuntimeBindings composes RuntimePublisher and RuntimeState so a trace
// starter can both inject live data and read persistent TUI-owned state.
// It is a type alias for runtime.TraceRuntimeBindings.
type TraceRuntimeBindings = runtime.TraceRuntimeBindings

// runtimeBindings is the TUI-owned concrete implementation of
// runtime.TraceRuntimeBindings. It guards all fields with a read-write mutex so
// the trace starter goroutine and the Bubble Tea update loop can safely exchange
// live data.
type runtimeBindings struct {
	mu sync.RWMutex

	// snapshotSource is the stats engine injected by the trace starter.
	snapshotSource runtime.SnapshotSource
	// streamSource is the active read-side source (may be swapped on reset).
	streamSource runtime.StreamSource
	// streamBuffer is the TUI-owned ring buffer; it always satisfies both
	// runtime.StreamSource (Len/Snapshot) and runtime.EventSink (Push).
	streamBuffer *eventstream.RingBuffer
	// streamSeq is the shared monotonic counter for stream row sequencing.
	streamSeq *eventstream.Sequencer
	// recorder handles optional parquet stream recording.
	recorder *parquet.Recorder
	// liveTrieSource is the flamegraph trie injected by the trace starter.
	liveTrieSource runtime.LiveTrieSource
	// probeManager is the BPF probe manager injected by the trace starter.
	probeManager runtime.ProbeManager
	// liveFilterSetter, when non-nil, applies filter changes to the running
	// event loop in-place so BPF probes need not be restarted.
	liveFilterSetter func(globalfilter.Filter)
	// filterEpoch increments on every filter change and is stored in parquet rows.
	filterEpoch atomic.Uint64
}

func newRuntimeBindings() *runtimeBindings {
	streamBuffer := eventstream.NewRingBuffer()
	return &runtimeBindings{
		streamSource: streamBuffer,
		streamBuffer: streamBuffer,
		streamSeq:    eventstream.NewSequencer(0),
		recorder:     parquet.NewRecorder(parquet.RecorderConfig{}),
	}
}

// SetDashboardSnapshotSource wires the stats engine into the dashboard.
func (r *runtimeBindings) SetDashboardSnapshotSource(source runtime.SnapshotSource) {
	r.mu.Lock()
	r.snapshotSource = source
	r.mu.Unlock()
}

// SetEventStreamSource wires the stream buffer into the TUI stream view.
func (r *runtimeBindings) SetEventStreamSource(source runtime.StreamSource) {
	r.mu.Lock()
	r.streamSource = source
	r.mu.Unlock()
}

// StreamBuffer returns the TUI-owned ring buffer, which satisfies runtime.StreamSource.
func (r *runtimeBindings) StreamBuffer() runtime.StreamSource {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.streamBuffer
}

// Recorder returns the parquet recorder for optional stream recording.
func (r *runtimeBindings) Recorder() *parquet.Recorder {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.recorder
}

// StreamSequencer returns the shared monotonic counter for stream row sequencing.
func (r *runtimeBindings) StreamSequencer() *eventstream.Sequencer {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.streamSeq
}

// FilterEpoch returns the current filter epoch used for parquet recording.
func (r *runtimeBindings) FilterEpoch() uint64 {
	return r.filterEpoch.Load()
}

// SetLiveTrie wires the live flamegraph trie into the TUI flamegraph view.
func (r *runtimeBindings) SetLiveTrie(liveTrie runtime.LiveTrieSource) {
	r.mu.Lock()
	r.liveTrieSource = liveTrie
	r.mu.Unlock()
}

// SetProbeManager wires the BPF probe manager into the TUI probes modal.
func (r *runtimeBindings) SetProbeManager(manager runtime.ProbeManager) {
	r.mu.Lock()
	r.probeManager = manager
	r.mu.Unlock()
}

// SetLiveFilterSetter registers (or, with nil, unregisters) the live filter
// callback so the TUI can update the running trace pipeline in-place.
func (r *runtimeBindings) SetLiveFilterSetter(setter func(globalfilter.Filter)) {
	r.mu.Lock()
	r.liveFilterSetter = setter
	r.mu.Unlock()
}

// applyLiveFilter swaps the active global filter in place via the setter
// registered by the trace starter, returning true if a setter was available.
// Returning false tells the caller it must fall back to a full trace restart
// (typically because no trace is currently running).
func (r *runtimeBindings) applyLiveFilter(filter globalfilter.Filter) bool {
	r.mu.RLock()
	setter := r.liveFilterSetter
	r.mu.RUnlock()
	if setter == nil {
		return false
	}
	setter(filter)
	return true
}

// dashboardSnapshotSource returns the currently wired stats engine source.
func (r *runtimeBindings) dashboardSnapshotSource() runtime.SnapshotSource {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.snapshotSource
}

// eventStreamSource returns the currently active stream read source.
func (r *runtimeBindings) eventStreamSource() runtime.StreamSource {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.streamSource
}

// liveTrie returns the currently wired flamegraph trie source.
func (r *runtimeBindings) liveTrie() runtime.LiveTrieSource {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.liveTrieSource
}

// currentProbeManager returns the currently wired probe manager.
func (r *runtimeBindings) currentProbeManager() runtime.ProbeManager {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.probeManager
}

func (r *runtimeBindings) resetStreamBuffer() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.streamBuffer == nil {
		r.streamBuffer = eventstream.NewRingBuffer()
	}
	r.streamBuffer.Reset()
	r.streamSource = r.streamBuffer
}

func (r *runtimeBindings) advanceFilterEpoch() uint64 {
	return r.filterEpoch.Add(1)
}

// resetDashboardSnapshotSource resets the dashboard snapshot source if it
// implements the Resetter contract (i.e. exposes Reset()), then returns a
// fresh snapshot. The check is intentionally narrow — only Reset() is required
// so that test doubles and future sources can satisfy it without also
// implementing Ingest (which belongs to statsengine.Accumulator and is not
// needed here). Errors from Snapshot are silently dropped since callers handle
// a nil snapshot.
func (r *runtimeBindings) resetDashboardSnapshotSource() *statsengine.Snapshot {
	src := r.dashboardSnapshotSource()
	if src == nil {
		return nil
	}
	// statsengine.Accumulator satisfies this interface; any other source that
	// exposes Reset() (e.g. test fakes) also qualifies.
	if resettable, ok := src.(interface{ Reset() }); ok {
		resettable.Reset()
	}
	snap, _ := src.Snapshot()
	return snap
}

// RuntimeBindingsFromContext returns the full TraceRuntimeBindings when the
// context was created by the TUI. Use RuntimePublisherFromContext when only
// write access is needed. Delegates to runtime.RuntimeBindingsFromContext.
func RuntimeBindingsFromContext(ctx context.Context) (TraceRuntimeBindings, bool) {
	return runtime.RuntimeBindingsFromContext(ctx)
}

// RuntimePublisherFromContext returns only the RuntimePublisher side of the TUI
// bindings. Use this when the caller only injects data and does not need to
// read persistent TUI state. Delegates to runtime.RuntimePublisherFromContext.
func RuntimePublisherFromContext(ctx context.Context) (RuntimePublisher, bool) {
	return runtime.RuntimePublisherFromContext(ctx)
}

// ContextWithRuntimeBindings stores trace runtime bindings on the context.
// Delegates to runtime.ContextWithRuntimeBindings.
func ContextWithRuntimeBindings(ctx context.Context, bindings TraceRuntimeBindings) context.Context {
	return runtime.ContextWithRuntimeBindings(ctx, bindings)
}

// ContextWithTraceFilters stores the active trace filters for the trace starter.
// Delegates to runtime.ContextWithTraceFilters.
func ContextWithTraceFilters(ctx context.Context, filter globalfilter.Filter) context.Context {
	return runtime.ContextWithTraceFilters(ctx, filter)
}

// TraceFiltersFromContext returns the active trace filters when provided by the TUI model.
// Delegates to runtime.TraceFiltersFromContext.
func TraceFiltersFromContext(ctx context.Context) (globalfilter.Filter, bool) {
	return runtime.TraceFiltersFromContext(ctx)
}

// RunWithTraceStarterConfig starts the TUI with explicit runtime flags.
func RunWithTraceStarterConfig(cfg flags.Config, starter TraceStarter) error {
	model := newModelWithRuntimeConfig(cfg.PidFilter, filterFromConfig(cfg), cfg.PidFilter, cfg.TidFilter, cfg.TUIExportEnable, starter)
	model.dashboard.SetAutoResetInterval(cfg.ResetTimer)
	// Apply the configurable fast-refresh cadence from the CLI flag so the
	// stream and flame tabs honour the -tui-fast-refresh value.
	model.dashboard.SetFastRefreshInterval(cfg.TUIFastRefreshInterval)
	program := tea.NewProgram(model)
	_, err := program.Run()
	return err
}

// NewTestFlamesModel builds the test-flames dashboard model without running the
// Bubble Tea program. It shares construction with
// RunTestFlamesWithTraceStarterConfig so in-process tests (teatest) exercise the
// exact same model wiring that `--testflames`/`--testliveflames` use.
func NewTestFlamesModel(cfg flags.Config, starter TraceStarter) Model {
	model := newModelWithRuntimeConfig(1, filterFromConfig(cfg), 1, -1, cfg.TUIExportEnable, starter)
	model.dashboard.SetAutoResetInterval(cfg.ResetTimer)
	// Apply the configurable fast-refresh cadence from the CLI flag.
	model.dashboard.SetFastRefreshInterval(cfg.TUIFastRefreshInterval)
	return model
}

// RunTestFlamesWithTraceStarterConfig starts test-flames mode with explicit runtime flags.
func RunTestFlamesWithTraceStarterConfig(cfg flags.Config, starter TraceStarter) error {
	program := tea.NewProgram(NewTestFlamesModel(cfg, starter))
	_, err := program.Run()
	return err
}

// keyboardState groups keyboard event tracking and press-suppression fields.
// These fields are read and written exclusively by keys_normalize.go methods.
type keyboardState struct {
	enhancements      tea.KeyboardEnhancementsMsg
	enhancementsKnown bool
	lastEventID       string
	lastEventAt       time.Time
	lastEventWasPress bool
	// Some terminals emit release+press for a single physical key event.
	// When we fallback-handle a release as a press, suppress the immediate
	// matching press to avoid double-handling.
	suppressID    string
	suppressUntil time.Time
}

// processState groups PID/TID filter values and the picker navigation
// return bookmark used to restore the dashboard after re-selecting a process.
type processState struct {
	pid int
	tid int
}

// Model is the top-level Bubble Tea model that routes between PID picker and
// dashboard. It delegates filter management to filterStack, trace lifecycle
// to traceLifecycle, and screen transitions to screenRouter.
type Model struct {
	screen      Screen
	pidPicker   pidpicker.Model
	dashboard   dashboardui.Model
	exporter    tuiexport.Model
	probeModal  probes.Model
	filterModal tracefilterui.Model
	recordModal recordingModal
	runtime     *runtimeBindings

	keys KeyMap

	helpOverlayVisible bool

	width    int
	height   int
	quitting bool

	attaching bool
	spin      spinner.Model
	lastErr   error

	// tracer owns trace start/stop and the active context.CancelFunc.
	tracer traceLifecycle
	// filters owns the filter chain, undo history, and label stack.
	filters filterStack
	// router owns screen-transition state (pending picker return).
	router screenRouter

	proc          processState
	exportEnabled bool
	isDark        bool
	focused       bool

	kb keyboardState
}

type pickerReturnState struct {
	pidFilter int
	tidFilter int
}

// Quitting reports whether the model has begun shutting down (the user pressed
// the quit key). Exposed for in-process tests that assert terminal state via
// teatest's FinalModel.
func (m Model) Quitting() bool {
	return m.quitting
}

// NewModel creates the top-level TUI model with default runtime flags.
// Prefer NewModelWithConfig to pass parsed CLI config explicitly.
func NewModel(initialPID int, startTrace TraceStarter) Model {
	return NewModelWithConfig(flags.NewFlags(), initialPID, startTrace)
}

// NewModelWithConfig creates the top-level TUI model with explicit runtime flags.
func NewModelWithConfig(cfg flags.Config, initialPID int, startTrace TraceStarter) Model {
	model := newModelWithRuntimeConfig(initialPID, filterFromConfig(cfg), cfg.PidFilter, cfg.TidFilter, cfg.TUIExportEnable, startTrace)
	// Seed the dashboard's auto-reset cadence from the parsed CLI flag
	// (default DefaultResetTimer; 0 disables). Init() will arm the
	// underlying tea.Tick when the dashboard becomes active.
	model.dashboard.SetAutoResetInterval(cfg.ResetTimer)
	return model
}

func newModelWithRuntimeConfig(initialPID int, startupFilter globalfilter.Filter, startupPidFilter, startupTidFilter int, exportEnabled bool, startTrace TraceStarter) Model {
	common.ApplyPalette(true)
	syncStylesFromCommon()

	keys := Keys
	if !exportEnabled {
		keys.Export = key.NewBinding()
	}

	rt := newRuntimeBindings()
	pidFilter, tidFilter := resolveStartupPIDFilters(initialPID, startupPidFilter, startupTidFilter)
	// Pass 0 for fastRefreshMs so the dashboard uses the package-level default
	// (200 ms). Callers that hold a flags.Config can override this via
	// SetFastRefreshInterval after construction.
	dashboard := newDashboardWithRuntime(rt, pidFilter, keys, 0)

	spin := spinner.New()
	spin.Spinner = spinner.MiniDot

	model := Model{
		screen:        ScreenPIDPicker,
		pidPicker:     pidpicker.New().SetDarkMode(true),
		dashboard:     dashboard,
		exporter:      tuiexport.NewModel(),
		probeModal:    probes.NewModel(rt.currentProbeManager()).SetDarkMode(true),
		filterModal:   tracefilterui.NewModel().SetDarkMode(true),
		recordModal:   newRecordingModal().SetDarkMode(true),
		runtime:       rt,
		keys:          keys,
		spin:          spin,
		tracer:        newTraceLifecycle(startTrace),
		filters:       newFilterStack(startupFilter),
		router:        newScreenRouter(),
		exportEnabled: exportEnabled,
		isDark:        true,
		focused:       true,
	}
	model.setProcessFilters(pidFilter, tidFilter)

	if initialPID > 0 {
		model.screen = ScreenDashboard
		model.attaching = true
	}

	return model
}

// resolveStartupPIDFilters computes the effective pid/tid filter values from
// the startup arguments. When initialPID is provided it overrides the config
// PID filter and forces tid to -1 (no TID filter).
func resolveStartupPIDFilters(initialPID, startupPidFilter, startupTidFilter int) (pid, tid int) {
	pid = selectedPIDFilter(startupPidFilter)
	tid = selectedPIDFilter(startupTidFilter)
	if initialPID > 0 {
		pid = selectedPIDFilter(initialPID)
		tid = -1
	}
	return pid, tid
}

// newDashboardWithRuntime creates a dark-mode dashboard bound to the given
// runtime and pre-configured with the initial PID filter. fastRefreshMs
// controls the high-frequency tick cadence for stream and flame tabs; pass 0
// to use the package-level default (200 ms).
func newDashboardWithRuntime(rt *runtimeBindings, pidFilter int, keys KeyMap, fastRefreshMs int) dashboardui.Model {
	dashboard := dashboardui.NewModelWithConfig(lateBoundDashboardSource{runtime: rt}, rt.eventStreamSource(), 1000, fastRefreshMs, keys)
	dashboard.SetDarkMode(true)
	dashboard.SetPidFilter(pidFilter)
	return dashboard
}

// Init initializes the active child model and optional tracing startup command.
func (m Model) Init() tea.Cmd {
	sizeCmd := initialWindowSizeCmd()
	if m.screen == ScreenDashboard && m.attaching {
		return tea.Batch(sizeCmd, tea.RequestWindowSize, tea.RequestBackgroundColor, m.spin.Tick, m.beginTraceCmd())
	}
	return tea.Batch(sizeCmd, tea.RequestWindowSize, tea.RequestBackgroundColor, m.pidPicker.Init())
}

func initialWindowSizeCmd() tea.Cmd {
	return func() tea.Msg {
		width, height := common.EffectiveViewport(0, 0)
		return tea.WindowSizeMsg{Width: width, Height: height}
	}
}

// Update routes messages, transitions screens, and manages tracing startup state.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	normalizedMsg, ok := m.keyNormalizer(msg)
	if !ok {
		return m, nil
	}
	msg = normalizedMsg

	if next, cmd, handled := m.dispatchTypedMsg(msg); handled {
		return next, cmd
	}
	if next, cmd, handled := m.dispatchAppMsg(msg); handled {
		return next, cmd
	}

	if next, cmd, handled := m.handleModalDispatch(msg); handled {
		return next, cmd
	}

	return m.updateActiveModel(msg)
}

// dispatchTypedMsg handles all typed message cases that require no modal check.
// Returns (model, cmd, true) when the message was consumed, or (_, _, false)
// to fall through to modal dispatch and then active-model routing.
func (m Model) dispatchTypedMsg(msg tea.Msg) (tea.Model, tea.Cmd, bool) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		next, cmd := m.updateActiveModel(msg)
		return next, cmd, true
	case tea.BackgroundColorMsg:
		m.applyTheme(msg.IsDark())
		return m, nil, true
	case tea.KeyboardEnhancementsMsg:
		m.kb.enhancements = msg
		m.kb.enhancementsKnown = true
		if msg.SupportsKeyDisambiguation() {
			log.Printf("tui: keyboard enhancements enabled (flags=%d, eventTypes=%t)", msg.Flags, msg.SupportsEventTypes())
		}
		return m, nil, true
	case tea.FocusMsg:
		next, cmd := m.handleFocusMsg()
		return next, cmd, true
	case tea.BlurMsg:
		m.focused = false
		// SetFocused returns nil on blur but still bumps autoResetGen so
		// that any in-flight tick scheduled before the blur is ignored.
		m.dashboard.SetFocused(false)
		return m, nil, true
	case tea.KeyPressMsg:
		if next, cmd, handled := m.handleGlobalKeyPress(msg); handled {
			return next, cmd, true
		}
		return m, nil, false
	}
	return m, nil, false
}

// dispatchAppMsg handles application-level message types (export, probe, trace,
// filter) that are not tea framework messages.
// It is called after dispatchTypedMsg returns unhandled for non-framework types.
func (m Model) dispatchAppMsg(msg tea.Msg) (tea.Model, tea.Cmd, bool) {
	switch msg := msg.(type) {
	case tuiexport.RequestMsg:
		return m, runExportCmd(m.exportEnabled, msg.Option, m.dashboard), true
	case tuiexport.CompletedMsg:
		var cmd tea.Cmd
		m.exporter, cmd = m.exporter.Update(msg)
		return m, cmd, true
	case tuiexport.FailedMsg:
		var cmd tea.Cmd
		m.exporter, cmd = m.exporter.Update(msg)
		return m, cmd, true
	case probes.ProbeToggledMsg:
		next, cmd := m.handleProbeToggledMsg(msg)
		return next, cmd, true
	case PidSelectedMsg:
		next, cmd := m.handlePidSelected(msg)
		return next, cmd, true
	case TidSelectedMsg:
		next, cmd := m.handleTidSelected(msg)
		return next, cmd, true
	case TracingStartedMsg:
		next, cmd := m.handleTracingStarted()
		return next, cmd, true
	case TracingErrorMsg:
		m.attaching = false
		m.lastErr = msg.Err
		return m, nil, true
	case messages.GlobalFilterRequestedMsg:
		next, cmd := m.applyGlobalFilter(msg.Filter, msg.Action)
		return next, cmd, true
	case messages.GlobalFilterUndoRequestedMsg:
		next, cmd := m.undoGlobalFilter()
		return next, cmd, true
	}
	return m, nil, false
}

// handleFocusMsg restores focus and re-arms the dashboard's auto-reset tick.
func (m Model) handleFocusMsg() (tea.Model, tea.Cmd) {
	m.focused = true
	// SetFocused returns a tea.Cmd that arms a fresh auto-reset tick
	// when focus returns (or nil if the timer is disabled). It also
	// bumps the dashboard's autoResetGen so any tick that was scheduled
	// before the blur and is still in flight is dropped on arrival.
	focusCmd := m.dashboard.SetFocused(true)
	if m.screen == ScreenDashboard && !m.attaching {
		// Init() arms its own auto-reset tick at the post-bump
		// generation, so discard focusCmd here to avoid two
		// concurrently-live ticks racing the cadence.
		return m, tea.Batch(m.dashboard.Init(), m.dashboard.SnapshotCmd())
	}
	return m, focusCmd
}

// handleProbeToggledMsg resets the dashboard aggregates after a probe toggle
// so the new probe set is reflected immediately.
func (m Model) handleProbeToggledMsg(msg probes.ProbeToggledMsg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	m.probeModal, cmd = m.probeModal.Update(msg)
	if snap := m.runtime.resetDashboardSnapshotSource(); snap != nil {
		next, dashboardCmd := m.dashboard.Update(messages.StatsTickMsg{Snap: snap})
		m.dashboard = next.(dashboardui.Model)
		return m, tea.Batch(dashboardCmd, cmd)
	}
	return m, cmd
}

// handleTracingStarted wires live sources into the dashboard once the trace
// starter confirms the trace is running.
func (m Model) handleTracingStarted() (tea.Model, tea.Cmd) {
	m.attaching = false
	m.dashboard.SetStreamSource(m.runtime.eventStreamSource())
	m.dashboard.SetLiveTrie(m.runtime.liveTrie())
	m.dashboard.SetGlobalFilter(m.filters.current())
	m.syncDashboardFilterState()
	width, height := common.EffectiveViewport(m.width, m.height)
	next, sizeCmd := m.dashboard.Update(tea.WindowSizeMsg{Width: width, Height: height})
	m.dashboard = next.(dashboardui.Model)
	return m, tea.Batch(sizeCmd, m.dashboard.Init(), m.dashboard.SnapshotCmd())
}

func (m *Model) keyNormalizer(msg tea.Msg) (tea.Msg, bool) {
	return m.normalizeKeyEvent(msg)
}

func (m Model) canHandleDashboardShortcut(msg tea.KeyPressMsg) bool {
	return m.screen == ScreenDashboard &&
		!m.attaching &&
		m.lastErr == nil &&
		!m.filterModal.Visible() &&
		!m.exporter.Visible() &&
		!m.recordModal.Visible() &&
		!m.probeModal.Visible() &&
		!m.dashboard.BlocksGlobalShortcuts(msg)
}

func (m Model) shouldCancelPickerToDashboard(msg tea.KeyPressMsg) bool {
	return m.screen == ScreenPIDPicker &&
		m.router.hasPendingReturn() &&
		(isEscKey(msg) || key.Matches(msg, m.keys.Quit))
}

func (m Model) shouldRouteQuitToEsc(msg tea.KeyPressMsg) bool {
	if m.helpOverlayVisible {
		return false
	}
	return m.screen == ScreenDashboard &&
		(m.filterModal.Visible() || m.exporter.Visible() || m.recordModal.Visible() || m.probeModal.Visible() || m.dashboard.BlocksGlobalShortcuts(msg))
}

// handleGlobalKeyPress intercepts keys that apply regardless of the active
// screen: help overlay toggle, quit, and dashboard-level shortcuts. Returns
// (model, cmd, handled); when handled is false the caller falls through to
// screen-specific routing.
func (m Model) handleGlobalKeyPress(msg tea.KeyPressMsg) (tea.Model, tea.Cmd, bool) {
	if m.helpOverlayVisible {
		return m.handleHelpOverlayKeyPress(msg)
	}
	if m.shouldCancelPickerToDashboard(msg) {
		next, cmd := m.cancelPickerToDashboard()
		return next, cmd, true
	}
	if key.Matches(msg, m.keys.Quit) {
		return m.handleQuitKeyPress(msg)
	}
	if isHelpOverlayOpenKey(msg) && !m.attaching && m.lastErr == nil {
		m.helpOverlayVisible = true
		return m, nil, true
	}
	if m.canHandleDashboardShortcut(msg) {
		if next, cmd, handled := m.handleDashboardShortcutKeys(msg); handled {
			return next, cmd, true
		}
	}
	return m, nil, false
}

// handleHelpOverlayKeyPress closes the help overlay on any quit/close/open
// key and consumes the event so it does not reach the underlying screen.
func (m Model) handleHelpOverlayKeyPress(msg tea.KeyPressMsg) (tea.Model, tea.Cmd, bool) {
	if isHelpOverlayQuitKey(msg) || isHelpOverlayCloseKey(msg) || isHelpOverlayOpenKey(msg) {
		m.helpOverlayVisible = false
	}
	return m, nil, true
}

// handleQuitKeyPress handles the quit key. On the dashboard it stops the
// trace and quits; when a modal is active the quit key is re-routed as Esc
// so modals close before the user needs to press q again.
func (m Model) handleQuitKeyPress(msg tea.KeyPressMsg) (tea.Model, tea.Cmd, bool) {
	if m.canHandleDashboardShortcut(msg) {
		if err := recorderStop(m.runtime.Recorder(), m.syncDashboardFilterState); err != nil {
			m.lastErr = err
			return m, nil, true
		}
		m.quitting = true
		m.tracer.stop()
		return m, tea.Quit, true
	}
	if m.shouldRouteQuitToEsc(msg) {
		return m.routeQuitAsEsc()
	}
	return m, nil, true
}

// routeQuitAsEsc synthesises an Esc key press and forwards it to whichever
// modal is currently visible, allowing quit to act as an intuitive close
// shortcut while a modal or sub-view is in focus.
func (m Model) routeQuitAsEsc() (tea.Model, tea.Cmd, bool) {
	esc := tea.KeyPressMsg{Code: tea.KeyEsc}
	if m.probeModal.Visible() {
		next, cmd := m.updateProbeModal(esc)
		return next, cmd, true
	}
	if m.filterModal.Visible() {
		next, cmd := m.updateFilterModal(esc)
		return next, cmd, true
	}
	if m.recordModal.Visible() {
		next, cmd := m.updateRecordModal(esc)
		return next, cmd, true
	}
	if m.exporter.Visible() {
		next, cmd := m.updateExportModal(esc)
		return next, cmd, true
	}
	next, cmd := m.dashboard.Update(esc)
	m.dashboard = next.(dashboardui.Model)
	return m, cmd, true
}

// handleDashboardShortcutKeys handles all dashboard-level hotkeys (export,
// record, probes, filter, undo, PID/TID reselect, auto-reset). The caller
// must verify canHandleDashboardShortcut before calling this method.
func (m Model) handleDashboardShortcutKeys(msg tea.KeyPressMsg) (tea.Model, tea.Cmd, bool) {
	if m.exportEnabled && key.Matches(msg, m.keys.Export) {
		m.exporter = m.exporter.Open()
		return m, nil, true
	}
	if key.Matches(msg, m.keys.Record) {
		return m.handleRecordKey()
	}
	if key.Matches(msg, m.keys.Probes) {
		m.probeModal = probes.NewModel(m.runtime.currentProbeManager()).SetDarkMode(m.isDark).Open()
		return m, nil, true
	}
	if key.Matches(msg, m.keys.Filter) {
		m.filterModal = m.filterModal.Open(m.filters.current())
		return m, nil, true
	}
	if key.Matches(msg, m.keys.FilterUndo) {
		next, cmd := m.undoGlobalFilter()
		return next, cmd, true
	}
	if key.Matches(msg, m.keys.NextFamily) {
		next, cmd := m.cycleFamilyScope(+1)
		return next, cmd, true
	}
	if key.Matches(msg, m.keys.PrevFamily) {
		next, cmd := m.cycleFamilyScope(-1)
		return next, cmd, true
	}
	if key.Matches(msg, m.keys.SelectPID) {
		next, cmd := m.reselectPID()
		return next, cmd, true
	}
	if key.Matches(msg, m.keys.SelectTID) {
		next, cmd := m.reselectTID()
		return next, cmd, true
	}
	if key.Matches(msg, m.keys.AutoReset) {
		next, cmd := m.cycleAutoResetInterval()
		return next, cmd, true
	}
	return m, nil, false
}

// handleRecordKey either stops an active recording or opens the record modal
// to start a new one.
func (m Model) handleRecordKey() (tea.Model, tea.Cmd, bool) {
	if recorderActive(m.runtime.Recorder()) {
		if err := recorderStop(m.runtime.Recorder(), m.syncDashboardFilterState); err != nil {
			m.lastErr = err
		}
		return m, nil, true
	}
	m.recordModal = m.recordModal.Open(defaultParquetRecordingFilename())
	return m, nil, true
}

// cycleAutoResetInterval advances the dashboard's auto-reset cadence to
// the next preset and re-arms the timer. The new cadence takes effect
// on the next tick; any in-flight tick from the previous cadence is
// dropped via the dashboard model's generation counter.
func (m Model) cycleAutoResetInterval() (tea.Model, tea.Cmd) {
	next := nextAutoResetInterval(m.dashboard.AutoResetInterval())
	cmd := m.dashboard.SetAutoResetInterval(next)
	return m, cmd
}

func (m Model) updateDashboardForModal(msg tea.Msg) (Model, tea.Cmd) {
	if _, isKey := msg.(tea.KeyPressMsg); isKey || m.screen != ScreenDashboard {
		return m, nil
	}
	next, cmd := m.dashboard.Update(msg)
	m.dashboard = next.(dashboardui.Model)
	return m, cmd
}

func (m Model) updateProbeModal(msg tea.Msg) (tea.Model, tea.Cmd) {
	m, dashboardCmd := m.updateDashboardForModal(msg)
	var cmd tea.Cmd
	m.probeModal, cmd = m.probeModal.Update(msg)
	return m, tea.Batch(dashboardCmd, cmd)
}

func (m Model) updateFilterModal(msg tea.Msg) (tea.Model, tea.Cmd) {
	m, dashboardCmd := m.updateDashboardForModal(msg)
	wasVisible := m.filterModal.Visible()
	m.filterModal = m.filterModal.Update(msg)
	if wasVisible && !m.filterModal.Visible() {
		next, cmd := m.applyGlobalFilter(m.filterModal.Filter(), "")
		return next, tea.Batch(dashboardCmd, cmd)
	}
	return m, dashboardCmd
}

func (m Model) updateExportModal(msg tea.Msg) (tea.Model, tea.Cmd) {
	m, dashboardCmd := m.updateDashboardForModal(msg)
	var cmd tea.Cmd
	m.exporter, cmd = m.exporter.Update(msg)
	return m, tea.Batch(dashboardCmd, cmd)
}

func (m Model) updateRecordModal(msg tea.Msg) (tea.Model, tea.Cmd) {
	m, dashboardCmd := m.updateDashboardForModal(msg)
	var (
		path   string
		submit bool
	)
	m.recordModal, path, submit = m.recordModal.Update(msg)
	if !submit {
		return m, dashboardCmd
	}
	if err := recorderStart(m.runtime.Recorder(), path, m.syncDashboardFilterState); err != nil {
		m.recordModal = m.recordModal.SetError(err)
		return m, dashboardCmd
	}
	m.recordModal = m.recordModal.Close()
	return m, dashboardCmd
}

func (m Model) handleModalDispatch(msg tea.Msg) (tea.Model, tea.Cmd, bool) {
	if m.attaching {
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return m, cmd, true
	}
	if m.filterModal.Visible() {
		next, cmd := m.updateFilterModal(msg)
		return next, cmd, true
	}
	if m.recordModal.Visible() {
		next, cmd := m.updateRecordModal(msg)
		return next, cmd, true
	}
	if m.probeModal.Visible() {
		next, cmd := m.updateProbeModal(msg)
		return next, cmd, true
	}
	if m.exporter.Visible() {
		next, cmd := m.updateExportModal(msg)
		return next, cmd, true
	}
	return m, nil, false
}

func (m Model) updateActiveModel(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m.screen {
	case ScreenPIDPicker:
		next, cmd := m.pidPicker.Update(msg)
		m.pidPicker = next.(pidpicker.Model)
		return m, cmd
	case ScreenDashboard:
		next, cmd := m.dashboard.Update(msg)
		m.dashboard = next.(dashboardui.Model)
		return m, cmd
	default:
		return m, nil
	}
}

// handlePidSelected stops any running trace, resets buffers, and starts a new
// trace for the newly selected PID.
func (m Model) handlePidSelected(msg PidSelectedMsg) (tea.Model, tea.Cmd) {
	pid := selectedPIDFilter(msg.Pid)
	if err := recorderStop(m.runtime.Recorder(), m.syncDashboardFilterState); err != nil {
		m.lastErr = err
		return m, nil
	}
	m.tracer.stop()
	m.runtime.resetStreamBuffer()
	m.setProcessFilters(pid, -1)
	m.router.pickerReturn = nil
	m.screen = ScreenDashboard
	m.attaching = true
	m.lastErr = nil
	return m, tea.Batch(m.spin.Tick, m.beginTraceCmd())
}

// handleTidSelected stops any running trace, resets buffers, and starts a new
// trace filtered to the selected TID within the current (or provided) PID.
func (m Model) handleTidSelected(msg TidSelectedMsg) (tea.Model, tea.Cmd) {
	tid := selectedPIDFilter(msg.Tid)
	pid := m.proc.pid
	if msg.Pid > 0 {
		pid = msg.Pid
	}
	if err := recorderStop(m.runtime.Recorder(), m.syncDashboardFilterState); err != nil {
		m.lastErr = err
		return m, nil
	}
	m.tracer.stop()
	m.runtime.resetStreamBuffer()
	m.setProcessFilters(pid, tid)
	m.router.pickerReturn = nil
	m.screen = ScreenDashboard
	m.attaching = true
	m.lastErr = nil
	return m, tea.Batch(m.spin.Tick, m.beginTraceCmd())
}

// reselectPID saves a return bookmark and switches to the PID picker so the
// user can choose a different process without losing dashboard state.
func (m Model) reselectPID() (tea.Model, tea.Cmd) {
	if err := recorderStop(m.runtime.Recorder(), m.syncDashboardFilterState); err != nil {
		m.lastErr = err
		return m, nil
	}
	m.router.savePendingReturn(m.proc.pid, m.proc.tid)
	m.tracer.stop()
	m.screen = ScreenPIDPicker
	m.attaching = false
	m.lastErr = nil
	m.exporter = tuiexport.NewModel()
	m.probeModal = probes.NewModel(m.runtime.currentProbeManager()).SetDarkMode(m.isDark)
	m.filterModal = tracefilterui.NewModel().SetDarkMode(m.isDark)
	m.recordModal = newRecordingModal().SetDarkMode(m.isDark)
	m.pidPicker = pidpicker.New().SetDarkMode(m.isDark)
	var sizeCmd tea.Cmd
	m.pidPicker, sizeCmd = applyWindowSizeToPicker(m.pidPicker, m.width, m.height)
	return m, tea.Batch(sizeCmd, m.pidPicker.Init())
}

// reselectTID saves a return bookmark and switches to the TID picker within
// the current PID so the user can narrow tracing to a specific thread.
func (m Model) reselectTID() (tea.Model, tea.Cmd) {
	pid := m.proc.pid
	if err := recorderStop(m.runtime.Recorder(), m.syncDashboardFilterState); err != nil {
		m.lastErr = err
		return m, nil
	}
	m.router.savePendingReturn(m.proc.pid, m.proc.tid)
	m.tracer.stop()
	m.screen = ScreenPIDPicker
	m.attaching = false
	m.lastErr = nil
	m.exporter = tuiexport.NewModel()
	m.probeModal = probes.NewModel(m.runtime.currentProbeManager()).SetDarkMode(m.isDark)
	m.filterModal = tracefilterui.NewModel().SetDarkMode(m.isDark)
	m.recordModal = newRecordingModal().SetDarkMode(m.isDark)
	m.pidPicker = pidpicker.NewTIDWithKeys(pid, pidpicker.DefaultKeyMap()).SetDarkMode(m.isDark)
	var sizeCmd tea.Cmd
	m.pidPicker, sizeCmd = applyWindowSizeToPicker(m.pidPicker, m.width, m.height)
	return m, tea.Batch(sizeCmd, m.pidPicker.Init())
}

func selectedPIDFilter(pid int) int {
	if pid <= 0 {
		return -1
	}
	return pid
}

// cancelPickerToDashboard restores the dashboard when the user presses Esc
// while in the picker after a reselectPID/reselectTID navigation.
func (m Model) cancelPickerToDashboard() (tea.Model, tea.Cmd) {
	returnState, ok := m.router.takePendingReturn()
	if !ok {
		return m, nil
	}
	if err := recorderStop(m.runtime.Recorder(), m.syncDashboardFilterState); err != nil {
		m.lastErr = err
		// Restore the pending return state since we didn't complete the transition.
		m.router.pickerReturn = &returnState
		return m, nil
	}
	m.tracer.stop()
	m.setProcessFilters(returnState.pidFilter, returnState.tidFilter)
	m.screen = ScreenDashboard
	m.attaching = true
	m.lastErr = nil
	return m, tea.Batch(m.spin.Tick, m.beginTraceCmd())
}

// beginTraceCmd creates a tea.Cmd that starts the trace with the current
// runtime bindings and active filter. It cancels any previously running trace.
func (m *Model) beginTraceCmd() tea.Cmd {
	return m.tracer.beginCmd(m.runtime, m.filters.current())
}

// filterFromConfig delegates to flags.BuildTraceFilter to resolve the active
// event filter from the CLI configuration fields.
func filterFromConfig(cfg flags.Config) globalfilter.Filter {
	return flags.BuildTraceFilter(cfg)
}

// setProcessFilters updates the proc pid/tid, rebinds filter process constraints,
// and synchronises the dashboard filter display.
func (m *Model) setProcessFilters(pid, tid int) {
	m.proc.pid = pid
	m.proc.tid = tid
	m.filters.rebindProcessFilters(pid, tid)
	m.syncDashboardFilterState()
}

// setGlobalFilter directly replaces the active filter, extracts the new
// PID/TID values, and synchronises the dashboard.
func (m *Model) setGlobalFilter(filter globalfilter.Filter) {
	m.filters.setGlobal(filter)
	m.proc.pid = m.filters.pidFromFilter()
	m.proc.tid = m.filters.tidFromFilter()
	m.syncDashboardFilterState()
}

// syncDashboardFilterState pushes all filter-related state (PID, global
// filter, label stack, recording status) into the dashboard model so the
// status bar stays consistent.
func (m *Model) syncDashboardFilterState() {
	m.dashboard.SetPidFilter(m.proc.pid)
	m.dashboard.SetGlobalFilter(m.filters.current())
	m.dashboard.SetFilterStack(m.filters.labelStack())
	m.dashboard.SetRecordingStatus(recorderStatus(m.runtime.Recorder()))
}

// applyGlobalFilter pushes a new filter onto the filter stack, applies it
// in-place when possible, or falls back to a full trace restart.
func (m Model) applyGlobalFilter(filter globalfilter.Filter, action string) (tea.Model, tea.Cmd) {
	changed := m.filters.push(filter, action)
	m.setGlobalFilter(m.filters.current())
	return m.reapplyActiveFilter(changed)
}

// replaceGlobalFilter swaps the active global filter for a re-scope (e.g. the
// [/] family cycle) WITHOUT pushing onto the undo stack, then re-applies it to
// the running pipeline using the same live-swap/restart path as
// applyGlobalFilter. The stack label stays the same length across calls.
func (m Model) replaceGlobalFilter(filter globalfilter.Filter) (tea.Model, tea.Cmd) {
	changed := !m.filters.current().Equal(filter)
	m.setGlobalFilter(filter)
	return m.reapplyActiveFilter(changed)
}

// reapplyActiveFilter pushes the current filter into the running pipeline,
// preferring an in-place live swap and falling back to a trace restart. It is
// the shared tail of applyGlobalFilter (push) and replaceGlobalFilter
// (setGlobal) so both routes drive the pipeline identically (DRY).
func (m Model) reapplyActiveFilter(changed bool) (tea.Model, tea.Cmd) {
	if !changed || m.screen != ScreenDashboard {
		return m, nil
	}

	m.runtime.advanceFilterEpoch()
	// Try the in-place swap first: hand the new filter to the running
	// eventloop via the registered setter and only reset the dashboard
	// aggregates so the displayed counts reflect the new filter going
	// forward. The BPF probes stay attached, so the user no longer sees
	// the multi-second 'Attaching tracepoints' overlay on filter changes.
	if m.runtime.applyLiveFilter(m.filters.current()) {
		m.dashboard.PrepareForTraceRestart()
		// PrepareForTraceRestart nils the dashboard's live-trie reference
		// because the full-restart path expects TracingStartedMsg to
		// rebind it. We skip that message on in-place swaps, so reconnect
		// the flamegraph to the still-running trace's live trie here.
		// Without this the Flame tab gets stuck on 'waiting for data...'.
		m.dashboard.SetLiveTrie(m.runtime.liveTrie())
		m.lastErr = nil
		return m, nil
	}

	// Fallback: no trace currently running (e.g. first invocation), so
	// restart the pipeline so the new filter takes effect on the next
	// trace start.
	m.tracer.stop()
	m.dashboard.PrepareForTraceRestart()
	m.attaching = true
	m.lastErr = nil
	return m, tea.Batch(m.spin.Tick, m.beginTraceCmd())
}

// undoGlobalFilter pops the filter stack and re-applies the previous filter,
// using the same in-place swap or restart logic as applyGlobalFilter.
func (m Model) undoGlobalFilter() (tea.Model, tea.Cmd) {
	prev, ok := m.filters.pop()
	if !ok {
		return m, nil
	}
	m.setGlobalFilter(prev)
	if m.screen != ScreenDashboard {
		return m, nil
	}

	m.runtime.advanceFilterEpoch()
	// Same in-place swap path as applyGlobalFilter — see comment there.
	if m.runtime.applyLiveFilter(prev) {
		m.dashboard.PrepareForTraceRestart()
		m.dashboard.SetLiveTrie(m.runtime.liveTrie())
		m.lastErr = nil
		return m, nil
	}

	m.tracer.stop()
	m.dashboard.PrepareForTraceRestart()
	m.attaching = true
	m.lastErr = nil
	return m, tea.Batch(m.spin.Tick, m.beginTraceCmd())
}

// startRecording opens the parquet recorder at path and syncs dashboard status.
// Tests and the Model's record-modal handler call this method.
func (m *Model) startRecording(path string) error {
	return recorderStart(m.runtime.Recorder(), path, m.syncDashboardFilterState)
}

// stopRecording closes an active parquet recorder and syncs dashboard status.
// Tests and the quit/reselect paths call this method.
func (m *Model) stopRecording() error {
	return recorderStop(m.runtime.Recorder(), m.syncDashboardFilterState)
}

func (m *Model) applyTheme(isDark bool) {
	if m.isDark == isDark {
		return
	}
	m.isDark = isDark
	common.ApplyPalette(isDark)
	syncStylesFromCommon()
	m.dashboard.SetDarkMode(isDark)
	m.pidPicker = m.pidPicker.SetDarkMode(isDark)
	m.probeModal = m.probeModal.SetDarkMode(isDark)
	m.filterModal = m.filterModal.SetDarkMode(isDark)
	m.recordModal = m.recordModal.SetDarkMode(isDark)
}

func (m Model) windowTitle() string {
	switch m.screen {
	case ScreenPIDPicker:
		return "ior - select process"
	case ScreenDashboard:
		if m.proc.pid > 0 {
			return fmt.Sprintf("ior - tracing PID %d", m.proc.pid)
		}
	}
	return "ior - I/O Riot"
}

// View renders the currently active screen and startup overlay state.
func (m Model) View() tea.View {
	title := m.windowTitle()
	if m.quitting {
		return altScreenView("", title)
	}

	width, height := common.EffectiveViewport(m.width, m.height)

	if m.attaching {
		line := fmt.Sprintf("%s Attaching tracepoints...", m.spin.View())
		return altScreenView(placeToViewport(width, height, ScreenStyle.Render(common.PanelStyle.Render(line))), title)
	}

	if m.lastErr != nil {
		return altScreenView(placeToViewport(width, height, ScreenStyle.Render(ErrorStyle.Render(m.lastErr.Error()))), title)
	}
	if m.helpOverlayVisible {
		helpView := renderGlobalHelpOverlay(width, height, m.helpSections())
		return altScreenView(helpView, title)
	}

	switch m.screen {
	case ScreenPIDPicker:
		return m.viewPickerScreen(width, height, title)
	case ScreenDashboard:
		return m.viewDashboardScreen(width, height, title)
	default:
		return altScreenView("", title)
	}
}

// viewPickerScreen renders the PID picker screen with optional export overlay.
func (m Model) viewPickerScreen(width, height int, title string) tea.View {
	base := m.pidPicker.View().Content
	if m.exporter.Visible() {
		return altScreenView(placeToViewport(width, height, m.exporter.View(width, height)+"\n"+base), title)
	}
	return altScreenView(placeToViewport(width, height, base), title)
}

// viewDashboardScreen renders the dashboard screen with the appropriate modal
// overlay (filter, record, probes, export) if one is active.
func (m Model) viewDashboardScreen(width, height int, title string) tea.View {
	base := m.dashboard.View().Content
	if m.filterModal.Visible() {
		return altScreenView(placeToViewport(width, height, m.filterModal.View(width, height)), title)
	}
	if m.recordModal.Visible() {
		return altScreenView(placeToViewport(width, height, m.recordModal.View(width, height)), title)
	}
	if m.probeModal.Visible() {
		return altScreenView(placeToViewport(width, height, m.probeModal.View(width, height)), title)
	}
	if m.exporter.Visible() {
		return altScreenView(placeToViewport(width, height, m.exporter.View(width, height)+"\n"+base), title)
	}
	return altScreenView(placeToViewport(width, height, base), title)
}

func isHelpOverlayOpenKey(msg tea.KeyPressMsg) bool {
	return msg.String() == "H"
}

func isEscKey(msg tea.KeyPressMsg) bool {
	return msg.Code == tea.KeyEsc || msg.String() == "esc"
}

func isHelpOverlayCloseKey(msg tea.KeyPressMsg) bool {
	return isEscKey(msg) || msg.String() == "?"
}

func isHelpOverlayQuitKey(msg tea.KeyPressMsg) bool {
	return msg.String() == "q"
}

func runExportCmd(exportEnabled bool, option tuiexport.Option, dashboard dashboardui.Model) tea.Cmd {
	return func() tea.Msg {
		if !exportEnabled {
			return tuiexport.FailedMsg{Err: fmt.Errorf("tui export is disabled by -tuiExport=false")}
		}
		switch option {
		case tuiexport.OptionCSV:
			path, err := dashboard.ExportStreamCSV()
			if err != nil {
				return tuiexport.FailedMsg{Err: err}
			}
			return tuiexport.CompletedMsg{Path: path}
		default:
			return tuiexport.FailedMsg{Err: fmt.Errorf("unknown export option")}
		}
	}
}

type lateBoundDashboardSource struct {
	runtime *runtimeBindings
}

// Snapshot returns a point-in-time dashboard snapshot from the underlying
// source, or (nil, nil) when no source is available. Errors are forwarded to
// the caller so they can decide how to handle a failed snapshot build.
func (s lateBoundDashboardSource) Snapshot() (*statsengine.Snapshot, error) {
	if s.runtime == nil {
		return nil, nil
	}
	source := s.runtime.dashboardSnapshotSource()
	if source == nil {
		return nil, nil
	}
	return source.Snapshot()
}

func (s lateBoundDashboardSource) Reset() {
	if s.runtime == nil {
		return
	}
	source := s.runtime.dashboardSnapshotSource()
	if source == nil {
		return
	}
	if resettable, ok := source.(interface{ Reset() }); ok {
		resettable.Reset()
	}
}

func placeToViewport(width, height int, content string) string {
	if width <= 0 || height <= 0 {
		return content
	}
	return lipgloss.Place(width, height, lipgloss.Left, lipgloss.Top, content)
}

// --- compile-time interface satisfaction assertions ---
//
// These blank-identifier assignments cause a build error if any concrete type
// drifts out of sync with the interface it claims to satisfy.

var (
	// *runtimeBindings must satisfy the full TUI runtime contract, which
	// composes RuntimePublisher (write side) and RuntimeState (read side).
	_ runtime.TraceRuntimeBindings = (*runtimeBindings)(nil)

	// lateBoundDashboardSource must satisfy the SnapshotSource contract used
	// by the dashboard model. It wraps the injected stats engine and forwards
	// calls through runtimeBindings so the dashboard source can be wired
	// before the actual engine is available.
	_ dashboardui.SnapshotSource = (*lateBoundDashboardSource)(nil)
)

func altScreenView(content, title string) tea.View {
	view := tea.NewView(content)
	view.AltScreen = true
	view.ReportFocus = true
	view.MouseMode = tea.MouseModeCellMotion
	view.WindowTitle = title
	view.KeyboardEnhancements.ReportEventTypes = true
	return view
}
