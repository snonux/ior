package tui

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ior/internal/flags"
	"ior/internal/globalfilter"
	"ior/internal/parquet"
	"ior/internal/probemanager"
	"ior/internal/statsengine"
	common "ior/internal/tui/common"
	dashboardui "ior/internal/tui/dashboard"
	"ior/internal/tui/eventstream"
	tuiexport "ior/internal/tui/export"
	flamegraphtui "ior/internal/tui/flamegraph"
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
// Long-lived tracing work should continue in background goroutines.
type TraceStarter func(context.Context) error

// SnapshotSource provides dashboard snapshots for TUI rendering.
type SnapshotSource interface {
	Snapshot() *statsengine.Snapshot
}

// ProbeManager exposes runtime probe controls to TUI layers.
type ProbeManager interface {
	States() []probemanager.ProbeState
	Toggle(syscall string) error
	ActiveCount() (int, int)
}

// RuntimePublisher is the write side of the TUI runtime contract.
// A trace starter calls these methods to inject live data into the active TUI.
type RuntimePublisher interface {
	SetDashboardSnapshotSource(source SnapshotSource)
	SetEventStreamSource(source eventstream.Source)
	SetLiveTrie(liveTrie flamegraphtui.LiveTrieSource)
	SetProbeManager(manager ProbeManager)
	// SetLiveFilterSetter registers (or, with nil, unregisters) a callback that
	// applies a new global filter to the running trace pipeline in place. The
	// trace starter passes its eventloop's SetFilter; the TUI calls it on every
	// filter change to avoid restarting the BPF probes.
	SetLiveFilterSetter(setter func(globalfilter.Filter))
}

// RuntimeState is the read side of the TUI runtime contract.
// A trace starter calls these methods to obtain persistent state owned by the TUI.
type RuntimeState interface {
	StreamBuffer() eventstream.Source
	Recorder() *parquet.Recorder
	StreamSequencer() *eventstream.Sequencer
	FilterEpoch() uint64
}

// TraceRuntimeBindings composes RuntimePublisher and RuntimeState so a trace
// starter can both inject live data and read persistent TUI-owned state.
type TraceRuntimeBindings interface {
	RuntimePublisher
	RuntimeState
}

type runtimeBindingsContextKey struct{}
type traceFiltersContextKey struct{}

type runtimeBindings struct {
	mu sync.RWMutex

	snapshotSource   SnapshotSource
	streamSource     eventstream.Source
	streamBuffer     *eventstream.RingBuffer
	streamSeq        *eventstream.Sequencer
	recorder         *parquet.Recorder
	liveTrieSource   flamegraphtui.LiveTrieSource
	probeManager     ProbeManager
	liveFilterSetter func(globalfilter.Filter)
	filterEpoch      atomic.Uint64
}

type traceFilters struct {
	filter globalfilter.Filter
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

func (r *runtimeBindings) SetDashboardSnapshotSource(source SnapshotSource) {
	r.mu.Lock()
	r.snapshotSource = source
	r.mu.Unlock()
}

func (r *runtimeBindings) SetEventStreamSource(source eventstream.Source) {
	r.mu.Lock()
	r.streamSource = source
	r.mu.Unlock()
}

func (r *runtimeBindings) StreamBuffer() eventstream.Source {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.streamBuffer
}

func (r *runtimeBindings) Recorder() *parquet.Recorder {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.recorder
}

func (r *runtimeBindings) StreamSequencer() *eventstream.Sequencer {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.streamSeq
}

func (r *runtimeBindings) FilterEpoch() uint64 {
	return r.filterEpoch.Load()
}

func (r *runtimeBindings) SetLiveTrie(liveTrie flamegraphtui.LiveTrieSource) {
	r.mu.Lock()
	r.liveTrieSource = liveTrie
	r.mu.Unlock()
}

func (r *runtimeBindings) SetProbeManager(manager ProbeManager) {
	r.mu.Lock()
	r.probeManager = manager
	r.mu.Unlock()
}

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

func (r *runtimeBindings) dashboardSnapshotSource() SnapshotSource {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.snapshotSource
}

func (r *runtimeBindings) eventStreamSource() eventstream.Source {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.streamSource
}

func (r *runtimeBindings) liveTrie() flamegraphtui.LiveTrieSource {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.liveTrieSource
}

func (r *runtimeBindings) currentProbeManager() ProbeManager {
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

func (r *runtimeBindings) resetDashboardSnapshotSource() *statsengine.Snapshot {
	src := r.dashboardSnapshotSource()
	if src == nil {
		return nil
	}
	if resettable, ok := src.(interface {
		Reset()
		Snapshot() *statsengine.Snapshot
	}); ok {
		resettable.Reset()
		return resettable.Snapshot()
	}
	return nil
}

// RuntimeBindingsFromContext returns the full TraceRuntimeBindings when the
// context was created by the TUI. Use RuntimePublisherFromContext when only
// write access is needed.
func RuntimeBindingsFromContext(ctx context.Context) (TraceRuntimeBindings, bool) {
	bindings, ok := ctx.Value(runtimeBindingsContextKey{}).(TraceRuntimeBindings)
	if !ok || bindings == nil {
		return nil, false
	}
	return bindings, true
}

// RuntimePublisherFromContext returns only the RuntimePublisher side of the
// TUI bindings. Use this when the caller only injects data and does not need
// to read persistent TUI state.
func RuntimePublisherFromContext(ctx context.Context) (RuntimePublisher, bool) {
	bindings, ok := ctx.Value(runtimeBindingsContextKey{}).(RuntimePublisher)
	if !ok || bindings == nil {
		return nil, false
	}
	return bindings, true
}

// ContextWithRuntimeBindings stores trace runtime bindings on the context.
func ContextWithRuntimeBindings(ctx context.Context, bindings TraceRuntimeBindings) context.Context {
	return context.WithValue(ctx, runtimeBindingsContextKey{}, bindings)
}

// ContextWithTraceFilters stores the active trace filters for the trace starter.
func ContextWithTraceFilters(ctx context.Context, filter globalfilter.Filter) context.Context {
	filters := traceFilters{filter: filter.Clone()}
	return context.WithValue(ctx, traceFiltersContextKey{}, filters)
}

// TraceFiltersFromContext returns the active trace filters when provided by the TUI model.
func TraceFiltersFromContext(ctx context.Context) (globalfilter.Filter, bool) {
	filters, ok := ctx.Value(traceFiltersContextKey{}).(traceFilters)
	if !ok {
		return globalfilter.Filter{}, false
	}
	return filters.filter.Clone(), true
}

// RunWithTraceStarterConfig starts the TUI with explicit runtime flags.
func RunWithTraceStarterConfig(cfg flags.Config, starter TraceStarter) error {
	model := newModelWithRuntimeConfig(cfg.PidFilter, filterFromConfig(cfg), cfg.PidFilter, cfg.TidFilter, cfg.TUIExportEnable, starter)
	model.dashboard.SetAutoResetInterval(cfg.ResetTimer)
	program := tea.NewProgram(model)
	_, err := program.Run()
	return err
}

// RunTestFlamesWithTraceStarterConfig starts test-flames mode with explicit runtime flags.
func RunTestFlamesWithTraceStarterConfig(cfg flags.Config, starter TraceStarter) error {
	model := newModelWithRuntimeConfig(1, filterFromConfig(cfg), 1, -1, cfg.TUIExportEnable, starter)
	model.dashboard.SetAutoResetInterval(cfg.ResetTimer)
	program := tea.NewProgram(model)
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

// filterState groups the trace filter chain: the active filter, the undo
// history, and the human-readable label stack used in the status bar.
type filterState struct {
	global  globalfilter.Filter
	history []globalfilter.Filter
	stack   []string
}

// processState groups PID/TID filter values and the picker navigation
// return bookmark used to restore the dashboard after re-selecting a process.
type processState struct {
	pid          int
	tid          int
	pickerReturn *pickerReturnState
}

// Model is the top-level Bubble Tea model that routes between PID picker and dashboard.
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

	startTrace TraceStarter
	traceStop  context.CancelFunc

	kb     keyboardState
	filter filterState
	proc   processState

	exportEnabled bool
	isDark        bool
	focused       bool
}

type pickerReturnState struct {
	pidFilter int
	tidFilter int
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

	spin := spinner.New()
	spin.Spinner = spinner.MiniDot
	if startTrace == nil {
		startTrace = defaultTraceStarter
	}
	keys := Keys
	if !exportEnabled {
		keys.Export = key.NewBinding()
	}

	runtime := newRuntimeBindings()
	dashboard := dashboardui.NewModelWithConfig(lateBoundDashboardSource{runtime: runtime}, runtime.eventStreamSource(), 1000, keys)
	dashboard.SetDarkMode(true)
	pidFilter := selectedPIDFilter(startupPidFilter)
	if initialPID > 0 {
		pidFilter = selectedPIDFilter(initialPID)
	}
	tidFilter := selectedPIDFilter(startupTidFilter)
	if initialPID > 0 {
		tidFilter = -1
	}
	dashboard.SetPidFilter(pidFilter)

	model := Model{
		screen:        ScreenPIDPicker,
		pidPicker:     pidpicker.New().SetDarkMode(true),
		dashboard:     dashboard,
		exporter:      tuiexport.NewModel(),
		probeModal:    probes.NewModel(runtime.currentProbeManager()).SetDarkMode(true),
		filterModal:   tracefilterui.NewModel().SetDarkMode(true),
		recordModal:   newRecordingModal().SetDarkMode(true),
		runtime:       runtime,
		keys:          keys,
		spin:          spin,
		startTrace:    startTrace,
		filter:        filterState{global: startupFilter.Clone()},
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

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m.updateActiveModel(msg)
	case tea.BackgroundColorMsg:
		m.applyTheme(msg.IsDark())
		return m, nil
	case tea.KeyboardEnhancementsMsg:
		m.kb.enhancements = msg
		m.kb.enhancementsKnown = true
		if msg.SupportsKeyDisambiguation() {
			log.Printf("tui: keyboard enhancements enabled (flags=%d, eventTypes=%t)", msg.Flags, msg.SupportsEventTypes())
		}
		return m, nil
	case tea.FocusMsg:
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
	case tea.BlurMsg:
		m.focused = false
		// SetFocused returns nil on blur but still bumps autoResetGen so
		// that any in-flight tick scheduled before the blur is ignored.
		m.dashboard.SetFocused(false)
		return m, nil
	case tea.KeyPressMsg:
		if next, cmd, handled := m.handleGlobalKeyPress(msg); handled {
			return next, cmd
		}
	case tuiexport.RequestMsg:
		return m, runExportCmd(m.exportEnabled, msg.Option, m.dashboard)
	case tuiexport.CompletedMsg:
		var cmd tea.Cmd
		m.exporter, cmd = m.exporter.Update(msg)
		return m, cmd
	case tuiexport.FailedMsg:
		var cmd tea.Cmd
		m.exporter, cmd = m.exporter.Update(msg)
		return m, cmd
	case probes.ProbeToggledMsg:
		var cmd tea.Cmd
		m.probeModal, cmd = m.probeModal.Update(msg)
		if snap := m.runtime.resetDashboardSnapshotSource(); snap != nil {
			next, dashboardCmd := m.dashboard.Update(messages.StatsTickMsg{Snap: snap})
			m.dashboard = next.(dashboardui.Model)
			return m, tea.Batch(dashboardCmd, cmd)
		}
		return m, cmd
	case PidSelectedMsg:
		return m.handlePidSelected(msg)
	case TidSelectedMsg:
		return m.handleTidSelected(msg)
	case TracingStartedMsg:
		m.attaching = false
		m.dashboard.SetStreamSource(m.runtime.eventStreamSource())
		m.dashboard.SetLiveTrie(m.runtime.liveTrie())
		m.dashboard.SetGlobalFilter(m.filter.global)
		m.syncDashboardFilterState()
		width, height := common.EffectiveViewport(m.width, m.height)
		next, sizeCmd := m.dashboard.Update(tea.WindowSizeMsg{Width: width, Height: height})
		m.dashboard = next.(dashboardui.Model)
		return m, tea.Batch(sizeCmd, m.dashboard.Init(), m.dashboard.SnapshotCmd())
	case TracingErrorMsg:
		m.attaching = false
		m.lastErr = msg.Err
		return m, nil
	case messages.GlobalFilterRequestedMsg:
		return m.applyGlobalFilter(msg.Filter, msg.Action)
	case messages.GlobalFilterUndoRequestedMsg:
		return m.undoGlobalFilter()
	}

	if next, cmd, handled := m.handleModalDispatch(msg); handled {
		return next, cmd
	}

	return m.updateActiveModel(msg)
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
		m.proc.pickerReturn != nil &&
		(isEscKey(msg) || key.Matches(msg, m.keys.Quit))
}

func (m Model) shouldRouteQuitToEsc(msg tea.KeyPressMsg) bool {
	if m.helpOverlayVisible {
		return false
	}
	return m.screen == ScreenDashboard &&
		(m.filterModal.Visible() || m.exporter.Visible() || m.recordModal.Visible() || m.probeModal.Visible() || m.dashboard.BlocksGlobalShortcuts(msg))
}

func (m Model) handleGlobalKeyPress(msg tea.KeyPressMsg) (tea.Model, tea.Cmd, bool) {
	if m.helpOverlayVisible {
		if isHelpOverlayQuitKey(msg) || isHelpOverlayCloseKey(msg) || isHelpOverlayOpenKey(msg) {
			m.helpOverlayVisible = false
		}
		return m, nil, true
	}
	if m.shouldCancelPickerToDashboard(msg) {
		next, cmd := m.cancelPickerToDashboard()
		return next, cmd, true
	}
	if key.Matches(msg, m.keys.Quit) {
		if m.canHandleDashboardShortcut(msg) {
			if err := m.stopRecording(); err != nil {
				m.lastErr = err
				return m, nil, true
			}
			m.quitting = true
			m.stopTrace()
			return m, tea.Quit, true
		}
		if m.shouldRouteQuitToEsc(msg) {
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
		return m, nil, true
	}
	if isHelpOverlayOpenKey(msg) && !m.attaching && m.lastErr == nil {
		m.helpOverlayVisible = true
		return m, nil, true
	}
	if m.exportEnabled && m.canHandleDashboardShortcut(msg) && key.Matches(msg, m.keys.Export) {
		m.exporter = m.exporter.Open()
		return m, nil, true
	}
	if m.canHandleDashboardShortcut(msg) && key.Matches(msg, m.keys.Record) {
		if m.recordingActive() {
			if err := m.stopRecording(); err != nil {
				m.lastErr = err
			}
			return m, nil, true
		}
		m.recordModal = m.recordModal.Open(defaultParquetRecordingFilename())
		return m, nil, true
	}
	if m.canHandleDashboardShortcut(msg) && key.Matches(msg, m.keys.Probes) {
		m.probeModal = probes.NewModel(m.runtime.currentProbeManager()).SetDarkMode(m.isDark).Open()
		return m, nil, true
	}
	if m.canHandleDashboardShortcut(msg) && key.Matches(msg, m.keys.Filter) {
		m.filterModal = m.filterModal.Open(m.filter.global)
		return m, nil, true
	}
	if m.canHandleDashboardShortcut(msg) && key.Matches(msg, m.keys.FilterUndo) {
		next, cmd := m.undoGlobalFilter()
		return next, cmd, true
	}
	if m.canHandleDashboardShortcut(msg) && key.Matches(msg, m.keys.SelectPID) {
		next, cmd := m.reselectPID()
		return next, cmd, true
	}
	if m.canHandleDashboardShortcut(msg) && key.Matches(msg, m.keys.SelectTID) {
		next, cmd := m.reselectTID()
		return next, cmd, true
	}
	if m.canHandleDashboardShortcut(msg) && key.Matches(msg, m.keys.AutoReset) {
		next, cmd := m.cycleAutoResetInterval()
		return next, cmd, true
	}
	return m, nil, false
}

// autoResetCycle is the ordered set of cadences exposed via the `I`
// hotkey. The first entry (0) disables the timer; the rest are
// progressively longer to give users a quick way to slow auto-resets
// down on long traces or turn them off entirely. The cycle wraps so
// pressing `I` past the last preset returns to off.
var autoResetCycle = []time.Duration{
	0,
	10 * time.Second,
	30 * time.Second,
	60 * time.Second,
	2 * time.Minute,
	5 * time.Minute,
}

// nextAutoResetInterval returns the next entry in autoResetCycle after
// `current`. If `current` is not in the cycle (e.g. the user passed a
// custom -resetTimer like 47s), the next entry is the first cycle value
// strictly greater than current; if there is none, we wrap to 0 (off).
func nextAutoResetInterval(current time.Duration) time.Duration {
	for i, d := range autoResetCycle {
		if d == current {
			return autoResetCycle[(i+1)%len(autoResetCycle)]
		}
	}
	for _, d := range autoResetCycle {
		if d > current {
			return d
		}
	}
	return autoResetCycle[0]
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
	if err := m.startRecording(path); err != nil {
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

func (m Model) handlePidSelected(msg PidSelectedMsg) (tea.Model, tea.Cmd) {
	pid := selectedPIDFilter(msg.Pid)
	if err := m.stopRecording(); err != nil {
		m.lastErr = err
		return m, nil
	}
	m.stopTrace()
	m.runtime.resetStreamBuffer()
	m.setProcessFilters(pid, -1)
	m.proc.pickerReturn = nil
	m.screen = ScreenDashboard
	m.attaching = true
	m.lastErr = nil
	return m, tea.Batch(m.spin.Tick, m.beginTraceCmd())
}

func (m Model) handleTidSelected(msg TidSelectedMsg) (tea.Model, tea.Cmd) {
	tid := selectedPIDFilter(msg.Tid)
	pid := m.proc.pid
	if msg.Pid > 0 {
		pid = msg.Pid
	}
	if err := m.stopRecording(); err != nil {
		m.lastErr = err
		return m, nil
	}
	m.stopTrace()
	m.runtime.resetStreamBuffer()
	m.setProcessFilters(pid, tid)
	m.proc.pickerReturn = nil
	m.screen = ScreenDashboard
	m.attaching = true
	m.lastErr = nil
	return m, tea.Batch(m.spin.Tick, m.beginTraceCmd())
}

func (m Model) reselectPID() (tea.Model, tea.Cmd) {
	if err := m.stopRecording(); err != nil {
		m.lastErr = err
		return m, nil
	}
	m.proc.pickerReturn = &pickerReturnState{
		pidFilter: m.proc.pid,
		tidFilter: m.proc.tid,
	}
	m.stopTrace()
	m.screen = ScreenPIDPicker
	m.attaching = false
	m.lastErr = nil
	m.exporter = tuiexport.NewModel()
	m.probeModal = probes.NewModel(m.runtime.currentProbeManager()).SetDarkMode(m.isDark)
	m.filterModal = tracefilterui.NewModel().SetDarkMode(m.isDark)
	m.recordModal = newRecordingModal().SetDarkMode(m.isDark)
	m.pidPicker = pidpicker.New().SetDarkMode(m.isDark)

	var sizeCmd tea.Cmd
	if m.width > 0 && m.height > 0 {
		msg := tea.WindowSizeMsg{Width: m.width, Height: m.height}
		next, cmd := m.pidPicker.Update(msg)
		m.pidPicker = next.(pidpicker.Model)
		sizeCmd = cmd
	}
	return m, tea.Batch(sizeCmd, m.pidPicker.Init())
}

func (m Model) reselectTID() (tea.Model, tea.Cmd) {
	pid := m.proc.pid

	if err := m.stopRecording(); err != nil {
		m.lastErr = err
		return m, nil
	}
	m.proc.pickerReturn = &pickerReturnState{
		pidFilter: m.proc.pid,
		tidFilter: m.proc.tid,
	}
	m.stopTrace()
	m.screen = ScreenPIDPicker
	m.attaching = false
	m.lastErr = nil
	m.exporter = tuiexport.NewModel()
	m.probeModal = probes.NewModel(m.runtime.currentProbeManager()).SetDarkMode(m.isDark)
	m.filterModal = tracefilterui.NewModel().SetDarkMode(m.isDark)
	m.recordModal = newRecordingModal().SetDarkMode(m.isDark)
	m.pidPicker = pidpicker.NewTIDWithKeys(pid, pidpicker.DefaultKeyMap()).SetDarkMode(m.isDark)

	var sizeCmd tea.Cmd
	if m.width > 0 && m.height > 0 {
		msg := tea.WindowSizeMsg{Width: m.width, Height: m.height}
		next, cmd := m.pidPicker.Update(msg)
		m.pidPicker = next.(pidpicker.Model)
		sizeCmd = cmd
	}
	return m, tea.Batch(sizeCmd, m.pidPicker.Init())
}

func selectedPIDFilter(pid int) int {
	if pid <= 0 {
		return -1
	}
	return pid
}

func (m Model) cancelPickerToDashboard() (tea.Model, tea.Cmd) {
	if m.proc.pickerReturn == nil {
		return m, nil
	}
	if err := m.stopRecording(); err != nil {
		m.lastErr = err
		return m, nil
	}
	returnState := *m.proc.pickerReturn
	m.proc.pickerReturn = nil
	m.stopTrace()
	m.setProcessFilters(returnState.pidFilter, returnState.tidFilter)
	m.screen = ScreenDashboard
	m.attaching = true
	m.lastErr = nil
	return m, tea.Batch(m.spin.Tick, m.beginTraceCmd())
}

func (m *Model) beginTraceCmd() tea.Cmd {
	ctx, cancel := context.WithCancel(context.Background())
	m.traceStop = cancel
	ctx = ContextWithRuntimeBindings(ctx, m.runtime)
	ctx = ContextWithTraceFilters(ctx, m.filter.global)
	return startTraceCmd(m.startTrace, ctx)
}

func startTraceCmd(starter TraceStarter, ctx context.Context) tea.Cmd {
	return func() tea.Msg {
		if err := starter(ctx); err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return TracingErrorMsg{Err: err}
		}
		return TracingStartedMsg{}
	}
}

func defaultTraceStarter(context.Context) error {
	return nil
}

// filterFromConfig delegates to the canonical Config.TraceFilter method.
func filterFromConfig(cfg flags.Config) globalfilter.Filter {
	return cfg.TraceFilter()
}

func (m *Model) setProcessFilters(pid, tid int) {
	m.proc.pid = pid
	m.proc.tid = tid
	m.filter.global = applyProcessFilters(m.filter.global, pid, tid)
	for i := range m.filter.history {
		m.filter.history[i] = applyProcessFilters(m.filter.history[i], pid, tid)
	}
	m.syncDashboardFilterState()
}

func (m *Model) setGlobalFilter(filter globalfilter.Filter) {
	m.filter.global = filter.Clone()
	// EqValue returns (0, false) when no equality filter is set;
	// selectedPIDFilter maps non-positive values to -1 ("no filter").
	pid, _ := m.filter.global.PID.EqValue()
	tid, _ := m.filter.global.TID.EqValue()
	m.proc.pid = selectedPIDFilter(pid)
	m.proc.tid = selectedPIDFilter(tid)
	m.syncDashboardFilterState()
}

func (m *Model) syncDashboardFilterState() {
	m.dashboard.SetPidFilter(m.proc.pid)
	m.dashboard.SetGlobalFilter(m.filter.global)
	m.dashboard.SetFilterStack(m.filter.stack)
	m.dashboard.SetRecordingStatus(m.recordingStatus())
}

func applyProcessFilters(filter globalfilter.Filter, pid, tid int) globalfilter.Filter {
	out := filter.Clone()
	out.PID = globalfilter.NewEqFilter(int64(pid))
	out.TID = globalfilter.NewEqFilter(int64(tid))
	return out
}

func (m Model) applyGlobalFilter(filter globalfilter.Filter, action string) (tea.Model, tea.Cmd) {
	nextFilter := filter.Clone()
	changed := !m.filter.global.Equal(nextFilter)
	if changed {
		m.filter.history = append(m.filter.history, m.filter.global.Clone())
		m.filter.stack = append(m.filter.stack, globalFilterActionLabel(m.filter.global, nextFilter, action))
	}
	m.setGlobalFilter(nextFilter)
	if !changed || m.screen != ScreenDashboard {
		return m, nil
	}

	m.runtime.advanceFilterEpoch()
	// Try the in-place swap first: hand the new filter to the running
	// eventloop via the registered setter and only reset the dashboard
	// aggregates so the displayed counts reflect the new filter going
	// forward. The BPF probes stay attached, so the user no longer sees
	// the multi-second 'Attaching tracepoints' overlay on filter changes.
	if m.runtime.applyLiveFilter(nextFilter) {
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
	m.stopTrace()
	m.dashboard.PrepareForTraceRestart()
	m.attaching = true
	m.lastErr = nil
	return m, tea.Batch(m.spin.Tick, m.beginTraceCmd())
}

func (m Model) undoGlobalFilter() (tea.Model, tea.Cmd) {
	if len(m.filter.history) == 0 {
		return m, nil
	}
	prev := m.filter.history[len(m.filter.history)-1]
	m.filter.history = m.filter.history[:len(m.filter.history)-1]
	if len(m.filter.stack) > 0 {
		m.filter.stack = m.filter.stack[:len(m.filter.stack)-1]
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

	m.stopTrace()
	m.dashboard.PrepareForTraceRestart()
	m.attaching = true
	m.lastErr = nil
	return m, tea.Batch(m.spin.Tick, m.beginTraceCmd())
}

func globalFilterActionLabel(prev, next globalfilter.Filter, action string) string {
	if strings.TrimSpace(action) != "" {
		return action
	}
	parts := make([]string, 0, 10)
	if prev.ErrorsOnly != next.ErrorsOnly {
		if next.ErrorsOnly {
			parts = append(parts, "errors")
		} else {
			parts = append(parts, "clear errors")
		}
	}
	parts = appendStringFilterChange(parts, "syscall", prev.Syscall, next.Syscall)
	parts = appendStringFilterChange(parts, "comm", prev.Comm, next.Comm)
	parts = appendStringFilterChange(parts, "file", prev.File, next.File)
	parts = appendNumericFilterChange(parts, "pid", prev.PID, next.PID, false)
	parts = appendNumericFilterChange(parts, "tid", prev.TID, next.TID, false)
	parts = appendNumericFilterChange(parts, "fd", prev.FD, next.FD, false)
	parts = appendNumericFilterChange(parts, "latency", prev.LatencyNs, next.LatencyNs, true)
	parts = appendNumericFilterChange(parts, "gap", prev.GapNs, next.GapNs, true)
	parts = appendNumericFilterChange(parts, "bytes", prev.Bytes, next.Bytes, false)
	parts = appendNumericFilterChange(parts, "ret", prev.RetVal, next.RetVal, false)
	if len(parts) == 0 {
		return next.Summary()
	}
	return strings.Join(parts, " ")
}

func appendStringFilterChange(parts []string, name string, prev, next *globalfilter.StringFilter) []string {
	if sameStringFilter(prev, next) {
		return parts
	}
	if next == nil || strings.TrimSpace(next.Pattern) == "" {
		return append(parts, "clear "+name)
	}
	return append(parts, fmt.Sprintf("%s~%s", name, strings.TrimSpace(next.Pattern)))
}

func appendNumericFilterChange(parts []string, name string, prev, next *globalfilter.NumericFilter, duration bool) []string {
	if sameNumericFilter(prev, next) {
		return parts
	}
	if next == nil {
		return append(parts, "clear "+name)
	}
	value := strconv.FormatInt(next.Value, 10)
	if duration {
		value = time.Duration(next.Value).String()
	}
	return append(parts, fmt.Sprintf("%s%s%s", name, globalfilter.CompareOpSymbol(next.Op), value))
}

func sameStringFilter(a, b *globalfilter.StringFilter) bool {
	if a == nil || strings.TrimSpace(a.Pattern) == "" {
		return b == nil || strings.TrimSpace(b.Pattern) == ""
	}
	if b == nil {
		return false
	}
	return strings.TrimSpace(a.Pattern) == strings.TrimSpace(b.Pattern)
}

func sameNumericFilter(a, b *globalfilter.NumericFilter) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Op == b.Op && a.Value == b.Value
}

func (m *Model) stopTrace() {
	if m.traceStop != nil {
		m.traceStop()
		m.traceStop = nil
	}
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
		base := m.pidPicker.View().Content
		if m.exporter.Visible() {
			return altScreenView(placeToViewport(width, height, m.exporter.View(width, height)+"\n"+base), title)
		}
		return altScreenView(placeToViewport(width, height, base), title)
	case ScreenDashboard:
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
	default:
		return altScreenView("", title)
	}
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
			return tuiexport.FailedMsg{Err: errors.New("tui export is disabled by -tuiExport=false")}
		}
		switch option {
		case tuiexport.OptionCSV:
			path, err := dashboard.ExportStreamCSV()
			if err != nil {
				return tuiexport.FailedMsg{Err: err}
			}
			return tuiexport.CompletedMsg{Path: path}
		default:
			return tuiexport.FailedMsg{Err: errors.New("unknown export option")}
		}
	}
}

func (m *Model) startRecording(path string) error {
	recorder := m.runtime.Recorder()
	if recorder == nil {
		return errors.New("recording runtime is unavailable")
	}
	if err := recorder.Start(path, parquet.StartOptions{Metadata: tuiParquetMetadata()}); err != nil {
		m.syncDashboardFilterState()
		return err
	}
	m.syncDashboardFilterState()
	return nil
}

func (m *Model) stopRecording() error {
	recorder := m.runtime.Recorder()
	if recorder == nil {
		return nil
	}
	if !m.recordingActive() {
		m.syncDashboardFilterState()
		return nil
	}
	err := recorder.Stop()
	m.syncDashboardFilterState()
	return err
}

func (m Model) recordingActive() bool {
	recorder := m.runtime.Recorder()
	if recorder == nil {
		return false
	}
	return recorder.Status().Active
}

func (m Model) recordingStatus() string {
	recorder := m.runtime.Recorder()
	if recorder == nil {
		return "rec: unavailable"
	}
	status := recorder.Status()
	if status.Active {
		return "rec: " + shortenRecordingPath(status.Path)
	}
	if status.LastError != nil {
		return "rec err: " + status.LastError.Error()
	}
	return "rec: off"
}

func defaultParquetRecordingFilename() string {
	return fmt.Sprintf("ior-recording-%s.parquet", time.Now().Format("20060102-150405"))
}

// tuiParquetMetadata delegates to the canonical parquet.NewFileMetadata.
func tuiParquetMetadata() parquet.FileMetadata {
	return parquet.NewFileMetadata("tui")
}

func shortenRecordingPath(path string) string {
	const maxLen = 36
	if len(path) <= maxLen {
		return path
	}
	return "..." + path[len(path)-maxLen+3:]
}

type lateBoundDashboardSource struct {
	runtime *runtimeBindings
}

func (s lateBoundDashboardSource) Snapshot() *statsengine.Snapshot {
	if s.runtime == nil {
		return nil
	}
	source := s.runtime.dashboardSnapshotSource()
	if source == nil {
		return nil
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

func altScreenView(content, title string) tea.View {
	view := tea.NewView(content)
	view.AltScreen = true
	view.ReportFocus = true
	view.MouseMode = tea.MouseModeCellMotion
	view.WindowTitle = title
	view.KeyboardEnhancements.ReportEventTypes = true
	return view
}
