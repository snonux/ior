package tui

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"ior/internal/flags"
	"ior/internal/globalfilter"
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

// TraceRuntimeBindings allows a trace starter to publish runtime dependencies
// (snapshot source, stream source, probe manager) into the active TUI model.
type TraceRuntimeBindings interface {
	SetDashboardSnapshotSource(source SnapshotSource)
	SetEventStreamSource(source eventstream.Source)
	SetLiveTrie(liveTrie flamegraphtui.LiveTrieSource)
	SetProbeManager(manager ProbeManager)
	StreamBuffer() *eventstream.RingBuffer
}

type runtimeBindingsContextKey struct{}
type traceFiltersContextKey struct{}

type runtimeBindings struct {
	mu sync.RWMutex

	snapshotSource SnapshotSource
	streamSource   eventstream.Source
	streamBuffer   *eventstream.RingBuffer
	liveTrieSource flamegraphtui.LiveTrieSource
	probeManager   ProbeManager
}

type traceFilters struct {
	filter globalfilter.Filter
}

func newRuntimeBindings() *runtimeBindings {
	streamBuffer := eventstream.NewRingBuffer()
	return &runtimeBindings{
		streamSource: streamBuffer,
		streamBuffer: streamBuffer,
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

func (r *runtimeBindings) StreamBuffer() *eventstream.RingBuffer {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.streamBuffer
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

// RuntimeBindingsFromContext returns model-scoped trace bindings when the
// context was created by the TUI.
func RuntimeBindingsFromContext(ctx context.Context) (TraceRuntimeBindings, bool) {
	bindings, ok := ctx.Value(runtimeBindingsContextKey{}).(*runtimeBindings)
	if !ok || bindings == nil {
		return nil, false
	}
	return bindings, true
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

// Run starts the TUI program in alternate screen mode.
func Run() error {
	return RunWithTraceStarter(defaultTraceStarter)
}

// RunWithTraceStarter starts the TUI program with a custom trace starter.
func RunWithTraceStarter(starter TraceStarter) error {
	return RunWithTraceStarterConfig(flags.Get(), starter)
}

// RunWithTraceStarterConfig starts the TUI with explicit runtime flags.
func RunWithTraceStarterConfig(cfg flags.Config, starter TraceStarter) error {
	model := newModelWithRuntimeConfig(cfg.PidFilter, filterFromConfig(cfg), cfg.PidFilter, cfg.TidFilter, cfg.TUIExportEnable, starter)
	program := tea.NewProgram(model)
	_, err := program.Run()
	return err
}

// RunTestFlamesWithTraceStarter starts the TUI directly on dashboard/flame view
// with a synthetic static flamegraph source.
func RunTestFlamesWithTraceStarter(starter TraceStarter) error {
	return RunTestFlamesWithTraceStarterConfig(flags.Get(), starter)
}

// RunTestFlamesWithTraceStarterConfig starts test-flames mode with explicit runtime flags.
func RunTestFlamesWithTraceStarterConfig(cfg flags.Config, starter TraceStarter) error {
	model := newModelWithRuntimeConfig(1, filterFromConfig(cfg), 1, -1, cfg.TUIExportEnable, starter)
	program := tea.NewProgram(model)
	_, err := program.Run()
	return err
}

// Model is the top-level Bubble Tea model that routes between PID picker and dashboard.
type Model struct {
	screen      Screen
	pidPicker   pidpicker.Model
	dashboard   dashboardui.Model
	exporter    tuiexport.Model
	probeModal  probes.Model
	filterModal tracefilterui.Model
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

	pidFilter     int
	tidFilter     int
	globalFilter  globalfilter.Filter
	filterHistory []globalfilter.Filter
	filterStack   []string
	pickerReturn  *pickerReturnState
	exportEnabled bool
	isDark        bool
	focused       bool

	keyboardEnhancements      tea.KeyboardEnhancementsMsg
	keyboardEnhancementsKnown bool

	lastKeyEventID       string
	lastKeyEventAt       time.Time
	lastKeyEventWasPress bool
	// Some terminals emit release+press for a single physical key event.
	// When we fallback-handle a release as a press, suppress the immediate
	// matching press to avoid double-handling.
	suppressPressKeyID string
	suppressPressUntil time.Time
}

type pickerReturnState struct {
	pidFilter int
	tidFilter int
}

// NewModel creates the top-level TUI model.
func NewModel(initialPID int, startTrace TraceStarter) Model {
	return NewModelWithConfig(flags.Get(), initialPID, startTrace)
}

// NewModelWithConfig creates the top-level TUI model with explicit runtime flags.
func NewModelWithConfig(cfg flags.Config, initialPID int, startTrace TraceStarter) Model {
	return newModelWithRuntimeConfig(initialPID, filterFromConfig(cfg), cfg.PidFilter, cfg.TidFilter, cfg.TUIExportEnable, startTrace)
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
		runtime:       runtime,
		keys:          keys,
		spin:          spin,
		startTrace:    startTrace,
		globalFilter:  startupFilter.Clone(),
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
		m.keyboardEnhancements = msg
		m.keyboardEnhancementsKnown = true
		if msg.SupportsKeyDisambiguation() {
			log.Printf("tui: keyboard enhancements enabled (flags=%d, eventTypes=%t)", msg.Flags, msg.SupportsEventTypes())
		}
		return m, nil
	case tea.FocusMsg:
		m.focused = true
		m.dashboard.SetFocused(true)
		if m.screen == ScreenDashboard && !m.attaching {
			return m, tea.Batch(m.dashboard.Init(), m.dashboard.SnapshotCmd())
		}
		return m, nil
	case tea.BlurMsg:
		m.focused = false
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
		m.dashboard.SetGlobalFilter(m.globalFilter)
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
		!m.probeModal.Visible() &&
		!m.dashboard.BlocksGlobalShortcuts(msg)
}

func (m Model) canQuitFromMainDashboard(msg tea.KeyPressMsg) bool {
	return m.screen == ScreenDashboard &&
		!m.attaching &&
		m.lastErr == nil &&
		!m.filterModal.Visible() &&
		!m.exporter.Visible() &&
		!m.probeModal.Visible() &&
		!m.dashboard.BlocksGlobalShortcuts(msg)
}

func (m Model) shouldCancelPickerToDashboard(msg tea.KeyPressMsg) bool {
	return m.screen == ScreenPIDPicker &&
		m.pickerReturn != nil &&
		(isEscKey(msg) || key.Matches(msg, m.keys.Quit))
}

func (m Model) shouldRouteQuitToEsc(msg tea.KeyPressMsg) bool {
	if m.helpOverlayVisible {
		return false
	}
	return m.screen == ScreenDashboard &&
		(m.filterModal.Visible() || m.exporter.Visible() || m.probeModal.Visible() || m.dashboard.BlocksGlobalShortcuts(msg))
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
		if m.canQuitFromMainDashboard(msg) {
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
	if m.canHandleDashboardShortcut(msg) && key.Matches(msg, m.keys.Probes) {
		m.probeModal = probes.NewModel(m.runtime.currentProbeManager()).SetDarkMode(m.isDark).Open()
		return m, nil, true
	}
	if m.canHandleDashboardShortcut(msg) && key.Matches(msg, m.keys.Filter) {
		m.filterModal = m.filterModal.Open(m.globalFilter)
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
	return m, nil, false
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

func (m *Model) normalizeKeyEvent(msg tea.Msg) (tea.Msg, bool) {
	switch keyMsg := msg.(type) {
	case tea.KeyPressMsg:
		keyID := keyEventID(keyMsg)
		if m.shouldSuppressPress(keyID) {
			return nil, false
		}
		m.recordKeyEvent(keyMsg, true)
		return keyMsg, true
	case tea.KeyReleaseMsg:
		pressMsg := tea.KeyPressMsg(keyMsg)
		keyID := keyEventID(pressMsg)
		if m.lastKeyEventWasPress && keyID != "" && keyID == m.lastKeyEventID && time.Since(m.lastKeyEventAt) <= 500*time.Millisecond {
			// Some terminals emit both press+release; avoid handling release as a duplicate.
			m.lastKeyEventWasPress = false
			return nil, false
		}
		if !releaseHasIdentity(pressMsg) {
			// Ignore release messages that don't carry enough identity information.
			// Some terminals emit these before a usable press event.
			return nil, false
		}
		// Fallback: treat release as press for terminals that only emit release events.
		if shouldSuppressMatchingPressAfterRelease(pressMsg) {
			m.armPressSuppression(keyID)
		}
		m.recordKeyEvent(pressMsg, false)
		return pressMsg, true
	default:
		return msg, true
	}
}

func (m *Model) shouldSuppressPress(keyID string) bool {
	if m.suppressPressKeyID == "" {
		return false
	}
	if time.Now().After(m.suppressPressUntil) {
		m.clearPressSuppression()
		return false
	}
	if keyID == "" || keyID != m.suppressPressKeyID {
		return false
	}
	m.clearPressSuppression()
	return true
}

func (m *Model) armPressSuppression(keyID string) {
	if keyID == "" {
		return
	}
	// Keep this short so fast repeated key presses still work naturally.
	m.suppressPressKeyID = keyID
	m.suppressPressUntil = time.Now().Add(60 * time.Millisecond)
}

func (m *Model) clearPressSuppression() {
	m.suppressPressKeyID = ""
	m.suppressPressUntil = time.Time{}
}

func (m *Model) recordKeyEvent(msg tea.KeyPressMsg, wasPress bool) {
	m.lastKeyEventID = keyEventID(msg)
	m.lastKeyEventAt = time.Now()
	m.lastKeyEventWasPress = wasPress
}

func keyEventID(msg tea.KeyPressMsg) string {
	return fmt.Sprintf("code:%d/mod:%d/key:%q/text:%q", msg.Code, msg.Mod, msg.String(), msg.Text)
}

func releaseHasIdentity(msg tea.KeyPressMsg) bool {
	if msg.Text != "" {
		return true
	}
	keyStr := msg.String()
	if keyStr != "" && keyStr != "\x00" {
		return true
	}
	// Some terminals emit release-only space events without text identity.
	return msg.Code == tea.KeySpace
}

func shouldSuppressMatchingPressAfterRelease(msg tea.KeyPressMsg) bool {
	keyStr := msg.String()
	return msg.Code == tea.KeySpace || keyStr == " " || keyStr == "space" || msg.Text == " "
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
	m.stopTrace()
	m.runtime.resetStreamBuffer()
	m.setProcessFilters(pid, -1)
	m.pickerReturn = nil
	m.screen = ScreenDashboard
	m.attaching = true
	m.lastErr = nil
	return m, tea.Batch(m.spin.Tick, m.beginTraceCmd())
}

func (m Model) handleTidSelected(msg TidSelectedMsg) (tea.Model, tea.Cmd) {
	tid := selectedPIDFilter(msg.Tid)
	pid := m.pidFilter
	if msg.Pid > 0 {
		pid = msg.Pid
	}
	m.stopTrace()
	m.runtime.resetStreamBuffer()
	m.setProcessFilters(pid, tid)
	m.pickerReturn = nil
	m.screen = ScreenDashboard
	m.attaching = true
	m.lastErr = nil
	return m, tea.Batch(m.spin.Tick, m.beginTraceCmd())
}

func (m Model) reselectPID() (tea.Model, tea.Cmd) {
	m.pickerReturn = &pickerReturnState{
		pidFilter: m.pidFilter,
		tidFilter: m.tidFilter,
	}
	m.stopTrace()
	m.screen = ScreenPIDPicker
	m.attaching = false
	m.lastErr = nil
	m.exporter = tuiexport.NewModel()
	m.probeModal = probes.NewModel(m.runtime.currentProbeManager()).SetDarkMode(m.isDark)
	m.filterModal = tracefilterui.NewModel().SetDarkMode(m.isDark)
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
	pid := m.pidFilter

	m.pickerReturn = &pickerReturnState{
		pidFilter: m.pidFilter,
		tidFilter: m.tidFilter,
	}
	m.stopTrace()
	m.screen = ScreenPIDPicker
	m.attaching = false
	m.lastErr = nil
	m.exporter = tuiexport.NewModel()
	m.probeModal = probes.NewModel(m.runtime.currentProbeManager()).SetDarkMode(m.isDark)
	m.filterModal = tracefilterui.NewModel().SetDarkMode(m.isDark)
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
	if m.pickerReturn == nil {
		return m, nil
	}
	returnState := *m.pickerReturn
	m.pickerReturn = nil
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
	ctx = context.WithValue(ctx, runtimeBindingsContextKey{}, m.runtime)
	ctx = ContextWithTraceFilters(ctx, m.globalFilter)
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

func filterFromConfig(cfg flags.Config) globalfilter.Filter {
	filter := cfg.GlobalFilter.Clone()
	if filter.IsActive() {
		return filter
	}
	if cfg.CommFilter != "" {
		filter.Comm = &globalfilter.StringFilter{Pattern: cfg.CommFilter}
	}
	if cfg.PathFilter != "" {
		filter.File = &globalfilter.StringFilter{Pattern: cfg.PathFilter}
	}
	if cfg.PidFilter > 0 {
		filter.PID = eqNumericFilter(cfg.PidFilter)
	}
	if cfg.TidFilter > 0 {
		filter.TID = eqNumericFilter(cfg.TidFilter)
	}
	return filter
}

func eqNumericFilter(value int) *globalfilter.NumericFilter {
	if value <= 0 {
		return nil
	}
	return &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: int64(value)}
}

func (m *Model) setProcessFilters(pid, tid int) {
	m.pidFilter = pid
	m.tidFilter = tid
	m.globalFilter = applyProcessFilters(m.globalFilter, pid, tid)
	for i := range m.filterHistory {
		m.filterHistory[i] = applyProcessFilters(m.filterHistory[i], pid, tid)
	}
	m.syncDashboardFilterState()
}

func (m *Model) setGlobalFilter(filter globalfilter.Filter) {
	m.globalFilter = filter.Clone()
	pid, _ := eqNumericFilterValue(m.globalFilter.PID)
	tid, _ := eqNumericFilterValue(m.globalFilter.TID)
	m.pidFilter = pid
	m.tidFilter = tid
	m.syncDashboardFilterState()
}

func (m *Model) syncDashboardFilterState() {
	m.dashboard.SetPidFilter(m.pidFilter)
	m.dashboard.SetGlobalFilter(m.globalFilter)
	m.dashboard.SetFilterStack(m.filterStack)
}

func applyProcessFilters(filter globalfilter.Filter, pid, tid int) globalfilter.Filter {
	out := filter.Clone()
	out.PID = eqNumericFilter(pid)
	out.TID = eqNumericFilter(tid)
	return out
}

func (m Model) applyGlobalFilter(filter globalfilter.Filter, action string) (tea.Model, tea.Cmd) {
	nextFilter := filter.Clone()
	changed := !m.globalFilter.Equal(nextFilter)
	if changed {
		m.filterHistory = append(m.filterHistory, m.globalFilter.Clone())
		m.filterStack = append(m.filterStack, globalFilterActionLabel(m.globalFilter, nextFilter, action))
	}
	m.setGlobalFilter(nextFilter)
	if !changed || m.screen != ScreenDashboard {
		return m, nil
	}

	m.stopTrace()
	m.dashboard.PrepareForTraceRestart()
	m.attaching = true
	m.lastErr = nil
	return m, tea.Batch(m.spin.Tick, m.beginTraceCmd())
}

func (m Model) undoGlobalFilter() (tea.Model, tea.Cmd) {
	if len(m.filterHistory) == 0 {
		return m, nil
	}
	prev := m.filterHistory[len(m.filterHistory)-1]
	m.filterHistory = m.filterHistory[:len(m.filterHistory)-1]
	if len(m.filterStack) > 0 {
		m.filterStack = m.filterStack[:len(m.filterStack)-1]
	}
	m.setGlobalFilter(prev)
	if m.screen != ScreenDashboard {
		return m, nil
	}

	m.stopTrace()
	m.dashboard.PrepareForTraceRestart()
	m.attaching = true
	m.lastErr = nil
	return m, tea.Batch(m.spin.Tick, m.beginTraceCmd())
}

func eqNumericFilterValue(filter *globalfilter.NumericFilter) (int, bool) {
	if filter == nil || filter.Op != globalfilter.OpEq || filter.Value <= 0 {
		return -1, false
	}
	return int(filter.Value), true
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
	return append(parts, fmt.Sprintf("%s%s%s", name, compareOpSymbol(next.Op), value))
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

func compareOpSymbol(op globalfilter.CompareOp) string {
	switch op {
	case globalfilter.OpEq:
		return "="
	case globalfilter.OpNeq:
		return "!="
	case globalfilter.OpGt:
		return ">"
	case globalfilter.OpGte:
		return ">="
	case globalfilter.OpLt:
		return "<"
	case globalfilter.OpLte:
		return "<="
	default:
		return "="
	}
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
}

func (m Model) windowTitle() string {
	switch m.screen {
	case ScreenPIDPicker:
		return "ior - select process"
	case ScreenDashboard:
		if m.pidFilter > 0 {
			return fmt.Sprintf("ior - tracing PID %d", m.pidFilter)
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

func renderHelpOverlay(width, height int, groups [][]key.Binding) string {
	if width <= 0 {
		width = 80
	}
	if height <= 0 {
		height = 24
	}

	lines := []string{"Help"}
	for _, group := range groups {
		parts := make([]string, 0, len(group))
		for _, binding := range group {
			h := binding.Help()
			parts = append(parts, fmt.Sprintf("%s %s", h.Key, h.Desc))
		}
		lines = append(lines, strings.Join(parts, " • "))
	}
	lines = append(lines, "", "Esc/?/q close")

	boxWidth := width - 6
	if boxWidth < 72 {
		boxWidth = 72
	}

	box := common.PanelStyle.Copy().
		Width(boxWidth).
		Render(strings.Join(lines, "\n"))

	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, box)
}

type helpSection struct {
	title string
	lines []string
}

func (m Model) helpSections() []helpSection {
	globalLines := []string{
		"H help  esc/? close help  q quit",
		"f filter  p pid picker  t tid picker  o probes",
	}
	if help := m.keys.Export.Help(); help.Key != "" || help.Desc != "" {
		globalLines[1] += "  e stream export"
	}

	return []helpSection{
		{
			title: "Global",
			lines: globalLines,
		},
		{
			title: "Dashboard Tabs",
			lines: []string{
				"tab/shift+tab tabs  1..7 jump tab  r reset baseline",
				"sys/files/proc/stream tables: arrows or hjkl move  pgup/pgdown page  g/G top/bottom",
				"sys/proc: v bubbles  b metric events/bytes",
				"files: d dirs toggle  v bubbles (dirs only)  b metric",
				"flame: arrows/hjkl nav  enter/click zoom  click ancestor undo  u/bs/esc undo  o order",
				"flame: / filter  n/N match next/prev  space pause  b metric",
				"stream: space pause  enter push filter  esc/F undo  /? n/N search",
				"stream: x/X export  E open",
			},
		},
		{
			title: "PID/TID Picker",
			lines: []string{
				"enter select  r refresh  esc/q back",
			},
		},
	}
}

func renderGlobalHelpOverlay(width, height int, sections []helpSection) string {
	if width <= 0 {
		width = 80
	}
	if height <= 0 {
		height = 24
	}

	boxWidth := width - 4
	if boxWidth > 100 {
		boxWidth = 100
	}
	if boxWidth < 74 {
		boxWidth = 74
	}
	contentWidth := boxWidth - 4
	if contentWidth < 20 {
		contentWidth = boxWidth
	}

	lines := make([]string, 0, 24)
	lines = append(lines, "Help")
	for _, section := range sections {
		lines = append(lines, "")
		lines = append(lines, section.title)
		for _, line := range section.lines {
			lines = append(lines, "  "+truncateHelpLine(line, contentWidth-2))
		}
	}
	lines = append(lines, "", "Esc/q close")

	maxLines := height - 4
	if maxLines < 6 {
		maxLines = 6
	}
	if len(lines) > maxLines {
		lines = lines[:maxLines-1]
		lines = append(lines, truncateHelpLine("... (resize for full help)", contentWidth))
	}

	box := common.PanelStyle.Copy().Width(boxWidth).Render(strings.Join(lines, "\n"))
	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, box)
}

func truncateHelpLine(s string, width int) string {
	if width <= 0 {
		return ""
	}
	if lipgloss.Width(s) <= width {
		return s
	}
	if width == 1 {
		return "…"
	}
	r := []rune(s)
	if len(r) >= width {
		return string(r[:width-1]) + "…"
	}
	return s
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
