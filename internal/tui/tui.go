package tui

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"ior/internal/flags"
	"ior/internal/probemanager"
	"ior/internal/statsengine"
	common "ior/internal/tui/common"
	dashboardui "ior/internal/tui/dashboard"
	"ior/internal/tui/eventstream"
	tuiexport "ior/internal/tui/export"
	"ior/internal/tui/messages"
	"ior/internal/tui/pidpicker"
	"ior/internal/tui/probes"
	"os"
	"strings"
	"sync"
	"time"

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
	SetEventStreamSource(source *eventstream.RingBuffer)
	SetProbeManager(manager ProbeManager)
}

type runtimeBindingsContextKey struct{}

type runtimeBindings struct {
	mu sync.RWMutex

	snapshotSource SnapshotSource
	streamSource   *eventstream.RingBuffer
	probeManager   ProbeManager
}

func newRuntimeBindings() *runtimeBindings {
	return &runtimeBindings{}
}

func (r *runtimeBindings) SetDashboardSnapshotSource(source SnapshotSource) {
	r.mu.Lock()
	r.snapshotSource = source
	r.mu.Unlock()
}

func (r *runtimeBindings) SetEventStreamSource(source *eventstream.RingBuffer) {
	r.mu.Lock()
	r.streamSource = source
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

func (r *runtimeBindings) eventStreamSource() *eventstream.RingBuffer {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.streamSource
}

func (r *runtimeBindings) currentProbeManager() ProbeManager {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.probeManager
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

// Run starts the TUI program in alternate screen mode.
func Run() error {
	return RunWithTraceStarter(defaultTraceStarter)
}

// RunWithTraceStarter starts the TUI program with a custom trace starter.
func RunWithTraceStarter(starter TraceStarter) error {
	cfg := flags.Get()
	model := newModelWithRuntimeConfig(cfg.PidFilter, cfg.PidFilter, cfg.TUIExportEnable, starter)
	program := tea.NewProgram(model)
	_, err := program.Run()
	return err
}

// Model is the top-level Bubble Tea model that routes between PID picker and dashboard.
type Model struct {
	screen     Screen
	pidPicker  pidpicker.Model
	dashboard  dashboardui.Model
	exporter   tuiexport.Model
	probeModal probes.Model
	runtime    *runtimeBindings

	keys KeyMap

	width    int
	height   int
	quitting bool

	attaching bool
	spin      spinner.Model
	lastErr   error

	startTrace TraceStarter
	traceStop  context.CancelFunc

	pidFilter     int
	exportEnabled bool
	isDark        bool
	focused       bool
}

// NewModel creates the top-level TUI model.
func NewModel(initialPID int, startTrace TraceStarter) Model {
	cfg := flags.Get()
	return newModelWithRuntimeConfig(initialPID, cfg.PidFilter, cfg.TUIExportEnable, startTrace)
}

func newModelWithRuntimeConfig(initialPID, startupPidFilter int, exportEnabled bool, startTrace TraceStarter) Model {
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
	dashboard.SetPidFilter(pidFilter)

	model := Model{
		screen:        ScreenPIDPicker,
		pidPicker:     pidpicker.New().SetDarkMode(true),
		dashboard:     dashboard,
		exporter:      tuiexport.NewModel(),
		probeModal:    probes.NewModel(runtime.currentProbeManager()).SetDarkMode(true),
		runtime:       runtime,
		keys:          keys,
		spin:          spin,
		startTrace:    startTrace,
		pidFilter:     pidFilter,
		exportEnabled: exportEnabled,
		isDark:        true,
		focused:       true,
	}

	if initialPID > 0 {
		flags.SetPidFilter(initialPID)
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
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m.updateActiveModel(msg)
	case tea.BackgroundColorMsg:
		m.applyTheme(msg.IsDark())
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
		if key.Matches(msg, m.keys.Quit) {
			m.quitting = true
			m.stopTrace()
			return m, tea.Quit
		}
		if m.exportEnabled && m.screen == ScreenDashboard && !m.attaching && m.lastErr == nil && key.Matches(msg, m.keys.Export) && !m.exporter.Visible() && !m.probeModal.Visible() && !m.dashboard.BlocksGlobalShortcuts() {
			m.exporter = m.exporter.Open()
			return m, nil
		}
		if m.screen == ScreenDashboard && !m.attaching && m.lastErr == nil && key.Matches(msg, m.keys.Probes) && !m.exporter.Visible() && !m.probeModal.Visible() && !m.dashboard.BlocksGlobalShortcuts() {
			m.probeModal = probes.NewModel(m.runtime.currentProbeManager()).SetDarkMode(m.isDark).Open()
			return m, nil
		}
		if m.screen == ScreenDashboard && !m.attaching && m.lastErr == nil && key.Matches(msg, m.keys.SelectPID) && !m.exporter.Visible() && !m.probeModal.Visible() && !m.dashboard.BlocksGlobalShortcuts() {
			return m.reselectPID()
		}
		if m.screen == ScreenDashboard && !m.attaching && m.lastErr == nil && key.Matches(msg, m.keys.SelectTID) && !m.exporter.Visible() && !m.probeModal.Visible() && !m.dashboard.BlocksGlobalShortcuts() {
			return m.reselectTID()
		}
	case tuiexport.RequestMsg:
		return m, runExportCmd(m.exportEnabled, msg.Option, m.dashboard.LatestSnapshot())
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
		return m, m.dashboard.Init()
	case TracingErrorMsg:
		m.attaching = false
		m.lastErr = msg.Err
		return m, nil
	}

	if m.attaching {
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return m, cmd
	}
	if m.probeModal.Visible() {
		var dashboardCmd tea.Cmd
		// Keep dashboard refresh/data flow alive while probe modal is open.
		if _, isKey := msg.(tea.KeyPressMsg); !isKey && m.screen == ScreenDashboard {
			next, cmd := m.dashboard.Update(msg)
			m.dashboard = next.(dashboardui.Model)
			dashboardCmd = cmd
		}
		var cmd tea.Cmd
		m.probeModal, cmd = m.probeModal.Update(msg)
		return m, tea.Batch(dashboardCmd, cmd)
	}
	if m.exporter.Visible() {
		var dashboardCmd tea.Cmd
		// Keep dashboard refresh/data flow alive while export modal is open.
		if _, isKey := msg.(tea.KeyPressMsg); !isKey && m.screen == ScreenDashboard {
			next, cmd := m.dashboard.Update(msg)
			m.dashboard = next.(dashboardui.Model)
			dashboardCmd = cmd
		}
		var cmd tea.Cmd
		m.exporter, cmd = m.exporter.Update(msg)
		return m, tea.Batch(dashboardCmd, cmd)
	}

	return m.updateActiveModel(msg)
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
	flags.SetPidFilter(pid)
	flags.SetTidFilter(-1)
	m.pidFilter = pid
	m.dashboard.SetPidFilter(pid)
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
	flags.SetPidFilter(pid)
	flags.SetTidFilter(tid)
	m.pidFilter = pid
	m.dashboard.SetPidFilter(pid)
	m.screen = ScreenDashboard
	m.attaching = true
	m.lastErr = nil
	return m, tea.Batch(m.spin.Tick, m.beginTraceCmd())
}

func (m Model) reselectPID() (tea.Model, tea.Cmd) {
	m.stopTrace()
	m.screen = ScreenPIDPicker
	m.attaching = false
	m.lastErr = nil
	m.exporter = tuiexport.NewModel()
	m.probeModal = probes.NewModel(m.runtime.currentProbeManager()).SetDarkMode(m.isDark)
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

	m.stopTrace()
	m.screen = ScreenPIDPicker
	m.attaching = false
	m.lastErr = nil
	m.exporter = tuiexport.NewModel()
	m.probeModal = probes.NewModel(m.runtime.currentProbeManager()).SetDarkMode(m.isDark)
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

func (m *Model) beginTraceCmd() tea.Cmd {
	ctx, cancel := context.WithCancel(context.Background())
	m.traceStop = cancel
	ctx = context.WithValue(ctx, runtimeBindingsContextKey{}, m.runtime)
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
}

// View renders the currently active screen and startup overlay state.
func (m Model) View() tea.View {
	if m.quitting {
		return altScreenView("")
	}

	width, height := common.EffectiveViewport(m.width, m.height)

	if m.attaching {
		line := fmt.Sprintf("%s Attaching tracepoints...", m.spin.View())
		return altScreenView(placeToViewport(width, height, ScreenStyle.Render(PanelStyle.Render(line))))
	}

	if m.lastErr != nil {
		return altScreenView(placeToViewport(width, height, ScreenStyle.Render(ErrorStyle.Render(m.lastErr.Error()))))
	}

	switch m.screen {
	case ScreenPIDPicker:
		base := m.pidPicker.View().Content
		if m.exporter.Visible() {
			return altScreenView(placeToViewport(width, height, m.exporter.View(width, height)+"\n"+base))
		}
		return altScreenView(placeToViewport(width, height, base))
	case ScreenDashboard:
		base := m.dashboard.View().Content
		if m.probeModal.Visible() {
			return altScreenView(placeToViewport(width, height, m.probeModal.View(width, height)))
		}
		if m.exporter.Visible() {
			return altScreenView(placeToViewport(width, height, m.exporter.View(width, height)+"\n"+base))
		}
		return altScreenView(placeToViewport(width, height, base))
	default:
		return altScreenView("")
	}
}

func runExportCmd(exportEnabled bool, option tuiexport.Option, snap *statsengine.Snapshot) tea.Cmd {
	return func() tea.Msg {
		if !exportEnabled {
			return tuiexport.FailedMsg{Err: errors.New("tui export is disabled by -tuiExport=false")}
		}
		switch option {
		case tuiexport.OptionCSV:
			path, err := exportSnapshotCSV(snap)
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

func exportSnapshotCSV(snap *statsengine.Snapshot) (string, error) {
	filename := fmt.Sprintf("ior-snapshot-%s.csv", time.Now().Format("20060102-150405"))
	f, err := os.Create(filename)
	if err != nil {
		return "", err
	}
	defer f.Close()

	w := csv.NewWriter(f)

	rows := [][]string{
		{"section", "name", "value1", "value2", "value3"},
		{"summary", "totals", fmt.Sprint(snapValue(snap, func(s *statsengine.Snapshot) uint64 { return s.TotalSyscalls })), fmt.Sprint(snapValue(snap, func(s *statsengine.Snapshot) uint64 { return s.TotalErrors })), fmt.Sprint(snapValue(snap, func(s *statsengine.Snapshot) uint64 { return s.TotalBytes }))},
		{"summary", "rates_per_sec", fmt.Sprintf("%.2f", snapValueF(snap, func(s *statsengine.Snapshot) float64 { return s.SyscallRatePerSec })), fmt.Sprintf("%.2f", snapValueF(snap, func(s *statsengine.Snapshot) float64 { return s.ReadBytesPerSec })), fmt.Sprintf("%.2f", snapValueF(snap, func(s *statsengine.Snapshot) float64 { return s.WriteBytesPerSec }))},
		{"summary", "latency_gap_mean_ns", fmt.Sprintf("%.2f", snapValueF(snap, func(s *statsengine.Snapshot) float64 { return s.LatencyMeanNs })), fmt.Sprintf("%.2f", snapValueF(snap, func(s *statsengine.Snapshot) float64 { return s.GapMeanNs })), ""},
		{"summary", "trend", trendSummary(snap, func(s *statsengine.Snapshot) statsengine.Trend { return s.LatencyTrend }), trendSummary(snap, func(s *statsengine.Snapshot) statsengine.Trend { return s.GapTrend }), trendSummary(snap, func(s *statsengine.Snapshot) statsengine.Trend { return s.ThroughputTrend })},
	}
	for _, row := range rows {
		if err := w.Write(row); err != nil {
			return "", err
		}
	}

	if snap != nil {
		for _, s := range snap.Syscalls() {
			if err := w.Write([]string{"syscall", s.Name, fmt.Sprint(s.Count), fmt.Sprintf("%.2f", s.RatePerSec), fmt.Sprint(s.Bytes)}); err != nil {
				return "", err
			}
			if err := w.Write([]string{"syscall_latency_ns", s.Name, fmt.Sprintf("%.2f", s.LatencyMeanNs), fmt.Sprint(s.LatencyMinNs), fmt.Sprint(s.LatencyMaxNs)}); err != nil {
				return "", err
			}
			if err := w.Write([]string{"syscall_percentiles_ns", s.Name, fmt.Sprint(s.LatencyP50Ns), fmt.Sprint(s.LatencyP95Ns), fmt.Sprint(s.LatencyP99Ns)}); err != nil {
				return "", err
			}
		}
		for _, r := range snap.Files() {
			if err := w.Write([]string{"file", r.Path, fmt.Sprint(r.Accesses), fmt.Sprint(r.BytesRead), fmt.Sprint(r.BytesWritten)}); err != nil {
				return "", err
			}
			if err := w.Write([]string{"file_latency_ns", r.Path, fmt.Sprintf("%.2f", r.AvgLatencyNs), fmt.Sprint(r.MaxLatencyNs), ""}); err != nil {
				return "", err
			}
		}
		for _, p := range snap.Processes() {
			if err := w.Write([]string{"process", fmt.Sprint(p.PID), fmt.Sprint(p.Syscalls), fmt.Sprintf("%.2f", p.RatePerSec), fmt.Sprint(p.Bytes)}); err != nil {
				return "", err
			}
			if err := w.Write([]string{"process_latency_ns", fmt.Sprint(p.PID), fmt.Sprintf("%.2f", p.AvgLatencyNs), "", ""}); err != nil {
				return "", err
			}
		}
		for _, b := range snap.LatencyHistogram.Buckets() {
			if err := w.Write([]string{"latency_hist", b.Label, fmt.Sprint(b.Count), fmt.Sprint(b.LowerNs), fmt.Sprint(b.UpperNs)}); err != nil {
				return "", err
			}
		}
		for _, b := range snap.GapHistogram.Buckets() {
			if err := w.Write([]string{"gap_hist", b.Label, fmt.Sprint(b.Count), fmt.Sprint(b.LowerNs), fmt.Sprint(b.UpperNs)}); err != nil {
				return "", err
			}
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return "", err
	}
	return filename, nil
}

func snapValue(snap *statsengine.Snapshot, get func(*statsengine.Snapshot) uint64) uint64 {
	if snap == nil {
		return 0
	}
	return get(snap)
}

func snapValueF(snap *statsengine.Snapshot, get func(*statsengine.Snapshot) float64) float64 {
	if snap == nil {
		return 0
	}
	return get(snap)
}

func trendSummary(snap *statsengine.Snapshot, get func(*statsengine.Snapshot) statsengine.Trend) string {
	if snap == nil {
		return "stable:0.00"
	}
	trend := get(snap)
	return fmt.Sprintf("%s:%.2f", trend.Direction, trend.DeltaPercent)
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
	lines = append(lines, "", "Esc/? close")

	boxWidth := width - 6
	if boxWidth > 110 {
		boxWidth = 110
	}
	if boxWidth < 72 {
		boxWidth = 72
	}

	box := PanelStyle.Copy().
		Width(boxWidth).
		Render(strings.Join(lines, "\n"))

	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, box)
}

func placeToViewport(width, height int, content string) string {
	if width <= 0 || height <= 0 {
		return content
	}
	return lipgloss.Place(width, height, lipgloss.Left, lipgloss.Top, content)
}

func altScreenView(content string) tea.View {
	view := tea.NewView(content)
	view.AltScreen = true
	view.ReportFocus = true
	return view
}
