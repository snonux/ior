package tui

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"ior/internal/flags"
	"ior/internal/statsengine"
	common "ior/internal/tui/common"
	dashboardui "ior/internal/tui/dashboard"
	"ior/internal/tui/eventstream"
	tuiexport "ior/internal/tui/export"
	"ior/internal/tui/pidpicker"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
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

type snapshotSource interface {
	Snapshot() *statsengine.Snapshot
}

var dashboardSourceState struct {
	mu     sync.RWMutex
	source snapshotSource
}

var eventStreamSourceState struct {
	mu     sync.RWMutex
	source *eventstream.RingBuffer
}

// SetDashboardSnapshotSource sets the snapshot source used by dashboard mode.
func SetDashboardSnapshotSource(source snapshotSource) {
	dashboardSourceState.mu.Lock()
	dashboardSourceState.source = source
	dashboardSourceState.mu.Unlock()
}

// SetEventStreamSource sets the event stream source used by dashboard mode.
func SetEventStreamSource(source *eventstream.RingBuffer) {
	eventStreamSourceState.mu.Lock()
	eventStreamSourceState.source = source
	eventStreamSourceState.mu.Unlock()
}

func getDashboardSnapshotSource() snapshotSource {
	dashboardSourceState.mu.RLock()
	defer dashboardSourceState.mu.RUnlock()
	return dashboardSourceState.source
}

func getEventStreamSource() *eventstream.RingBuffer {
	eventStreamSourceState.mu.RLock()
	defer eventStreamSourceState.mu.RUnlock()
	return eventStreamSourceState.source
}

// Run starts the TUI program in alternate screen mode.
func Run() error {
	return RunWithTraceStarter(defaultTraceStarter)
}

// RunWithTraceStarter starts the TUI program with a custom trace starter.
func RunWithTraceStarter(starter TraceStarter) error {
	model := NewModel(flags.Get().PidFilter, starter)
	program := tea.NewProgram(model, tea.WithAltScreen())
	_, err := program.Run()
	return err
}

// Model is the top-level Bubble Tea model that routes between PID picker and dashboard.
type Model struct {
	screen    Screen
	pidPicker pidpicker.Model
	dashboard dashboardui.Model
	exporter  tuiexport.Model

	keys KeyMap

	width    int
	height   int
	quitting bool

	attaching bool
	spin      spinner.Model
	lastErr   error
	showHelp  bool

	startTrace TraceStarter
	traceStop  context.CancelFunc
}

// NewModel creates the top-level TUI model.
func NewModel(initialPID int, startTrace TraceStarter) Model {
	spin := spinner.New()
	spin.Spinner = spinner.MiniDot
	if startTrace == nil {
		startTrace = defaultTraceStarter
	}
	keys := Keys
	if !flags.Get().TUIExportEnable {
		keys.Export = key.NewBinding()
	}

	model := Model{
		screen:     ScreenPIDPicker,
		pidPicker:  pidpicker.New(),
		dashboard:  dashboardui.NewModelWithConfig(lateBoundDashboardSource{}, getEventStreamSource(), 1000, keys),
		exporter:   tuiexport.NewModel(),
		keys:       keys,
		spin:       spin,
		startTrace: startTrace,
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
		return tea.Batch(sizeCmd, tea.WindowSize(), m.spin.Tick, m.beginTraceCmd())
	}
	return tea.Batch(sizeCmd, tea.WindowSize(), m.pidPicker.Init())
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
	case tea.KeyMsg:
		if key.Matches(msg, m.keys.Quit) {
			m.quitting = true
			m.stopTrace()
			return m, tea.Quit
		}
		if !m.exporter.Visible() && key.Matches(msg, m.keys.Help) {
			m.showHelp = !m.showHelp
			return m, nil
		}
		if !m.exporter.Visible() && m.showHelp && key.Matches(msg, m.keys.Esc) {
			m.showHelp = false
			return m, nil
		}
		if !m.exporter.Visible() && m.showHelp {
			return m, nil
		}
		if flags.Get().TUIExportEnable && m.screen == ScreenDashboard && !m.attaching && m.lastErr == nil && key.Matches(msg, m.keys.Export) && !m.exporter.Visible() && !m.dashboard.BlocksGlobalShortcuts() {
			m.exporter = m.exporter.Open()
			return m, nil
		}
	case tuiexport.RequestMsg:
		return m, runExportCmd(msg.Option, m.dashboard.LatestSnapshot())
	case tuiexport.CompletedMsg:
		var cmd tea.Cmd
		m.exporter, cmd = m.exporter.Update(msg)
		return m, cmd
	case tuiexport.FailedMsg:
		var cmd tea.Cmd
		m.exporter, cmd = m.exporter.Update(msg)
		return m, cmd
	case PidSelectedMsg:
		return m.handlePidSelected(msg)
	case TracingStartedMsg:
		m.attaching = false
		m.dashboard.SetStreamSource(getEventStreamSource())
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
	if m.exporter.Visible() {
		var dashboardCmd tea.Cmd
		// Keep dashboard refresh/data flow alive while export modal is open.
		if _, isKey := msg.(tea.KeyMsg); !isKey && m.screen == ScreenDashboard {
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
	m.screen = ScreenDashboard
	m.attaching = true
	m.lastErr = nil
	return m, tea.Batch(m.spin.Tick, m.beginTraceCmd())
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

// View renders the currently active screen and startup overlay state.
func (m Model) View() string {
	if m.quitting {
		return ""
	}

	width, height := common.EffectiveViewport(m.width, m.height)

	if m.attaching {
		line := fmt.Sprintf("%s Attaching tracepoints...", m.spin.View())
		return placeToViewport(width, height, ScreenStyle.Render(PanelStyle.Render(line)))
	}

	if m.lastErr != nil {
		return placeToViewport(width, height, ScreenStyle.Render(ErrorStyle.Render(m.lastErr.Error())))
	}

	switch m.screen {
	case ScreenPIDPicker:
		base := m.pidPicker.View()
		if m.exporter.Visible() {
			return placeToViewport(width, height, m.exporter.View(width, height)+"\n"+base)
		}
		if m.showHelp {
			return placeToViewport(width, height, renderHelpOverlay(width, height, [][]key.Binding{m.keys.PickerShortHelp()})+"\n"+base)
		}
		return placeToViewport(width, height, base)
	case ScreenDashboard:
		base := m.dashboard.View()
		if m.exporter.Visible() {
			return placeToViewport(width, height, m.exporter.View(width, height)+"\n"+base)
		}
		if m.showHelp {
			return placeToViewport(width, height, renderHelpOverlay(width, height, m.keys.DashboardFullHelp())+"\n"+base)
		}
		return placeToViewport(width, height, base)
	default:
		return ""
	}
}

func runExportCmd(option tuiexport.Option, snap *statsengine.Snapshot) tea.Cmd {
	return func() tea.Msg {
		if !flags.Get().TUIExportEnable {
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

type lateBoundDashboardSource struct{}

func (lateBoundDashboardSource) Snapshot() *statsengine.Snapshot {
	source := getDashboardSnapshotSource()
	if source == nil {
		return nil
	}
	return source.Snapshot()
}

type lateBoundEventStreamSource struct{}

func (lateBoundEventStreamSource) Source() *eventstream.RingBuffer {
	return getEventStreamSource()
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

	box := PanelStyle.Copy().
		Width(72).
		Render(strings.Join(lines, "\n"))

	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, box)
}

func placeToViewport(width, height int, content string) string {
	if width <= 0 || height <= 0 {
		return content
	}
	return lipgloss.Place(width, height, lipgloss.Left, lipgloss.Top, content)
}
