package tui

import (
	"context"
	"errors"
	"fmt"
	"ior/internal/flags"
	"ior/internal/statsengine"
	"ior/internal/tui/pidpicker"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
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

type dashboardTickMsg struct{}

var dashboardSourceState struct {
	mu     sync.RWMutex
	source snapshotSource
}

// SetDashboardSnapshotSource sets the snapshot source used by dashboard mode.
func SetDashboardSnapshotSource(source snapshotSource) {
	dashboardSourceState.mu.Lock()
	dashboardSourceState.source = source
	dashboardSourceState.mu.Unlock()
}

func getDashboardSnapshotSource() snapshotSource {
	dashboardSourceState.mu.RLock()
	defer dashboardSourceState.mu.RUnlock()
	return dashboardSourceState.source
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
	dashboard dashboardModel

	keys KeyMap

	width    int
	height   int
	quitting bool

	attaching bool
	spin      spinner.Model
	lastErr   error

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

	model := Model{
		screen:     ScreenPIDPicker,
		pidPicker:  pidpicker.New(),
		dashboard:  newDashboardModel(getDashboardSnapshotSource()),
		keys:       Keys,
		spin:       spin,
		startTrace: startTrace,
	}

	if initialPID > 0 {
		flags.SetPidFilter(initialPID)
		model.dashboard.selectedPID = initialPID
		model.screen = ScreenDashboard
		model.attaching = true
	}

	return model
}

// Init initializes the active child model and optional tracing startup command.
func (m Model) Init() tea.Cmd {
	if m.screen == ScreenDashboard && m.attaching {
		return tea.Batch(m.spin.Tick, m.beginTraceCmd())
	}
	return m.pidPicker.Init()
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
	case PidSelectedMsg:
		return m.handlePidSelected(msg)
	case TracingStartedMsg:
		m.attaching = false
		return m, dashboardTickCmd()
	case TracingErrorMsg:
		m.attaching = false
		m.lastErr = msg.Err
		return m, nil
	case dashboardTickMsg:
		m.dashboard.refresh()
		return m, dashboardTickCmd()
	}

	if m.attaching {
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return m, cmd
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
		m.dashboard = next.(dashboardModel)
		return m, cmd
	default:
		return m, nil
	}
}

func (m Model) handlePidSelected(msg PidSelectedMsg) (tea.Model, tea.Cmd) {
	pid := selectedPIDFilter(msg.Pid)
	m.stopTrace()
	flags.SetPidFilter(pid)
	m.dashboard.selectedPID = pid
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

	if m.attaching {
		line := fmt.Sprintf("%s Attaching tracepoints...", m.spin.View())
		return ScreenStyle.Render(PanelStyle.Render(line))
	}

	if m.lastErr != nil {
		return ScreenStyle.Render(ErrorStyle.Render(m.lastErr.Error()))
	}

	switch m.screen {
	case ScreenPIDPicker:
		return m.pidPicker.View()
	case ScreenDashboard:
		return m.dashboard.View()
	default:
		return ""
	}
}

type dashboardModel struct {
	selectedPID int
	source      snapshotSource
	latest      *statsengine.Snapshot
}

func newDashboardModel(source snapshotSource) dashboardModel {
	return dashboardModel{
		selectedPID: -1,
		source:      source,
	}
}

func (d dashboardModel) Init() tea.Cmd {
	return nil
}

func (d dashboardModel) Update(tea.Msg) (tea.Model, tea.Cmd) {
	return d, nil
}

func (d dashboardModel) View() string {
	if d.latest != nil {
		return PanelStyle.Render(
			fmt.Sprintf("Dashboard (%d syscalls, %.1f/s)", d.latest.TotalSyscalls, d.latest.SyscallRatePerSec),
		)
	}
	if d.selectedPID > 0 {
		return PanelStyle.Render(fmt.Sprintf("Dashboard (PID %d)", d.selectedPID))
	}
	return PanelStyle.Render("Dashboard (All PIDs)")
}

func (d *dashboardModel) refresh() {
	if source := getDashboardSnapshotSource(); source != nil {
		d.source = source
	}
	if d.source == nil {
		return
	}
	d.latest = d.source.Snapshot()
}

func dashboardTickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(time.Time) tea.Msg { return dashboardTickMsg{} })
}
