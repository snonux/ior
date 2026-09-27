package dashboard

import (
	"time"

	tea "charm.land/bubbletea/v2"
)

const defaultRefreshMs = 1000
const streamRefreshMs = 200
const flameRefreshMs = 200
const bubbleRefreshMs = 33

// The periodic tick chains the dashboard runs. Each handler re-arms its own
// chain while the chain is still wanted (focused, right tab, something to
// animate) and lets it die otherwise; tab entry, Init and focus regain start
// a chain again. The auto-reset chain lives in autoreset.go because it
// carries a generation and a countdown.
type refreshTickMsg struct{}
type streamTickMsg struct{}
type flameTickMsg struct{}
type bubbleTickMsg struct{}

// tickScheduler owns the cadences of the dashboard's periodic tick chains and
// builds the commands that schedule them. It holds no model state beyond the
// cadences, so which chain runs when stays with the Model's tick handlers.
type tickScheduler struct {
	// refreshEvery is the stats refresh cadence (always positive).
	refreshEvery time.Duration
	// fastRefreshEvery is the high-frequency tick cadence for the stream and
	// flame tabs. When zero it falls back to the streamRefreshMs /
	// flameRefreshMs package-level constants so the model is
	// backwards-compatible with callers that do not supply a fast-refresh
	// interval.
	fastRefreshEvery time.Duration
}

// newTickScheduler builds the cadences from the constructor's millisecond
// arguments. A non-positive refreshMs falls back to defaultRefreshMs; a zero
// fastRefreshMs selects the per-tab constant fallback.
func newTickScheduler(refreshMs, fastRefreshMs int) tickScheduler {
	if refreshMs <= 0 {
		refreshMs = defaultRefreshMs
	}
	return tickScheduler{
		refreshEvery:     time.Duration(refreshMs) * time.Millisecond,
		fastRefreshEvery: time.Duration(fastRefreshMs) * time.Millisecond,
	}
}

// setFastInterval overrides the stream/flame cadence; a zero or negative
// value restores the constant fallback.
func (s *tickScheduler) setFastInterval(d time.Duration) {
	if d < 0 {
		d = 0
	}
	s.fastRefreshEvery = d
}

// streamInterval is the effective stream tab cadence.
func (s *tickScheduler) streamInterval() time.Duration {
	return fastOr(s.fastRefreshEvery, streamRefreshMs*time.Millisecond)
}

// flameInterval is the effective flame tab cadence.
func (s *tickScheduler) flameInterval() time.Duration {
	return fastOr(s.fastRefreshEvery, flameRefreshMs*time.Millisecond)
}

func fastOr(configured, fallback time.Duration) time.Duration {
	if configured <= 0 {
		return fallback
	}
	return configured
}

// refreshCmd schedules the next stats refresh tick.
func (s *tickScheduler) refreshCmd() tea.Cmd {
	return tea.Tick(s.refreshEvery, func(time.Time) tea.Msg { return refreshTickMsg{} })
}

// streamCmd schedules the next high-frequency stream tab refresh tick.
func (s *tickScheduler) streamCmd() tea.Cmd {
	return tea.Tick(s.streamInterval(), func(time.Time) tea.Msg { return streamTickMsg{} })
}

// flameCmd schedules the next high-frequency flame tab refresh tick.
func (s *tickScheduler) flameCmd() tea.Cmd {
	return tea.Tick(s.flameInterval(), func(time.Time) tea.Msg { return flameTickMsg{} })
}

// bubbleCmd schedules the next bubble-chart animation frame. Its cadence is
// fixed, so it needs no scheduler state; it is a method so every tick chain
// is started through the same collaborator.
func (s *tickScheduler) bubbleCmd() tea.Cmd {
	return tea.Tick(bubbleRefreshMs*time.Millisecond, func(time.Time) tea.Msg { return bubbleTickMsg{} })
}

// tabEntryTickCmd starts the tick chain tab needs while it is active: the
// tab's own InitCmd (the stream and flame fast ticks) or, failing that, the
// bubble animation when the tab shows a bubble chart. It is shared by Init
// and by the tab-switch path so both start the same chain.
func (m *Model) tabEntryTickCmd(tab Tab) tea.Cmd {
	if d := lookupTab(tab); d.InitCmd != nil {
		// Pass the model so the closure reads the configured fast cadence
		// rather than falling back to a constant.
		return d.InitCmd(m)
	}
	if m.bubbleEnabledForTab(tab) {
		return m.ticks.bubbleCmd()
	}
	return nil
}

func (m *Model) handleRefreshTick() (tea.Model, tea.Cmd) {
	if !m.focused {
		return m, nil
	}
	tick := m.statsTick()
	return m, tea.Batch(
		m.ticks.refreshCmd(),
		func() tea.Msg { return tick },
	)
}

func (m *Model) handleStreamTick() (tea.Model, tea.Cmd) {
	if !m.focused || m.activeTab != TabStream {
		return m, nil
	}
	m.streamModel.Refresh()
	// Re-arm with the configurable fast-refresh cadence.
	return m, m.ticks.streamCmd()
}

func (m *Model) handleFlameTick() (tea.Model, tea.Cmd) {
	if !m.focused || m.activeTab != TabFlame {
		return m, nil
	}
	// Always re-arm the fast tick. The snapshot refresh itself runs on a
	// background goroutine via RefreshFromLiveTrieCmd, so even when a previous
	// refresh is still in flight (the cmd returns nil and skips), the tick
	// channel stays alive. The cadence is controlled by fastRefreshEvery.
	cmds := []tea.Cmd{m.ticks.flameCmd()}
	if m.liveTrie != nil {
		if refreshCmd := m.flamegraphModel.RefreshFromLiveTrieCmd(); refreshCmd != nil {
			cmds = append(cmds, refreshCmd)
		}
	}
	return m, tea.Batch(cmds...)
}

func (m *Model) handleBubbleTick() (tea.Model, tea.Cmd) {
	if !m.focused || !m.bubbleEnabledForTab(m.activeTab) {
		return m, nil
	}
	_ = m.tickActiveBubbleChart()
	if m.activeBubbleChartHasNodes() {
		return m, m.ticks.bubbleCmd()
	}
	return m, nil
}

// FastRefreshInterval reports the high-frequency tick cadence for the stream
// and flame tabs (0 when the built-in default applies). It exists so the
// parent package can assert its startup wiring without running the program.
func (m *Model) FastRefreshInterval() time.Duration {
	return m.ticks.fastRefreshEvery
}

// SetFastRefreshInterval overrides the high-frequency tick cadence used by the
// stream and flame tabs. A zero or negative value resets the behaviour to the
// package-level constants. Callers use this to apply -tui-fast-refresh after
// constructing the dashboard model.
func (m *Model) SetFastRefreshInterval(d time.Duration) {
	m.ticks.setFastInterval(d)
}
