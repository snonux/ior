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
// animate) and lets it die otherwise; tab entry, Init (through
// tickChainsStartMsg) and focus regain start a chain again. Every tick
// carries the generation of the chain that scheduled it: starting a chain
// bumps the generation, so a chain that is still in flight when a new one
// starts is dropped on its next tick instead of running alongside it. The
// auto-reset chain lives in autoreset.go because it also carries a
// countdown.
type refreshTickMsg struct{ generation uint64 }
type streamTickMsg struct{ generation uint64 }
type flameTickMsg struct{ generation uint64 }
type bubbleTickMsg struct{ generation uint64 }

// tickChainsStartMsg starts the refresh chain and the active tab's chain.
// Init emits it instead of scheduling those ticks itself: starting a chain
// supersedes the previous one by bumping its generation, and Init must stay
// free of side effects. Handling it always supersedes, so two Inits in a row
// (a focus regain followed by a trace start, say) leave one chain of each
// kind rather than two.
type tickChainsStartMsg struct{}

// tickChain is the generation of one tick chain. A tick is current only
// while it carries the generation the chain had when it was scheduled.
type tickChain struct{ gen uint64 }

// restart supersedes the running chain and returns the new generation.
func (c *tickChain) restart() uint64 {
	c.gen++
	return c.gen
}

// isCurrent reports whether a tick of generation gen belongs to the live
// chain.
func (c *tickChain) isCurrent(gen uint64) bool {
	return gen == c.gen
}

// tickScheduler owns the cadences and generations of the dashboard's
// periodic tick chains and builds the commands that schedule them. The
// "...Cmd" methods re-arm the live chain; the "start..." methods supersede it
// and begin a new one. When each chain should run stays with the Model's
// tick handlers and chain-start paths.
type tickScheduler struct {
	// refreshEvery is the stats refresh cadence (always positive).
	refreshEvery time.Duration
	// fastRefreshEvery is the high-frequency tick cadence for the stream and
	// flame tabs. When zero it falls back to the streamRefreshMs /
	// flameRefreshMs package-level constants so the model is
	// backwards-compatible with callers that do not supply a fast-refresh
	// interval.
	fastRefreshEvery time.Duration
	// refresh, fast and bubble are the generations of the stats refresh
	// chain, the stream/flame fast chain (only one of the two tabs is
	// active at a time, so they share a chain) and the bubble animation
	// chain.
	refresh tickChain
	fast    tickChain
	bubble  tickChain
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

// refreshCmd re-arms the stats refresh chain.
func (s *tickScheduler) refreshCmd() tea.Cmd {
	gen := s.refresh.gen
	return tea.Tick(s.refreshEvery, func(time.Time) tea.Msg { return refreshTickMsg{generation: gen} })
}

// streamCmd re-arms the fast chain on the stream tab's cadence.
func (s *tickScheduler) streamCmd() tea.Cmd {
	gen := s.fast.gen
	return tea.Tick(s.streamInterval(), func(time.Time) tea.Msg { return streamTickMsg{generation: gen} })
}

// flameCmd re-arms the fast chain on the flame tab's cadence.
func (s *tickScheduler) flameCmd() tea.Cmd {
	gen := s.fast.gen
	return tea.Tick(s.flameInterval(), func(time.Time) tea.Msg { return flameTickMsg{generation: gen} })
}

// bubbleCmd re-arms the bubble animation chain; its cadence is fixed.
func (s *tickScheduler) bubbleCmd() tea.Cmd {
	gen := s.bubble.gen
	return tea.Tick(bubbleRefreshMs*time.Millisecond, func(time.Time) tea.Msg { return bubbleTickMsg{generation: gen} })
}

// startStream supersedes the fast chain and starts it on the stream cadence.
func (s *tickScheduler) startStream() tea.Cmd {
	s.fast.restart()
	return s.streamCmd()
}

// startFlame supersedes the fast chain and starts it on the flame cadence.
func (s *tickScheduler) startFlame() tea.Cmd {
	s.fast.restart()
	return s.flameCmd()
}

// startBubble supersedes the bubble chain and schedules its first frame.
func (s *tickScheduler) startBubble() tea.Cmd {
	s.bubble.restart()
	return s.bubbleCmd()
}

// tabEntryTickCmd starts the tick chain tab needs while it is active: the
// tab's own InitCmd (the stream and flame fast chain) or, failing that, the
// bubble animation when the tab shows a bubble chart. It is shared by the
// chain start Init requests and by the tab-switch path so both start the
// same chain; starting supersedes the chain already running.
func (m *Model) tabEntryTickCmd(tab Tab) tea.Cmd {
	if d := lookupTab(tab); d.InitCmd != nil {
		// Pass the model so the closure reads the configured fast cadence
		// rather than falling back to a constant.
		return d.InitCmd(m)
	}
	if m.bubbleEnabledForTab(tab) {
		return m.ticks.startBubble()
	}
	return nil
}

// tickChainsStartCmd is Init's side-effect-free request to start the
// refresh chain and the active tab's chain (see tickChainsStartMsg).
func tickChainsStartCmd() tea.Cmd {
	return func() tea.Msg { return tickChainsStartMsg{} }
}

// handleTickChainsStart supersedes every chain Init starts and, while
// focused, schedules the first tick of each. A blurred dashboard starts
// nothing: its handlers would drop the ticks anyway, and focus regain asks
// for a fresh start.
func (m *Model) handleTickChainsStart() (tea.Model, tea.Cmd) {
	m.ticks.refresh.restart()
	m.ticks.fast.restart()
	m.ticks.bubble.restart()
	if !m.focused {
		return m, nil
	}
	return m, batchCmds(m.ticks.refreshCmd(), m.tabEntryTickCmd(m.activeTab))
}

func (m *Model) handleRefreshTick(msg refreshTickMsg) (tea.Model, tea.Cmd) {
	if !m.focused || !m.ticks.refresh.isCurrent(msg.generation) {
		return m, nil
	}
	// The snapshot is built by a command, not here: Update runs on the UI
	// goroutine and a build with stale percentile reservoirs takes up to
	// ~22ms (statstick.go). refreshStatsCmd is nil while the previous build
	// is still running; tea.Batch drops nil commands.
	return m, tea.Batch(m.ticks.refreshCmd(), m.refreshStatsCmd())
}

func (m *Model) handleStreamTick(msg streamTickMsg) (tea.Model, tea.Cmd) {
	if !m.focused || m.activeTab != TabStream || !m.ticks.fast.isCurrent(msg.generation) {
		return m, nil
	}
	m.streamModel.Refresh()
	// Re-arm with the configurable fast-refresh cadence.
	return m, m.ticks.streamCmd()
}

func (m *Model) handleFlameTick(msg flameTickMsg) (tea.Model, tea.Cmd) {
	if !m.focused || m.activeTab != TabFlame || !m.ticks.fast.isCurrent(msg.generation) {
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

// handleBubbleTick advances the active bubble chart one frame and re-arms the
// chain only while the chart is still animating. Once the springs have settled
// and the drift wobble has faded (bubbleChart.Tick returns false) the chain
// ends: an idle chart costs nothing, where re-arming for as long as there were
// nodes kept a 30fps tick + full re-render alive forever. New data restarts
// the chain (refreshBubbleData -> startBubble), as do tab entry, a resize, the
// v and b keys and focus regain (AGENTS.md lists the triggers). A workload
// that changes the bubbles on every stats tick keeps the chain alive, since
// each real change restarts the drift window.
func (m *Model) handleBubbleTick(msg bubbleTickMsg) (tea.Model, tea.Cmd) {
	if !m.focused || !m.bubbleEnabledForTab(m.activeTab) || !m.ticks.bubble.isCurrent(msg.generation) {
		return m, nil
	}
	if m.tickActiveBubbleChart() {
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
