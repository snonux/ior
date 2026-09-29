package dashboard

import (
	"fmt"
	"time"

	tea "charm.land/bubbletea/v2"
)

// autoResetTickMsg fires when the auto-reset timer elapses. It carries the
// generation it was scheduled for so that stale ticks (from a previous
// interval setting, a focus change or a superseded chain) are ignored rather
// than triggering a wrong-cadence reset.
type autoResetTickMsg struct {
	generation uint64
}

// autoResetArmMsg starts a fresh auto-reset tick chain. Init emits it instead
// of scheduling the tick itself. Starting a chain has side effects - it
// restarts the countdown and supersedes the running chain - and Init must be
// free of them. Before this message existed, Init scheduled the tick without
// restarting the countdown, so the chrome counted down from whenever the
// interval was configured (model construction) rather than from the tick Init
// actually scheduled once the trace started. Update handles the message on
// the live model, where the countdown start is recorded together with the
// tick it describes.
type autoResetArmMsg struct {
	generation uint64
}

// autoReset owns the periodic auto-reset timer: its cadence, the generation
// that identifies the live tick chain, and the instant the current countdown
// started. It decides whether a tick is current and what the chrome shows;
// the reset itself stays with the Model (resetBaselineCmd).
type autoReset struct {
	// every is the reset cadence; zero disables the timer.
	every time.Duration
	// gen is bumped whenever a tick chain is superseded - a cadence change,
	// a focus change or a fresh arm - so in-flight ticks of the previous
	// chain are dropped on arrival.
	gen uint64
	// armedAt is the instant the current countdown started. The next reset
	// is expected at armedAt + every; status uses this to render the live
	// countdown ("12s/30s"). The zero value means "not armed".
	armedAt time.Time
	// now is the clock; nil means time.Now. Tests inject a fixed clock.
	now func() time.Time
}

func (a *autoReset) clock() time.Time {
	if a.now == nil {
		return time.Now()
	}
	return a.now()
}

// interval reports the cadence; zero means disabled.
func (a *autoReset) interval() time.Duration {
	return a.every
}

// setInterval reconfigures the cadence (negative clamps to zero, which
// disables the timer), supersedes the live chain and restarts the countdown,
// or clears it when disabling.
func (a *autoReset) setInterval(d time.Duration) {
	if d < 0 {
		d = 0
	}
	a.every = d
	a.gen++
	if d > 0 {
		a.armedAt = a.clock()
	} else {
		a.armedAt = time.Time{}
	}
}

// invalidate supersedes the live chain without touching the cadence, so a
// tick already in flight is dropped when it arrives.
func (a *autoReset) invalidate() {
	a.gen++
}

// restartCountdown stamps the start of a new countdown while the timer is
// enabled; a disabled timer keeps its (zero) countdown.
func (a *autoReset) restartCountdown() {
	if a.every > 0 {
		a.armedAt = a.clock()
	}
}

// running reports whether ticks should be scheduled at all.
func (a *autoReset) running(focused bool) bool {
	return a.every > 0 && focused
}

// isCurrent reports whether a tick or arm message of generation gen belongs
// to the live chain and may act: it must carry the current generation, the
// timer must be enabled and the dashboard focused.
func (a *autoReset) isCurrent(gen uint64, focused bool) bool {
	return gen == a.gen && a.running(focused)
}

// tickCmd schedules the next tick of the live chain after the current
// cadence. It returns nil when the timer is disabled or the dashboard is
// blurred, so callers can compose it without extra branching.
func (a *autoReset) tickCmd(focused bool) tea.Cmd {
	if !a.running(focused) {
		return nil
	}
	gen := a.gen
	return tea.Tick(a.every, func(time.Time) tea.Msg {
		return autoResetTickMsg{generation: gen}
	})
}

// armCmd is Init's side-effect-free way to start a chain: it only reads the
// current generation and emits an autoResetArmMsg for Update to act on
// (see arm). Nil under the same conditions as tickCmd.
func (a *autoReset) armCmd(focused bool) tea.Cmd {
	if !a.running(focused) {
		return nil
	}
	gen := a.gen
	return func() tea.Msg { return autoResetArmMsg{generation: gen} }
}

// arm handles an autoResetArmMsg: a current one supersedes any chain still
// running, restarts the countdown and schedules the first tick; a stale one
// (the cadence or focus changed after Init) is dropped.
func (a *autoReset) arm(gen uint64, focused bool) tea.Cmd {
	if !a.isCurrent(gen, focused) {
		return nil
	}
	a.gen++
	a.restartCountdown()
	return a.tickCmd(focused)
}

// status is the human-readable label for the auto-reset cadence shown in the
// dashboard chrome.
//   - "off" when the timer is disabled.
//   - "<remaining>/<total>" while running and focused, e.g. "12s/30s".
//     The countdown updates on every render (driven by the periodic
//     refresh tick) so users can see when the next reset will fire.
//   - "<total> (paused)" when enabled but the TUI has lost focus, so
//     the user knows the timer will not fire until focus returns.
//
// Disabled timers stay "off" regardless of focus.
func (a *autoReset) status(focused bool) string {
	if a.every <= 0 {
		return "auto-reset: off"
	}
	if !focused {
		return "auto-reset: " + a.every.String() + " (paused)"
	}
	return "auto-reset: " + formatAutoResetRemaining(a.armedAt, a.every, a.clock()) + "/" + a.every.String()
}

// formatAutoResetRemaining renders the time left at now until the next
// scheduled tick as a compact whole-second duration string ("12s",
// "1m23s"). When armedAt is the zero value (not armed yet) or the deadline
// has already elapsed, it returns "0s" so the chrome always shows a value
// rather than an empty placeholder.
func formatAutoResetRemaining(armedAt time.Time, every time.Duration, now time.Time) string {
	if armedAt.IsZero() || every <= 0 {
		return "0s"
	}
	remaining := armedAt.Add(every).Sub(now)
	if remaining < 0 {
		remaining = 0
	}
	seconds := int(remaining.Round(time.Second).Seconds())
	if seconds < 60 {
		return fmt.Sprintf("%ds", seconds)
	}
	minutes := seconds / 60
	secs := seconds % 60
	if secs == 0 {
		return fmt.Sprintf("%dm", minutes)
	}
	return fmt.Sprintf("%dm%ds", minutes, secs)
}

// handleAutoResetTick fires the same reset path as the `r` key (live trie
// + stats engine) and re-arms the timer for the next tick. Stale ticks
// from a previous chain are dropped via the generation counter so that
// changing the interval does not double-fire. While the dashboard is
// blurred the tick is also dropped without re-arming; SetFocused will
// arm a fresh tick on focus regain.
func (m *Model) handleAutoResetTick(msg autoResetTickMsg) (tea.Model, tea.Cmd) {
	if !m.autoReset.isCurrent(msg.generation, m.focused) {
		return m, nil
	}
	m.autoReset.restartCountdown()
	return m, batchCmds(m.resetBaselineCmd(), m.autoReset.tickCmd(m.focused))
}

// handleAutoResetArm starts the chain Init asked for (see autoResetArmMsg).
func (m *Model) handleAutoResetArm(msg autoResetArmMsg) (tea.Model, tea.Cmd) {
	return m, m.autoReset.arm(msg.generation, m.focused)
}

// SetAutoResetInterval reconfigures the auto-reset cadence. A zero or
// negative value disables the timer. Returns a tea.Cmd that arms the new
// timer (or nil when disabling). The generation counter is bumped so any
// in-flight tick scheduled under the previous interval is ignored.
func (m *Model) SetAutoResetInterval(d time.Duration) tea.Cmd {
	m.autoReset.setInterval(d)
	return m.autoReset.tickCmd(m.focused)
}

// AutoResetInterval reports the current auto-reset cadence. Zero means
// the timer is disabled.
func (m *Model) AutoResetInterval() time.Duration {
	return m.autoReset.interval()
}

// AutoResetGeneration identifies the live auto-reset tick chain; it changes
// whenever that chain is superseded (a cadence or focus change, or an arm
// from Init being handled). It exists so the parent package can assert that
// Init's arm message reached the dashboard through its routing, without
// running the program.
func (m *Model) AutoResetGeneration() uint64 {
	return m.autoReset.gen
}

// SetFocused controls whether periodic refresh ticks are processed and
// returns a tea.Cmd that arms a fresh auto-reset tick when focus returns
// (or nil otherwise). The auto-reset generation counter is bumped on
// every focus change so any in-flight tick scheduled before a blur is
// dropped when it eventually arrives — the tick payload's generation
// will no longer match. Without bumping, a tick that was already in
// flight when blur occurred could fire moments after the user re-focuses
// and surprise them with a reset.
func (m *Model) SetFocused(focused bool) tea.Cmd {
	if m.focused == focused {
		return nil
	}
	m.focused = focused
	m.autoReset.invalidate()
	if !focused {
		return nil
	}
	m.autoReset.restartCountdown()
	return m.autoReset.tickCmd(m.focused)
}

// autoResetStatus is the chrome label for the auto-reset timer; see
// autoReset.status.
func (m *Model) autoResetStatus() string {
	return m.autoReset.status(m.focused)
}
