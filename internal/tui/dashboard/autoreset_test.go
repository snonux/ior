package dashboard

import (
	"testing"
	"time"

	common "ior/internal/tui/common"

	tea "charm.land/bubbletea/v2"
)

// fakeClock is a settable clock for the autoReset countdown.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)}
}

// runCmd executes cmd and returns its message, or nil for a nil command.
func runCmd(cmd tea.Cmd) tea.Msg {
	if cmd == nil {
		return nil
	}
	return cmd()
}

func TestAutoResetSetIntervalArmsAndBumpsGeneration(t *testing.T) {
	clock := newFakeClock()
	a := autoReset{now: clock.now}

	a.setInterval(30 * time.Second)
	if a.interval() != 30*time.Second {
		t.Fatalf("interval = %v, want 30s", a.interval())
	}
	if a.gen != 1 {
		t.Fatalf("gen = %d, want 1 after the first setInterval", a.gen)
	}
	if !a.armedAt.Equal(clock.t) {
		t.Fatalf("armedAt = %v, want the clock's %v", a.armedAt, clock.t)
	}
	if a.tickCmd(true) == nil {
		t.Fatal("an enabled, focused timer must schedule a tick")
	}
}

func TestAutoResetZeroAndNegativeIntervalDisable(t *testing.T) {
	for _, d := range []time.Duration{0, -5 * time.Second} {
		t.Run(d.String(), func(t *testing.T) {
			clock := newFakeClock()
			a := autoReset{now: clock.now}
			a.setInterval(30 * time.Second)
			gen := a.gen

			a.setInterval(d)
			if a.interval() != 0 {
				t.Fatalf("interval = %v, want 0 (disabled)", a.interval())
			}
			if a.gen == gen {
				t.Fatal("disabling must still supersede the running chain")
			}
			if !a.armedAt.IsZero() {
				t.Fatalf("armedAt = %v, want zero once disabled", a.armedAt)
			}
			if a.tickCmd(true) != nil || a.armCmd(true) != nil {
				t.Fatal("a disabled timer must neither tick nor arm")
			}
			if a.isCurrent(a.gen, true) {
				t.Fatal("no generation is current while the timer is disabled")
			}
			if got := a.status(true); got != "auto-reset: off" {
				t.Fatalf("status = %q, want auto-reset: off", got)
			}
			a.restartCountdown()
			if !a.armedAt.IsZero() {
				t.Fatal("restartCountdown must not arm a disabled timer")
			}
		})
	}
}

func TestAutoResetIsCurrentRejectsStaleBlurredAndDisabled(t *testing.T) {
	a := autoReset{now: newFakeClock().now}
	a.setInterval(time.Second)
	stale := a.gen
	a.invalidate()

	if a.isCurrent(stale, true) {
		t.Fatal("a tick of a superseded generation must be dropped")
	}
	if !a.isCurrent(a.gen, true) {
		t.Fatal("a tick of the live generation must act while focused")
	}
	if a.isCurrent(a.gen, false) {
		t.Fatal("no tick may act while blurred")
	}
	if a.tickCmd(false) != nil || a.armCmd(false) != nil {
		t.Fatal("a blurred timer must neither tick nor arm")
	}
}

func TestAutoResetTickCmdCarriesScheduledGeneration(t *testing.T) {
	a := autoReset{now: newFakeClock().now}
	a.setInterval(time.Millisecond)
	cmd := a.tickCmd(true)
	gen := a.gen
	// A generation bump after scheduling must not leak into the payload:
	// the in-flight tick has to identify the chain it was scheduled for.
	a.invalidate()
	msg, ok := runCmd(cmd).(autoResetTickMsg)
	if !ok {
		t.Fatalf("tickCmd produced %T, want autoResetTickMsg", runCmd(cmd))
	}
	if msg.generation != gen {
		t.Fatalf("tick generation = %d, want the scheduled %d", msg.generation, gen)
	}
	if a.isCurrent(msg.generation, true) {
		t.Fatal("the pre-bump tick must be stale")
	}
}

// TestAutoResetArmSupersedesRunningChain pins what arm does with a current
// arm message: restart the countdown at the arm instant and start a new
// chain, so a tick of the chain that was running before is dropped.
func TestAutoResetArmSupersedesRunningChain(t *testing.T) {
	clock := newFakeClock()
	a := autoReset{now: clock.now}
	a.setInterval(30 * time.Second)
	armMsg, ok := runCmd(a.armCmd(true)).(autoResetArmMsg)
	if !ok {
		t.Fatal("armCmd must emit an autoResetArmMsg")
	}
	oldGen := a.gen

	clock.advance(20 * time.Second)
	next := a.arm(armMsg.generation, true)
	if next == nil {
		t.Fatal("a current arm must schedule the first tick")
	}
	if a.gen == oldGen {
		t.Fatal("arm must start a new generation")
	}
	if a.isCurrent(oldGen, true) {
		t.Fatal("ticks of the chain running before the arm must be dropped")
	}
	if !a.armedAt.Equal(clock.t) {
		t.Fatalf("armedAt = %v, want the arm instant %v", a.armedAt, clock.t)
	}
	if got := a.status(true); got != "auto-reset: 30s/30s" {
		t.Fatalf("status right after arm = %q, want the full countdown", got)
	}
}

// TestAutoResetArmDroppedWhenSupersededBeforeArming covers the window between
// Init emitting its arm message and Update handling it: a cadence change, a
// disable or a blur in that window must win, and the late arm must neither
// schedule a tick nor touch the countdown.
func TestAutoResetArmDroppedWhenSupersededBeforeArming(t *testing.T) {
	cases := []struct {
		name    string
		change  func(a *autoReset)
		focused bool
	}{
		{"interval changed", func(a *autoReset) { a.setInterval(time.Minute) }, true},
		{"disabled", func(a *autoReset) { a.setInterval(0) }, true},
		{"focus changed", func(a *autoReset) { a.invalidate() }, true},
		{"blurred", func(*autoReset) {}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clock := newFakeClock()
			a := autoReset{now: clock.now}
			a.setInterval(30 * time.Second)
			armMsg := runCmd(a.armCmd(true)).(autoResetArmMsg)
			tc.change(&a)
			gen, armedAt := a.gen, a.armedAt

			clock.advance(5 * time.Second)
			if cmd := a.arm(armMsg.generation, tc.focused); cmd != nil {
				t.Fatal("a superseded arm must not schedule a tick")
			}
			if a.gen != gen || !a.armedAt.Equal(armedAt) {
				t.Fatalf("a dropped arm changed state: gen %d->%d, armedAt %v->%v", gen, a.gen, armedAt, a.armedAt)
			}
		})
	}
}

func TestAutoResetStatusCountsDownFromArmedAt(t *testing.T) {
	clock := newFakeClock()
	a := autoReset{now: clock.now}
	a.setInterval(30 * time.Second)

	clock.advance(12 * time.Second)
	if got := a.status(true); got != "auto-reset: 18s/30s" {
		t.Fatalf("status = %q, want auto-reset: 18s/30s", got)
	}
	clock.advance(time.Minute)
	if got := a.status(true); got != "auto-reset: 0s/30s" {
		t.Fatalf("overdue status = %q, want auto-reset: 0s/30s", got)
	}
	if got := a.status(false); got != "auto-reset: 30s (paused)" {
		t.Fatalf("blurred status = %q, want auto-reset: 30s (paused)", got)
	}
	// A timer that is enabled but never armed shows 0s rather than a
	// countdown from the zero time.
	unarmed := autoReset{every: 30 * time.Second, now: clock.now}
	if got := unarmed.status(true); got != "auto-reset: 0s/30s" {
		t.Fatalf("unarmed status = %q, want auto-reset: 0s/30s", got)
	}
}

func TestAutoResetNilClockFallsBackToWallClock(t *testing.T) {
	var a autoReset
	before := time.Now()
	a.setInterval(time.Second)
	if a.armedAt.Before(before) || a.armedAt.After(time.Now()) {
		t.Fatalf("armedAt = %v, want the wall clock", a.armedAt)
	}
}

// TestInitDoesNotArmAutoReset pins that Init is side-effect free: it leaves
// the generation and the countdown alone and only emits the arm message,
// which Update turns into the chain whose countdown the chrome shows. This
// is the regression for the countdown drifting from the real tick: the
// interval is configured at construction, Init runs only once the trace has
// started, and the countdown has to start with the tick Init schedules.
func TestInitDoesNotArmAutoReset(t *testing.T) {
	clock := newFakeClock()
	engine := &fakeSnapshotSource{}
	m := NewModelWithConfig(engine, nil, 250, 200, common.DefaultKeyMap())
	m.autoReset.now = clock.now
	constructionTick := m.SetAutoResetInterval(30 * time.Second)
	if constructionTick == nil {
		t.Fatal("SetAutoResetInterval must return a tick for a positive interval")
	}
	constructionGen := m.autoReset.gen
	constructedAt := m.autoReset.armedAt

	clock.advance(20 * time.Second)
	batch, ok := runCmd(m.Init()).(tea.BatchMsg)
	if !ok || len(batch) == 0 {
		t.Fatal("Init must batch its ticks")
	}
	if m.autoReset.gen != constructionGen || !m.autoReset.armedAt.Equal(constructedAt) {
		t.Fatal("Init mutated the auto-reset state")
	}
	armMsg, ok := runCmd(batch[len(batch)-1]).(autoResetArmMsg)
	if !ok {
		t.Fatalf("Init's last command must be the auto-reset arm, got %T", runCmd(batch[len(batch)-1]))
	}

	next, cmd := m.Update(armMsg)
	m = next.(*Model)
	if cmd == nil {
		t.Fatal("handling the arm must schedule the first auto-reset tick")
	}
	if !m.autoReset.armedAt.Equal(clock.t) {
		t.Fatalf("armedAt = %v, want the arm instant %v", m.autoReset.armedAt, clock.t)
	}
	if got := m.autoResetStatus(); got != "auto-reset: 30s/30s" {
		t.Fatalf("status after arm = %q, want the full countdown", got)
	}

	// The construction-time tick was superseded by the arm: it must not
	// reset the engine when it arrives.
	next, cmd = m.Update(autoResetTickMsg{generation: constructionGen})
	m = next.(*Model)
	if cmd != nil || engine.resetCount != 0 {
		t.Fatalf("superseded tick acted: cmd=%v resetCount=%d", cmd, engine.resetCount)
	}

	// The live chain's tick resets and re-arms at the same generation.
	gen := m.autoReset.gen
	clock.advance(30 * time.Second)
	next, cmd = m.Update(autoResetTickMsg{generation: gen})
	m = next.(*Model)
	if cmd == nil || engine.resetCount != 1 {
		t.Fatalf("live tick: cmd=%v resetCount=%d, want a re-arm and one reset", cmd, engine.resetCount)
	}
	if m.autoReset.gen != gen {
		t.Fatal("re-arming after a tick must keep the chain's generation")
	}
	if !m.autoReset.armedAt.Equal(clock.t) {
		t.Fatal("a tick must restart the countdown")
	}
}

// TestInitWithoutAutoResetHasNoArm covers the disabled timer: Init neither
// arms nor emits an arm message, and a stray arm message is inert.
func TestInitWithoutAutoResetHasNoArm(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
	if batch, ok := runCmd(m.Init()).(tea.BatchMsg); ok && len(batch) != 2 {
		t.Fatalf("Init batched %d commands, want the refresh and flame ticks only", len(batch))
	}
	if _, cmd := m.Update(autoResetArmMsg{generation: m.autoReset.gen}); cmd != nil {
		t.Fatal("an arm message must be inert while the timer is disabled")
	}
}

// TestManualResetBeforeArmKeepsAutoResetState covers a reset (the `r` key)
// that lands before Init's arm message is handled: the manual reset must not
// disturb the auto-reset chain, and the arm still starts it.
func TestManualResetBeforeArmKeepsAutoResetState(t *testing.T) {
	clock := newFakeClock()
	engine := &fakeSnapshotSource{}
	m := NewModelWithConfig(engine, nil, 250, 200, common.DefaultKeyMap())
	m.autoReset.now = clock.now
	m.SetAutoResetInterval(30 * time.Second)
	batch := runCmd(m.Init()).(tea.BatchMsg)
	armMsg := runCmd(batch[len(batch)-1]).(autoResetArmMsg)
	gen, armedAt := m.autoReset.gen, m.autoReset.armedAt

	_ = m.resetBaselineCmd()
	if engine.resetCount != 1 {
		t.Fatalf("manual reset count = %d, want 1", engine.resetCount)
	}
	if m.autoReset.gen != gen || !m.autoReset.armedAt.Equal(armedAt) {
		t.Fatal("a manual reset must not touch the auto-reset chain")
	}
	if _, cmd := m.Update(armMsg); cmd == nil {
		t.Fatal("the arm must still start the chain after a manual reset")
	}
}
