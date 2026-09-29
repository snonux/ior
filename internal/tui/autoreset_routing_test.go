package tui

import (
	"context"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
)

// The dashboard's Init schedules no timer: it returns immediate requests (the
// tick chain start and the auto-reset arm) that only take effect once the
// root model routes them back to the dashboard. These tests follow those
// requests through the root model's routing. Arming a chain bumps the
// dashboard's auto-reset generation, which is how delivery is observed.

// newAutoResetRoutingModel returns a root model on a running dashboard with
// the auto-reset timer enabled.
func newAutoResetRoutingModel(t *testing.T) *Model {
	t.Helper()
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false
	m.width, m.height = 120, 30
	m.dashboard.SetAutoResetInterval(time.Minute)
	return m
}

// deliverImmediate runs cmd, flattening batches, and routes every message it
// yields through the root model's Update. The commands those updates return
// are discarded unrun: they are the scheduled ticks, and running them would
// wait on real timers. Callers only pass commands that are immediate (Init's
// requests, size and snapshot commands).
func deliverImmediate(t *testing.T, m *Model, cmd tea.Cmd) {
	t.Helper()
	if cmd == nil {
		return
	}
	msg := cmd()
	if batch, ok := msg.(tea.BatchMsg); ok {
		for _, sub := range batch {
			deliverImmediate(t, m, sub)
		}
		return
	}
	next, _ := m.Update(msg)
	if next != m {
		t.Fatalf("Update returned %T at a different address", next)
	}
}

func TestTracingStartedArmsDashboardAutoReset(t *testing.T) {
	m := newAutoResetRoutingModel(t)
	m.attaching = true
	gen := m.dashboard.AutoResetGeneration()

	_, cmd := m.Update(TracingStartedMsg{})
	if got := m.dashboard.AutoResetGeneration(); got != gen {
		t.Fatalf("handling TracingStarted armed synchronously (gen %d -> %d); Init must only request it", gen, got)
	}
	deliverImmediate(t, m, cmd)
	if got := m.dashboard.AutoResetGeneration(); got != gen+1 {
		t.Fatalf("auto-reset generation = %d, want %d: the arm did not reach the dashboard", got, gen+1)
	}
}

func TestFocusRegainArmsDashboardAutoReset(t *testing.T) {
	m := newAutoResetRoutingModel(t)
	m.Update(tea.BlurMsg{})
	_, cmd := m.Update(tea.FocusMsg{})
	// SetFocused(true) has already superseded the pre-blur chain.
	gen := m.dashboard.AutoResetGeneration()

	deliverImmediate(t, m, cmd)
	if got := m.dashboard.AutoResetGeneration(); got != gen+1 {
		t.Fatalf("auto-reset generation = %d, want %d: the focus arm did not reach the dashboard", got, gen+1)
	}
}

func TestAutoResetArmReachesDashboardBehindModals(t *testing.T) {
	for _, state := range []string{"filter modal", "record modal", "probe modal", "export modal", "help overlay"} {
		t.Run(state, func(t *testing.T) {
			m := newAutoResetRoutingModel(t)
			initCmd := m.dashboard.Init()
			setTopLevelFlameRefreshHidden(m, state, true)
			if !topLevelFlameRefreshHidden(m, state) {
				t.Fatal("test setup did not open the overlay")
			}
			gen := m.dashboard.AutoResetGeneration()

			deliverImmediate(t, m, initCmd)
			if got := m.dashboard.AutoResetGeneration(); got != gen+1 {
				t.Fatalf("auto-reset generation = %d, want %d: the arm was swallowed by the %s", got, gen+1, state)
			}
		})
	}
}

// TestAttachingSwallowsArmAndTracingStartedRearms: an arm still in flight
// when a trace restart begins is swallowed by the attaching screen, and the
// TracingStarted that ends the attach arms the chain again.
func TestAttachingSwallowsArmAndTracingStartedRearms(t *testing.T) {
	m := newAutoResetRoutingModel(t)
	initCmd := m.dashboard.Init()
	m.attaching = true
	gen := m.dashboard.AutoResetGeneration()

	deliverImmediate(t, m, initCmd)
	if got := m.dashboard.AutoResetGeneration(); got != gen {
		t.Fatalf("auto-reset generation = %d, want %d: the arm reached the dashboard while attaching", got, gen)
	}

	_, cmd := m.Update(TracingStartedMsg{})
	if m.attaching {
		t.Fatal("TracingStarted must end the attach")
	}
	deliverImmediate(t, m, cmd)
	if got := m.dashboard.AutoResetGeneration(); got != gen+1 {
		t.Fatalf("auto-reset generation = %d, want %d: TracingStarted did not re-arm", got, gen+1)
	}
}
