package tui

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"ior/internal/flags"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
)

func TestPidSelectedTransitionsToDashboardAndSetsPIDFilter(t *testing.T) {
	flags.SetPidFilter(-1)
	m := NewModel(-1, func(context.Context) error { return nil })

	next, cmd := m.Update(PidSelectedMsg{Pid: 42})
	if cmd == nil {
		t.Fatalf("expected tracing start command")
	}

	updated := next.(Model)
	if updated.screen != ScreenDashboard {
		t.Fatalf("expected dashboard screen, got %v", updated.screen)
	}
	if !updated.attaching {
		t.Fatalf("expected attaching state to be true")
	}
	if got := flags.Get().PidFilter; got != 42 {
		t.Fatalf("expected pid filter 42, got %d", got)
	}
}

func TestInitialPIDSkipsPickerAndStartsTracing(t *testing.T) {
	flags.SetPidFilter(-1)
	m := NewModel(7, func(context.Context) error { return nil })

	if m.screen != ScreenDashboard {
		t.Fatalf("expected initial screen dashboard, got %v", m.screen)
	}

	cmd := m.Init()
	if cmd == nil {
		t.Fatalf("expected init command when initial pid is set")
	}
}

func TestPidSelectedAllSetsNoFilter(t *testing.T) {
	flags.SetPidFilter(999)
	m := NewModel(-1, func(context.Context) error { return nil })

	next, _ := m.Update(PidSelectedMsg{Pid: 0})
	updated := next.(Model)

	if got := flags.Get().PidFilter; got != -1 {
		t.Fatalf("expected pid filter -1 for all pids, got %d", got)
	}
	if updated.dashboard.selectedPID != -1 {
		t.Fatalf("expected dashboard selected pid -1, got %d", updated.dashboard.selectedPID)
	}
}

func TestTracingErrorMessageClearsAttachingState(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })
	m.attaching = true

	next, _ := m.Update(TracingErrorMsg{Err: errors.New("boom")})
	updated := next.(Model)
	if updated.attaching {
		t.Fatalf("expected attaching to be false after tracing error")
	}
	if updated.lastErr == nil || updated.lastErr.Error() != "boom" {
		t.Fatalf("expected tracing error to be stored")
	}
}

func TestViewShowsAttachingAndErrorStates(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })
	m.attaching = true
	attachingView := m.View()
	if !strings.Contains(attachingView, "Attaching tracepoints...") {
		t.Fatalf("expected attaching view, got %q", attachingView)
	}

	m.attaching = false
	m.lastErr = errors.New("failed")
	errorView := m.View()
	if !strings.Contains(errorView, "failed") {
		t.Fatalf("expected error view, got %q", errorView)
	}
}

func TestQuitKeySetsQuittingState(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })

	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	if cmd == nil {
		t.Fatalf("expected quit cmd")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Fatalf("expected tea.QuitMsg")
	}

	updated := next.(Model)
	if !updated.quitting {
		t.Fatalf("expected quitting state")
	}
}

func TestQuitKeyMatchesSingleBindingWithoutPanic(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })
	m.keys.Quit = key.NewBinding(key.WithKeys("x"), key.WithHelp("x", "quit"))

	_, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'z'}})

	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'x'}})
	if cmd == nil {
		t.Fatalf("expected quit cmd")
	}
	updated := next.(Model)
	if !updated.quitting {
		t.Fatalf("expected quitting state")
	}
}

func TestStartTraceCmdLaunchesBeforeStarterReturns(t *testing.T) {
	cmd := startTraceCmd(func(context.Context) error { return nil }, context.Background())
	msg := cmd()
	if _, ok := msg.(TracingStartedMsg); !ok {
		t.Fatalf("expected TracingStartedMsg, got %T", msg)
	}
}

func TestStartTraceCmdEmitsErrorMsg(t *testing.T) {
	cmd := startTraceCmd(func(context.Context) error { return errors.New("trace failed") }, context.Background())
	msg := cmd()
	traceErr, ok := msg.(TracingErrorMsg)
	if !ok {
		t.Fatalf("expected TracingErrorMsg, got %T", msg)
	}
	if traceErr.Err == nil || traceErr.Err.Error() != "trace failed" {
		t.Fatalf("unexpected trace error message: %+v", traceErr)
	}
}

func TestQuitInvokesTraceStop(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })
	done := make(chan struct{})
	m.traceStop = func() {
		close(done)
	}

	_, quitCmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	if quitCmd == nil {
		t.Fatalf("expected quit command")
	}

	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("expected stopTrace to be invoked on quit")
	}
}
