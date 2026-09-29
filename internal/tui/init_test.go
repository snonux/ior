package tui

import (
	"reflect"
	"testing"

	"ior/internal/runtime"

	tea "charm.land/bubbletea/v2"
)

// initObservable is the part of the top-level Model that Init could change
// through its pointer receiver. It holds no funcs, so reflect.DeepEqual
// compares it meaningfully; the tracer is reduced to whether a session runs
// and which shutdown reporter it holds.
type initObservable struct {
	screen        Screen
	pickerReturn  *pickerReturnState
	attaching     bool
	quitting      bool
	helpOverlay   bool
	width, height int
	lastErr       error
	errorKind     errorScreenKind
	shutdown      runtime.TraceShutdownProgress
	traceRunning  bool
	reporter      *runtime.TraceShutdownReporter
	filters       filterStack
	proc          processState
	exportEnabled bool
	isDark        bool
	focused       bool
	view          string
}

func observeInit(m *Model) initObservable {
	return initObservable{
		screen:        m.router.current(),
		pickerReturn:  m.router.pickerReturn,
		attaching:     m.attaching,
		quitting:      m.quitting,
		helpOverlay:   m.helpOverlayVisible,
		width:         m.width,
		height:        m.height,
		lastErr:       m.lastErr,
		errorKind:     m.errorKind,
		shutdown:      m.shutdown,
		traceRunning:  m.tracer.running(),
		reporter:      m.tracer.shutdownReporter,
		filters:       m.filters,
		proc:          m.proc,
		exportEnabled: m.exportEnabled,
		isDark:        m.isDark,
		focused:       m.focused,
		view:          m.View().Content,
	}
}

// TestInitDoesNotMutateModel pins that Init is side-effect free on both
// startup screens: calling it, and running every command it returns, leaves
// the model exactly as constructed and starts no trace session. Starting the
// trace is Update's job (initialTraceStartMsg); before, Init stored the new
// session's cancel func and shutdown reporter on the tracer itself.
func TestInitDoesNotMutateModel(t *testing.T) {
	cases := []struct {
		name       string
		initialPID int
		wantStart  bool
	}{
		{name: "dashboard startup", initialPID: 4242, wantStart: true},
		{name: "picker startup", initialPID: -1, wantStart: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			starter := newRecordingStarter()
			m := NewModel(tc.initialPID, starter.start)
			t.Cleanup(m.tracer.stop)
			before := observeInit(m)

			cmd := m.Init()
			if got := cmdEmits[initialTraceStartMsg](cmd); got != tc.wantStart {
				t.Fatalf("Init requested the startup trace = %v, want %v", got, tc.wantStart)
			}
			// Twice, as a redundant Init must be just as harmless.
			_ = m.Init()

			after := observeInit(m)
			if before.view != after.view {
				t.Fatal("Init changed the rendered view")
			}
			before.view, after.view = "", ""
			if !reflect.DeepEqual(before, after) {
				t.Fatalf("Init mutated the model:\nbefore %+v\nafter  %+v", before, after)
			}
			select {
			case <-starter.sessions:
				t.Fatal("Init ran the trace starter itself")
			default:
			}
		})
	}
}

// TestInitialTraceStartIgnoredWhenNotWanted is the negative side of
// handleInitialTraceStart: the request only starts a trace while the
// model is still attaching on the dashboard with nothing running.
func TestInitialTraceStartIgnoredWhenNotWanted(t *testing.T) {
	cases := []struct {
		name       string
		initialPID int
		setup      func(t *testing.T, m *Model)
	}{
		{
			name:       "picker screen",
			initialPID: -1,
			setup:      func(*testing.T, *Model) {},
		},
		{
			// The user quit while the start request was still in flight:
			// the quit found no session to stop and quits immediately, so
			// a session started now would outlive the program.
			name:       "quit before the request arrived",
			initialPID: 4242,
			setup: func(t *testing.T, m *Model) {
				_, cmd := m.Update(tea.KeyPressMsg{Code: 'q', Text: "q"})
				if !m.quitting || !cmdEmits[tea.QuitMsg](cmd) {
					t.Fatalf("quit while attaching: quitting=%v, want an immediate quit", m.quitting)
				}
			},
		},
		{
			name:       "no longer attaching",
			initialPID: 4242,
			setup: func(_ *testing.T, m *Model) {
				m.attaching = false
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := NewModel(tc.initialPID, newRecordingStarter().start)
			t.Cleanup(m.tracer.stop)
			tc.setup(t, m)

			_, cmd := m.Update(initialTraceStartMsg{})
			if cmd != nil {
				t.Fatal("an unwanted startup trace request returned a command")
			}
			if m.tracer.running() || m.tracer.shutdownReporter != nil {
				t.Fatal("an unwanted startup trace request armed a trace session")
			}
		})
	}
}

// TestRepeatedInitialTraceStartKeepsTheRunningSession pins that a second
// start request (a repeated Init) does not restart the startup trace: the
// first session stays live and no second one is started.
func TestRepeatedInitialTraceStartKeepsTheRunningSession(t *testing.T) {
	starter := newRecordingStarter()
	m := NewModel(4242, starter.start)
	t.Cleanup(m.tracer.stop)

	runCmdAsync(initTraceCmd(t, m))
	first := starter.next(t)
	reporter := m.tracer.shutdownReporter

	if _, cmd := m.Update(initialTraceStartMsg{}); cmd != nil {
		t.Fatal("a second start request restarted the running startup trace")
	}
	requireLive(t, first, "startup trace after a second start request")
	if m.tracer.shutdownReporter != reporter {
		t.Fatal("a second start request replaced the session's shutdown reporter")
	}
}
