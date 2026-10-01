package tui

import (
	"context"
	"strings"
	"testing"

	"ior/internal/runtime"
	"ior/internal/streamrow"
	"ior/internal/tui/eventstream"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
)

// publishSessionStream does what the trace core's wireRuntimeBindings does
// with a session's bindings: it takes the session's gated stream sink and
// publishes that same sink back as the TUI's stream source.
func publishSessionStream(t *testing.T, s traceSessionBindings) runtime.EventSink {
	t.Helper()
	sink := s.StreamBuffer()
	if sink == nil {
		t.Fatal("the session has no stream sink")
	}
	s.SetEventStreamSource(sink)
	return sink
}

// warningBadgeModel is a top-level model on the dashboard (default tab, not
// the Stream tab) whose trace sessions the test drives by hand.
func warningBadgeModel(t *testing.T) *Model {
	t.Helper()
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.Update(tea.WindowSizeMsg{Width: 160, Height: 40})
	return m
}

// startTracing delivers the trace starter's success, which hands the stream
// source the session published to the dashboard (handleTracingStarted).
func startTracing(m *Model) {
	m.attaching = false
	m.Update(TracingStartedMsg{})
}

// dashboardStatusLine is the dashboard's status line: the last non-blank
// line of the top-level frame (the frame is padded below it), unstyled.
func dashboardStatusLine(m *Model) string {
	lines := strings.Split(m.View().Content, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if line := strings.TrimSpace(ansi.Strip(lines[i])); line != "" {
			return line
		}
	}
	return ""
}

// TestSessionStreamSourceCountsWarnings pins the warning badge through the
// real session wiring (task ys2): in the TUI the stream source is the
// session's gated sink, not the ring buffer, so the sink must forward
// WarningCount. Without the forward the eventstream model saw no
// warningCounter and the badge vanished as soon as a trace started - exactly
// the setup in which the wrong -tid and zero-probes warnings are pushed.
func TestSessionStreamSourceCountsWarnings(t *testing.T) {
	m := warningBadgeModel(t)
	sink := publishSessionStream(t, m.runtime.beginSession())
	sink.Push(streamrow.NewWarning(1, "no probes attached"))

	model := eventstream.NewModel(m.runtime.eventStreamSource())
	if got := model.WarningCount(); got != 1 {
		t.Fatalf("WarningCount through the %T source = %d, want 1", m.runtime.eventStreamSource(), got)
	}

	startTracing(m)
	if line := dashboardStatusLine(m); !strings.Contains(line, "warnings: 1 (7:Stream)") {
		t.Fatalf("status line after tracing started = %q, want the warning badge", line)
	}
}

// TestWarningBadgeAcrossTraceRestart pins the count over session changes: a
// restart's new session publishes a new sink over the same ring buffer, so
// the earlier warning is still counted; a PID change resets the ring buffer,
// which zeroes the count and removes the badge.
func TestWarningBadgeAcrossTraceRestart(t *testing.T) {
	m := warningBadgeModel(t)
	publishSessionStream(t, m.runtime.beginSession()).Push(streamrow.NewWarning(1, "wrong -tid"))
	startTracing(m)

	publishSessionStream(t, m.runtime.beginSession())
	startTracing(m)
	if line := dashboardStatusLine(m); !strings.Contains(line, "warnings: 1 (7:Stream)") {
		t.Fatalf("status line after a restart = %q, want the earlier warning still counted", line)
	}

	m.runtime.resetStreamBuffer()
	publishSessionStream(t, m.runtime.beginSession())
	startTracing(m)
	if line := dashboardStatusLine(m); strings.Contains(line, "warn") {
		t.Fatalf("status line after the PID-change reset = %q, want no badge", line)
	}
	afterReset := eventstream.NewModel(m.runtime.eventStreamSource())
	if got := afterReset.WarningCount(); got != 0 {
		t.Fatalf("WarningCount after the reset = %d, want 0", got)
	}
}
