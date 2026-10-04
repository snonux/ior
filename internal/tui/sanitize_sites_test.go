package tui

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// hostileErrText carries the task io2 payloads: an OSC 8 hyperlink, SGR
// hidden text and a raw C1 CSI byte.
const hostileErrText = "open /tmp/\x1b]8;;http://evil\aclick\x1b]8;;\a/\x1b[8mhidden/\x9b31m"

// assertNoHostilePayload fails when out still carries one of the payload
// sequences. The theme's own styling emits ESC[...m, so only the injected
// sequences are checked.
func assertNoHostilePayload(t *testing.T, what, out string) {
	t.Helper()
	for _, bad := range []string{"\x1b]8", "\x1b[8m", "\a", "\x9b"} {
		if strings.Contains(out, bad) {
			t.Fatalf("%s contains injected %q: %q", what, bad, out)
		}
	}
}

// TestErrorScreenSanitizesErrorKeepsLineFeeds checks the full-screen error
// view strips escape sequences from the error text but keeps its line
// breaks (common.SanitizeLines), so multi-line errors keep their layout.
func TestErrorScreenSanitizesErrorKeepsLineFeeds(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false
	m.width, m.height = 120, 40
	m.setError(errors.New(hostileErrText+"\nsecond-line-marker"), errorScreenFatal)

	out := m.View().Content
	assertNoHostilePayload(t, "error screen", out)
	lines := strings.Split(out, "\n")
	first, second := -1, -1
	for i, line := range lines {
		if strings.Contains(line, "?]8;;http://evil?click") {
			first = i
		}
		if strings.Contains(line, "second-line-marker") {
			second = i
		}
	}
	if first < 0 || second != first+1 {
		t.Fatalf("expected sanitised error and its second line on consecutive lines (got %d, %d):\n%s", first, second, out)
	}
}

// TestRecordingModalSanitizesError checks the recording modal's error line.
func TestRecordingModalSanitizesError(t *testing.T) {
	m := newRecordingModal().Open("/tmp/rec.parquet").SetError(errors.New(hostileErrText))
	out := m.View(100, 30)
	assertNoHostilePayload(t, "recording modal", out)
	if !strings.Contains(out, "Error:") {
		t.Fatalf("recording modal lost its error line: %q", out)
	}
}
