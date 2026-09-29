package flamegraph

import (
	"strings"
	"testing"

	"charm.land/lipgloss/v2"
)

// Hostile frame names (task io2): an OSC 8 hyperlink, an unterminated CSI
// (which used to swallow padOrTrim's padding) and a raw C1 CSI byte.
const (
	flameOSC8         = "\x1b]8;;http://evil\aclick\x1b]8;;\a"
	flameUnterminated = "abc\x1b["
	flameRawCSI       = "x\x9b8my"
)

func hostileFlameSnapshot() *snapshotNode {
	return &snapshotNode{Name: "root", Total: 90, Children: []*snapshotNode{
		{Name: flameOSC8, Total: 30, Children: []*snapshotNode{{Name: flameRawCSI, Total: 30}}},
		{Name: flameUnterminated, Total: 30},
		{Name: "plain", Total: 30},
	}}
}

// assertNoFlameInjection fails when out carries any of the payloads' control
// bytes. The renderer's own styling emits ESC[...m, so only the injected
// sequences are checked.
func assertNoFlameInjection(t *testing.T, out string) {
	t.Helper()
	for _, bad := range []string{"\x1b]", "\a", "\x9b", flameUnterminated} {
		if strings.Contains(out, bad) {
			t.Fatalf("output contains injected %q: %q", bad, out)
		}
	}
}

// TestLayoutSanitizesFrameNamesKeepsPaths checks frame names are sanitised
// where tuiFrame is built while Path stays the raw lookup key.
func TestLayoutSanitizesFrameNamesKeepsPaths(t *testing.T) {
	frames := buildTerminalLayout(hostileFlameSnapshot(), 80, 8)
	sawRawPath := false
	for _, f := range frames {
		assertNoFlameInjection(t, f.Name)
		sawRawPath = sawRawPath || strings.Contains(f.Path, flameOSC8)
	}
	if !sawRawPath {
		t.Fatal("expected Path to keep the raw node name as lookup key")
	}
	zoomPath := "root" + pathSeparator + flameOSC8
	for _, f := range applyZoomLineage(frames, hostileFlameSnapshot(), zoomPath, 80) {
		assertNoFlameInjection(t, f.Name)
	}
}

// TestRenderHostileFrameNamesKeepsWidth renders every frame selected in turn
// (so the toolbar and status line echo each hostile name and path) and checks
// no payload reaches the output and every line is exactly width cells.
func TestRenderHostileFrameNamesKeepsWidth(t *testing.T) {
	const width, height = 80, 12
	frames := buildTerminalLayout(hostileFlameSnapshot(), width, height)
	for sel := range frames {
		out := RenderTerminalView(RenderContext{Frames: frames, Width: width, Height: height, SelectedIdx: sel, MetricLabel: "samples", IsDark: true})
		assertNoFlameInjection(t, out)
		for i, line := range strings.Split(out, "\n") {
			if got := lipgloss.Width(line); got != width {
				t.Fatalf("selected %d line %d width=%d want %d: %q", sel, i, got, width, stripSGR(line))
			}
		}
	}
}

// TestCompactFramePathSanitizes checks the raw Path is sanitised when shown.
func TestCompactFramePathSanitizes(t *testing.T) {
	got := compactFramePath("root" + pathSeparator + flameOSC8 + pathSeparator + flameRawCSI)
	assertNoFlameInjection(t, got)
	if !strings.Contains(got, "?]8;;http://evil?click") {
		t.Fatalf("compactFramePath = %q, want placeholders for control bytes", got)
	}
}
