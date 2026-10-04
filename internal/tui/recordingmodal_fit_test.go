package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"ior/internal/globalfilter"
	"ior/internal/probemanager"
	"ior/internal/tui/probes"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

// modalFitWidths are the view widths the top-level modal sweeps cover (task
// rz2), every height from 1 to 30 rows each.
var modalFitWidths = []int{1, 7, 20, 30, 52, 80, 120}

// assertModalFrame fails unless out is exactly width x height cells,
// measured by lipgloss and by ansi, every line.
func assertModalFrame(t *testing.T, label, out string, width, height int) {
	t.Helper()
	lines := strings.Split(out, "\n")
	if len(lines) != height || lipgloss.Height(out) != height {
		t.Fatalf("%s: frame is %d rows, want %d:\n%s", label, len(lines), height, ansi.Strip(out))
	}
	for _, line := range lines {
		if lipgloss.Width(line) != width || ansi.StringWidth(line) != width {
			t.Fatalf("%s: line %q is %d/%d cells, want %d:\n%s", label, ansi.Strip(line),
				lipgloss.Width(line), ansi.StringWidth(line), width, ansi.Strip(out))
		}
	}
}

// typeInto sends one key press per rune of text to the record modal.
func typeInto(m recordingModal, text string) recordingModal {
	for _, r := range text {
		m, _, _ = m.Update(tea.KeyPressMsg{Code: r, Text: string(r)})
	}
	return m
}

// recordFitStates are the record modal states the sweep draws, sized to
// width (Resize) as the TUI does: the default path, a CJK/emoji path typed
// past the input, and start errors in CJK and emoji wider than every
// narrow box, so the error reaches the per-line cut.
func recordFitStates(width int) map[string]recordingModal {
	base := newRecordingModal().Resize(width)
	wideErr := errors.New("open /tmp/日本語😀😀/記録ファイル👩‍👩‍👧.parquet: 許可がありません permission denied")
	return map[string]recordingModal{
		"default":    base.Open("ior-20261001-120000.parquet"),
		"typed-wide": typeInto(base.Open(""), "記録😀ファイル名前😀😀"+strings.Repeat("x", 30)+"日本"),
		"error-wide": base.Open("x.parquet").SetError(wideErr),
		"error-long": base.Open("x.parquet").SetError(errors.New(strings.Repeat("disk-full ", 12))),
	}
}

// TestRecordingModalFitsEverySize is the task rz2 regression for the record
// modal: a fixed 74-column box at least 44 wide, placed with
// lipgloss.Place, overflowed every smaller terminal. Every state at every
// swept size is exactly the view's size, the input's cursor is always
// drawn, the key hint from two rows (twelve columns) and the border from
// four rows (five with an error) and seven columns.
func TestRecordingModalFitsEverySize(t *testing.T) {
	for _, width := range modalFitWidths {
		for name, m := range recordFitStates(width) {
			for height := 1; height <= 30; height++ {
				label := fmt.Sprintf("%s %dx%d", name, width, height)
				out := m.View(width, height)
				assertModalFrame(t, label, out, width, height)
				plain := ansi.Strip(out)
				if !strings.Contains(out, "\x1b[7") {
					t.Fatalf("%s: no cursor drawn:\n%s", label, plain)
				}
				if height >= 2 && width >= 12+6 && !strings.Contains(plain, "Enter start") {
					t.Fatalf("%s: key hint missing:\n%s", label, plain)
				}
				compact := 4
				if m.err != "" {
					compact = 5
				}
				boxed := strings.Contains(plain, "╭") && strings.Contains(plain, "╰")
				if want := height >= compact && width >= 7; boxed != want {
					t.Fatalf("%s: boxed=%v, want %v:\n%s", label, boxed, want, plain)
				}
			}
		}
	}
}

// TestRecordingModalNormalSizes pins the normal-size content: title, label,
// the path, the wrapped error and the whole hint.
func TestRecordingModalNormalSizes(t *testing.T) {
	m := newRecordingModal().Resize(80).Open("ior-20261001-120000.parquet").SetError(errors.New("open x.parquet: permission denied"))
	for _, size := range [][2]int{{80, 24}, {120, 40}} {
		plain := ansi.Strip(m.View(size[0], size[1]))
		for _, want := range []string{"Start Parquet Recording", "Filename:", "ior-20261001-120000.parquet",
			"Error: open x.parquet: permission denied", "Enter start • Esc cancel"} {
			if !strings.Contains(plain, want) {
				t.Fatalf("%dx%d: %q missing:\n%s", size[0], size[1], want, plain)
			}
		}
	}
}

// TestRecordingModalNonPositiveSizesAndHidden: a hidden modal draws
// nothing, and zero or negative sizes draw the 80x24 frame without a panic.
func TestRecordingModalNonPositiveSizesAndHidden(t *testing.T) {
	if got := newRecordingModal().View(80, 24); got != "" {
		t.Fatalf("hidden modal drew %q", got)
	}
	m := newRecordingModal().Open("x.parquet")
	for _, size := range [][2]int{{0, 0}, {-1, -5}} {
		assertModalFrame(t, fmt.Sprint(size), m.View(size[0], size[1]), 80, 24)
	}
}

// TestDashboardModalFramesFitTheTerminal draws the dashboard screen with
// each top-level modal open (filter, record, probes) through the TUI's own
// View at every swept size: the frame is exactly the terminal's size (task
// rz2: placeToViewport only pads, so the modals' boxes used to scroll small
// terminals), and the modal, not the dashboard, is drawn.
func TestDashboardModalFramesFitTheTerminal(t *testing.T) {
	states := make([]probemanager.ProbeState, 40)
	for i := range states {
		states[i] = probemanager.ProbeState{Syscall: fmt.Sprintf("sys_%03d", i)}
	}
	open := map[string]func(m *Model){
		"filter": func(m *Model) {
			m.filterModal = m.filterModal.Open(globalfilter.Filter{Comm: &globalfilter.StringFilter{Pattern: "日本語😀"}})
		},
		"record": func(m *Model) { m.recordModal = m.recordModal.Open("ior-記録😀.parquet") },
		"probes": func(m *Model) {
			m.probeModal = probes.NewModel(fakeProbeManager{states: states}).SetSize(m.width, m.height).Open()
		},
	}
	for name, openModal := range open {
		for _, width := range []int{1, 20, 52, 120} {
			for _, height := range []int{1, 3, 5, 10, 24} {
				m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
				m.runtime.setProbeManager(fakeProbeManager{states: states})
				m.router.showDashboard()
				m.attaching = false
				next, _ := m.Update(tea.WindowSizeMsg{Width: width, Height: height})
				m = next.(*Model)
				openModal(m)
				label := fmt.Sprintf("%s %dx%d", name, width, height)
				assertModalFrame(t, label, m.View().Content, width, height)
			}
		}
	}
}
