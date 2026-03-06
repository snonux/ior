package flamegraph

import (
	"reflect"
	"testing"

	coreflamegraph "ior/internal/flamegraph"

	tea "charm.land/bubbletea/v2"
)

func TestNewModelDefaults(t *testing.T) {
	m := NewModel(nil)
	if m.liveTrie != nil {
		t.Fatalf("expected nil liveTrie when constructor input is nil")
	}
	if m.matchIndices == nil {
		t.Fatalf("expected matchIndices map to be initialized")
	}
	if len(m.fieldPresets) == 0 {
		t.Fatalf("expected default field presets to be initialized")
	}
	if !m.isDark {
		t.Fatalf("expected dark mode enabled by default")
	}
}

func TestSetViewportAndDarkMode(t *testing.T) {
	m := NewModel(nil)
	m.SetViewport(120, 40)
	m.SetDarkMode(false)
	if m.width != 120 || m.height != 40 {
		t.Fatalf("expected viewport 120x40, got %dx%d", m.width, m.height)
	}
	if m.isDark {
		t.Fatalf("expected dark mode to be disabled")
	}
}

func TestRefreshFromLiveTrieTracksVersionAndSnapshot(t *testing.T) {
	trie := coreflamegraph.NewLiveTrie([]string{"comm", "path"}, "count")
	m := NewModel(trie)

	if changed := m.RefreshFromLiveTrie(); !changed {
		t.Fatalf("expected first refresh to load baseline snapshot")
	}
	if m.snapshot == nil {
		t.Fatalf("expected snapshot to be populated after refresh")
	}

	if changed := m.RefreshFromLiveTrie(); changed {
		t.Fatalf("expected no refresh when version is unchanged")
	}
}

func TestKeyboardNavigationDeepNarrowTree(t *testing.T) {
	m := NewModel(nil)
	m.frames = []tuiFrame{
		{Name: "root", Depth: 0, Col: 0, Path: "root"},
		{Name: "child", Depth: 1, Col: 0, Path: "root" + pathSeparator + "child"},
		{Name: "leaf", Depth: 2, Col: 0, Path: "root" + pathSeparator + "child" + pathSeparator + "leaf"},
	}

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'k'}[0], Text: "k"})
	if m.selectedIdx != 1 {
		t.Fatalf("expected selection to move deeper to idx 1, got %d", m.selectedIdx)
	}
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'k'}[0], Text: "k"})
	if m.selectedIdx != 2 {
		t.Fatalf("expected selection to move deeper to idx 2, got %d", m.selectedIdx)
	}
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'j'}[0], Text: "j"})
	if m.selectedIdx != 1 {
		t.Fatalf("expected selection to move shallower to idx 1, got %d", m.selectedIdx)
	}
}

func TestKeyboardNavigationShallowWideSiblings(t *testing.T) {
	m := NewModel(nil)
	m.frames = []tuiFrame{
		{Name: "root", Depth: 0, Col: 0, Path: "root"},
		{Name: "A", Depth: 1, Col: 0, Path: "root" + pathSeparator + "A"},
		{Name: "B", Depth: 1, Col: 30, Path: "root" + pathSeparator + "B"},
		{Name: "C", Depth: 1, Col: 60, Path: "root" + pathSeparator + "C"},
	}

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'k'}[0], Text: "k"})
	if m.selectedIdx != 1 {
		t.Fatalf("expected first deeper frame to be A, got idx %d", m.selectedIdx)
	}
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'l'}[0], Text: "l"})
	if m.selectedIdx != 2 {
		t.Fatalf("expected next sibling B, got idx %d", m.selectedIdx)
	}
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'l'}[0], Text: "l"})
	if m.selectedIdx != 3 {
		t.Fatalf("expected next sibling C, got idx %d", m.selectedIdx)
	}
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'l'}[0], Text: "l"})
	if m.selectedIdx != 3 {
		t.Fatalf("expected selection to clamp at last sibling, got idx %d", m.selectedIdx)
	}
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'h'}[0], Text: "h"})
	if m.selectedIdx != 2 {
		t.Fatalf("expected previous sibling B, got idx %d", m.selectedIdx)
	}
}

func TestKeyboardNavigationSingleNodeClamped(t *testing.T) {
	m := NewModel(nil)
	m.frames = []tuiFrame{{Name: "root", Depth: 0, Col: 0, Path: "root"}}

	keys := []tea.KeyPressMsg{
		{Code: []rune{'j'}[0], Text: "j"},
		{Code: []rune{'k'}[0], Text: "k"},
		{Code: []rune{'h'}[0], Text: "h"},
		{Code: []rune{'l'}[0], Text: "l"},
		{Code: tea.KeyDown},
		{Code: tea.KeyUp},
		{Code: tea.KeyLeft},
		{Code: tea.KeyRight},
	}
	for _, keyMsg := range keys {
		m = pressFlameKey(t, m, keyMsg)
		if m.selectedIdx != 0 {
			t.Fatalf("expected single-node selection to stay at idx 0, got %d", m.selectedIdx)
		}
	}
}

func TestZoomInUndoResetAndNestedZoom(t *testing.T) {
	m := newZoomModel()

	m.selectedIdx = mustFrameIndex(t, m.frames, "root"+pathSeparator+"A")
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyEnter})
	if got, want := m.zoomPath, "root"+pathSeparator+"A"; got != want {
		t.Fatalf("expected zoomPath %q, got %q", want, got)
	}
	if len(m.zoomStack) != 1 || m.zoomStack[0].path != "" {
		t.Fatalf("expected one zoom stack entry from root, got %#v", m.zoomStack)
	}
	if m.zoomRoot == nil || m.zoomRoot.Name != "A" {
		t.Fatalf("expected zoomRoot A, got %+v", m.zoomRoot)
	}

	m.selectedIdx = mustFrameIndex(t, m.frames, "root"+pathSeparator+"A"+pathSeparator+"A1")
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyEnter})
	if got, want := m.zoomPath, "root"+pathSeparator+"A"+pathSeparator+"A1"; got != want {
		t.Fatalf("expected nested zoomPath %q, got %q", want, got)
	}
	if len(m.zoomStack) != 2 || m.zoomStack[1].path != "root"+pathSeparator+"A" {
		t.Fatalf("expected nested zoom stack to preserve parent path, got %#v", m.zoomStack)
	}

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyBackspace})
	if got, want := m.zoomPath, "root"+pathSeparator+"A"; got != want {
		t.Fatalf("expected zoomPath after undo %q, got %q", want, got)
	}
	if len(m.zoomStack) != 1 {
		t.Fatalf("expected one stack entry after undo, got %d", len(m.zoomStack))
	}

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyEsc})
	if m.zoomPath != "" || m.zoomRoot != nil || len(m.zoomStack) != 0 {
		t.Fatalf("expected zoom reset to root state, got path=%q root=%+v stack=%d", m.zoomPath, m.zoomRoot, len(m.zoomStack))
	}
}

func TestZoomInOnCurrentRootSetsStatusMessage(t *testing.T) {
	m := newZoomModel()
	m.selectedIdx = mustFrameIndex(t, m.frames, "root")

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyEnter})
	if m.zoomPath != "" {
		t.Fatalf("expected zoom path to remain root, got %q", m.zoomPath)
	}
	if m.statusMessage != "Zoom unchanged: selected frame is current view root" {
		t.Fatalf("unexpected status message: %q", m.statusMessage)
	}
}

func TestZoomTransitionAnimatesToNewLayout(t *testing.T) {
	m := newZoomModel()
	pathA := "root" + pathSeparator + "A"
	preWidth := m.frames[mustFrameIndex(t, m.frames, pathA)].Width

	m.selectedIdx = mustFrameIndex(t, m.frames, pathA)
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyEnter})
	if !m.animating {
		t.Fatalf("expected zoom-in to start animation")
	}
	currentWidth := m.frames[mustFrameIndex(t, m.frames, pathA)].Width
	targetWidth := m.targetFrames[mustFrameIndex(t, m.targetFrames, pathA)].Width
	if currentWidth == targetWidth {
		t.Fatalf("expected intermediate zoom frame width to differ from target (current=%d target=%d, pre=%d)", currentWidth, targetWidth, preWidth)
	}

	for i := 0; i < 180 && m.animating; i++ {
		next, _ := m.Update(animTickMsg{})
		m = next.(Model)
	}
	if m.animating {
		t.Fatalf("expected zoom animation to settle within 180 ticks")
	}
	finalWidth := m.frames[mustFrameIndex(t, m.frames, pathA)].Width
	if finalWidth != targetWidth {
		t.Fatalf("expected final zoom width %d, got %d", targetWidth, finalWidth)
	}
}

func TestSearchLifecycleAndMatchNavigation(t *testing.T) {
	m := NewModel(nil)
	m.frames = []tuiFrame{
		{Name: "alpha", Path: "root" + pathSeparator + "alpha"},
		{Name: "beta", Path: "root" + pathSeparator + "beta"},
		{Name: "alphabet", Path: "root" + pathSeparator + "alphabet"},
	}

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'/'}[0], Text: "/"})
	if !m.searchActive {
		t.Fatalf("expected search mode to activate on '/'")
	}
	for _, r := range []rune{'a', 'l', 'p'} {
		m = pressFlameKey(t, m, tea.KeyPressMsg{Code: r, Text: string(r)})
	}
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyEnter})

	if m.searchActive {
		t.Fatalf("expected search mode to close on enter")
	}
	if got := len(m.matchIndices); got != 2 {
		t.Fatalf("expected 2 matches for 'alp', got %d", got)
	}
	first := m.selectedIdx
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'n'}[0], Text: "n"})
	if m.selectedIdx == first {
		t.Fatalf("expected 'n' to jump to next match")
	}
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'N'}[0], Text: "N"})
	if m.selectedIdx != first {
		t.Fatalf("expected 'N' to jump back to previous match")
	}
}

func TestSearchEscapeClearsState(t *testing.T) {
	m := NewModel(nil)
	m.frames = []tuiFrame{{Name: "alpha", Path: "root" + pathSeparator + "alpha"}}

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'/'}[0], Text: "/"})
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'a'}[0], Text: "a"})
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyEsc})

	if m.searchActive {
		t.Fatalf("expected search mode to close on escape")
	}
	if m.searchQuery != "" || len(m.matchIndices) != 0 {
		t.Fatalf("expected search state to reset on escape, got query=%q matches=%d", m.searchQuery, len(m.matchIndices))
	}
	if m.statusMessage != "Filter cleared" {
		t.Fatalf("expected filter cleared status message, got %q", m.statusMessage)
	}
}

func TestSearchSubmitSetsFilterStatusMessage(t *testing.T) {
	m := NewModel(nil)
	m.frames = []tuiFrame{
		{Name: "alpha", Path: "root" + pathSeparator + "alpha"},
		{Name: "beta", Path: "root" + pathSeparator + "beta"},
	}

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'/'}[0], Text: "/"})
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'a'}[0], Text: "a"})
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyEnter})
	if m.statusMessage != `Filter "a": 2 matches` {
		t.Fatalf("unexpected status after applying filter: %q", m.statusMessage)
	}

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'/'}[0], Text: "/"})
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyEsc})
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'/'}[0], Text: "/"})
	for _, r := range []rune{'z', 'z'} {
		m = pressFlameKey(t, m, tea.KeyPressMsg{Code: r, Text: string(r)})
	}
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyEnter})
	if m.statusMessage != `Filter "zz": no matches` {
		t.Fatalf("unexpected status for unmatched filter: %q", m.statusMessage)
	}
}

func TestControlPauseToggle(t *testing.T) {
	m := NewModel(nil)
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'p'}[0], Text: "p"})
	if !m.paused {
		t.Fatalf("expected pause to toggle on")
	}
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'p'}[0], Text: "p"})
	if m.paused {
		t.Fatalf("expected pause to toggle off")
	}
}

func TestControlResetBaseline(t *testing.T) {
	liveTrie := coreflamegraph.NewLiveTrie([]string{"comm", "path", "tracepoint"}, "count")
	m := NewModel(liveTrie)
	m.snapshot = &snapshotNode{Name: "root", Total: 10}
	m.frames = []tuiFrame{{Name: "root", Path: "root"}}
	m.zoomPath = "root"
	m.zoomStack = []zoomState{{path: "", previousSelectedIdx: 0}}
	m.selectedIdx = 3

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'r'}[0], Text: "r"})
	if m.snapshot != nil || len(m.frames) != 0 || len(m.zoomStack) != 0 || m.zoomPath != "" {
		t.Fatalf("expected baseline reset to clear snapshot/layout/zoom state")
	}
	if m.statusMessage != "Baseline reset" {
		t.Fatalf("expected reset status message, got %q", m.statusMessage)
	}
}

func TestControlCycleFieldOrderReconfiguresLiveTrie(t *testing.T) {
	liveTrie := coreflamegraph.NewLiveTrie([]string{"comm", "path", "tracepoint"}, "count")
	m := NewModel(liveTrie)
	initial := append([]string(nil), m.fieldPresets[m.fieldIndex]...)

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'o'}[0], Text: "o"})
	if m.fieldIndex != 1 {
		t.Fatalf("expected field index to advance to 1, got %d", m.fieldIndex)
	}
	next := m.fieldPresets[m.fieldIndex]
	if reflect.DeepEqual(initial, next) {
		t.Fatalf("expected next field preset to differ from initial")
	}
	if got := liveTrie.Fields(); !reflect.DeepEqual(got, next) {
		t.Fatalf("expected live trie fields %v, got %v", next, got)
	}
}

func TestControlHelpToggle(t *testing.T) {
	m := NewModel(nil)
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'?'}[0], Text: "?"})
	if !m.showHelp {
		t.Fatalf("expected help overlay to toggle on")
	}
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'?'}[0], Text: "?"})
	if m.showHelp {
		t.Fatalf("expected help overlay to toggle off")
	}
}

func TestDataRefreshAnimationConvergesOverTicks(t *testing.T) {
	m := NewModel(nil)
	m.width = 120
	m.height = 20
	m.snapshot = &snapshotNode{
		Name:  "root",
		Total: 100,
		Children: []*snapshotNode{
			{Name: "A", Total: 60},
			{Name: "B", Total: 40},
		},
	}
	m.rebuildFrames(false)
	initial := append([]tuiFrame(nil), m.frames...)

	m.snapshot = &snapshotNode{
		Name:  "root",
		Total: 100,
		Children: []*snapshotNode{
			{Name: "A", Total: 20},
			{Name: "B", Total: 80},
		},
	}
	m.rebuildFrames(true)
	if !m.animating {
		t.Fatalf("expected animation to start after animated rebuild")
	}

	next, _ := m.Update(animTickMsg{})
	m = next.(Model)
	if len(m.frames) != len(initial) {
		t.Fatalf("expected frame count to remain stable during animation")
	}

	for i := 0; i < 180 && m.animating; i++ {
		next, _ = m.Update(animTickMsg{})
		m = next.(Model)
	}
	if m.animating {
		t.Fatalf("expected animation to settle within 180 ticks")
	}
	if len(m.frames) != len(m.targetFrames) {
		t.Fatalf("expected settled frame count to match targets")
	}
	for i := range m.frames {
		if m.frames[i].Width != m.targetFrames[i].Width || m.frames[i].Col != m.targetFrames[i].Col {
			t.Fatalf("frame %d did not converge to target: got col=%d width=%d want col=%d width=%d",
				i, m.frames[i].Col, m.frames[i].Width, m.targetFrames[i].Col, m.targetFrames[i].Width)
		}
	}
}

func TestResizeRecalculatesLayoutAndCullsNarrowFrames(t *testing.T) {
	m := NewModel(nil)
	m.width = 120
	m.height = 40
	m.snapshot = &snapshotNode{
		Name:  "root",
		Total: 100,
		Children: []*snapshotNode{
			{
				Name:  "big",
				Total: 99,
				Children: []*snapshotNode{
					{Name: "deep", Total: 99},
				},
			},
			{Name: "tiny", Total: 1},
		},
	}
	m.rebuildFrames(false)
	_ = mustFrameIndex(t, m.frames, "root"+pathSeparator+"tiny")

	next, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	m = next.(Model)
	for i := 0; i < 180 && m.animating; i++ {
		next, _ = m.Update(animTickMsg{})
		m = next.(Model)
	}

	for _, frame := range m.frames {
		if frame.Col+frame.Width > 80 {
			t.Fatalf("frame exceeds resized width: %+v", frame)
		}
		if frame.Row >= 24 {
			t.Fatalf("frame row exceeds resized height: %+v", frame)
		}
	}
	for _, frame := range m.frames {
		if frame.Path == "root"+pathSeparator+"tiny" {
			t.Fatalf("expected tiny frame to be culled at width 80")
		}
	}
}

func newZoomModel() Model {
	m := NewModel(nil)
	m.width = 120
	m.height = 30
	m.snapshot = &snapshotNode{
		Name:  "root",
		Total: 100,
		Children: []*snapshotNode{
			{
				Name:  "A",
				Total: 60,
				Children: []*snapshotNode{
					{Name: "A1", Total: 30},
					{Name: "A2", Total: 30},
				},
			},
			{Name: "B", Total: 40},
		},
	}
	m.rebuildFrames(false)
	return m
}

func mustFrameIndex(t *testing.T, frames []tuiFrame, path string) int {
	t.Helper()
	for idx, frame := range frames {
		if frame.Path == path {
			return idx
		}
	}
	t.Fatalf("frame path %q not found", path)
	return -1
}

func pressFlameKey(t *testing.T, m Model, keyMsg tea.KeyPressMsg) Model {
	t.Helper()
	next, _ := m.Update(keyMsg)
	return next.(Model)
}
