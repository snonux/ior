package flamegraph

import (
	"reflect"
	"strings"
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
	if got, want := m.fieldPresets[0], []string{"comm", "tracepoint", "path"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("default field preset[0] = %v, want %v", got, want)
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

func TestRefreshFromLiveTrieAllowsInitialLoadWhilePaused(t *testing.T) {
	trie := coreflamegraph.NewLiveTrie([]string{"comm", "path"}, "count")
	m := NewModel(trie)
	m.paused = true

	if changed := m.RefreshFromLiveTrie(); !changed {
		t.Fatalf("expected initial paused refresh to load first snapshot")
	}
	if m.snapshot == nil {
		t.Fatalf("expected snapshot to be available after initial paused refresh")
	}
	if changed := m.RefreshFromLiveTrie(); changed {
		t.Fatalf("expected subsequent paused refresh to be skipped once snapshot exists")
	}
}

func TestRefreshFromLiveTriePausedBlocksAfterNavigableSnapshot(t *testing.T) {
	trie := coreflamegraph.NewLiveTrie([]string{"comm", "path"}, "count")
	m := NewModel(trie)
	m.paused = true
	m.snapshot = &snapshotNode{Name: "root", Total: 1}
	m.frames = []tuiFrame{
		{Name: "root", Path: "root"},
		{Name: "child", Path: "root" + pathSeparator + "child"},
	}
	m.hasNavigableSnapshot = true
	m.lastVersion = 1

	if changed := m.RefreshFromLiveTrie(); changed {
		t.Fatalf("expected paused refresh to remain frozen once navigable snapshot exists")
	}
	if got, want := m.lastVersion, uint64(1); got != want {
		t.Fatalf("expected version to remain unchanged while paused, got %d want %d", got, want)
	}
}

func TestRefreshFromLiveTriePausedBlocksAfterAnySnapshot(t *testing.T) {
	trie := coreflamegraph.NewLiveTrie([]string{"comm", "path"}, "count")
	m := NewModel(trie)
	m.paused = true
	m.snapshot = &snapshotNode{Name: "root", Total: 1}
	m.frames = []tuiFrame{{Name: "root", Path: "root"}}
	m.hasNavigableSnapshot = false
	m.lastVersion = 1

	if changed := m.RefreshFromLiveTrie(); changed {
		t.Fatalf("expected paused refresh to freeze after first snapshot even when non-navigable")
	}
	if got, want := m.lastVersion, uint64(1); got != want {
		t.Fatalf("expected paused refresh to keep existing snapshot version, got %d want %d", got, want)
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

func TestHorizontalTraversalFallbackFromRoot(t *testing.T) {
	m := NewModel(nil)
	m.frames = []tuiFrame{
		{Name: "root", Depth: 0, Col: 0, Path: "root"},
		{Name: "A", Depth: 1, Col: 0, Path: "root" + pathSeparator + "A"},
		{Name: "B", Depth: 1, Col: 30, Path: "root" + pathSeparator + "B"},
	}
	m.selectedIdx = 0

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyRight})
	if m.selectedIdx != 1 {
		t.Fatalf("expected right arrow from root to move to first traversable frame, got idx %d", m.selectedIdx)
	}

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'l'}[0], Text: "l"})
	if m.selectedIdx != 2 {
		t.Fatalf("expected vi right key to move to next frame, got idx %d", m.selectedIdx)
	}

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyLeft})
	if m.selectedIdx != 1 {
		t.Fatalf("expected left arrow to move back to previous frame, got idx %d", m.selectedIdx)
	}

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'h'}[0], Text: "h"})
	if m.selectedIdx != 0 {
		t.Fatalf("expected vi left key to move back to root, got idx %d", m.selectedIdx)
	}
}

func TestPageUpJumpsSelectionToTopMostDepth(t *testing.T) {
	m := NewModel(nil)
	m.frames = []tuiFrame{
		{Name: "root", Depth: 0, Col: 0, Path: "root"},
		{Name: "A", Depth: 1, Col: 0, Path: "root" + pathSeparator + "A"},
		{Name: "B", Depth: 1, Col: 40, Path: "root" + pathSeparator + "B"},
		{Name: "A1", Depth: 2, Col: 0, Path: "root" + pathSeparator + "A" + pathSeparator + "A1"},
		{Name: "B1", Depth: 2, Col: 40, Path: "root" + pathSeparator + "B" + pathSeparator + "B1"},
		{Name: "A2", Depth: 3, Col: 0, Path: "root" + pathSeparator + "A" + pathSeparator + "A1" + pathSeparator + "A2"},
		{Name: "B2", Depth: 3, Col: 40, Path: "root" + pathSeparator + "B" + pathSeparator + "B1" + pathSeparator + "B2"},
	}
	m.selectedIdx = mustFrameIndex(t, m.frames, "root"+pathSeparator+"B"+pathSeparator+"B1")

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyPgUp})
	if got, want := m.frames[m.selectedIdx].Path, "root"+pathSeparator+"B"+pathSeparator+"B1"+pathSeparator+"B2"; got != want {
		t.Fatalf("expected pgup to jump to deepest top frame %q, got %q", want, got)
	}
}

func TestPageDownJumpsSelectionToCurrentViewRoot(t *testing.T) {
	m := newZoomModel()
	m.selectedIdx = mustFrameIndex(t, m.frames, "root"+pathSeparator+"A")
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyEnter})
	m.selectedIdx = mustFrameIndex(t, m.frames, "root"+pathSeparator+"A"+pathSeparator+"A1")

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyPgDown})
	if got, want := m.frames[m.selectedIdx].Path, "root"+pathSeparator+"A"; got != want {
		t.Fatalf("expected pgdn to jump to current zoom root %q, got %q", want, got)
	}
}

func TestPausedStateStillAllowsNavigation(t *testing.T) {
	m := NewModel(nil)
	m.frames = []tuiFrame{
		{Name: "root", Depth: 0, Col: 0, Path: "root"},
		{Name: "A", Depth: 1, Col: 0, Path: "root" + pathSeparator + "A"},
	}
	m.paused = true
	m.selectedIdx = 0

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyRight})
	if m.selectedIdx != 1 {
		t.Fatalf("expected navigation to work while paused, got idx %d", m.selectedIdx)
	}
}

func TestMouseClickSelectsFrameAndZooms(t *testing.T) {
	m := newZoomModel()
	targetPath := "root" + pathSeparator + "A"
	targetIdx := mustFrameIndex(t, m.frames, targetPath)

	x, y, ok := firstClickablePointForFrame(m, targetIdx)
	if !ok {
		t.Fatalf("expected clickable point for %q", targetPath)
	}

	next, _ := m.Update(tea.MouseClickMsg{X: x, Y: y, Button: tea.MouseLeft})
	m = next.(Model)

	if got := m.zoomPath; got != targetPath {
		t.Fatalf("expected mouse click to zoom into %q, got %q", targetPath, got)
	}
	if got := m.frames[m.selectedIdx].Path; got != targetPath {
		t.Fatalf("expected clicked frame to remain selected after zoom, got %q", got)
	}
}

func TestMouseClickOutsideBarsDoesNotChangeSelectionOrZoom(t *testing.T) {
	m := newZoomModel()
	beforeSelection := m.selectedIdx
	beforeZoom := m.zoomPath

	next, _ := m.Update(tea.MouseClickMsg{X: 1, Y: 0, Button: tea.MouseLeft}) // toolbar row
	m = next.(Model)

	if m.selectedIdx != beforeSelection {
		t.Fatalf("expected toolbar click to preserve selection, got idx %d want %d", m.selectedIdx, beforeSelection)
	}
	if m.zoomPath != beforeZoom {
		t.Fatalf("expected toolbar click to preserve zoom path, got %q want %q", m.zoomPath, beforeZoom)
	}
}

func TestZoomKeepsNarrowLineageRail(t *testing.T) {
	m := newZoomModel()
	targetPath := "root" + pathSeparator + "A"
	targetIdx := mustFrameIndex(t, m.frames, targetPath)
	selectedWidth := m.frames[targetIdx].Width
	expectedRailWidth := min(max(selectedWidth, 3), max(3, m.width/3))

	m.selectedIdx = targetIdx
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyEnter})
	m = settleFlameAnimation(t, m)

	rootIdx := mustFrameIndex(t, m.frames, "root")
	zoomIdx := mustFrameIndex(t, m.frames, targetPath)
	if m.frames[rootIdx].Width != expectedRailWidth {
		t.Fatalf("expected root lineage width %d, got %d", expectedRailWidth, m.frames[rootIdx].Width)
	}
	if m.frames[zoomIdx].Width != expectedRailWidth {
		t.Fatalf("expected zoom lineage width %d, got %d", expectedRailWidth, m.frames[zoomIdx].Width)
	}
	if m.frames[rootIdx].Col != 0 || m.frames[zoomIdx].Col != 0 {
		t.Fatalf("expected lineage rail at column 0, got root=%d zoom=%d", m.frames[rootIdx].Col, m.frames[zoomIdx].Col)
	}
}

func TestMouseClickOnLineageAncestorUndoesToThatZoomLevel(t *testing.T) {
	m := newZoomModel()
	m.selectedIdx = mustFrameIndex(t, m.frames, "root"+pathSeparator+"A")
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyEnter})
	m = settleFlameAnimation(t, m)
	m.selectedIdx = mustFrameIndex(t, m.frames, "root"+pathSeparator+"A"+pathSeparator+"A1")
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyEnter})
	m = settleFlameAnimation(t, m)
	if got, want := m.zoomPath, "root"+pathSeparator+"A"+pathSeparator+"A1"; got != want {
		t.Fatalf("expected nested zoom path %q, got %q", want, got)
	}

	ancestorPath := "root" + pathSeparator + "A"
	ancestorIdx := mustFrameIndex(t, m.frames, ancestorPath)
	x, y, ok := firstClickablePointForFrame(m, ancestorIdx)
	if !ok {
		t.Fatalf("expected clickable lineage point for ancestor %q", ancestorPath)
	}

	next, _ := m.Update(tea.MouseClickMsg{X: x, Y: y, Button: tea.MouseLeft})
	m = next.(Model)
	if got := m.zoomPath; got != ancestorPath {
		t.Fatalf("expected click on lineage ancestor to undo zoom to %q, got %q", ancestorPath, got)
	}
}

func TestStaticFixtureArrowTraversalVisitsAllFrames(t *testing.T) {
	trie := coreflamegraph.NewLiveTrie([]string{"comm", "path", "tracepoint"}, "count")
	coreflamegraph.SeedTestFlameData(trie)

	m := NewModel(trie)
	m.SetViewport(180, 40)
	if changed := m.RefreshFromLiveTrie(); !changed {
		t.Fatalf("expected seeded fixture refresh to load frames")
	}
	if len(m.frames) < 2 {
		t.Fatalf("expected seeded fixture to contain navigable frames, got %d", len(m.frames))
	}

	visited := map[int]bool{m.selectedIdx: true}
	for i := 0; i < len(m.frames)*4; i++ {
		m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyRight})
		visited[m.selectedIdx] = true
	}
	for i := 0; i < len(m.frames)*4; i++ {
		m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyLeft})
		visited[m.selectedIdx] = true
	}

	if got, want := len(visited), len(m.frames); got != want {
		t.Fatalf("expected arrow traversal to visit all frames: visited=%d frames=%d", got, want)
	}
	if !strings.Contains(m.View().Content, "sel:") {
		t.Fatalf("expected view to expose selected-frame status line")
	}
}

func TestLiveFixtureArrowTraversalWhileStreamingVisitsAllFrames(t *testing.T) {
	trie := coreflamegraph.NewLiveTrie([]string{"comm", "path", "tracepoint"}, "count")
	coreflamegraph.SeedTestLiveFlameData(trie, 0)

	m := NewModel(trie)
	m.SetViewport(180, 40)
	if changed := m.RefreshFromLiveTrie(); !changed {
		t.Fatalf("expected initial refresh to load frames")
	}
	if len(m.frames) < 2 {
		t.Fatalf("expected seeded fixture to contain navigable frames, got %d", len(m.frames))
	}

	selectedPath := func(model Model) string {
		if len(model.frames) == 0 || model.selectedIdx < 0 || model.selectedIdx >= len(model.frames) {
			return ""
		}
		return model.frames[model.selectedIdx].Path
	}

	visitedPaths := map[string]bool{selectedPath(m): true}
	moves := 0
	for i := 0; i < len(m.frames)*4; i++ {
		trie.Reset()
		coreflamegraph.SeedTestLiveFlameData(trie, uint64(i+1))
		if changed := m.RefreshFromLiveTrie(); !changed {
			t.Fatalf("expected refresh after synthetic live ingest at step %d", i)
		}
		before := selectedPath(m)
		m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyRight})
		after := selectedPath(m)
		if after != before {
			moves++
		}
		visitedPaths[after] = true
	}
	for i := 0; i < len(m.frames)*4; i++ {
		trie.Reset()
		coreflamegraph.SeedTestLiveFlameData(trie, uint64(i+1+len(m.frames)*4))
		if changed := m.RefreshFromLiveTrie(); !changed {
			t.Fatalf("expected refresh after synthetic live ingest (reverse) at step %d", i)
		}
		before := selectedPath(m)
		m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyLeft})
		after := selectedPath(m)
		if after != before {
			moves++
		}
		visitedPaths[after] = true
	}

	if moves == 0 {
		t.Fatalf("expected live-stream navigation to change selection at least once")
	}
	if len(visitedPaths) < 8 {
		t.Fatalf("expected traversal across live updates to reach multiple frame paths, got %d", len(visitedPaths))
	}
}

func TestSelectionRestoresByPathAcrossLiveRefresh(t *testing.T) {
	trie := coreflamegraph.NewLiveTrie([]string{"comm", "path", "tracepoint"}, "count")
	coreflamegraph.SeedTestLiveFlameData(trie, 0)

	m := NewModel(trie)
	m.SetViewport(180, 40)
	if changed := m.RefreshFromLiveTrie(); !changed {
		t.Fatalf("expected initial refresh")
	}
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyRight})
	selected := m.frames[m.selectedIdx].Path
	if selected == "" || selected == "root" {
		t.Fatalf("expected selection to move off root, got %q", selected)
	}

	trie.Reset()
	coreflamegraph.SeedTestLiveFlameData(trie, 2)
	if changed := m.RefreshFromLiveTrie(); !changed {
		t.Fatalf("expected refresh after live update")
	}
	if got := m.frames[m.selectedIdx].Path; got != selected {
		t.Fatalf("expected selection path to persist across refresh, got %q want %q", got, selected)
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

func TestArrowDownFallsBackToVisibleDepthFromRoot(t *testing.T) {
	m := NewModel(nil)
	m.frames = []tuiFrame{
		{Name: "root", Depth: 0, Col: 0, Path: "root"},
		{Name: "child", Depth: 1, Col: 0, Path: "root" + pathSeparator + "child"},
	}
	m.selectedIdx = 0

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyDown})
	if m.selectedIdx != 1 {
		t.Fatalf("expected down arrow to move selection to child when root has no shallower row, got %d", m.selectedIdx)
	}
}

func TestArrowEscapeSequencesAreRecognized(t *testing.T) {
	tests := []struct {
		key      string
		dir      string
		ansiCode byte
	}{
		{key: "\x1b[A", dir: "up", ansiCode: 'A'},
		{key: "\x1b[B", dir: "down", ansiCode: 'B'},
		{key: "\x1b[C", dir: "right", ansiCode: 'C'},
		{key: "\x1b[D", dir: "left", ansiCode: 'D'},
		{key: "\x1bOA", dir: "up", ansiCode: 'A'},   // application mode
		{key: "\x1bOB", dir: "down", ansiCode: 'B'}, // application mode
		{key: "\x1b[1;2A", dir: "up", ansiCode: 'A'},
	}
	for _, tc := range tests {
		if !keyMatchesDirection(tc.key, tc.dir, tc.ansiCode) {
			t.Fatalf("expected key %q to match %s", tc.key, tc.dir)
		}
	}
}

func TestFilteredNavigationSkipsHiddenBranches(t *testing.T) {
	m := NewModel(nil)
	m.frames = []tuiFrame{
		{Name: "root", Depth: 0, Col: 0, Row: 0, Path: "root"},
		{Name: "keep", Depth: 1, Col: 0, Row: 1, Path: "root" + pathSeparator + "keep"},
		{Name: "drop", Depth: 1, Col: 40, Row: 1, Path: "root" + pathSeparator + "drop"},
	}
	m.searchQuery = "keep"
	m.recomputeFilterState()
	m.selectedIdx = 1

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyRight})
	if m.selectedIdx != 1 {
		t.Fatalf("expected sibling navigation to stay on visible filtered branch, got idx %d", m.selectedIdx)
	}

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyDown})
	if m.selectedIdx != 0 {
		t.Fatalf("expected down key to move to visible root ancestor, got idx %d", m.selectedIdx)
	}
}

func TestZoomInUndoSingleLevelAndNestedEsc(t *testing.T) {
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

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyEsc})
	if got, want := m.zoomPath, "root"+pathSeparator+"A"; got != want {
		t.Fatalf("expected zoomPath after esc undo %q, got %q", want, got)
	}
	if len(m.zoomStack) != 1 {
		t.Fatalf("expected one stack entry after esc undo, got %d", len(m.zoomStack))
	}

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyEsc})
	if m.zoomPath != "" || m.zoomRoot != nil || len(m.zoomStack) != 0 {
		t.Fatalf("expected second esc undo to return to root state, got path=%q root=%+v stack=%d", m.zoomPath, m.zoomRoot, len(m.zoomStack))
	}
}

func TestZoomResetToRoot(t *testing.T) {
	m := newZoomModel()
	m.selectedIdx = mustFrameIndex(t, m.frames, "root"+pathSeparator+"A")
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyEnter})
	m.selectedIdx = mustFrameIndex(t, m.frames, "root"+pathSeparator+"A"+pathSeparator+"A1")
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyEnter})
	if m.zoomPath == "" || len(m.zoomStack) == 0 {
		t.Fatalf("expected nested zoom before reset")
	}

	m.zoomReset()
	if m.zoomPath != "" || m.zoomRoot != nil || len(m.zoomStack) != 0 {
		t.Fatalf("expected explicit zoom reset to clear zoom stack, got path=%q root=%+v stack=%d", m.zoomPath, m.zoomRoot, len(m.zoomStack))
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
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeySpace, Text: " "})
	if m.paused {
		t.Fatalf("expected space key to toggle pause off")
	}
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeySpace, Text: " "})
	if !m.paused {
		t.Fatalf("expected space key to toggle pause on")
	}
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'p'}[0], Text: "p"})
	if m.paused {
		t.Fatalf("expected p key to toggle pause off")
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

func TestViewIncludesSelectionStatusBar(t *testing.T) {
	m := NewModel(nil)
	m.width = 120
	m.height = 20
	m.frames = []tuiFrame{
		{Name: "root", Depth: 0, Col: 0, Row: 0, Width: 120, Total: 100, Percent: 100, Path: "root"},
		{Name: "child", Depth: 1, Col: 0, Row: 1, Width: 60, Total: 40, Percent: 40, Path: "root" + pathSeparator + "child"},
	}
	m.selectedIdx = 1
	m.globalTotal = 100

	view := m.View().Content
	if !strings.Contains(view, "[LIVE] sel:2/2 child") {
		t.Fatalf("expected selection status bar to include selected frame info, got %q", view)
	}
	if !strings.Contains(view, "40.00% of total events") {
		t.Fatalf("expected selection status bar to include selected share, got %q", view)
	}
}

func TestViewSelectionStatusUsesBytesLabelInBytesMode(t *testing.T) {
	m := NewModel(nil)
	m.width = 120
	m.height = 20
	m.countField = "bytes"
	m.frames = []tuiFrame{
		{Name: "root", Depth: 0, Col: 0, Row: 0, Width: 120, Total: 200, Percent: 100, Path: "root"},
		{Name: "child", Depth: 1, Col: 0, Row: 1, Width: 60, Total: 80, Percent: 40, Path: "root" + pathSeparator + "child"},
	}
	m.selectedIdx = 1
	m.globalTotal = 200

	view := m.View().Content
	if !strings.Contains(view, "40.00% of total bytes") {
		t.Fatalf("expected bytes-based selection share label, got %q", view)
	}
}

func TestViewFitsViewportHeightAndKeepsSearchFooterVisible(t *testing.T) {
	m := NewModel(nil)
	m.width = 100
	m.height = 12
	m.frames = []tuiFrame{
		{Name: "root", Depth: 0, Col: 0, Row: 0, Width: 100, Total: 100, Percent: 100, Path: "root"},
		{Name: "child", Depth: 1, Col: 0, Row: 1, Width: 80, Total: 80, Percent: 80, Path: "root" + pathSeparator + "child"},
	}
	m.selectedIdx = 1
	m.globalTotal = 100
	m.searchActive = true
	m.searchInput.SetValue("child")

	view := m.View().Content
	lines := strings.Split(view, "\n")
	if got, max := len(lines), m.height; got > max {
		t.Fatalf("expected flame view to fit viewport height <=%d, got %d lines", max, got)
	}
	if !strings.Contains(view, "matches") {
		t.Fatalf("expected search footer to remain visible in viewport, got %q", view)
	}
	if !strings.Contains(view, "[LIVE] sel:2/2 child") {
		t.Fatalf("expected selection status line to remain visible, got %q", view)
	}
}

func TestViewFilterSelectionStatusUsesFilteredTotalAndKeepsContextVisible(t *testing.T) {
	snapshot := &snapshotNode{
		Name:  "root",
		Total: 100,
		Children: []*snapshotNode{
			{
				Name:  "keep",
				Total: 60,
				Children: []*snapshotNode{
					{Name: "needle", Total: 60},
				},
			},
			{
				Name:  "drop",
				Total: 40,
				Children: []*snapshotNode{
					{Name: "noise", Total: 40},
				},
			},
		},
	}
	m := NewModel(nil)
	m.width = 220
	m.height = 12
	m.frames = BuildTerminalLayout(snapshot, m.width, m.height)
	m.globalTotal = 100
	m.selectedIdx = mustFrameIndex(t, m.frames, "root"+pathSeparator+"keep"+pathSeparator+"needle")
	m.searchQuery = "needle"
	m.recomputeFilterState()

	view := m.View().Content
	if !strings.Contains(view, "100.00% of filtered events") {
		t.Fatalf("expected filtered selection share in status line, got %q", view)
	}
	if !strings.Contains(view, "drop") || !strings.Contains(view, "noise") {
		t.Fatalf("expected non-matching branches to remain visible while filtering, got %q", view)
	}
}

func TestControlCycleFieldOrderReconfiguresLiveTrie(t *testing.T) {
	liveTrie := coreflamegraph.NewLiveTrie([]string{"comm", "path", "tracepoint"}, "count")
	m := NewModel(liveTrie)
	initial := append([]string(nil), m.fieldPresets[m.fieldIndex]...)
	expectedNextIdx := (m.fieldIndex + 1) % len(m.fieldPresets)

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'o'}[0], Text: "o"})
	if m.fieldIndex != expectedNextIdx {
		t.Fatalf("expected field index to advance to %d, got %d", expectedNextIdx, m.fieldIndex)
	}
	next := m.fieldPresets[m.fieldIndex]
	if reflect.DeepEqual(initial, next) {
		t.Fatalf("expected next field preset to differ from initial")
	}
	if got := liveTrie.Fields(); !reflect.DeepEqual(got, next) {
		t.Fatalf("expected live trie fields %v, got %v", next, got)
	}
}

func TestControlMetricToggleReconfiguresLiveTrieCountField(t *testing.T) {
	liveTrie := coreflamegraph.NewLiveTrie([]string{"comm", "path", "tracepoint"}, "count")
	m := NewModel(liveTrie)

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'b'}[0], Text: "b"})
	if got, want := m.countField, "bytes"; got != want {
		t.Fatalf("expected model count field %q, got %q", want, got)
	}
	if got, want := liveTrie.CountField(), "bytes"; got != want {
		t.Fatalf("expected live trie count field %q, got %q", want, got)
	}
	if got, want := m.statusMessage, "Metric: bytes (new baseline)"; got != want {
		t.Fatalf("expected metric toggle status %q, got %q", want, got)
	}

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'b'}[0], Text: "b"})
	if got, want := m.countField, "count"; got != want {
		t.Fatalf("expected model count field %q after second toggle, got %q", want, got)
	}
	if got, want := liveTrie.CountField(), "count"; got != want {
		t.Fatalf("expected live trie count field %q after second toggle, got %q", want, got)
	}
}

func TestNewModelAlignsPresetIndexToLiveTrieFields(t *testing.T) {
	liveTrie := coreflamegraph.NewLiveTrie([]string{"comm", "path", "tracepoint"}, "count")
	m := NewModel(liveTrie)
	if got, want := m.fieldPresets[m.fieldIndex], []string{"comm", "path", "tracepoint"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("expected model field preset to align with trie fields, got %v want %v", got, want)
	}
}

func TestNewModelAlignsCountFieldToLiveTrie(t *testing.T) {
	liveTrie := coreflamegraph.NewLiveTrie([]string{"comm", "path", "tracepoint"}, "bytes")
	m := NewModel(liveTrie)
	if got, want := m.countField, "bytes"; got != want {
		t.Fatalf("expected model count field to align with trie field, got %q want %q", got, want)
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

func TestRebuildKeepsSelectionOnVisibleRowsWhenTruncated(t *testing.T) {
	m := NewModel(nil)
	m.width = 80
	m.height = 4 // only 2 render rows remain after toolbar+status
	m.snapshot = &snapshotNode{
		Name: "root",
		Children: []*snapshotNode{
			{
				Name: "a",
				Children: []*snapshotNode{
					{
						Name: "b",
						Children: []*snapshotNode{
							{Name: "c", Total: 5},
						},
					},
				},
			},
		},
	}

	m.rebuildFrames(false)
	if len(m.frames) == 0 {
		t.Fatalf("expected rebuilt frames")
	}
	rowOffset := m.visibleRowOffset()
	if m.frames[m.selectedIdx].Row < rowOffset {
		t.Fatalf("expected selected frame row %d to be visible (offset=%d)", m.frames[m.selectedIdx].Row, rowOffset)
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

func firstClickablePointForFrame(m Model, frameIdx int) (x, y int, ok bool) {
	if frameIdx < 0 || frameIdx >= len(m.frames) {
		return 0, 0, false
	}
	frame := m.frames[frameIdx]
	left := frame.Col
	right := min(m.width, frame.Col+frame.Width)
	if left < 0 {
		left = 0
	}
	if right <= left {
		return 0, 0, false
	}
	for row := 0; row < m.height; row++ {
		for col := left; col < right; col++ {
			if m.frameIndexAt(col, row) == frameIdx {
				return col, row, true
			}
		}
	}
	return 0, 0, false
}

func settleFlameAnimation(t *testing.T, m Model) Model {
	t.Helper()
	for i := 0; i < 240 && m.animating; i++ {
		next, _ := m.Update(animTickMsg{})
		m = next.(Model)
	}
	if m.animating {
		t.Fatalf("expected flame animation to settle within 240 ticks")
	}
	return m
}
