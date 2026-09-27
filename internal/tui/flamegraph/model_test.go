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
	if m.search.matchIndices == nil {
		t.Fatalf("expected matchIndices map to be initialized")
	}
	if len(m.fieldPresets) == 0 {
		t.Fatalf("expected default field presets to be initialized")
	}
	if got, want := m.fieldPresets[0], []string{"comm", "tracepoint", "path"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("default field preset[0] = %v, want %v", got, want)
	}
	if got, want := m.fieldPresets[5], []string{"tracepoint", "comm", "pid"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("default field preset[5] = %v, want %v", got, want)
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
	trie := coreflamegraph.NewLiveTrie([]string{"comm", "path"}, "count", "count")
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
	trie := coreflamegraph.NewLiveTrie([]string{"comm", "path"}, "count", "count")
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

func TestRefreshFromLiveTriePausedBlocksAfterAnySnapshot(t *testing.T) {
	trie := coreflamegraph.NewLiveTrie([]string{"comm", "path"}, "count", "count")
	m := NewModel(trie)
	m.paused = true
	m.snapshot = &snapshotNode{Name: "root", Total: 1}
	m.anim.frames = []tuiFrame{{Name: "root", Path: "root"}}
	m.lastVersion = 1

	if changed := m.RefreshFromLiveTrie(); changed {
		t.Fatalf("expected paused refresh to freeze after the first snapshot")
	}
	if got, want := m.lastVersion, uint64(1); got != want {
		t.Fatalf("expected paused refresh to keep existing snapshot version, got %d want %d", got, want)
	}
}

func TestKeyboardNavigationDeepNarrowTree(t *testing.T) {
	m := NewModel(nil)
	m.anim.frames = []tuiFrame{
		{Name: "root", Depth: 0, Col: 0, Path: "root"},
		{Name: "child", Depth: 1, Col: 0, Path: "root" + pathSeparator + "child"},
		{Name: "leaf", Depth: 2, Col: 0, Path: "root" + pathSeparator + "child" + pathSeparator + "leaf"},
	}

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'k'}[0], Text: "k"})
	if m.sel.selectedIdx != 1 {
		t.Fatalf("expected selection to move deeper to idx 1, got %d", m.sel.selectedIdx)
	}
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'k'}[0], Text: "k"})
	if m.sel.selectedIdx != 2 {
		t.Fatalf("expected selection to move deeper to idx 2, got %d", m.sel.selectedIdx)
	}
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'j'}[0], Text: "j"})
	if m.sel.selectedIdx != 1 {
		t.Fatalf("expected selection to move shallower to idx 1, got %d", m.sel.selectedIdx)
	}
}

func TestKeyboardNavigationShallowWideSiblings(t *testing.T) {
	m := NewModel(nil)
	m.anim.frames = []tuiFrame{
		{Name: "root", Depth: 0, Col: 0, Path: "root"},
		{Name: "A", Depth: 1, Col: 0, Path: "root" + pathSeparator + "A"},
		{Name: "B", Depth: 1, Col: 30, Path: "root" + pathSeparator + "B"},
		{Name: "C", Depth: 1, Col: 60, Path: "root" + pathSeparator + "C"},
	}

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'k'}[0], Text: "k"})
	if m.sel.selectedIdx != 1 {
		t.Fatalf("expected first deeper frame to be A, got idx %d", m.sel.selectedIdx)
	}
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'l'}[0], Text: "l"})
	if m.sel.selectedIdx != 2 {
		t.Fatalf("expected next sibling B, got idx %d", m.sel.selectedIdx)
	}
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'l'}[0], Text: "l"})
	if m.sel.selectedIdx != 3 {
		t.Fatalf("expected next sibling C, got idx %d", m.sel.selectedIdx)
	}
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'l'}[0], Text: "l"})
	if m.sel.selectedIdx != 3 {
		t.Fatalf("expected selection to clamp at last sibling, got idx %d", m.sel.selectedIdx)
	}
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'h'}[0], Text: "h"})
	if m.sel.selectedIdx != 2 {
		t.Fatalf("expected previous sibling B, got idx %d", m.sel.selectedIdx)
	}
}

func TestHorizontalTraversalFallbackFromRoot(t *testing.T) {
	m := NewModel(nil)
	m.anim.frames = []tuiFrame{
		{Name: "root", Depth: 0, Col: 0, Path: "root"},
		{Name: "A", Depth: 1, Col: 0, Path: "root" + pathSeparator + "A"},
		{Name: "B", Depth: 1, Col: 30, Path: "root" + pathSeparator + "B"},
	}
	m.sel.selectedIdx = 0

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyRight})
	if m.sel.selectedIdx != 1 {
		t.Fatalf("expected right arrow from root to move to first traversable frame, got idx %d", m.sel.selectedIdx)
	}

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'l'}[0], Text: "l"})
	if m.sel.selectedIdx != 2 {
		t.Fatalf("expected vi right key to move to next frame, got idx %d", m.sel.selectedIdx)
	}

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyLeft})
	if m.sel.selectedIdx != 1 {
		t.Fatalf("expected left arrow to move back to previous frame, got idx %d", m.sel.selectedIdx)
	}

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'h'}[0], Text: "h"})
	if m.sel.selectedIdx != 0 {
		t.Fatalf("expected vi left key to move back to root, got idx %d", m.sel.selectedIdx)
	}
}

func TestPageUpJumpsSelectionToTopMostDepth(t *testing.T) {
	m := NewModel(nil)
	m.anim.frames = []tuiFrame{
		{Name: "root", Depth: 0, Col: 0, Path: "root"},
		{Name: "A", Depth: 1, Col: 0, Path: "root" + pathSeparator + "A"},
		{Name: "B", Depth: 1, Col: 40, Path: "root" + pathSeparator + "B"},
		{Name: "A1", Depth: 2, Col: 0, Path: "root" + pathSeparator + "A" + pathSeparator + "A1"},
		{Name: "B1", Depth: 2, Col: 40, Path: "root" + pathSeparator + "B" + pathSeparator + "B1"},
		{Name: "A2", Depth: 3, Col: 0, Path: "root" + pathSeparator + "A" + pathSeparator + "A1" + pathSeparator + "A2"},
		{Name: "B2", Depth: 3, Col: 40, Path: "root" + pathSeparator + "B" + pathSeparator + "B1" + pathSeparator + "B2"},
	}
	m.sel.selectedIdx = mustFrameIndex(t, m.anim.frames, "root"+pathSeparator+"B"+pathSeparator+"B1")

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyPgUp})
	if got, want := m.anim.frames[m.sel.selectedIdx].Path, "root"+pathSeparator+"B"+pathSeparator+"B1"+pathSeparator+"B2"; got != want {
		t.Fatalf("expected pgup to jump to deepest top frame %q, got %q", want, got)
	}
}

func TestPageDownJumpsSelectionToCurrentViewRoot(t *testing.T) {
	m := newZoomModel()
	m.sel.selectedIdx = mustFrameIndex(t, m.anim.frames, "root"+pathSeparator+"A")
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyEnter})
	m.sel.selectedIdx = mustFrameIndex(t, m.anim.frames, "root"+pathSeparator+"A"+pathSeparator+"A1")

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyPgDown})
	if got, want := m.anim.frames[m.sel.selectedIdx].Path, "root"+pathSeparator+"A"; got != want {
		t.Fatalf("expected pgdn to jump to current zoom root %q, got %q", want, got)
	}
}

func TestPausedStateStillAllowsNavigation(t *testing.T) {
	m := NewModel(nil)
	m.anim.frames = []tuiFrame{
		{Name: "root", Depth: 0, Col: 0, Path: "root"},
		{Name: "A", Depth: 1, Col: 0, Path: "root" + pathSeparator + "A"},
	}
	m.paused = true
	m.sel.selectedIdx = 0

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyRight})
	if m.sel.selectedIdx != 1 {
		t.Fatalf("expected navigation to work while paused, got idx %d", m.sel.selectedIdx)
	}
}

func TestMouseClickSelectsFrameAndZooms(t *testing.T) {
	m := newZoomModel()
	targetPath := "root" + pathSeparator + "A"
	targetIdx := mustFrameIndex(t, m.anim.frames, targetPath)

	x, y, ok := firstClickablePointForFrame(m, targetIdx)
	if !ok {
		t.Fatalf("expected clickable point for %q", targetPath)
	}

	next, _ := m.Update(tea.MouseClickMsg{X: x, Y: y, Button: tea.MouseLeft})
	m = next.(*Model)

	if got := m.zoom.zoomPath; got != targetPath {
		t.Fatalf("expected mouse click to zoom into %q, got %q", targetPath, got)
	}
	if got := m.anim.frames[m.sel.selectedIdx].Path; got != targetPath {
		t.Fatalf("expected clicked frame to remain selected after zoom, got %q", got)
	}
}

func TestMouseClickOutsideBarsDoesNotChangeSelectionOrZoom(t *testing.T) {
	m := newZoomModel()
	beforeSelection := m.sel.selectedIdx
	beforeZoom := m.zoom.zoomPath

	next, _ := m.Update(tea.MouseClickMsg{X: 1, Y: 0, Button: tea.MouseLeft}) // toolbar row
	m = next.(*Model)

	if m.sel.selectedIdx != beforeSelection {
		t.Fatalf("expected toolbar click to preserve selection, got idx %d want %d", m.sel.selectedIdx, beforeSelection)
	}
	if m.zoom.zoomPath != beforeZoom {
		t.Fatalf("expected toolbar click to preserve zoom path, got %q want %q", m.zoom.zoomPath, beforeZoom)
	}
}

func TestZoomLineageSpansFullViewportWidth(t *testing.T) {
	m := newZoomModel()
	targetPath := "root" + pathSeparator + "A"
	targetIdx := mustFrameIndex(t, m.anim.frames, targetPath)

	m.sel.selectedIdx = targetIdx
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyEnter})
	m = settleFlameAnimation(t, m)

	rootIdx := mustFrameIndex(t, m.anim.frames, "root")
	zoomIdx := mustFrameIndex(t, m.anim.frames, targetPath)
	if m.anim.frames[rootIdx].Width != m.width {
		t.Fatalf("expected root lineage width %d, got %d", m.width, m.anim.frames[rootIdx].Width)
	}
	if m.anim.frames[zoomIdx].Width != m.width {
		t.Fatalf("expected zoom lineage width %d, got %d", m.width, m.anim.frames[zoomIdx].Width)
	}
	if m.anim.frames[rootIdx].Col != 0 || m.anim.frames[zoomIdx].Col != 0 {
		t.Fatalf("expected full-width lineage bars at column 0, got root=%d zoom=%d", m.anim.frames[rootIdx].Col, m.anim.frames[zoomIdx].Col)
	}
}

func TestZoomLineageKeepsAllFramesWithinViewportWidth(t *testing.T) {
	m := newZoomModel()
	m.sel.selectedIdx = mustFrameIndex(t, m.anim.frames, "root"+pathSeparator+"A")
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyEnter})
	m = settleFlameAnimation(t, m)

	for _, frame := range m.anim.frames {
		if frame.Col+frame.Width > m.width {
			t.Fatalf("frame exceeds viewport width %d: %+v", m.width, frame)
		}
	}
}

func TestZoomLineageDoesNotShiftZoomedSubtreeHorizontally(t *testing.T) {
	m := newZoomModel()
	rootPath := "root" + pathSeparator + "A"
	childPath := rootPath + pathSeparator + "A1"
	m.sel.selectedIdx = mustFrameIndex(t, m.anim.frames, rootPath)
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyEnter})
	m = settleFlameAnimation(t, m)

	rootIdx := mustFrameIndex(t, m.anim.frames, rootPath)
	childIdx := mustFrameIndex(t, m.anim.frames, childPath)
	if got := m.anim.frames[rootIdx].Col; got != 0 {
		t.Fatalf("expected zoom lineage root column 0, got %d", got)
	}
	if got := m.anim.frames[childIdx].Col; got != 0 {
		t.Fatalf("expected first child column to stay aligned at 0, got %d", got)
	}
}

func TestZoomLineageParentsAreNeverNarrowerThanChildren(t *testing.T) {
	m := newZoomModel()
	rootPath := "root" + pathSeparator + "A"
	m.sel.selectedIdx = mustFrameIndex(t, m.anim.frames, rootPath)
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyEnter})
	m = settleFlameAnimation(t, m)

	for _, frame := range m.anim.frames {
		parentPath := parentFramePath(frame.Path)
		if parentPath == "" {
			continue
		}
		parentIdx := m.anim.indexByPath(parentPath)
		if parentIdx < 0 {
			continue
		}
		parent := m.anim.frames[parentIdx]
		if parent.Width < frame.Width {
			t.Fatalf("expected parent %q width %d >= child %q width %d", parent.Path, parent.Width, frame.Path, frame.Width)
		}
	}
}

func TestApplyZoomLineagePreservesHeightTotals(t *testing.T) {
	snapshot := &snapshotNode{
		Name: "root",
		Children: []*snapshotNode{
			{
				Name: "A",
				Children: []*snapshotNode{
					{Name: "A1", Total: 7, HeightTotal: 70},
					{Name: "A2", Total: 3, HeightTotal: 30},
				},
			},
			{Name: "B", Total: 4, HeightTotal: 40},
		},
	}
	zoomPath := "root" + pathSeparator + "A"
	zoomRoot := findNodeByPath(snapshot, zoomPath)
	if zoomRoot == nil {
		t.Fatalf("expected zoom root for %q", zoomPath)
	}
	zoomFrames := buildTerminalLayoutWithPath(zoomRoot, 100, 20, zoomPath)
	zoomRootFrame := mustFindFrame(t, zoomFrames, zoomPath)
	if got, want := zoomRootFrame.HeightTotal, uint64(100); got != want {
		t.Fatalf("zoom root HeightTotal = %d, want %d before lineage", got, want)
	}

	frames := applyZoomLineage(zoomFrames, snapshot, zoomPath, 100)
	root := mustFindFrame(t, frames, "root")
	zoom := mustFindFrame(t, frames, zoomPath)
	leaf := mustFindFrame(t, frames, zoomPath+pathSeparator+"A1")

	if got, want := root.HeightTotal, uint64(140); got != want {
		t.Fatalf("lineage root HeightTotal = %d, want %d", got, want)
	}
	if got, want := zoom.HeightTotal, zoomRootFrame.HeightTotal; got != want {
		t.Fatalf("lineage zoom HeightTotal = %d, want %d", got, want)
	}
	if got, want := leaf.HeightTotal, uint64(70); got != want {
		t.Fatalf("descendant HeightTotal = %d, want %d", got, want)
	}
}

func TestMouseClickOnLineageAncestorUndoesToThatZoomLevel(t *testing.T) {
	m := newZoomModel()
	m.sel.selectedIdx = mustFrameIndex(t, m.anim.frames, "root"+pathSeparator+"A")
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyEnter})
	m = settleFlameAnimation(t, m)
	m.sel.selectedIdx = mustFrameIndex(t, m.anim.frames, "root"+pathSeparator+"A"+pathSeparator+"A1")
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyEnter})
	m = settleFlameAnimation(t, m)
	if got, want := m.zoom.zoomPath, "root"+pathSeparator+"A"+pathSeparator+"A1"; got != want {
		t.Fatalf("expected nested zoom path %q, got %q", want, got)
	}

	ancestorPath := "root" + pathSeparator + "A"
	ancestorIdx := mustFrameIndex(t, m.anim.frames, ancestorPath)
	x, y, ok := firstClickablePointForFrame(m, ancestorIdx)
	if !ok {
		t.Fatalf("expected clickable lineage point for ancestor %q", ancestorPath)
	}

	next, _ := m.Update(tea.MouseClickMsg{X: x, Y: y, Button: tea.MouseLeft})
	m = next.(*Model)
	if got := m.zoom.zoomPath; got != ancestorPath {
		t.Fatalf("expected click on lineage ancestor to undo zoom to %q, got %q", ancestorPath, got)
	}
}

func TestMouseClickDirectDeepZoomThenAncestorClickReRootsToAncestor(t *testing.T) {
	m := newZoomModel()
	deepPath := "root" + pathSeparator + "A" + pathSeparator + "A1"
	deepIdx := mustFrameIndex(t, m.anim.frames, deepPath)
	x, y, ok := firstClickablePointForFrame(m, deepIdx)
	if !ok {
		t.Fatalf("expected clickable point for %q", deepPath)
	}

	next, _ := m.Update(tea.MouseClickMsg{X: x, Y: y, Button: tea.MouseLeft})
	m = next.(*Model)
	if got := m.zoom.zoomPath; got != deepPath {
		t.Fatalf("expected direct deep click to zoom into %q, got %q", deepPath, got)
	}

	ancestorPath := "root" + pathSeparator + "A"
	ancestorIdx := mustFrameIndex(t, m.anim.frames, ancestorPath)
	x, y, ok = firstClickablePointForFrame(m, ancestorIdx)
	if !ok {
		t.Fatalf("expected clickable point for ancestor %q", ancestorPath)
	}

	next, _ = m.Update(tea.MouseClickMsg{X: x, Y: y, Button: tea.MouseLeft})
	m = next.(*Model)
	if got := m.zoom.zoomPath; got != ancestorPath {
		t.Fatalf("expected ancestor click to re-root to %q, got %q", ancestorPath, got)
	}
	if got := m.currentRootPath(); got != ancestorPath {
		t.Fatalf("expected current root %q after ancestor click, got %q", ancestorPath, got)
	}
	if idx := mustFrameIndex(t, m.anim.frames, ancestorPath); m.anim.frames[idx].Width != m.width {
		t.Fatalf("expected ancestor %q to span full width %d, got %d", ancestorPath, m.width, m.anim.frames[idx].Width)
	}
}

func TestMouseClickDirectDeepZoomUndoReturnsToRoot(t *testing.T) {
	m := newZoomModel()
	deepPath := "root" + pathSeparator + "A" + pathSeparator + "A1"
	deepIdx := mustFrameIndex(t, m.anim.frames, deepPath)
	x, y, ok := firstClickablePointForFrame(m, deepIdx)
	if !ok {
		t.Fatalf("expected clickable point for %q", deepPath)
	}

	next, _ := m.Update(tea.MouseClickMsg{X: x, Y: y, Button: tea.MouseLeft})
	m = next.(*Model)
	if got, want := m.zoom.zoomPath, deepPath; got != want {
		t.Fatalf("expected direct deep click to zoom into %q, got %q", want, got)
	}
	if got, want := len(m.zoom.zoomStack), 1; got != want {
		t.Fatalf("expected single undo step after direct deep click, got %d", got)
	}

	m.zoomUndo()
	if m.zoom.zoomPath != "" {
		t.Fatalf("expected undo after direct deep click to return to root, got %q", m.zoom.zoomPath)
	}
	if len(m.zoom.zoomStack) != 0 {
		t.Fatalf("expected zoom stack cleared after undo to root, got %d", len(m.zoom.zoomStack))
	}
}

func TestStaticFixtureArrowTraversalVisitsAllFrames(t *testing.T) {
	trie := coreflamegraph.NewLiveTrie([]string{"comm", "path", "tracepoint"}, "count", "count")
	coreflamegraph.SeedTestFlameData(trie)

	m := NewModel(trie)
	m.SetViewport(180, 40)
	if changed := m.RefreshFromLiveTrie(); !changed {
		t.Fatalf("expected seeded fixture refresh to load frames")
	}
	if len(m.anim.frames) < 2 {
		t.Fatalf("expected seeded fixture to contain navigable frames, got %d", len(m.anim.frames))
	}

	visited := map[int]bool{m.sel.selectedIdx: true}
	for i := 0; i < len(m.anim.frames)*4; i++ {
		m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyRight})
		visited[m.sel.selectedIdx] = true
	}
	for i := 0; i < len(m.anim.frames)*4; i++ {
		m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyLeft})
		visited[m.sel.selectedIdx] = true
	}

	if got, want := len(visited), len(m.anim.frames); got != want {
		t.Fatalf("expected arrow traversal to visit all frames: visited=%d frames=%d", got, want)
	}
	if !strings.Contains(m.View().Content, "sel:") {
		t.Fatalf("expected view to expose selected-frame status line")
	}
}

func TestLiveFixtureArrowTraversalWhileStreamingVisitsAllFrames(t *testing.T) {
	trie := coreflamegraph.NewLiveTrie([]string{"comm", "path", "tracepoint"}, "count", "count")
	coreflamegraph.SeedTestLiveFlameData(trie, 0)

	m := NewModel(trie)
	m.SetViewport(180, 40)
	if changed := m.RefreshFromLiveTrie(); !changed {
		t.Fatalf("expected initial refresh to load frames")
	}
	if len(m.anim.frames) < 2 {
		t.Fatalf("expected seeded fixture to contain navigable frames, got %d", len(m.anim.frames))
	}

	selectedPath := func(model *Model) string {
		if len(model.anim.frames) == 0 || model.sel.selectedIdx < 0 || model.sel.selectedIdx >= len(model.anim.frames) {
			return ""
		}
		return model.anim.frames[model.sel.selectedIdx].Path
	}

	visitedPaths := map[string]bool{selectedPath(m): true}
	moves := 0
	for i := 0; i < len(m.anim.frames)*4; i++ {
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
	for i := 0; i < len(m.anim.frames)*4; i++ {
		trie.Reset()
		coreflamegraph.SeedTestLiveFlameData(trie, uint64(i+1+len(m.anim.frames)*4))
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
	trie := coreflamegraph.NewLiveTrie([]string{"comm", "path", "tracepoint"}, "count", "count")
	coreflamegraph.SeedTestLiveFlameData(trie, 0)

	m := NewModel(trie)
	m.SetViewport(180, 40)
	if changed := m.RefreshFromLiveTrie(); !changed {
		t.Fatalf("expected initial refresh")
	}
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyRight})
	selected := m.anim.frames[m.sel.selectedIdx].Path
	if selected == "" || selected == "root" {
		t.Fatalf("expected selection to move off root, got %q", selected)
	}

	trie.Reset()
	coreflamegraph.SeedTestLiveFlameData(trie, 2)
	if changed := m.RefreshFromLiveTrie(); !changed {
		t.Fatalf("expected refresh after live update")
	}
	if got := m.anim.frames[m.sel.selectedIdx].Path; got != selected {
		t.Fatalf("expected selection path to persist across refresh, got %q want %q", got, selected)
	}
}

func TestKeyboardNavigationSingleNodeClamped(t *testing.T) {
	m := NewModel(nil)
	m.anim.frames = []tuiFrame{{Name: "root", Depth: 0, Col: 0, Path: "root"}}

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
		if m.sel.selectedIdx != 0 {
			t.Fatalf("expected single-node selection to stay at idx 0, got %d", m.sel.selectedIdx)
		}
	}
}

func TestArrowDownFallsBackToVisibleDepthFromRoot(t *testing.T) {
	m := NewModel(nil)
	m.anim.frames = []tuiFrame{
		{Name: "root", Depth: 0, Col: 0, Path: "root"},
		{Name: "child", Depth: 1, Col: 0, Path: "root" + pathSeparator + "child"},
	}
	m.sel.selectedIdx = 0

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyDown})
	if m.sel.selectedIdx != 1 {
		t.Fatalf("expected down arrow to move selection to child when root has no shallower row, got %d", m.sel.selectedIdx)
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

func TestArrowEscapeSequencesRejectMalformedValues(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		ansiCode byte
	}{
		{name: "missing escape", key: "up", ansiCode: 'A'},
		{name: "too short", key: "\x1b[", ansiCode: 'A'},
		{name: "wrong final", key: "\x1b[A", ansiCode: 'B'},
		{name: "unsupported introducer", key: "\x1bPA", ansiCode: 'A'},
		{name: "application mode with extra payload", key: "\x1bO1A", ansiCode: 'A'},
	}
	for _, tc := range tests {
		if isArrowEscapeSequence(tc.key, tc.ansiCode) {
			t.Fatalf("expected %s sequence %q to be rejected", tc.name, tc.key)
		}
	}
}

func TestFilteredNavigationSkipsHiddenBranches(t *testing.T) {
	m := NewModel(nil)
	m.anim.frames = []tuiFrame{
		{Name: "root", Depth: 0, Col: 0, Row: 0, Path: "root"},
		{Name: "keep", Depth: 1, Col: 0, Row: 1, Path: "root" + pathSeparator + "keep"},
		{Name: "drop", Depth: 1, Col: 40, Row: 1, Path: "root" + pathSeparator + "drop"},
	}
	m.search.searchQuery = "keep"
	m.recomputeFilterState()
	m.sel.selectedIdx = 1

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyRight})
	if m.sel.selectedIdx != 1 {
		t.Fatalf("expected sibling navigation to stay on visible filtered branch, got idx %d", m.sel.selectedIdx)
	}

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyDown})
	if m.sel.selectedIdx != 0 {
		t.Fatalf("expected down key to move to visible root ancestor, got idx %d", m.sel.selectedIdx)
	}
}

func TestZoomInUndoSingleLevelAndNestedEsc(t *testing.T) {
	m := newZoomModel()

	m.sel.selectedIdx = mustFrameIndex(t, m.anim.frames, "root"+pathSeparator+"A")
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyEnter})
	if got, want := m.zoom.zoomPath, "root"+pathSeparator+"A"; got != want {
		t.Fatalf("expected zoomPath %q, got %q", want, got)
	}
	if len(m.zoom.zoomStack) != 1 || m.zoom.zoomStack[0].path != "" {
		t.Fatalf("expected one zoom stack entry from root, got %#v", m.zoom.zoomStack)
	}
	if m.zoom.zoomRoot == nil || m.zoom.zoomRoot.Name != "A" {
		t.Fatalf("expected zoomRoot A, got %+v", m.zoom.zoomRoot)
	}

	m.sel.selectedIdx = mustFrameIndex(t, m.anim.frames, "root"+pathSeparator+"A"+pathSeparator+"A1")
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyEnter})
	if got, want := m.zoom.zoomPath, "root"+pathSeparator+"A"+pathSeparator+"A1"; got != want {
		t.Fatalf("expected nested zoomPath %q, got %q", want, got)
	}
	if len(m.zoom.zoomStack) != 2 || m.zoom.zoomStack[1].path != "root"+pathSeparator+"A" {
		t.Fatalf("expected nested zoom stack to preserve parent path, got %#v", m.zoom.zoomStack)
	}

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyEsc})
	if got, want := m.zoom.zoomPath, "root"+pathSeparator+"A"; got != want {
		t.Fatalf("expected zoomPath after esc undo %q, got %q", want, got)
	}
	if len(m.zoom.zoomStack) != 1 {
		t.Fatalf("expected one stack entry after esc undo, got %d", len(m.zoom.zoomStack))
	}

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyEsc})
	if m.zoom.zoomPath != "" || m.zoom.zoomRoot != nil || len(m.zoom.zoomStack) != 0 {
		t.Fatalf("expected second esc undo to return to root state, got path=%q root=%+v stack=%d", m.zoom.zoomPath, m.zoom.zoomRoot, len(m.zoom.zoomStack))
	}
}

func TestZoomResetToRoot(t *testing.T) {
	m := newZoomModel()
	m.sel.selectedIdx = mustFrameIndex(t, m.anim.frames, "root"+pathSeparator+"A")
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyEnter})
	m.sel.selectedIdx = mustFrameIndex(t, m.anim.frames, "root"+pathSeparator+"A"+pathSeparator+"A1")
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyEnter})
	if m.zoom.zoomPath == "" || len(m.zoom.zoomStack) == 0 {
		t.Fatalf("expected nested zoom before reset")
	}

	m.zoomReset()
	if m.zoom.zoomPath != "" || m.zoom.zoomRoot != nil || len(m.zoom.zoomStack) != 0 {
		t.Fatalf("expected explicit zoom reset to clear zoom stack, got path=%q root=%+v stack=%d", m.zoom.zoomPath, m.zoom.zoomRoot, len(m.zoom.zoomStack))
	}
}

func TestZoomInOnCurrentRootSetsStatusMessage(t *testing.T) {
	m := newZoomModel()
	m.sel.selectedIdx = mustFrameIndex(t, m.anim.frames, "root")

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyEnter})
	if m.zoom.zoomPath != "" {
		t.Fatalf("expected zoom path to remain root, got %q", m.zoom.zoomPath)
	}
	if m.statusMessage != "Zoom unchanged: selected frame is current view root" {
		t.Fatalf("unexpected status message: %q", m.statusMessage)
	}
}

func TestZoomTransitionAppliesNewLayoutImmediately(t *testing.T) {
	m := newZoomModel()
	pathA := "root" + pathSeparator + "A"

	m.sel.selectedIdx = mustFrameIndex(t, m.anim.frames, pathA)
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyEnter})
	if m.anim.animating {
		t.Fatalf("expected zoom-in layout update to apply immediately")
	}
	currentWidth := m.anim.frames[mustFrameIndex(t, m.anim.frames, pathA)].Width
	targetWidth := m.anim.targetFrames[mustFrameIndex(t, m.anim.targetFrames, pathA)].Width
	if currentWidth != targetWidth {
		t.Fatalf("expected zoom width %d after immediate layout update, got %d", targetWidth, currentWidth)
	}
}

func TestSearchLifecycleAndMatchNavigation(t *testing.T) {
	m := NewModel(nil)
	m.anim.frames = []tuiFrame{
		{Name: "alpha", Path: "root" + pathSeparator + "alpha"},
		{Name: "beta", Path: "root" + pathSeparator + "beta"},
		{Name: "alphabet", Path: "root" + pathSeparator + "alphabet"},
	}

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'/'}[0], Text: "/"})
	if !m.search.searchActive {
		t.Fatalf("expected search mode to activate on '/'")
	}
	for _, r := range []rune{'a', 'l', 'p'} {
		m = pressFlameKey(t, m, tea.KeyPressMsg{Code: r, Text: string(r)})
	}
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyEnter})

	if m.search.searchActive {
		t.Fatalf("expected search mode to close on enter")
	}
	if got := len(m.search.matchIndices); got != 2 {
		t.Fatalf("expected 2 matches for 'alp', got %d", got)
	}
	first := m.sel.selectedIdx
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'n'}[0], Text: "n"})
	if m.sel.selectedIdx == first {
		t.Fatalf("expected 'n' to jump to next match")
	}
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'N'}[0], Text: "N"})
	if m.sel.selectedIdx != first {
		t.Fatalf("expected 'N' to jump back to previous match")
	}
}

func TestSearchEscapeClearsState(t *testing.T) {
	m := NewModel(nil)
	m.anim.frames = []tuiFrame{{Name: "alpha", Path: "root" + pathSeparator + "alpha"}}

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'/'}[0], Text: "/"})
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'a'}[0], Text: "a"})
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyEsc})

	if m.search.searchActive {
		t.Fatalf("expected search mode to close on escape")
	}
	if m.search.searchQuery != "" || len(m.search.matchIndices) != 0 {
		t.Fatalf("expected search state to reset on escape, got query=%q matches=%d", m.search.searchQuery, len(m.search.matchIndices))
	}
	if m.statusMessage != "Filter cleared" {
		t.Fatalf("expected filter cleared status message, got %q", m.statusMessage)
	}
}

func TestSearchSubmitSetsFilterStatusMessage(t *testing.T) {
	m := NewModel(nil)
	m.anim.frames = []tuiFrame{
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
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeySpace, Text: " "})
	if !m.paused {
		t.Fatalf("expected space key to toggle pause on")
	}
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeySpace, Text: " "})
	if m.paused {
		t.Fatalf("expected space key to toggle pause off")
	}
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'p'}[0], Text: "p"})
	if m.paused {
		t.Fatalf("expected p key not to toggle pause")
	}
}

func TestControlResetBaseline(t *testing.T) {
	liveTrie := coreflamegraph.NewLiveTrie([]string{"comm", "path", "tracepoint"}, "count", "count")
	m := NewModel(liveTrie)
	m.snapshot = &snapshotNode{Name: "root", Total: 10}
	m.anim.frames = []tuiFrame{{Name: "root", Path: "root"}}
	m.zoom.zoomPath = "root"
	m.zoom.zoomStack = []zoomState{{path: ""}}
	m.sel.selectedIdx = 3

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'r'}[0], Text: "r"})
	if m.snapshot != nil || len(m.anim.frames) != 0 || len(m.zoom.zoomStack) != 0 || m.zoom.zoomPath != "" {
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
	m.anim.frames = []tuiFrame{
		{Name: "root", Depth: 0, Col: 0, Row: 0, Width: 120, Total: 100, Percent: 100, Path: "root"},
		{Name: "child", Depth: 1, Col: 0, Row: 1, Width: 60, Total: 40, Percent: 40, Path: "root" + pathSeparator + "child"},
	}
	m.sel.selectedIdx = 1
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
	m.anim.frames = []tuiFrame{
		{Name: "root", Depth: 0, Col: 0, Row: 0, Width: 120, Total: 200, Percent: 100, Path: "root"},
		{Name: "child", Depth: 1, Col: 0, Row: 1, Width: 60, Total: 80, Percent: 40, Path: "root" + pathSeparator + "child"},
	}
	m.sel.selectedIdx = 1
	m.globalTotal = 200

	view := m.View().Content
	if !strings.Contains(view, "40.00% of total bytes") {
		t.Fatalf("expected bytes-based selection share label, got %q", view)
	}
}

func TestSelectionStatusLineIncludesSelectedHeightValueAndMaxShare(t *testing.T) {
	m := NewModel(nil)
	m.width = 220
	m.height = 20
	m.heightField = "duration"
	m.anim.frames = []tuiFrame{
		{Name: "root", Depth: 0, Col: 0, Row: 0, Width: 120, Total: 100, Percent: 100, Path: "root", HeightTotal: 200},
		{Name: "child", Depth: 1, Col: 0, Row: 1, Width: 60, Total: 40, Percent: 40, Path: "root" + pathSeparator + "child", HeightTotal: 50},
	}
	m.sel.selectedIdx = 1
	m.globalTotal = 100

	line := m.selectionStatusLine()
	if !strings.Contains(line, "height(duration)=50 (25.0% of max)") {
		t.Fatalf("expected selected height metric fragment, got %q", line)
	}
}

func TestSelectionStatusLineUsesHeightLabelWithoutSelectedValueWhenNoSelection(t *testing.T) {
	m := NewModel(nil)
	m.width = 220
	m.height = 20
	m.heightField = "duration"

	line := m.selectionStatusLine()
	if !strings.Contains(line, "height:duration") {
		t.Fatalf("expected height field label without selected value when no frames, got %q", line)
	}
}

func TestViewFitsViewportHeightAndKeepsSearchFooterVisible(t *testing.T) {
	m := NewModel(nil)
	m.width = 100
	m.height = 12
	m.anim.frames = []tuiFrame{
		{Name: "root", Depth: 0, Col: 0, Row: 0, Width: 100, Total: 100, Percent: 100, Path: "root"},
		{Name: "child", Depth: 1, Col: 0, Row: 1, Width: 80, Total: 80, Percent: 80, Path: "root" + pathSeparator + "child"},
	}
	m.sel.selectedIdx = 1
	m.globalTotal = 100
	m.search.searchActive = true
	m.search.searchInput.SetValue("child")

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
	m.anim.frames = buildTerminalLayout(snapshot, m.width, m.height)
	m.globalTotal = 100
	m.sel.selectedIdx = mustFrameIndex(t, m.anim.frames, "root"+pathSeparator+"keep"+pathSeparator+"needle")
	m.search.searchQuery = "needle"
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
	liveTrie := coreflamegraph.NewLiveTrie([]string{"comm", "path", "tracepoint"}, "count", "count")
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
	liveTrie := coreflamegraph.NewLiveTrie([]string{"comm", "path", "tracepoint"}, "count", "count")
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
	if got, want := m.countField, "duration"; got != want {
		t.Fatalf("expected model count field %q after second toggle, got %q", want, got)
	}
	if got, want := liveTrie.CountField(), "duration"; got != want {
		t.Fatalf("expected live trie count field %q after second toggle, got %q", want, got)
	}

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'b'}[0], Text: "b"})
	if got, want := m.countField, "count"; got != want {
		t.Fatalf("expected model count field %q after third toggle, got %q", want, got)
	}
	if got, want := liveTrie.CountField(), "count"; got != want {
		t.Fatalf("expected live trie count field %q after third toggle, got %q", want, got)
	}
}

func TestControlHeightToggleReconfiguresLiveTrieHeightField(t *testing.T) {
	liveTrie := coreflamegraph.NewLiveTrie([]string{"comm", "path", "tracepoint"}, "count", "")
	m := NewModel(liveTrie)

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'v'}[0], Text: "v"})
	if got, want := m.heightField, "duration"; got != want {
		t.Fatalf("expected model height field %q, got %q", want, got)
	}
	if got, want := liveTrie.HeightField(), "duration"; got != want {
		t.Fatalf("expected live trie height field %q, got %q", want, got)
	}
	if got, want := m.statusMessage, "Height: duration (new baseline)"; got != want {
		t.Fatalf("expected height toggle status %q, got %q", want, got)
	}

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'v'}[0], Text: "v"})
	if got, want := m.heightField, "bytes"; got != want {
		t.Fatalf("expected model height field %q after second toggle, got %q", want, got)
	}
	if got, want := liveTrie.HeightField(), "bytes"; got != want {
		t.Fatalf("expected live trie height field %q after second toggle, got %q", want, got)
	}

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'v'}[0], Text: "v"})
	if got, want := m.heightField, "count"; got != want {
		t.Fatalf("expected model height field %q after third toggle, got %q", want, got)
	}
	if got, want := liveTrie.HeightField(), "count"; got != want {
		t.Fatalf("expected live trie height field %q after third toggle, got %q", want, got)
	}

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'v'}[0], Text: "v"})
	if got, want := m.heightField, ""; got != want {
		t.Fatalf("expected model height field %q after fourth toggle, got %q", want, got)
	}
	if got, want := liveTrie.HeightField(), ""; got != want {
		t.Fatalf("expected live trie height field %q after fourth toggle, got %q", want, got)
	}
	if got, want := m.statusMessage, "Height: off (new baseline)"; got != want {
		t.Fatalf("expected height toggle off status %q, got %q", want, got)
	}
}

func TestControlMetricToggleUnknownValueFallsBackToCount(t *testing.T) {
	liveTrie := coreflamegraph.NewLiveTrie([]string{"comm", "path", "tracepoint"}, "count", "")
	m := NewModel(liveTrie)
	m.countField = "unexpected"

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'b'}[0], Text: "b"})
	if got, want := m.countField, "count"; got != want {
		t.Fatalf("expected model count field fallback %q, got %q", want, got)
	}
	if got, want := liveTrie.CountField(), "count"; got != want {
		t.Fatalf("expected live trie count field fallback %q, got %q", want, got)
	}
	if got, want := m.statusMessage, "Metric: events (new baseline)"; got != want {
		t.Fatalf("expected metric fallback status %q, got %q", want, got)
	}
}

func TestControlHeightToggleUnknownValueFallsBackToOff(t *testing.T) {
	liveTrie := coreflamegraph.NewLiveTrie([]string{"comm", "path", "tracepoint"}, "count", "")
	m := NewModel(liveTrie)
	m.heightField = "unexpected"

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: []rune{'v'}[0], Text: "v"})
	if got, want := m.heightField, ""; got != want {
		t.Fatalf("expected model height field fallback %q, got %q", want, got)
	}
	if got, want := liveTrie.HeightField(), ""; got != want {
		t.Fatalf("expected live trie height field fallback %q, got %q", want, got)
	}
	if got, want := m.statusMessage, "Height: off (new baseline)"; got != want {
		t.Fatalf("expected height fallback status %q, got %q", want, got)
	}
}

func TestNewModelAlignsPresetIndexToLiveTrieFields(t *testing.T) {
	liveTrie := coreflamegraph.NewLiveTrie([]string{"comm", "path", "tracepoint"}, "count", "count")
	m := NewModel(liveTrie)
	if got, want := m.fieldPresets[m.fieldIndex], []string{"comm", "path", "tracepoint"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("expected model field preset to align with trie fields, got %v want %v", got, want)
	}
}

func TestNewModelAlignsCountFieldToLiveTrie(t *testing.T) {
	liveTrie := coreflamegraph.NewLiveTrie([]string{"comm", "path", "tracepoint"}, "bytes", "bytes")
	m := NewModel(liveTrie)
	if got, want := m.countField, "bytes"; got != want {
		t.Fatalf("expected model count field to align with trie field, got %q want %q", got, want)
	}
}

func TestNewModelAlignsHeightFieldToLiveTrie(t *testing.T) {
	liveTrie := coreflamegraph.NewLiveTrie([]string{"comm", "path", "tracepoint"}, "count", "bytes")
	m := NewModel(liveTrie)
	if got, want := m.heightField, "bytes"; got != want {
		t.Fatalf("expected model height field to align with trie field, got %q want %q", got, want)
	}
}

func TestCurrentViewCacheKeyChangesWhenCountFieldChanges(t *testing.T) {
	m := NewModel(nil)
	m.width = 120
	m.height = 20
	m.anim.frames = []tuiFrame{{Name: "root", Path: "root"}}

	before := m.currentViewCacheKey()
	m.countField = "bytes"
	after := m.currentViewCacheKey()

	if before == after {
		t.Fatalf("expected cache key to change when count field changes")
	}
	if got, want := after.countField, "bytes"; got != want {
		t.Fatalf("expected cache key count field %q, got %q", want, got)
	}
}

func TestCurrentViewCacheKeyChangesWhenHeightFieldChanges(t *testing.T) {
	m := NewModel(nil)
	m.width = 120
	m.height = 20
	m.anim.frames = []tuiFrame{{Name: "root", Path: "root"}}

	before := m.currentViewCacheKey()
	m.heightField = "duration"
	after := m.currentViewCacheKey()

	if before == after {
		t.Fatalf("expected cache key to change when height field changes")
	}
	if got, want := after.heightField, "duration"; got != want {
		t.Fatalf("expected cache key height field %q, got %q", want, got)
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
	initial := append([]tuiFrame(nil), m.anim.frames...)

	m.snapshot = &snapshotNode{
		Name:  "root",
		Total: 100,
		Children: []*snapshotNode{
			{Name: "A", Total: 20},
			{Name: "B", Total: 80},
		},
	}
	m.rebuildFrames(true)
	if !m.anim.animating {
		t.Fatalf("expected animation to start after animated rebuild")
	}

	next, _ := m.Update(animTickMsg{})
	m = next.(*Model)
	if len(m.anim.frames) != len(initial) {
		t.Fatalf("expected frame count to remain stable during animation")
	}

	for i := 0; i < 180 && m.anim.animating; i++ {
		next, _ = m.Update(animTickMsg{})
		m = next.(*Model)
	}
	if m.anim.animating {
		t.Fatalf("expected animation to settle within 180 ticks")
	}
	if len(m.anim.frames) != len(m.anim.targetFrames) {
		t.Fatalf("expected settled frame count to match targets")
	}
	for i := range m.anim.frames {
		if m.anim.frames[i].Width != m.anim.targetFrames[i].Width || m.anim.frames[i].Col != m.anim.targetFrames[i].Col {
			t.Fatalf("frame %d did not converge to target: got col=%d width=%d want col=%d width=%d",
				i, m.anim.frames[i].Col, m.anim.frames[i].Width, m.anim.targetFrames[i].Col, m.anim.targetFrames[i].Width)
		}
	}
}

func TestAnimationCmdFollowsAnimatingState(t *testing.T) {
	m := NewModel(nil)
	if cmd := m.AnimationCmd(); cmd != nil {
		t.Fatalf("expected no animation command when model is idle")
	}

	m.anim.animating = true
	cmd := m.AnimationCmd()
	if cmd == nil {
		t.Fatalf("expected animation command when model is animating")
	}
	if _, ok := cmd().(animTickMsg); !ok {
		t.Fatalf("expected animation command to emit animTickMsg")
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
	if len(m.anim.frames) == 0 {
		t.Fatalf("expected rebuilt frames")
	}
	rowOffset := visibleRowOffset(m.anim.frames, m.height, m.search.navigable())
	if m.anim.frames[m.sel.selectedIdx].Row < rowOffset {
		t.Fatalf("expected selected frame row %d to be visible (offset=%d)", m.anim.frames[m.sel.selectedIdx].Row, rowOffset)
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
	_ = mustFrameIndex(t, m.anim.frames, "root"+pathSeparator+"tiny")

	next, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	m = next.(*Model)
	for i := 0; i < 180 && m.anim.animating; i++ {
		next, _ = m.Update(animTickMsg{})
		m = next.(*Model)
	}

	for _, frame := range m.anim.frames {
		if frame.Col+frame.Width > 80 {
			t.Fatalf("frame exceeds resized width: %+v", frame)
		}
		if frame.Row >= 24 {
			t.Fatalf("frame row exceeds resized height: %+v", frame)
		}
	}
	for _, frame := range m.anim.frames {
		if frame.Path == "root"+pathSeparator+"tiny" {
			t.Fatalf("expected tiny frame to be culled at width 80")
		}
	}
}

func TestSetViewportSameSizeKeepsPausedZoomLayoutStable(t *testing.T) {
	m := newZoomModel()
	m.sel.selectedIdx = mustFrameIndex(t, m.anim.frames, "root"+pathSeparator+"A")
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyEnter})
	m.paused = true

	rootIdx := mustFrameIndex(t, m.anim.frames, "root"+pathSeparator+"A")
	if got, want := m.anim.frames[rootIdx].Width, m.width; got != want {
		t.Fatalf("expected zoom root to span full width before redundant viewport set, got %d want %d", got, want)
	}

	beforeFrames := append([]tuiFrame(nil), m.anim.frames...)
	beforeTargets := append([]tuiFrame(nil), m.anim.targetFrames...)
	m.SetViewport(m.width, m.height)

	if m.anim.animating {
		t.Fatalf("expected redundant viewport set to avoid starting animation")
	}
	if !reflect.DeepEqual(m.anim.frames, beforeFrames) {
		t.Fatalf("expected redundant viewport set to preserve current frames")
	}
	if !reflect.DeepEqual(m.anim.targetFrames, beforeTargets) {
		t.Fatalf("expected redundant viewport set to preserve target frames")
	}
	rootIdx = mustFrameIndex(t, m.anim.frames, "root"+pathSeparator+"A")
	if got, want := m.anim.frames[rootIdx].Width, m.width; got != want {
		t.Fatalf("expected zoom root to remain full width after redundant viewport set, got %d want %d", got, want)
	}
}

func newZoomModel() *Model {
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

func parentFramePath(path string) string {
	lastSep := strings.LastIndex(path, pathSeparator)
	if lastSep <= 0 {
		return ""
	}
	return path[:lastSep]
}

func pressFlameKey(t *testing.T, m *Model, keyMsg tea.KeyPressMsg) *Model {
	t.Helper()
	next, _ := m.Update(keyMsg)
	return next.(*Model)
}

func firstClickablePointForFrame(m *Model, frameIdx int) (x, y int, ok bool) {
	if frameIdx < 0 || frameIdx >= len(m.anim.frames) {
		return 0, 0, false
	}
	frame := m.anim.frames[frameIdx]
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

func settleFlameAnimation(t *testing.T, m *Model) *Model {
	t.Helper()
	for i := 0; i < 240 && m.anim.animating; i++ {
		next, _ := m.Update(animTickMsg{})
		m = next.(*Model)
	}
	if m.anim.animating {
		t.Fatalf("expected flame animation to settle within 240 ticks")
	}
	return m
}
