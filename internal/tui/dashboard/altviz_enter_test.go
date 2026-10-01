package dashboard

import (
	"testing"

	"ior/internal/globalfilter"
)

// Task cr2: Enter used to do nothing in the Syscalls bubbles and treemap and
// in the Files directory bubbles, treemap and icicle although their header
// says "j/k select". The selection of those views is their own (a keyed
// treemap offset, the bubble chart's highlighted bubble), so Enter must act
// on the item that is highlighted, not on the table row the table offset
// would point at.

// syscallEnterName presses Enter and returns the syscall name of the
// emitted filter, failing when it is not an exact-name syscall filter.
func syscallEnterName(t *testing.T, m *Model) string {
	t.Helper()
	req, ok := enterFilterRequest(t, m)
	if !ok {
		t.Fatal("Enter emitted no filter request")
	}
	if req.Filter.Syscall == nil || req.Filter.Family != nil {
		t.Fatalf("Enter pushed %+v, want a syscall-name filter", req.Filter)
	}
	return req.Filter.Syscall.Pattern
}

func TestSyscallsTreemapEnterFiltersTheHighlightedTile(t *testing.T) {
	m := newVizModel(t, TabSyscalls, tabVizModeTreemap, sysRanking(9, 5, 1))
	m = pressJ(t, m, 2) // read, write, close by count: the third tile
	assertSyscallsTreemapSelection(t, m, 2, "close")
	// The table offset still points at row 0: Enter must not follow it.
	if got, want := syscallEnterName(t, m), globalfilter.ExactPattern("close"); got != want {
		t.Fatalf("Enter pushed %q, want the highlighted tile %q", got, want)
	}
}

func TestSyscallsTreemapEnterIgnoresTheTableFamilyColumn(t *testing.T) {
	m := newVizModel(t, TabSyscalls, tabVizModeTreemap, sysRanking(9, 5, 1))
	m.syscallsTab.col = syscallFamilyColumn // left over from the table view
	if got := syscallEnterName(t, m); got != globalfilter.ExactPattern("read") {
		t.Fatalf("Enter pushed %q, want the syscall name, not a family", got)
	}
}

func TestSyscallsBubblesEnterFiltersTheHighlightedBubble(t *testing.T) {
	m := newVizModel(t, TabSyscalls, tabVizModeBubbles, sysRanking(9, 5, 1))
	chart := &m.syscallsTab.bubble
	if len(chart.nodes) != 3 {
		t.Fatalf("chart has %d bubbles, want 3", len(chart.nodes))
	}
	for i := range chart.nodes {
		id := chart.nodes[chart.selected].ID
		if got, want := syscallEnterName(t, m), globalfilter.ExactPattern(id); got != want {
			t.Fatalf("bubble %d (%q): Enter pushed %q", i, id, got)
		}
		m = pressJ(t, m, 1)
		chart = &m.syscallsTab.bubble
	}
}

func TestSyscallsAltViewsEnterWithoutDataDoesNothing(t *testing.T) {
	for _, mode := range []tabVizMode{tabVizModeBubbles, tabVizModeTreemap} {
		m := newVizModel(t, TabSyscalls, mode, syscallsSnapshot())
		if req, ok := enterFilterRequest(t, m); ok {
			t.Fatalf("mode %d: Enter on an empty view emitted %+v", mode, req)
		}
	}
}

// dirEnterPattern presses Enter and returns the directory pattern of the
// emitted file filter.
func dirEnterPattern(t *testing.T, m *Model) string {
	t.Helper()
	req, ok := enterFilterRequest(t, m)
	if !ok || req.Filter.File == nil {
		t.Fatalf("Enter emitted no file filter (ok=%v)", ok)
	}
	return req.Filter.File.Pattern
}

func TestFilesTreemapEnterFiltersTheHighlightedDirectory(t *testing.T) {
	m := newFilesVizModel(t, tabVizModeTreemap, icicleSnapshot(9, 1))
	keys := m.filesDirSelectionKeys()
	if len(keys) < 2 {
		t.Fatalf("treemap has %d tiles, want at least 2", len(keys))
	}
	for i, key := range keys {
		m.filesDirTab.offset = i
		if got, want := dirEnterPattern(t, m), globalfilter.DirPattern(key); got != want {
			t.Fatalf("tile %d (%q): Enter pushed %q, want %q", i, key, got, want)
		}
	}
}

func TestFilesBubblesEnterFiltersTheHighlightedDirectory(t *testing.T) {
	m := newFilesVizModel(t, tabVizModeBubbles, icicleSnapshot(9, 1))
	chart := &m.filesTab.bubble
	if len(chart.nodes) == 0 {
		t.Fatal("chart has no bubbles")
	}
	for i := range chart.nodes {
		id := chart.nodes[chart.selected].ID
		if got, want := dirEnterPattern(t, m), globalfilter.DirPattern(id); got != want {
			t.Fatalf("bubble %d (%q): Enter pushed %q, want %q", i, id, got, want)
		}
		m = pressJ(t, m, 1)
		chart = &m.filesTab.bubble
	}
}

func TestFilesIcicleEnterFiltersTheHighlightedTileWhenItIsADirectoryRow(t *testing.T) {
	m := newFilesVizModel(t, tabVizModeIcicle, icicleSnapshot(9, 1))
	rows := make(map[string]bool)
	for _, row := range m.sortedDirRows() {
		rows[dirKey(row)] = true
	}
	for i, key := range m.filesDirSelectionKeys() {
		m.filesDirTab.offset = i
		req, ok := enterFilterRequest(t, m)
		if rows[key] != ok {
			t.Fatalf("tile %d (%q): Enter emitted a request = %v, directory row exists = %v", i, key, ok, rows[key])
		}
		if ok && req.Filter.File.Pattern != globalfilter.DirPattern(key) {
			t.Fatalf("tile %d (%q): Enter pushed %q", i, key, req.Filter.File.Pattern)
		}
	}
}
