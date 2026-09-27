package dashboard

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"ior/internal/statsengine"
	common "ior/internal/tui/common"
	"ior/internal/tui/messages"

	tea "charm.land/bubbletea/v2"
)

// These tests cover the Files tab's dir-grouped selection across stats
// ticks (task zb): the treemap and icicle reorder their items on every
// refresh and the icicle has more tiles than there are directories, so the
// selection must follow the selected item by path rather than be clamped
// against the directory count or left on whatever moved into its slot.

func filesSnapshot(files ...statsengine.FileSnapshot) *statsengine.Snapshot {
	snap := statsengine.NewSnapshot(nil, nil, nil, nil, files, nil,
		statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	return &snap
}

// newFilesVizModel returns a focused dashboard on the dir-grouped Files tab
// in mode, sized so the icicle has room for every tile, with snap delivered
// through a real stats tick.
func newFilesVizModel(t *testing.T, mode tabVizMode, snap *statsengine.Snapshot) *Model {
	t.Helper()
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
	m.activeTab = TabFiles
	m.filesDirGrouped = true
	m.filesTab.mode = mode
	m.width = 120
	m.height = 28
	return tickStats(t, m, messages.StatsTickMsg{Snap: snap})
}

func tickStats(t *testing.T, m *Model, msg messages.StatsTickMsg) *Model {
	t.Helper()
	next, _ := m.Update(msg)
	return next.(*Model)
}

func pressJ(t *testing.T, m *Model, times int) *Model {
	t.Helper()
	for range times {
		next, _ := m.Update(tea.KeyPressMsg{Code: 'j', Text: "j"})
		m = next.(*Model)
	}
	return m
}

// icicleSnapshot yields five icicle tiles over two directories, ordered
// /a, /a/b, /a/b/c, /a/d, /a/d/e while /a/b/c outweighs /a/d/e.
func icicleSnapshot(abcAccesses, adeAccesses uint64) *statsengine.Snapshot {
	return filesSnapshot(
		statsengine.FileSnapshot{Path: "/a/b/c/file1", Accesses: abcAccesses},
		statsengine.FileSnapshot{Path: "/a/d/e/file2", Accesses: adeAccesses},
	)
}

func TestFilesVizSelectionSurvivesStatsTick(t *testing.T) {
	tests := []struct {
		name     string
		mode     tabVizMode
		initial  *statsengine.Snapshot
		presses  int
		selected string
		refresh  *statsengine.Snapshot
		want     int
	}{
		{
			// The audit repro: offset 4 used to be clamped against the two
			// directories and snap back to 1 on every tick.
			name:     "icicle unchanged snapshot",
			mode:     tabVizModeIcicle,
			initial:  icicleSnapshot(9, 7),
			presses:  4,
			selected: "/a/d/e",
			refresh:  icicleSnapshot(9, 7),
			want:     4,
		},
		{
			// /a/d/e outgrows /a/b/c, so its subtree is laid out first.
			name:     "icicle reordered snapshot",
			mode:     tabVizModeIcicle,
			initial:  icicleSnapshot(9, 7),
			presses:  4,
			selected: "/a/d/e",
			refresh:  icicleSnapshot(9, 20),
			want:     2,
		},
		{
			name: "treemap reordered snapshot",
			mode: tabVizModeTreemap,
			initial: filesSnapshot(
				statsengine.FileSnapshot{Path: "/x/f", Accesses: 9},
				statsengine.FileSnapshot{Path: "/y/f", Accesses: 5},
				statsengine.FileSnapshot{Path: "/z/f", Accesses: 1},
			),
			presses:  2,
			selected: "/z",
			refresh: filesSnapshot(
				statsengine.FileSnapshot{Path: "/x/f", Accesses: 9},
				statsengine.FileSnapshot{Path: "/y/f", Accesses: 5},
				statsengine.FileSnapshot{Path: "/z/f", Accesses: 30},
			),
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newFilesVizModel(t, tt.mode, tt.initial)
			m = pressJ(t, m, tt.presses)
			if got := m.filesDirSelection().selectedKey(); got != tt.selected {
				t.Fatalf("before tick: selected %q, want %q", got, tt.selected)
			}

			// Two ticks: the selection must hold, not drift tick by tick.
			for tick := range 2 {
				m = tickStats(t, m, messages.StatsTickMsg{Snap: tt.refresh})
				if m.filesDirTab.offset != tt.want {
					t.Fatalf("tick %d: offset %d, want %d", tick, m.filesDirTab.offset, tt.want)
				}
				if got := m.filesDirSelection().selectedKey(); got != tt.selected {
					t.Fatalf("tick %d: selected %q, want %q", tick, got, tt.selected)
				}
			}
			if status := stripANSIEscape(m.View().Content); !strings.Contains(status, "sel:"+strconv.Itoa(tt.want+1)+"/") {
				t.Fatalf("expected rendered selection sel:%d/..., got:\n%s", tt.want+1, status)
			}
		})
	}
}

func TestFilesIcicleSelectionFallsBackWhenSelectedTileDisappears(t *testing.T) {
	m := newFilesVizModel(t, tabVizModeIcicle, icicleSnapshot(9, 7))
	m = pressJ(t, m, 4)

	// /a/d/e is gone: only /a, /a/b, /a/b/c remain, so the offset is
	// clamped to the last surviving tile instead of indexing past the end.
	m = tickStats(t, m, messages.StatsTickMsg{Snap: filesSnapshot(
		statsengine.FileSnapshot{Path: "/a/b/c/file1", Accesses: 9},
	)})
	if m.filesDirTab.offset != 2 {
		t.Fatalf("expected offset clamped to 2, got %d", m.filesDirTab.offset)
	}
	if got := m.filesDirSelection().selectedKey(); got != "/a/b/c" {
		t.Fatalf("expected fallback selection /a/b/c, got %q", got)
	}
}

func TestFilesVizSelectionResetsOnEmptySnapshot(t *testing.T) {
	for _, mode := range []tabVizMode{tabVizModeTreemap, tabVizModeIcicle} {
		m := newFilesVizModel(t, mode, icicleSnapshot(9, 7))
		m = pressJ(t, m, 1)

		m = tickStats(t, m, messages.StatsTickMsg{Snap: filesSnapshot()})
		if m.filesDirTab.offset != 0 {
			t.Fatalf("mode %d: expected offset 0 on empty snapshot, got %d", mode, m.filesDirTab.offset)
		}
		if got := m.filesDirSelection().selectedKey(); got != "" {
			t.Fatalf("mode %d: expected no selection on empty snapshot, got %q", mode, got)
		}
		_ = m.View() // must render the empty state without indexing tiles

		m = tickStats(t, m, messages.StatsTickMsg{Snap: icicleSnapshot(9, 7)})
		if m.filesDirTab.offset != 0 || m.filesDirSelection().selectedKey() == "" {
			t.Fatalf("mode %d: expected first item selected after data returns, got %q at %d",
				mode, m.filesDirSelection().selectedKey(), m.filesDirTab.offset)
		}
	}
}

func TestFilesVizSelectionKeptOnFailedStatsTick(t *testing.T) {
	good := icicleSnapshot(9, 7)
	m := newFilesVizModel(t, tabVizModeIcicle, good)
	m = pressJ(t, m, 4)

	m = tickStats(t, m, messages.StatsTickMsg{Err: errors.New("snapshot build failed")})
	if m.latest != good {
		t.Fatalf("expected last good snapshot kept on failed tick")
	}
	if m.filesDirTab.offset != 4 || m.filesDirSelection().selectedKey() != "/a/d/e" {
		t.Fatalf("expected selection /a/d/e at 4 kept, got %q at %d", m.filesDirSelection().selectedKey(), m.filesDirTab.offset)
	}
}

func TestFilesTreemapNavigationBoundedByTreemapItems(t *testing.T) {
	// /idle has no accesses, so the treemap drops it: two items, three dirs.
	m := newFilesVizModel(t, tabVizModeTreemap, filesSnapshot(
		statsengine.FileSnapshot{Path: "/x/f", Accesses: 9},
		statsengine.FileSnapshot{Path: "/y/f", Accesses: 5},
		statsengine.FileSnapshot{Path: "/idle/f"},
	))
	m = pressJ(t, m, 5)
	if m.filesDirTab.offset != 1 {
		t.Fatalf("expected treemap selection bounded to offset 1, got %d", m.filesDirTab.offset)
	}
}

func TestFilesDirTableSelectionPolicyOnStatsTick(t *testing.T) {
	initial := filesSnapshot(
		statsengine.FileSnapshot{Path: "/x/f", Accesses: 9},
		statsengine.FileSnapshot{Path: "/y/f", Accesses: 5},
	)
	refresh := filesSnapshot(
		statsengine.FileSnapshot{Path: "/w/f", Accesses: 20},
		statsengine.FileSnapshot{Path: "/x/f", Accesses: 9},
		statsengine.FileSnapshot{Path: "/y/f", Accesses: 5},
	)
	tests := []struct {
		name   string
		sort   tableSortState[fileDirSortKey]
		wantAt int
		want   string
	}{
		// Unsorted, the table keeps its positional selection (/w now
		// leads the default accesses order, so row 1 is /x).
		{name: "default order is positional", wantAt: 1, want: "/x"},
		// Sorted by directory, the selected /y is followed to its new row.
		{name: "sorted follows directory", sort: tableSortState[fileDirSortKey]{active: true, key: fileDirSortKeyDir}, wantAt: 2, want: "/y"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newFilesVizModel(t, tabVizModeTable, initial)
			m.filesDirTab.sort = tt.sort
			m = pressJ(t, m, 1)
			m = tickStats(t, m, messages.StatsTickMsg{Snap: refresh})
			if m.filesDirTab.offset != tt.wantAt {
				t.Fatalf("offset %d, want %d", m.filesDirTab.offset, tt.wantAt)
			}
			if got := m.filesDirSelection().selectedKey(); got != tt.want {
				t.Fatalf("selected %q, want %q", got, tt.want)
			}
		})
	}
}

// selectFilesDirKey moves the dir-grouped selection onto key with j presses.
func selectFilesDirKey(t *testing.T, m *Model, key string) *Model {
	t.Helper()
	for range m.filesDirRowCountForMode() {
		if m.filesDirSelection().selectedKey() == key {
			return m
		}
		m = pressJ(t, m, 1)
	}
	if got := m.filesDirSelection().selectedKey(); got != key {
		t.Fatalf("could not select %q, stuck on %q", key, got)
	}
	return m
}

func assertFilesDirSelection(t *testing.T, m *Model, wantAt int, want string) {
	t.Helper()
	if m.filesDirTab.offset != wantAt || m.filesDirSelection().selectedKey() != want {
		t.Fatalf("selected %q at %d, want %q at %d",
			m.filesDirSelection().selectedKey(), m.filesDirTab.offset, want, wantAt)
	}
}

func TestFilesVizSelectionSurvivesMetricToggle(t *testing.T) {
	// /x leads by events, /y by bytes, so b swaps their order.
	snap := filesSnapshot(
		statsengine.FileSnapshot{Path: "/x/f", Accesses: 9, BytesRead: 10},
		statsengine.FileSnapshot{Path: "/y/f", Accesses: 1, BytesRead: 1000},
	)
	for _, mode := range []tabVizMode{tabVizModeTreemap, tabVizModeIcicle} {
		m := newFilesVizModel(t, mode, snap)
		m = selectFilesDirKey(t, m, "/y")
		assertFilesDirSelection(t, m, 1, "/y")

		m = pressKey(m, 'b')
		if m.filesTab.bubble.Metric() != bubbleMetricBytes {
			t.Fatalf("mode %d: expected b to switch to the bytes metric", mode)
		}
		assertFilesDirSelection(t, m, 0, "/y")
	}
}

func TestFilesVizSelectionSurvivesModeCycle(t *testing.T) {
	// Reverse directory sort puts /c first in the table (and bubbles);
	// the treemap orders by events (/a/b, /c) and the icicle adds the /a
	// parent tile (/a, /a/b, /c), so /c sits at a different offset in
	// every mode.
	m := newFilesVizModel(t, tabVizModeTable, filesSnapshot(
		statsengine.FileSnapshot{Path: "/a/b/f", Accesses: 9},
		statsengine.FileSnapshot{Path: "/c/f", Accesses: 5},
	))
	m.filesDirTab.sort = tableSortState[fileDirSortKey]{active: true, key: fileDirSortKeyDir, reverse: true}
	assertFilesDirSelection(t, m, 0, "/c")

	steps := []struct {
		mode   tabVizMode
		wantAt int
	}{
		{tabVizModeBubbles, 0},
		{tabVizModeTreemap, 1},
		{tabVizModeIcicle, 2},
		{tabVizModeTable, 0},
	}
	for _, step := range steps {
		m = pressKey(m, 'v')
		if m.filesTab.mode != step.mode {
			t.Fatalf("expected mode %d after v, got %d", step.mode, m.filesTab.mode)
		}
		assertFilesDirSelection(t, m, step.wantAt, "/c")
	}
}

// deepIcicleSnapshot has a five-level /a/b/c/d/e branch laid out before /z,
// so /z's tile index depends on how many levels the viewport shows.
func deepIcicleSnapshot() *statsengine.Snapshot {
	return filesSnapshot(
		statsengine.FileSnapshot{Path: "/a/b/c/d/e/f", Accesses: 20},
		statsengine.FileSnapshot{Path: "/z/f", Accesses: 1},
	)
}

func TestFilesIcicleSelectionSurvivesViewportChange(t *testing.T) {
	t.Run("window resize", func(t *testing.T) {
		m := newFilesVizModel(t, tabVizModeIcicle, deepIcicleSnapshot())
		next, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 8})
		m = next.(*Model)
		m = selectFilesDirKey(t, m, "/z")
		assertFilesDirSelection(t, m, 4, "/z") // four levels shown

		next, _ = m.Update(tea.WindowSizeMsg{Width: 120, Height: 28})
		m = next.(*Model)
		assertFilesDirSelection(t, m, 5, "/z") // all five levels shown
	})
	t.Run("help toggle", func(t *testing.T) {
		m := newFilesVizModel(t, tabVizModeIcicle, deepIcicleSnapshot())
		m.height = 9
		m.showHelp = true // expanded help leaves room for four levels
		m = selectFilesDirKey(t, m, "/z")
		assertFilesDirSelection(t, m, 4, "/z")

		next, _ := m.Update(tea.KeyPressMsg{Code: tea.KeyF1})
		m = next.(*Model)
		if m.showHelp {
			t.Fatalf("expected F1 to collapse the help bar")
		}
		assertFilesDirSelection(t, m, 5, "/z")
	})
}

func TestFilesBubblesSelectionTracksPositionWhenUnsorted(t *testing.T) {
	// Bubbles mode follows the table rule: the offset is the table
	// selection carried through bubbles mode (j/k move the bubble chart's
	// own selection there), so unsorted it stays positional across ticks.
	m := newFilesVizModel(t, tabVizModeBubbles, filesSnapshot(
		statsengine.FileSnapshot{Path: "/x/f", Accesses: 9},
		statsengine.FileSnapshot{Path: "/y/f", Accesses: 5},
	))
	m.filesDirTab.offset = 1
	assertFilesDirSelection(t, m, 1, "/y")

	m = tickStats(t, m, messages.StatsTickMsg{Snap: filesSnapshot(
		statsengine.FileSnapshot{Path: "/w/f", Accesses: 20},
		statsengine.FileSnapshot{Path: "/x/f", Accesses: 9},
		statsengine.FileSnapshot{Path: "/y/f", Accesses: 5},
	)})
	assertFilesDirSelection(t, m, 1, "/x")
}
