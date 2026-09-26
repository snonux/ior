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
			if got := m.selectedFilesDirKey(); got != tt.selected {
				t.Fatalf("before tick: selected %q, want %q", got, tt.selected)
			}

			// Two ticks: the selection must hold, not drift tick by tick.
			for tick := range 2 {
				m = tickStats(t, m, messages.StatsTickMsg{Snap: tt.refresh})
				if m.filesDirTab.offset != tt.want {
					t.Fatalf("tick %d: offset %d, want %d", tick, m.filesDirTab.offset, tt.want)
				}
				if got := m.selectedFilesDirKey(); got != tt.selected {
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
	if got := m.selectedFilesDirKey(); got != "/a/b/c" {
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
		if got := m.selectedFilesDirKey(); got != "" {
			t.Fatalf("mode %d: expected no selection on empty snapshot, got %q", mode, got)
		}
		_ = m.View() // must render the empty state without indexing tiles

		m = tickStats(t, m, messages.StatsTickMsg{Snap: icicleSnapshot(9, 7)})
		if m.filesDirTab.offset != 0 || m.selectedFilesDirKey() == "" {
			t.Fatalf("mode %d: expected first item selected after data returns, got %q at %d",
				mode, m.selectedFilesDirKey(), m.filesDirTab.offset)
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
	if m.filesDirTab.offset != 4 || m.selectedFilesDirKey() != "/a/d/e" {
		t.Fatalf("expected selection /a/d/e at 4 kept, got %q at %d", m.selectedFilesDirKey(), m.filesDirTab.offset)
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
			if got := m.selectedFilesDirKey(); got != tt.want {
				t.Fatalf("selected %q, want %q", got, tt.want)
			}
		})
	}
}
