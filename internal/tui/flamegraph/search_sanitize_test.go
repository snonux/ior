package flamegraph

import (
	"strings"
	"testing"
)

// hostileQueries are committed search texts a paste can leave behind: the
// textinput drops only control runes, so these reach the renderer. fmt's %q
// escapes some (NBSP, bidi override) but prints U+2800 and U+FFFC as is, so the
// status line has to sanitise the query itself (task ms2).
var hostileQueries = []string{"a\u2800b", "a\u00a0b", "a\u202eb", "a\ufffcb"}

const hostileRunes = "\u2800\u00a0\u202e\ufffc"

func assertNoHostileRunes(t *testing.T, label, out string) {
	t.Helper()
	for _, r := range hostileRunes {
		if strings.ContainsRune(out, r) {
			t.Errorf("%s still contains %U: %q", label, r, out)
		}
	}
}

// TestFilterStatusSanitisesTheCommittedQuery covers the status line shown
// while a filter has matches and the placeholder shown when it matches
// nothing: neither may print a blank-rendering or bidi rune of the query.
func TestFilterStatusSanitisesTheCommittedQuery(t *testing.T) {
	snapshot := &snapshotNode{Name: "root", Total: 10, Children: []*snapshotNode{{Name: "child", Total: 10}}}
	frames := buildTerminalLayout(snapshot, 80, 6)
	for _, query := range hostileQueries {
		withMatch := RenderTerminalView(RenderContext{
			Frames: frames, Width: 160, Height: 6, SelectedIdx: 1,
			MatchSet: map[int]bool{1: true}, MetricLabel: "events", IsDark: true, SearchQuery: query,
		})
		assertNoHostileRunes(t, "filtered status for "+query, withMatch)
		noMatch := RenderTerminalView(RenderContext{
			Frames: frames, Width: 160, Height: 6, SelectedIdx: 0,
			FilterSet: map[int]bool{}, MetricLabel: "events", IsDark: true, SearchQuery: query,
		})
		assertNoHostileRunes(t, "no-match placeholder for "+query, noMatch)
	}
}

// TestFilterStatusKeepsOrdinaryQueryText is the negative: a plain query is
// shown exactly as before, quotes included.
func TestFilterStatusKeepsOrdinaryQueryText(t *testing.T) {
	snapshot := &snapshotNode{Name: "root", Total: 10, Children: []*snapshotNode{{Name: "child", Total: 10}}}
	frames := buildTerminalLayout(snapshot, 80, 6)
	out := RenderTerminalView(RenderContext{
		Frames: frames, Width: 160, Height: 6, SelectedIdx: 1,
		MatchSet: map[int]bool{1: true}, MetricLabel: "events", IsDark: true, SearchQuery: "ch ild",
	})
	if !strings.Contains(out, `Filter "ch ild"`) {
		t.Fatalf("ordinary query was altered: %q", out)
	}
}
