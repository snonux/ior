package flamegraph

import (
	"strings"
	"testing"
)

// TestToolbarAndStatusSanitizeQueryAndMessage checks the search query and
// status message echoed by the toolbar and the selection status line carry
// no OSC 8 link, SGR hidden text or raw C1 CSI byte (task io2). These two
// lines are what View places above and below the flame area.
func TestToolbarAndStatusSanitizeQueryAndMessage(t *testing.T) {
	m := NewModel(nil)
	m.width = 400
	m.anim.frames = []tuiFrame{{Name: "root", Width: 400, Path: "root"}}
	m.search.searchQuery = "q\x1b]8;;http://evil\aclick\x1b]8;;\a"
	m.statusMessage = "msg\x1b[8mhidden\x9b31m"

	toolbar := m.toolbarLine()
	status := m.selectionStatusLine()
	for name, out := range map[string]string{"toolbar": toolbar, "status line": status} {
		for _, bad := range []string{"\x1b]8", "\x1b[8m", "\a", "\x9b"} {
			if strings.Contains(out, bad) {
				t.Fatalf("%s contains injected %q: %q", name, bad, out)
			}
		}
		if !strings.Contains(out, "filter:q?]8;;http://evil?click") {
			t.Fatalf("%s lost the sanitised query: %q", name, stripSGR(out))
		}
	}
	if !strings.Contains(toolbar, "msg?[8mhidden?31m") {
		t.Fatalf("toolbar lost the sanitised status message: %q", stripSGR(toolbar))
	}
}
