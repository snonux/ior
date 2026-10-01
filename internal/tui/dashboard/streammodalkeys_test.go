package dashboard

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
)

// TestStreamSearchModalGetsRealEditingKeys drives the dashboard the way the
// terminal does: with the Stream search modal open, Ctrl+X must type nothing
// and Ctrl+A must move to the start of the input, so typing "z" afterwards
// prepends it. Before task 9z2 the stream handed the modal the key's name,
// which typed "ctrl+x" and "ctrl+a" as text.
func TestStreamSearchModalGetsRealEditingKeys(t *testing.T) {
	m := newFitModel(t, fitCase{tab: TabStream}, false, 100, 30)
	m = pressStreamKey(t, m, '/')
	if !m.streamModel.SearchModalVisible() {
		t.Fatal("/ did not open the search modal")
	}
	presses := []tea.KeyPressMsg{
		{Code: 'a', Text: "a"},
		{Code: 'b', Text: "b"},
		{Code: 'x', Mod: tea.ModCtrl},
		{Code: 'a', Mod: tea.ModCtrl},
		{Code: 'z', Text: "z"},
	}
	for _, press := range presses {
		next, _ := m.Update(press)
		m = next.(*Model)
	}
	if !m.streamModel.SearchModalVisible() {
		t.Fatal("the search modal closed while editing")
	}
	out := ansi.Strip(m.View().Content)
	if !strings.Contains(out, "/zab") || strings.Contains(out, "ctrl") {
		t.Fatalf("search input does not read \"zab\":\n%s", out)
	}
}
