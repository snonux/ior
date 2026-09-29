package flamegraph

import "testing"

// TestInitDoesNotMutateModel pins that Init is side-effect free: it starts
// nothing (the dashboard drives refreshes and animation) and leaves the
// rendered model unchanged.
func TestInitDoesNotMutateModel(t *testing.T) {
	m := NewModel(nil)
	m.width, m.height = 80, 24
	m.anim.frames = []tuiFrame{{Name: "alpha", Path: "root" + pathSeparator + "alpha"}}
	beforeView := m.View().Content
	beforeGen, beforeInFlight := m.refreshGeneration, m.refreshInFlight

	if cmd := m.Init(); cmd != nil {
		t.Fatal("Init must not schedule anything")
	}
	if m.View().Content != beforeView || m.refreshGeneration != beforeGen || m.refreshInFlight != beforeInFlight {
		t.Fatal("Init mutated the model")
	}
}
