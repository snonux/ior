package flamegraph

import (
	coreflamegraph "ior/internal/flamegraph"
	"testing"
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
