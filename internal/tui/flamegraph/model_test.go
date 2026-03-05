package flamegraph

import (
	coreflamegraph "ior/internal/flamegraph"
	"testing"

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

func pressFlameKey(t *testing.T, m Model, keyMsg tea.KeyPressMsg) Model {
	t.Helper()
	next, _ := m.Update(keyMsg)
	return next.(Model)
}
