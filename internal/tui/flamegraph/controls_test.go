package flamegraph

import (
	"errors"
	"testing"

	coreflamegraph "ior/internal/flamegraph"
)

type setHeightErrorTrie struct {
	*coreflamegraph.LiveTrie
	err error
}

func (t *setHeightErrorTrie) SetHeightField(string) error {
	return t.err
}

type forcedHeightFieldTrie struct {
	*coreflamegraph.LiveTrie
	field string
}

func (t *forcedHeightFieldTrie) HeightField() string {
	return t.field
}

func TestToggleHeightFieldErrorKeepsExistingState(t *testing.T) {
	base := coreflamegraph.NewLiveTrie([]string{"comm", "path", "tracepoint"}, "count", "")
	liveTrie := &setHeightErrorTrie{
		LiveTrie: base,
		err:      errors.New("set-height failed"),
	}
	m := NewModel(liveTrie)
	m.snapshot = &snapshotNode{Name: "root", Total: 10}
	m.frames = []tuiFrame{{Name: "root", Path: "root", Total: 10}}

	m.toggleHeightField()

	if got, want := m.heightField, ""; got != want {
		t.Fatalf("heightField = %q, want %q on SetHeightField error", got, want)
	}
	if got, want := m.statusMessage, "Height toggle error: set-height failed"; got != want {
		t.Fatalf("statusMessage = %q, want %q", got, want)
	}
	if m.snapshot == nil || len(m.frames) == 0 {
		t.Fatalf("expected snapshot/layout state to remain intact on SetHeightField error")
	}
}

func TestHeightFieldLabelReturnsRawValueForUnknownField(t *testing.T) {
	m := NewModel(nil)
	m.heightField = "custom-height"

	if got, want := m.heightFieldLabel(), "custom-height"; got != want {
		t.Fatalf("heightFieldLabel() = %q, want %q", got, want)
	}
}

func TestSyncHeightFieldToTrieNilLiveTrieClearsField(t *testing.T) {
	m := NewModel(nil)
	m.heightField = "bytes"

	m.syncHeightFieldToTrie()

	if got, want := m.heightField, ""; got != want {
		t.Fatalf("heightField = %q, want %q for nil liveTrie", got, want)
	}
}

func TestSyncHeightFieldToTrieUnknownFieldFallsBackToOff(t *testing.T) {
	base := coreflamegraph.NewLiveTrie([]string{"comm", "path", "tracepoint"}, "count", "")
	liveTrie := &forcedHeightFieldTrie{
		LiveTrie: base,
		field:    "mystery",
	}
	m := NewModel(nil)
	m.liveTrie = liveTrie
	m.heightField = "duration"

	m.syncHeightFieldToTrie()

	if got, want := m.heightField, ""; got != want {
		t.Fatalf("heightField = %q, want %q for unknown trie height field", got, want)
	}
}
