package dashboard

import (
	"slices"
	"strconv"
)

// keyedSelection is a selection offset into an ordered list of item
// identities (keys) that a stats tick, a metric change or a viz-mode change
// can reorder or resize - the treemaps and the icicle reorder their items by
// metric value on every refresh. It is the one implementation behind every
// tab's "keep the same item selected" rule: record the selected item's key
// before the change, re-find it afterwards, and clamp the offset against the
// new list when the item is gone (or when there is nothing to follow).
//
// A tab exposes one through an accessor (filesDirSelection,
// syscallsTreemapSelection, processesSelection) and wires it into its
// CaptureSelection and KeepSelection registry hooks.
type keyedSelection struct {
	// offset is the selection index the tab renders and navigates with.
	offset *int
	// keys returns, in selection order, the identity of every item offset
	// indexes right now. It is evaluated again after the change, so it must
	// read the live model state rather than a copy taken earlier.
	keys func() []string
}

// selectedKey returns the identity of the selected item (the offset clamped
// to the list, as the renderers clamp it), or "" when the list is empty.
func (s keyedSelection) selectedKey() string {
	keys := s.keys()
	if len(keys) == 0 {
		return ""
	}
	return keys[clampOffset(*s.offset, len(keys))]
}

// reanchor moves the selection onto key in the current list. An empty key,
// or one that is no longer listed, clamps the offset against the list
// instead; an empty list resets it to 0.
func (s keyedSelection) reanchor(key string) {
	*s.offset = reanchorOffset(*s.offset, s.keys(), key, findKeyOffset)
}

// capture records the selected item and returns the function that
// re-anchors onto it once the change is in place. With byKey false the
// selection is positional: the returned function only clamps the offset
// against the new list.
func (s keyedSelection) capture(byKey bool) (reanchor func()) {
	key := ""
	if byKey {
		key = s.selectedKey()
	}
	return func() { s.reanchor(key) }
}

// keep runs change - which must be applied exactly once - and keeps the
// selected item selected across it.
func (s keyedSelection) keep(change func()) {
	reanchor := s.capture(true)
	change()
	reanchor()
}

// findKeyOffset locates key in a keyedSelection's key list.
func findKeyOffset(keys []string, key string) (int, bool) {
	index := slices.Index(keys, key)
	return index, index >= 0
}

// treemapItemKeys returns the selection keys of treemap items in layout
// order, so index i here is tile i on screen.
func treemapItemKeys(items []syscallTreemapItem) []string {
	keys := make([]string, 0, len(items))
	for _, item := range items {
		keys = append(keys, item.Key)
	}
	return keys
}

// processKey is a process's selection identity: its PID. The treemap items
// and the table rows share it, so a selection can move between the two
// when the viz mode changes.
func processKey(pid uint32) string {
	return strconv.FormatUint(uint64(pid), 10)
}
