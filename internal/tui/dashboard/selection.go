package dashboard

import (
	"slices"

	"ior/internal/statsengine"
)

// keyedSelection is a selection offset into an ordered list of item
// identities (keys) that a stats tick, a metric change or a viz-mode change
// can reorder or resize - the treemaps and the icicle reorder their items by
// metric value on every refresh. It is the one implementation behind every
// tab's "keep the same item selected" rule: record the selected item's key
// before the change, re-find it afterwards, and clamp the offset against the
// new list when the item is gone (or when there is nothing to follow).
//
// A tab exposes one per selection through an accessor (filesDirSelection,
// syscallsTableSelection, syscallsTreemapSelection, processesTableSelection,
// processesTreemapSelection) and wires them into its CaptureSelection and
// KeepSelection registry hooks.
type keyedSelection struct {
	// offset is the selection index the tab renders and navigates with.
	offset *int
	// keys returns, in selection order, the identity of every item offset
	// indexes right now. It is evaluated again after the change, so it must
	// read the live model state rather than a copy taken earlier.
	keys func() []string
	// wanted survives the moments when keys is empty (the snapshot right
	// after a reset, a filter that hides everything): it remembers the
	// selected item so it can be re-selected when rows return. Nil for a
	// selection without such storage; the value lives on the Model because
	// keyedSelection itself is rebuilt on every call.
	wanted *stickyKey
}

// stickyKey is a selection's memory of the item it lost to an empty list. A
// list that is empty is not a list the item was removed from - the 30s
// auto-reset and every filter swap empty it for a tick - so the selection
// keeps the item's key and its offset and looks for the key again once rows
// come back, instead of falling to row 0.
type stickyKey struct {
	// key is the remembered item identity; "" means nothing is remembered.
	key string
	// offset is the selection offset at the moment the list went empty. If
	// it has changed by the time rows return, the user has navigated in
	// between and the remembered key is stale.
	offset int
}

// remember records key as the item to look for when rows return.
func (k *stickyKey) remember(key string, offset int) {
	k.key, k.offset = key, offset
}

// take returns the remembered key, or "" when nothing is remembered, and
// forgets it: a remembered item is looked for once, in the first non-empty
// list, and then either found or given up on.
func (k *stickyKey) take(offset int) string {
	key, at := k.key, k.offset
	k.key, k.offset = "", 0
	if at != offset {
		return ""
	}
	return key
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
// instead. An empty list leaves the offset alone and remembers key (see
// stickyKey), so the selection is not lost to a reset.
func (s keyedSelection) reanchor(key string) {
	*s.offset = reanchorSticky(*s.offset, s.wanted, s.keys(), key, findKeyOffset)
}

// capture records the selected item and returns the function that
// re-anchors onto it once the change is in place. With byKey false the
// selection is positional: the returned function only clamps the offset
// against the new list. When the list is empty at capture time the item
// remembered from an earlier empty list (if any) is the one to follow.
func (s keyedSelection) capture(byKey bool) (reanchor func()) {
	key := ""
	if byKey {
		key = s.selectedKey()
		if key == "" {
			key = takeWanted(s.wanted, *s.offset)
		}
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

// takeWanted returns the item remembered in wanted for the selection at
// offset, or "" for none (wanted may be nil).
func takeWanted(wanted *stickyKey, offset int) string {
	if wanted == nil {
		return ""
	}
	return wanted.take(offset)
}

// reanchorSticky is reanchorOffset that survives an empty row list. With
// rows it behaves as reanchorOffset. Without rows it returns current
// unchanged - not 0 - and remembers selected in wanted, so a selection
// captured against a populated snapshot is found again when the next
// non-empty one arrives; the offset stays where it was so that a positional
// (unkeyed) selection also keeps its place.
func reanchorSticky[T any](current int, wanted *stickyKey, rows []T, selected string, find func([]T, string) (int, bool)) int {
	if len(rows) > 0 {
		if wanted != nil {
			// Rows are back (or never left): whatever was remembered is
			// resolved by this call, found or not, and must not linger.
			wanted.take(current)
		}
		return reanchorOffset(current, rows, selected, find)
	}
	if selected != "" && wanted != nil {
		wanted.remember(selected, current)
	}
	return current
}

// keepSelections runs change exactly once and keeps every one of sels on
// its selected item across it: for a tab whose several selections (table
// and treemap) a single change can reorder.
func keepSelections(change func(), sels ...keyedSelection) {
	reanchors := make([]func(), 0, len(sels))
	for _, sel := range sels {
		reanchors = append(reanchors, sel.capture(true))
	}
	change()
	captureSelections(reanchors...)()
}

// captureSelections combines the re-anchor functions of several captures
// into one CaptureSelection result.
func captureSelections(reanchors ...func()) func() {
	return func() {
		for _, reanchor := range reanchors {
			reanchor()
		}
	}
}

// keysOf maps rows to their selection keys, in order.
func keysOf[T any](rows []T, key func(T) string) []string {
	keys := make([]string, 0, len(rows))
	for _, row := range rows {
		keys = append(keys, key(row))
	}
	return keys
}

// findKeyOffset locates key in a keyedSelection's key list.
func findKeyOffset(keys []string, key string) (int, bool) {
	index := slices.Index(keys, key)
	return index, index >= 0
}

// treemapItemKeys returns the selection keys of treemap items in layout
// order, so index i here is tile i on screen.
func treemapItemKeys(items []syscallTreemapItem) []string {
	return keysOf(items, func(item syscallTreemapItem) string { return item.Key })
}

// processKey is a process row's selection identity: its displayed ID
// (statsengine.ProcessID), the PID suffixed with the row's lifetime ordinal
// when the kernel recycled the PID during the session, so the rows of two
// processes that shared a PID stay separately selectable. The first lifetime
// keeps the bare PID. The treemap items, bubbles and table rows share it, so
// a selection can move between them when the viz mode changes.
func processKey(pid, lifetime uint32) string {
	return statsengine.ProcessID(pid, lifetime)
}

// processRowKey is processKey for a snapshot row.
func processRowKey(row statsengine.ProcessSnapshot) string {
	return processKey(row.PID, row.Lifetime)
}
