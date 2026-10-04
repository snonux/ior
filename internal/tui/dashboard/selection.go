package dashboard

import (
	"slices"
	"time"

	"ior/internal/statsengine"
	common "ior/internal/tui/common"
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
	// wanted survives the moments when the item is not in keys (the empty
	// snapshot right after a reset, the first non-empty one that lacks an
	// idle item, a filter that hides everything): it remembers the selected
	// item so it can be re-selected when it returns, until the user moves
	// the selection or stickyKeyGrace passes. Nil for a selection without
	// such storage; the value lives on the Model because keyedSelection
	// itself is rebuilt on every call.
	wanted *stickyKey
}

// stickyKeyGrace bounds how long a stickyKey stays a wish. Its start is the
// moment the list first went empty, so a table a filter has emptied for an
// hour does not re-select its old row when it is unfiltered, while the
// window is still long enough (two default auto-reset intervals) for a
// workload that is quiet after a reset to bring the selected item back.
const stickyKeyGrace = common.SelectionWishGrace

// stickyClock is the clock stickyKey expiry reads; tests replace it.
var stickyClock = time.Now

// stickyKey is a selection's wish to be on an item it lost track of. A list
// that is empty is not a list the item was removed from - the 30s auto-reset
// and every filter swap empty it for a tick - and the snapshot right after
// it holds only the rows active in its first window, so an item that is idle
// for that one tick is missing from the first non-empty list as well. The
// selection therefore keeps the item's key across empty AND non-empty lists
// that lack it, and moves onto it when it appears - the same rule the flame
// selection follows with its wantedPath. The wish ends when
//   - the item is found (the selection is on it),
//   - the user moves the selection or re-sorts (forget: a decision by the
//     user, including a clamped no-op move on an empty list, must not be
//     undone by a wish they never saw),
//   - stickyKeyGrace has passed since the list first went empty.
//
// While a wish is pending it takes precedence over the row the offset
// clamped to in the meantime: that row is only a placeholder.
type stickyKey struct {
	// key is the remembered item identity; "" means nothing is remembered.
	key string
	// since is when the wish was first made, the start of the grace window.
	since time.Time
}

// remember records key as the item to look for. Repeating the pending key
// (every empty tick does) keeps the original start of the grace window, so
// an ever-empty list still lets the wish expire.
func (k *stickyKey) remember(key string) {
	if k.key == key {
		return
	}
	k.key, k.since = key, stickyClock()
}

// peek returns the pending wish, or "" for none. A wish past its grace is
// dropped here.
func (k *stickyKey) peek() string {
	if k == nil || k.key == "" {
		return ""
	}
	if stickyClock().Sub(k.since) > stickyKeyGrace {
		k.forget()
		return ""
	}
	return k.key
}

// forget ends the wish. It is nil-safe so navigation code can call it for a
// selection that has no stickyKey.
func (k *stickyKey) forget() {
	if k != nil {
		k.key, k.since = "", time.Time{}
	}
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
// instead (and a listed-nowhere key stays wished, see stickyKey). An empty
// list leaves the offset alone and remembers key, so the selection is not
// lost to a reset.
func (s keyedSelection) reanchor(key string) {
	*s.offset = reanchorSticky(*s.offset, s.wanted, s.keys(), key, findKeyOffset)
}

// capture records the item to follow and returns the function that
// re-anchors onto it once the change is in place. A pending wish (stickyKey)
// wins over the currently selected row, which is only where the offset
// clamped to while the wished item was missing. With byKey false the
// selection is positional: the returned function only clamps the offset
// against the new list.
func (s keyedSelection) capture(byKey bool) (reanchor func()) {
	key := ""
	if byKey {
		key = s.wanted.peek()
		if key == "" {
			key = s.selectedKey()
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

// reanchorSticky is reanchorOffset that survives an empty row list and a
// missing key. With rows it behaves as reanchorOffset, and resolves the
// wish: found ends it, missing keeps it pending (the offset clamps
// meanwhile). Without rows it returns current unchanged - not 0 - and
// remembers selected in wanted, so a selection captured against a populated
// snapshot is found again when the item returns; the offset stays where it
// was so that a positional (unkeyed) selection also keeps its place.
func reanchorSticky[T any](current int, wanted *stickyKey, rows []T, selected string, find func([]T, string) (int, bool)) int {
	if len(rows) == 0 {
		if selected != "" && wanted != nil {
			wanted.remember(selected)
		}
		return current
	}
	if wanted != nil {
		// The wish ends when found, and also when this re-anchor was not about
		// it: selected is the wish itself whenever the wish was pending at
		// capture time (see capture), so a different or empty selected means
		// the capture skipped it. That is reachable for the Files table, whose
		// capture yields "" while it is not the shown sorted table (the user
		// switched to a directory view); the wish must not linger to yank the
		// selection when the table returns.
		if _, found := find(rows, selected); found || wanted.key != selected {
			wanted.forget()
		}
	}
	return reanchorOffset(current, rows, selected, find)
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
