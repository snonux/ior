package dashboard

import "slices"

// bubbleFrameNode is the part of a bubble that shows up in the painted grid:
// its label and its exact position and size. Comparing these floats exactly
// is deliberate: bit-identical inputs paint an identical frame, and any
// difference at all just costs one re-paint.
type bubbleFrameNode struct {
	label     string
	x, y, rad float64
}

// bubbleFrameKey is everything Render's output depends on: the header and
// status text (which already carry the tab label, metric, selection counts
// and the selected bubble's numbers), the size, the theme, the selection and
// the geometry of every bubble.
type bubbleFrameKey struct {
	header, status string
	width, height  int
	isDark         bool
	selected       int
	nodes          []bubbleFrameNode
}

func (k *bubbleFrameKey) equal(o *bubbleFrameKey) bool {
	return k.header == o.header && k.status == o.status &&
		k.width == o.width && k.height == o.height &&
		k.isDark == o.isDark && k.selected == o.selected &&
		slices.Equal(k.nodes, o.nodes)
}

// bubbleFrameCache remembers the last rendered view together with the key it
// was rendered for. It is keyed on the rendering inputs themselves rather
// than invalidated by the mutators, so a code path that changes the chart
// without knowing about the cache (or a test that pokes fields directly)
// cannot serve a stale frame. Only one frame is kept: the chart is drawn in
// one size at a time, and an idle chart asks for that same frame repeatedly.
type bubbleFrameCache struct {
	key     bubbleFrameKey // key of view
	probe   bubbleFrameKey // key being looked up; its nodes buffer is reused
	view    string
	hasView bool
}

// lookup returns the cached view when it was rendered for the chart's
// current state. On a miss the probe key stays available for store.
func (f *bubbleFrameCache) lookup(c *bubbleChart, header, status string, width, height int) (string, bool) {
	f.probe.header, f.probe.status = header, status
	f.probe.width, f.probe.height = width, height
	f.probe.isDark, f.probe.selected = c.isDark, c.selected
	f.probe.nodes = f.probe.nodes[:0]
	for _, n := range c.nodes {
		f.probe.nodes = append(f.probe.nodes, bubbleFrameNode{label: n.Label, x: n.x, y: n.y, rad: n.radius})
	}
	if f.hasView && f.key.equal(&f.probe) {
		return f.view, true
	}
	return "", false
}

// store remembers view as the rendering of the key of the last lookup. It
// swaps the two keys so that neither's node buffer is reallocated.
func (f *bubbleFrameCache) store(view string) {
	f.key, f.probe = f.probe, f.key
	f.view, f.hasView = view, true
}
