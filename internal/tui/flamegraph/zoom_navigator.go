package flamegraph

import "strings"

// ZoomNavigator owns the zoom state of the flamegraph view: the current zoom
// path, the snapshot node it resolves to, and the undo stack. It only tracks
// which subtree is the view root; laying out frames for that root is the
// Model's job (Model.rebuildFrames), which it does after every successful zoom
// transition reported here.
type ZoomNavigator struct {
	zoomPath      string
	zoomStack     []zoomState
	zoomRoot      *snapshotNode
	zoomLineWidth int
}

// path returns the zoom path, or "" when the view shows the whole snapshot.
func (z *ZoomNavigator) path() string {
	return z.zoomPath
}

// layoutRoot returns the node the frame layout starts from and its path: the
// zoom root when one is resolved, otherwise snapshot with an empty path.
func (z *ZoomNavigator) layoutRoot(snapshot *snapshotNode) (*snapshotNode, string) {
	if z.zoomRoot != nil {
		return z.zoomRoot, z.zoomPath
	}
	return snapshot, ""
}

// adoptRoot installs a zoom root that a background refresh resolved for the
// current zoom path in a newer snapshot (nil when the path vanished).
func (z *ZoomNavigator) adoptRoot(root *snapshotNode) {
	z.zoomRoot = root
}

// resolveRoot re-resolves the zoom root for the current zoom path in snapshot.
// With no zoom path the root is cleared; a path missing from snapshot also
// leaves a nil root, so the layout falls back to the whole snapshot.
func (z *ZoomNavigator) resolveRoot(snapshot *snapshotNode) {
	if z.zoomPath == "" {
		z.zoomRoot = nil
		return
	}
	z.zoomRoot = findNodeByPath(snapshot, z.zoomPath)
}

// currentRootPath returns the path of the current view root.
// When zoomed in, that is the zoom path; otherwise it is the first frame's path.
func (z *ZoomNavigator) currentRootPath(frames []tuiFrame) string {
	if z.zoomPath != "" {
		return z.zoomPath
	}
	if len(frames) == 0 {
		return ""
	}
	return frames[0].Path
}

// setPath makes path the view root without touching the undo stack. An empty
// path or the snapshot root's own path zooms out to the whole snapshot. It
// returns false, leaving the state unchanged, when snapshot is nil or path does
// not exist in it.
func (z *ZoomNavigator) setPath(path string, snapshot *snapshotNode) bool {
	if snapshot == nil {
		return false
	}
	if path == "" || path == frameName(snapshot.Name, 0) {
		z.zoomRoot = nil
		z.zoomPath = ""
		z.zoomLineWidth = 0
		return true
	}
	target := findNodeByPath(snapshot, path)
	if target == nil {
		return false
	}
	z.zoomRoot = target
	z.zoomPath = path
	z.zoomLineWidth = 0
	return true
}

// descend zooms into path and pushes the previous view root onto the undo
// stack. On failure (see setPath) neither the zoom nor the stack changes.
func (z *ZoomNavigator) descend(path string, snapshot *snapshotNode) bool {
	prevRootPath := z.zoomPath
	if !z.setPath(path, snapshot) {
		return false
	}
	z.zoomStack = append(z.zoomStack, zoomState{path: prevRootPath})
	return true
}

// ascendTo zooms out directly to the ancestor path and rebuilds the undo stack
// from its path prefixes, so undo keeps walking up one level at a time. On
// failure (see setPath) neither the zoom nor the stack changes.
func (z *ZoomNavigator) ascendTo(path string, snapshot *snapshotNode) bool {
	if !z.setPath(path, snapshot) {
		return false
	}
	z.zoomStack = buildZoomStack(path)
	return true
}

// undo pops the most recent undo entry and zooms back to it. It returns false
// when the stack is empty or snapshot is nil (nothing is popped), and also when
// the popped path no longer resolves in snapshot; that entry is dropped so a
// repeated undo moves on to the next one.
func (z *ZoomNavigator) undo(snapshot *snapshotNode) bool {
	if len(z.zoomStack) == 0 || snapshot == nil {
		return false
	}
	lastIdx := len(z.zoomStack) - 1
	last := z.zoomStack[lastIdx]
	z.zoomStack = z.zoomStack[:lastIdx]
	return z.setPath(last.path, snapshot)
}

// reset clears all zoom state, including the undo stack.
func (z *ZoomNavigator) reset() {
	z.zoomRoot = nil
	z.zoomPath = ""
	z.zoomStack = nil
	z.zoomLineWidth = 0
}

// alreadyAtRoot reports whether no zoom is active and the stack is empty.
func (z *ZoomNavigator) alreadyAtRoot() bool {
	return z.zoomRoot == nil && len(z.zoomStack) == 0
}

// buildZoomStack builds the ancestor zoom stack for a direct deep-zoom path.
// It creates entries for every path prefix so undo walks back up one step at a
// time: root → A → A/A1 etc.
func buildZoomStack(path string) []zoomState {
	parts := strings.Split(path, pathSeparator)
	if len(parts) <= 1 {
		return nil
	}
	stack := []zoomState{{path: ""}}
	for idx := 1; idx < len(parts)-1; idx++ {
		stack = append(stack, zoomState{path: strings.Join(parts[:idx+1], pathSeparator)})
	}
	return stack
}
