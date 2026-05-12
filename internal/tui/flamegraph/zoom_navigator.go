package flamegraph

import "strings"

// ZoomNavigator manages the zoom path, stack, and root node for the flamegraph
// view. It tracks the current zoom level, supports undo via a stack, and rebuilds
// the frame layout whenever the zoom target changes.
type ZoomNavigator struct {
	zoomPath      string
	zoomStack     []zoomState
	zoomRoot      *snapshotNode
	zoomLineWidth int
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

// rootSnapshotPath returns the canonical root path derived from the snapshot or frames.
func (z *ZoomNavigator) rootSnapshotPath(snapshot *snapshotNode, frames []tuiFrame) string {
	if snapshot != nil {
		return frameName(snapshot.Name, 0)
	}
	if len(frames) > 0 {
		return frames[0].Path
	}
	return ""
}

// reset clears all zoom state and returns a status message.
func (z *ZoomNavigator) reset() string {
	z.zoomRoot = nil
	z.zoomPath = ""
	z.zoomStack = nil
	z.zoomLineWidth = 0
	return "Zoom reset to root"
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
