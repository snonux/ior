# TUI Flamegraph Expected Behavior

This document records the expected interaction and layout behavior for the TUI
flamegraph. It is intended as a stable reference for regressions and for tests
under `internal/tui/flamegraph/` and `internal/tui/dashboard/`.

## Interaction

- `space` toggles pause. `p` does not pause the flamegraph and remains reserved
  for the global PID picker at the top-level TUI.
- `enter` and left-click zoom into the selected or clicked frame.
- Clicking an ancestor frame in the zoom lineage re-roots the view to that
  ancestor.
- `u`, `backspace`, and `esc` undo one zoom step.
- Direct clicks into a deep descendant create a single undo step back to the
  previous zoom root, not an implicit stack of every skipped ancestor.
- While paused, navigation and zoom must continue to work against the frozen
  snapshot.

## Layout

- The selected frame must not render with underline or a horizontal highlight
  line across the bar.
- The current zoom root must span the full flamegraph width.
- The children of the current zoom root must be normalized to the full viewport
  width, even when the zoom root has self time or exclusive weight.
- Zooming from any direction must produce the same full-width result for the
  newly selected zoom root.
- The zoom lineage rows shown above the zoomed subtree provide context, but they
  must not steal horizontal space from the zoomed subtree.

## Rendering

- Rendering the dashboard view must not mutate persistent flamegraph state.
- Redundant same-size viewport updates must be no-ops.
- In paused mode, repeated renders must not reintroduce stale frame geometry or
  leave artifacts from a previous layout on screen.

## Regression Coverage

These expectations are covered by tests in:

- `internal/tui/flamegraph/renderer_test.go`
- `internal/tui/flamegraph/model_test.go`
- `internal/tui/flamegraph/stress_test.go`
- `internal/tui/dashboard/model_test.go`
