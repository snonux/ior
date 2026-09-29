package flamegraph

import (
	"testing"
	"time"
)

func TestFrameCoordToTargetRowKeepsUniformBarMapping(t *testing.T) {
	frames := []tuiFrame{
		{Name: "root", Row: 0, Col: 0, Width: 20, Path: "root"},
		{Name: "a", Row: 1, Col: 0, Width: 20, Path: "root" + pathSeparator + "a"},
		{Name: "b", Row: 2, Col: 0, Width: 20, Path: "root" + pathSeparator + "a" + pathSeparator + "b"},
		{Name: "leaf", Row: 3, Col: 0, Width: 20, Path: "root" + pathSeparator + "a" + pathSeparator + "b" + pathSeparator + "leaf"},
	}
	availableRows := 8
	params := computeRenderParamsForAvailableRows(frames, availableRows, false)
	want := []int{3, 3, 2, 2, 1, 1, 0, 0}
	for dataRow, expected := range want {
		line, ok := frameCoordToLine(dataRow, params)
		if !ok || line.row != expected || line.band != -1 {
			t.Fatalf("dataRow=%d: got %+v ok=%v want row=%d band=-1", dataRow, line, ok, expected)
		}
	}
}

func TestFrameCoordToTargetRowHeightMetricMapsExpandedLeafBand(t *testing.T) {
	frames := []tuiFrame{
		{Name: "root", Row: 0, Col: 0, Width: 20, Path: "root"},
		{Name: "leaf", Row: 1, Col: 0, Width: 20, Path: "root" + pathSeparator + "leaf", HeightTotal: 100},
	}
	availableRows := 6
	params := computeRenderParamsForAvailableRows(frames, availableRows, true)
	// The leaf row fills dataRows 0..4 as bands 4..0 (top band first, as
	// buildRenderRows emits them); the root row is a plain line (band -1).
	want := []frameLine{
		{row: 1, band: 4, leafBarHeight: 5}, {row: 1, band: 3, leafBarHeight: 5},
		{row: 1, band: 2, leafBarHeight: 5}, {row: 1, band: 1, leafBarHeight: 5},
		{row: 1, band: 0, leafBarHeight: 5}, {row: 0, band: -1},
	}
	for dataRow, expected := range want {
		if got, ok := frameCoordToLine(dataRow, params); !ok || got != expected {
			t.Fatalf("dataRow=%d: got %+v ok=%v want %+v", dataRow, got, ok, expected)
		}
	}
}

func TestFrameIndexAtHeightMetricMapsClicksInExpandedLeafBand(t *testing.T) {
	frames := []tuiFrame{
		{Name: "root", Row: 0, Col: 0, Width: 20, Path: "root"},
		{Name: "leaf", Row: 1, Col: 0, Width: 20, Path: "root" + pathSeparator + "leaf", HeightTotal: 100},
	}
	for y := 1; y <= 5; y++ {
		if got := frameIndexAt(frames, 10, y, 20, 9, false, true); got != 1 {
			t.Fatalf("y=%d: expected leaf frame index 1, got %d", y, got)
		}
	}
	if got := frameIndexAt(frames, 10, 6, 20, 9, false, true); got != 0 {
		t.Fatalf("y=6: expected root frame index 0, got %d", got)
	}
}

func animatorTestFrames(width int) []tuiFrame {
	return []tuiFrame{
		{Name: "root", Row: 0, Col: 0, Width: width, Depth: 0, Path: "root"},
		{Name: "a", Row: 1, Col: 0, Width: width / 2, Depth: 1, Path: "root" + pathSeparator + "a"},
	}
}

func TestFrameAnimatorSnapsWithoutPreviousLayout(t *testing.T) {
	fa := newFrameAnimator()
	target := animatorTestFrames(40)
	ancestry := buildFrameAncestry(target)

	// animate=true with nothing on screen yet has nothing to animate from.
	fa.applyTargetFrames(target, ancestry, true)
	if fa.isAnimating() {
		t.Fatal("animating without a previous layout")
	}
	if got := fa.currentFrames(); len(got) != len(target) || got[1] != target[1] {
		t.Fatalf("currentFrames = %v, want %v", got, target)
	}
	if got := fa.currentAncestry(); len(got.parent) != len(target) || got.parent[1] != 0 {
		t.Fatalf("currentAncestry not installed: %+v", got)
	}
}

func TestFrameAnimatorAnimatesTowardsNewLayout(t *testing.T) {
	fa := newFrameAnimator()
	first := animatorTestFrames(40)
	fa.applyTargetFrames(first, buildFrameAncestry(first), false)

	second := animatorTestFrames(80)
	fa.applyTargetFrames(second, buildFrameAncestry(second), false)
	if fa.isAnimating() {
		t.Fatal("animate=false must snap to the target")
	}

	third := animatorTestFrames(20)
	fa.applyTargetFrames(third, buildFrameAncestry(third), true)
	if !fa.isAnimating() {
		t.Fatal("expected an animation between differing layouts")
	}
	for ticks := 0; fa.tickAnimation(); ticks++ {
		if ticks >= 600 {
			t.Fatal("animation did not settle within 600 ticks")
		}
	}
	if fa.isAnimating() {
		t.Fatal("animation did not settle")
	}
	if got := fa.currentFrames()[1].Width; got != third[1].Width {
		t.Fatalf("settled width = %d, want %d", got, third[1].Width)
	}
}

func TestFrameAnimatorIndexByPathAndReset(t *testing.T) {
	fa := newFrameAnimator()
	frames := animatorTestFrames(40)
	fa.applyTargetFrames(frames, buildFrameAncestry(frames), false)

	if got := fa.indexByPath(frames[1].Path); got != 1 {
		t.Fatalf("indexByPath = %d, want 1", got)
	}
	if got := fa.indexByPath("root" + pathSeparator + "missing"); got != -1 {
		t.Fatalf("indexByPath(missing) = %d, want -1", got)
	}

	fa.reset()
	if len(fa.currentFrames()) != 0 || fa.indexByPath("root") != -1 {
		t.Fatal("reset kept frames")
	}
	if fa.isAnimating() || len(fa.currentAncestry().parent) != 0 {
		t.Fatal("reset kept animation or ancestry state")
	}
}

// TestFrameAnimatorSnapSyncsSprings checks that a snapped layout leaves the
// springs at the snapped positions: re-applying it animated must not jump
// back to the layout before the snap, and a later animation starts from what
// is on screen.
func TestFrameAnimatorSnapSyncsSprings(t *testing.T) {
	fa := newFrameAnimator()
	first := animatorTestFrames(40)
	fa.applyTargetFrames(first, buildFrameAncestry(first), false)
	snapped := animatorTestFrames(80)
	fa.applyTargetFrames(snapped, buildFrameAncestry(snapped), false)

	fa.applyTargetFrames(snapped, buildFrameAncestry(snapped), true)
	if fa.isAnimating() {
		t.Fatal("re-applying the snapped layout animated from the pre-snap positions")
	}
	if got := fa.currentFrames()[1].Width; got != snapped[1].Width {
		t.Fatalf("width = %d, want snapped %d", got, snapped[1].Width)
	}

	next := animatorTestFrames(20)
	fa.applyTargetFrames(next, buildFrameAncestry(next), true)
	if !fa.isAnimating() {
		t.Fatal("expected an animation towards the next layout")
	}
	if got := fa.currentFrames()[1].Width; got != snapped[1].Width {
		t.Fatalf("animation starts at width %d, want the on-screen %d", got, snapped[1].Width)
	}
}

// TestFrameAnimatorTickLoopLifecycle covers the tick loop bookkeeping: a live
// loop is reused rather than replaced, a stopped or lost loop is replaced by
// one with a new generation, and reset makes acceptsTick reject every tick
// scheduled before it.
func TestFrameAnimatorTickLoopLifecycle(t *testing.T) {
	fa := newFrameAnimator()
	animate := func() {
		t.Helper()
		first, second := animatorTestFrames(40), animatorTestFrames(80)
		fa.applyTargetFrames(first, buildFrameAncestry(first), false)
		fa.applyTargetFrames(second, buildFrameAncestry(second), true)
		if !fa.isAnimating() {
			t.Fatal("expected an animation between differing layouts")
		}
	}
	now := time.Now()

	animate()
	live, start := fa.startTicks(now)
	if !start || !fa.acceptsTick(live) {
		t.Fatal("startTicks did not start a loop when none was live")
	}
	if _, start := fa.startTicks(now.Add(animFrameDuration / 2)); start {
		t.Fatal("startTicks started a second loop beside the live one")
	}
	if !fa.acceptsTick(live) {
		t.Fatal("restarting the animation retired the live loop's pending tick")
	}

	fa.stopTicks()
	next, start := fa.startTicks(now)
	if !start || fa.acceptsTick(live) || !fa.acceptsTick(next) {
		t.Fatal("a stopped loop was not replaced by a new generation")
	}

	lost := next
	late := now.Add(animFrameDuration + tickLostAfter)
	recovered, start := fa.startTicks(late)
	if !start || fa.acceptsTick(lost) || !fa.acceptsTick(recovered) {
		t.Fatal("an overdue loop was not replaced by a new generation")
	}

	fa.reset()
	if fa.acceptsTick(recovered) {
		t.Fatal("reset accepted a tick of the previous generation")
	}
	animate()
	if fa.acceptsTick(recovered) {
		t.Fatal("a new animation revived a tick scheduled before the reset")
	}
	if _, start := fa.startTicks(late); !start {
		t.Fatal("reset left the old tick loop marked live")
	}
}
