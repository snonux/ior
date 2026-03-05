package flamegraph

import "testing"

func TestAnimationStateConvergesToTarget(t *testing.T) {
	state := NewAnimationState(30, 6.0, 1.0)
	state.SetTargets([]tuiFrame{{Path: "root", Col: 0, Width: 10}})
	state.SetTargets([]tuiFrame{{Path: "root", Col: 100, Width: 50}})

	active := true
	for i := 0; i < 180 && active; i++ {
		active = state.Tick(0)
	}
	if active {
		t.Fatalf("expected springs to settle within 180 ticks")
	}

	frames := state.CurrentFrames()
	if len(frames) != 1 {
		t.Fatalf("expected one interpolated frame, got %d", len(frames))
	}
	if frames[0].Col != 100 || frames[0].Width != 50 {
		t.Fatalf("expected settled frame at col=100 width=50, got col=%d width=%d", frames[0].Col, frames[0].Width)
	}
	if state.Tick(0) {
		t.Fatalf("expected settled animation to remain inactive")
	}
}

func TestAnimationStateHandlesAddedAndRemovedFrames(t *testing.T) {
	state := NewAnimationState(30, 6.0, 1.0)
	state.SetTargets([]tuiFrame{
		{Path: "root", Col: 0, Width: 20},
		{Path: "root\x1fchild", Col: 20, Width: 20},
	})
	if got := len(state.CurrentFrames()); got != 2 {
		t.Fatalf("expected 2 frames after initial targets, got %d", got)
	}

	state.SetTargets([]tuiFrame{
		{Path: "root\x1fchild", Col: 40, Width: 30},
	})
	frames := state.CurrentFrames()
	if len(frames) != 1 {
		t.Fatalf("expected removed frame to be dropped, got %d frames", len(frames))
	}
	if frames[0].Path != "root\x1fchild" {
		t.Fatalf("expected remaining frame path root\\x1fchild, got %q", frames[0].Path)
	}
}
