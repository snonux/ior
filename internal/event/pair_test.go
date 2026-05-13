package event

import (
	"testing"

	"ior/internal/types"
)

func TestPairCalculateDurationsFirstEvent(t *testing.T) {
	enter := &types.OpenEvent{
		Time: 1000,
		Pid:  1,
		Tid:  2,
	}
	exit := &types.RetEvent{
		Time: 1100,
		Pid:  1,
		Tid:  2,
		Ret:  0,
	}

	pair := NewPair(enter)
	pair.ExitEv = exit
	pair.CalculateDurations(0)

	if pair.Duration != 100 {
		t.Fatalf("Duration = %d, want 100", pair.Duration)
	}
	if pair.DurationToPrev != 0 {
		t.Fatalf("DurationToPrev = %d, want 0 for first event", pair.DurationToPrev)
	}
}

func TestPairCalculateDurationsWithPreviousExit(t *testing.T) {
	enter := &types.OpenEvent{
		Time: 2000,
		Pid:  1,
		Tid:  2,
	}
	exit := &types.RetEvent{
		Time: 2100,
		Pid:  1,
		Tid:  2,
		Ret:  0,
	}

	pair := NewPair(enter)
	pair.ExitEv = exit
	pair.CalculateDurations(1500)

	if pair.Duration != 100 {
		t.Fatalf("Duration = %d, want 100", pair.Duration)
	}
	if pair.DurationToPrev != 500 {
		t.Fatalf("DurationToPrev = %d, want 500", pair.DurationToPrev)
	}
}

// TestPairCalculateDurationsNegativeDelta verifies that non-monotonic BPF
// timestamps (exit < enter due to cross-CPU clock skew) do not cause uint64
// underflow. Both Duration and DurationToPrev must clamp to zero.
func TestPairCalculateDurationsNegativeDelta(t *testing.T) {
	enter := &types.OpenEvent{
		Time: 2000,
		Pid:  1,
		Tid:  2,
	}
	// Simulate clock skew: exit timestamp is earlier than enter.
	exit := &types.RetEvent{
		Time: 1900,
		Pid:  1,
		Tid:  2,
		Ret:  0,
	}

	pair := NewPair(enter)
	pair.ExitEv = exit
	// prevPairTime > enterTime also triggers underflow in DurationToPrev.
	pair.CalculateDurations(3000)

	if pair.Duration != 0 {
		t.Fatalf("Duration = %d, want 0 when exit < enter (underflow guard)", pair.Duration)
	}
	if pair.DurationToPrev != 0 {
		t.Fatalf("DurationToPrev = %d, want 0 when enter < prevPairTime (underflow guard)", pair.DurationToPrev)
	}
}

func TestPairRecycleHandlesMissingExitEvent(t *testing.T) {
	pair := NewPair(&types.OpenEvent{
		Time: 1000,
		Pid:  1,
		Tid:  2,
	})

	pair.Recycle()
}
