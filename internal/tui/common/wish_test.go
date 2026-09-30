package common

import (
	"testing"

	"ior/internal/statsengine"
)

// TestCarryRetentionOutlivesTheSelectionWish ties the two clocks together:
// Engine.Reset remembers the ordinal of a silent process for
// statsengine.ProcessCarryRetention, and a selection looks for that process for
// SelectionWishGrace. If the retention were shorter than the wish, a silent
// selected process "8#1" would reopen as "8" and the wish could never match
// (or match a successor of the PID). statsengine cannot import this package, so
// the relation is pinned here, from the side that may import it.
func TestCarryRetentionOutlivesTheSelectionWish(t *testing.T) {
	if statsengine.ProcessCarryRetention < 2*SelectionWishGrace {
		t.Fatalf("statsengine.ProcessCarryRetention %s < 2*SelectionWishGrace %s",
			statsengine.ProcessCarryRetention, 2*SelectionWishGrace)
	}
}
