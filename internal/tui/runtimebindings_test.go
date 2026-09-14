package tui

import (
	"testing"

	"ior/internal/globalfilter"
)

func TestSlowTraceTeardownKeepsNextSessionLiveFilterSetter(t *testing.T) {
	bindings := newRuntimeBindings()
	var firstCalls int
	finishFirstSession := bindings.SetLiveFilterSetter(func(globalfilter.Filter) {
		firstCalls++
	})

	var secondCalls int
	finishSecondSession := bindings.SetLiveFilterSetter(func(globalfilter.Filter) {
		secondCalls++
	})

	// Session one finishes only after session two has registered its setter.
	// Its stale cleanup must not clear the setter now owned by session two.
	finishFirstSession()
	if applied := bindings.applyLiveFilter(globalfilter.Filter{}); !applied {
		t.Fatal("slow teardown from the first session unregistered the second session's setter")
	}
	if firstCalls != 0 {
		t.Fatalf("first session setter calls = %d, want 0", firstCalls)
	}
	if secondCalls != 1 {
		t.Fatalf("second session setter calls = %d, want 1", secondCalls)
	}

	finishSecondSession()
	if applied := bindings.applyLiveFilter(globalfilter.Filter{}); applied {
		t.Fatal("current session teardown left its live filter setter registered")
	}
}
