package tui

import (
	"testing"

	"ior/internal/globalfilter"
	"ior/internal/runtime"
)

func TestSlowTraceTeardownKeepsNextSessionLiveFilterSetter(t *testing.T) {
	bindings := newRuntimeBindings()
	var firstCalls int
	finishFirstSession := bindings.setLiveFilterSetter(func(globalfilter.Filter) {
		firstCalls++
	})

	var secondCalls int
	finishSecondSession := bindings.setLiveFilterSetter(func(globalfilter.Filter) {
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

// The helpers below publish straight into the runtime bindings, outside any
// trace session, for tests that exercise the TUI side of one wired session.
// Production code has no such ungated setters: trace sessions publish only
// through their traceSessionBindings view.

func (r *runtimeBindings) setDashboardSnapshotSource(source runtime.ResettableSnapshotSource) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.snapshotSource = source
}

func (r *runtimeBindings) setEventStreamSource(source runtime.StreamSource) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.streamSource = source
}

func (r *runtimeBindings) setLiveTrie(liveTrie runtime.LiveTrieSource) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.liveTrieSource = liveTrie
}

func (r *runtimeBindings) setProbeManager(manager runtime.ProbeManager) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.probeManager = manager
}

func (r *runtimeBindings) setLiveFilterSetter(setter func(globalfilter.Filter)) func() {
	r.mu.Lock()
	registration := r.installLiveFilterSetterLocked(setter)
	r.mu.Unlock()
	return r.liveFilterUnregisterer(registration)
}
