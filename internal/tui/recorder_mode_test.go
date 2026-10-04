package tui

import (
	"testing"

	"ior/internal/parquet"
)

// TestRuntimeBindingsRecorderShedsInsteadOfBlocking pins the TUI side of the
// overflow policy of task 4s2: the recorder of the TUI bindings must keep the
// non-blocking shed mode, because the event loop that records also feeds the
// live views. Switching it to BlockWhenFull (the headless mode) would let a slow
// disk freeze the UI.
func TestRuntimeBindingsRecorderShedsInsteadOfBlocking(t *testing.T) {
	rec, ok := newRuntimeBindings().Recorder().(*parquet.Recorder)
	if !ok {
		t.Fatalf("TUI recorder is %T, want *parquet.Recorder", newRuntimeBindings().Recorder())
	}
	if rec.Config().BlockWhenFull {
		t.Fatal("the TUI recorder blocks on a full queue; it must shed so the event loop never stalls")
	}
	if rec.Config().QueueCapacity >= parquet.HeadlessQueueCapacity {
		t.Fatalf("TUI recorder QueueCapacity = %d, want the smaller shed-mode default (< %d)",
			rec.Config().QueueCapacity, parquet.HeadlessQueueCapacity)
	}
}
