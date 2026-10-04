package internal

import (
	"context"
	"testing"

	"ior/internal/flags"
	"ior/internal/runtime"
)

// TestTestFlamesStatsSurviveAReset is task xs2: in -testflames and
// -testliveflames nothing feeds the synthetic stats engine after the start, so
// a manual reset (r), the auto-reset cycle (I) or a probe toggle used to clear
// the Syscalls, Files and Processes tabs to "no data" for the rest of the
// session. The published stats source reseeds itself on Reset.
func TestTestFlamesStatsSurviveAReset(t *testing.T) {
	starters := map[string]func(flags.Config) runtime.TraceStarter{
		"static": tuiTestFlamesStarter,
		"live":   tuiTestLiveFlamesStarter,
	}
	for name, newStarter := range starters {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			bindings := &fakeRuntimeBindings{}
			if err := newStarter(flags.Config{})(ctx, runtime.TraceRequest{Bindings: bindings}); err != nil {
				t.Fatal(err)
			}
			source := bindings.publishedSnapshotSrc
			if source == nil {
				t.Fatal("the starter published no stats source")
			}
			before, err := source.Snapshot()
			if err != nil || len(before.Syscalls()) == 0 || len(before.Files()) == 0 || len(before.Processes()) == 0 {
				t.Fatalf("seeded snapshot has %d syscalls, %d files, %d processes (err %v)",
					len(before.Syscalls()), len(before.Files()), len(before.Processes()), err)
			}
			for range 3 { // repeated resets, like the auto-reset cycle
				source.Reset()
				after, err := source.Snapshot()
				if err != nil {
					t.Fatal(err)
				}
				if len(after.Syscalls()) != len(before.Syscalls()) || len(after.Files()) != len(before.Files()) ||
					len(after.Processes()) != len(before.Processes()) {
					t.Fatalf("after a reset: %d syscalls, %d files, %d processes; want the seeded %d, %d, %d",
						len(after.Syscalls()), len(after.Files()), len(after.Processes()),
						len(before.Syscalls()), len(before.Files()), len(before.Processes()))
				}
			}
		})
	}
}
