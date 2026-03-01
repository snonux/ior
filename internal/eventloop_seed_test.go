package internal

import (
	"os"
	"testing"
)

func TestSeedTrackedPidCommCachesTrackedPidComm(t *testing.T) {
	pid := uint32(os.Getpid())
	want := resolveCommFromProc(pid)
	if want == "" {
		t.Fatalf("expected comm for pid %d", pid)
	}

	el := &eventLoop{
		cfg: eventLoopConfig{
			pidFilter: int(pid),
		},
		comms: make(map[uint32]string),
	}

	el.seedTrackedPidComm()

	got, ok := el.cachedComm(pid)
	if !ok {
		t.Fatalf("expected pid %d to be seeded", pid)
	}
	if got != want {
		t.Fatalf("seeded comm = %q, want %q", got, want)
	}
}

func TestSeedTrackedPidCommSeedsCurrentProcessWhenPidFilterDisabled(t *testing.T) {
	el := &eventLoop{
		cfg: eventLoopConfig{
			pidFilter: -1,
		},
		comms: make(map[uint32]string),
	}

	el.seedTrackedPidComm()

	if _, ok := el.cachedComm(uint32(os.Getpid())); !ok {
		t.Fatalf("expected current process pid to be seeded")
	}
}
