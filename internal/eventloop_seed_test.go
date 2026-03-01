package internal

import (
	"os"
	"testing"
)

func TestSeedTrackedPidCommCachesTrackedPidComm(t *testing.T) {
	pid := uint32(os.Getpid())
	el := &eventLoop{
		cfg: eventLoopConfig{
			pidFilter: int(pid),
		},
		comms: make(map[uint32]string),
	}

	want := el.comm(pid)
	if want == "" {
		t.Fatalf("expected comm for pid %d", pid)
	}
	delete(el.comms, pid)

	el.seedTrackedPidComm()

	if got := el.comms[pid]; got != want {
		t.Fatalf("seeded comm = %q, want %q", got, want)
	}
}

func TestSeedTrackedPidCommSkipsWhenPidFilterDisabled(t *testing.T) {
	el := &eventLoop{
		cfg: eventLoopConfig{
			pidFilter: -1,
		},
		comms: make(map[uint32]string),
	}

	el.seedTrackedPidComm()

	if len(el.comms) != 0 {
		t.Fatalf("expected no comms to be seeded when pid filter is disabled")
	}
}
