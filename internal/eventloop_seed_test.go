package internal

import (
	"os"
	"testing"

	"ior/internal/flags"
)

func TestSeedTrackedPidCommCachesTrackedPidComm(t *testing.T) {
	oldPID := flags.Get().PidFilter
	flags.SetPidFilter(os.Getpid())
	t.Cleanup(func() {
		flags.SetPidFilter(oldPID)
	})

	el := &eventLoop{
		comms: make(map[uint32]string),
	}

	pid := uint32(os.Getpid())
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
	oldPID := flags.Get().PidFilter
	flags.SetPidFilter(-1)
	t.Cleanup(func() {
		flags.SetPidFilter(oldPID)
	})

	el := &eventLoop{
		comms: make(map[uint32]string),
	}

	el.seedTrackedPidComm()

	if len(el.comms) != 0 {
		t.Fatalf("expected no comms to be seeded when pid filter is disabled")
	}
}
