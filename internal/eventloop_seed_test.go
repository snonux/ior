package internal

import (
	"os"
	"testing"
)

func TestProcTidPathPrefix(t *testing.T) {
	if got, want := procTidPathPrefix(42), "/proc/42"; got != want {
		t.Fatalf("procTidPathPrefix() = %q, want %q", got, want)
	}
}

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
		commResolver: newCommResolver(make(map[uint32]string)),
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
		commResolver: newCommResolver(make(map[uint32]string)),
	}

	el.seedTrackedPidComm()

	if _, ok := el.cachedComm(uint32(os.Getpid())); !ok {
		t.Fatalf("expected current process pid to be seeded")
	}
}
