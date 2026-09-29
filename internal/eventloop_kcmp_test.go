package internal

import (
	"encoding/binary"
	"os"
	"syscall"
	"testing"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

func TestKcmpFileUsesTheCallerProcess(t *testing.T) {
	callerPID := uint32(os.Getpid())
	el := newFilteredEventLoop(t, globalfilter.Filter{})
	el.fdState().set(7, callerPID, file.NewFd(7, "/caller", syscall.O_RDONLY))
	ep := feedKcmpPair(t, el, callerPID, uint64(callerPID)<<32, 7, 8,
		types.TWO_FD_EVENT_SCHEMA_VERSION, false)
	defer ep.Recycle()
	if ep.File == nil || ep.File.Name() != "/caller" || ep.File.FD() != 7 {
		t.Fatalf("file=%v, want /caller fd 7", ep.File)
	}
}

func TestKcmpFileKeepsCapturedOwnershipAfterCallerExit(t *testing.T) {
	// No such host PID can have a live procfs entry on Linux, but the file was
	// learned from an earlier event and the producer's sys_enter ownership proof
	// remains valid after process exit.
	const exitedPID = ^uint32(0)
	el := newFilteredEventLoop(t, globalfilter.Filter{})
	el.fdState().set(7, exitedPID, file.NewFd(7, "/exited", syscall.O_RDONLY))
	ep := feedKcmpPair(t, el, exitedPID, uint64(exitedPID)<<32, 7, 8,
		types.TWO_FD_EVENT_SCHEMA_VERSION, false)
	defer ep.Recycle()
	if ep.File == nil || ep.File.Name() != "/exited" {
		t.Fatalf("file=%v, want captured /exited identity", ep.File)
	}
}

func TestKcmpForeignTargetHasNoFile(t *testing.T) {
	callerPID := uint32(os.Getpid())
	targetPID := uint32(os.Getppid())
	if targetPID == 0 || targetPID == callerPID {
		t.Skip("no distinct parent process")
	}
	el := newFilteredEventLoop(t, globalfilter.Filter{})
	el.fdState().set(7, callerPID, file.NewFd(7, "/caller", syscall.O_RDONLY))
	el.fdState().set(7, targetPID, file.NewFd(7, "/foreign", syscall.O_RDWR))
	// The producer writes a zero owner when pid1 is not the caller.
	ep := feedKcmpPair(t, el, callerPID, 0, 7, 8,
		types.TWO_FD_EVENT_SCHEMA_VERSION, false)
	defer ep.Recycle()
	if ep.File != nil || len(el.fdState().procFdCache) != 0 {
		t.Fatalf("foreign kcmp target resolved an fd: file=%v", ep.File)
	}
}

func TestKcmpNonFileComparisonsHaveNoFile(t *testing.T) {
	for name, comparison := range map[string]uint32{
		"VM": 1, "FILES": 2, "FS": 3, "SIGHAND": 4, "IO": 5,
		"SYSVSEM": 6, "EPOLL_TFD": 7, "unknown": 8, "invalid": ^uint32(0),
	} {
		t.Run(name, func(t *testing.T) {
			callerPID := uint32(os.Getpid())
			el := newFilteredEventLoop(t, globalfilter.Filter{})
			el.fdState().set(7, callerPID, file.NewFd(7, "/must-not-appear", syscall.O_RDONLY))
			// Deliberately include valid-looking indices: older BPF objects
			// captured unused indices and truncated EPOLL_TFD's idx2 pointer.
			ep := feedKcmpPair(t, el, callerPID, uint64(callerPID)<<32|uint64(comparison), 7, 8,
				types.TWO_FD_EVENT_SCHEMA_VERSION, false)
			defer ep.Recycle()
			if ep.File != nil || len(el.fdState().procFdCache) != 0 {
				t.Fatalf("comparison %s resolved an fd: file=%v", name, ep.File)
			}
		})
	}
}

func TestKcmpMissingOrInvalidOwnerHasNoFile(t *testing.T) {
	callerPID := uint32(os.Getpid())
	for _, tt := range []struct {
		name   string
		extra  uint64
		fd     int32
		schema uint32
		legacy bool
	}{
		{name: "legacy wire layout", fd: 7, legacy: true},
		{name: "older current layout with owner-like high bits", extra: uint64(callerPID) << 32, fd: 7, schema: types.TWO_FD_EVENT_PRE_KCMP_OWNER_SCHEMA_VERSION},
		{name: "missing owner", fd: 7, schema: types.TWO_FD_EVENT_SCHEMA_VERSION},
		{name: "mismatched host owner", extra: uint64(^uint32(0)) << 32, fd: 7, schema: types.TWO_FD_EVENT_SCHEMA_VERSION},
		{name: "invalid descriptor", extra: uint64(callerPID) << 32, fd: -1, schema: types.TWO_FD_EVENT_SCHEMA_VERSION},
	} {
		t.Run(tt.name, func(t *testing.T) {
			el := newFilteredEventLoop(t, globalfilter.Filter{})
			el.fdState().set(7, callerPID, file.NewFd(7, "/caller", syscall.O_RDONLY))
			ep := feedKcmpPair(t, el, callerPID, tt.extra, tt.fd, 7, tt.schema, tt.legacy)
			defer ep.Recycle()
			if ep.File != nil || len(el.fdState().procFdCache) != 0 {
				t.Fatalf("unusable kcmp operands resolved an fd: file=%v", ep.File)
			}
		})
	}
}

func TestKcmpFileDoesNotResolveAnUntrackedDescriptorViaProcfs(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "kcmp-target")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	fd := int32(f.Fd())
	callerPID := uint32(os.Getpid())
	el := newFilteredEventLoop(t, globalfilter.Filter{})
	ep := feedKcmpPair(t, el, callerPID, uint64(callerPID)<<32, fd, fd,
		types.TWO_FD_EVENT_SCHEMA_VERSION, false)
	defer ep.Recycle()
	if ep.File != nil || len(el.fdState().procFdCache) != 0 {
		t.Fatalf("untracked kcmp descriptor used live procfs: file=%v cache=%v", ep.File, el.fdState().procFdCache)
	}
}

func TestKcmpFileFilterUsesTheReportedTarget(t *testing.T) {
	callerPID := uint32(os.Getpid())
	el := newFilteredEventLoop(t, globalfilter.Filter{
		File: &globalfilter.StringFilter{Pattern: "/target"},
	})
	el.fdState().set(7, callerPID, file.NewFd(7, "/target", syscall.O_RDONLY))
	ep := feedKcmpPair(t, el, callerPID, uint64(callerPID)<<32, 7, 8,
		types.TWO_FD_EVENT_SCHEMA_VERSION, false)
	defer ep.Recycle()
	if ep.File == nil || ep.File.Name() != "/target" {
		t.Fatalf("filtered pair file=%v", ep.File)
	}
}

func feedKcmpPair(t *testing.T, el *eventLoop, eventPID uint32, extra uint64, fdA, fdB int32, schema uint32, legacy bool) *event.Pair {
	t.Helper()
	_, enterRaw := makeEnterTwoFdEvent(t, defaulTime, eventPID, crossTidA,
		fdA, fdB, extra, types.SYS_ENTER_KCMP)
	if legacy {
		enterRaw = enterRaw[:40]
	} else if schema == types.TWO_FD_EVENT_PRE_KCMP_OWNER_SCHEMA_VERSION {
		// Older BPF objects used the wide named layout for all two-fd calls.
		wide := make([]byte, 568)
		copy(wide, enterRaw[:40])
		binary.LittleEndian.PutUint32(wide[560:564], schema)
		enterRaw = wide
	} else {
		binary.LittleEndian.PutUint32(enterRaw[40:44], schema)
	}
	_, exitRaw := makeExitRetEvent(t, defaulTime+openPairLatency, eventPID, crossTidA,
		types.SYS_EXIT_KCMP, 0)
	ep := feedRawPair(t, el, enterRaw, exitRaw)
	if ep == nil {
		t.Fatal("kcmp pair was not emitted")
	}
	return ep
}
