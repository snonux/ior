package internal

import (
	"syscall"
	"testing"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/types"

	"golang.org/x/sys/unix"
)

// runLandlockCreateRuleset feeds one landlock_create_ruleset enter/exit pair
// through handleEventfdExit, after pre-registering fd 6 as a real log file so
// a clobbered fd table entry is observable.
func runLandlockCreateRuleset(t *testing.T, flags int32, ret int64) (*eventLoop, *event.Pair) {
	t.Helper()
	const pid = uint32(90)
	el := mustNewEventLoop(t, eventLoopConfig{})
	el.fdState().set(6, pid, file.NewFd(6, "/var/log/app.log", syscall.O_WRONLY))

	enter := &types.EventfdEvent{
		EventType: types.ENTER_EVENTFD_EVENT,
		TraceId:   types.SYS_ENTER_LANDLOCK_CREATE_RULESET,
		Time:      100,
		Pid:       pid,
		Tid:       pid,
		Flags:     flags,
		Fd:        -1,
		Ret:       -1,
	}
	exit := &types.EventfdEvent{
		EventType: types.EXIT_EVENTFD_EVENT,
		TraceId:   types.SYS_EXIT_LANDLOCK_CREATE_RULESET,
		Time:      200,
		Pid:       pid,
		Tid:       pid,
		Flags:     flags,
		Fd:        -1,
		Ret:       ret,
	}
	ep := &event.Pair{EnterEv: enter, ExitEv: exit}
	if ok := el.handleEventfdExit(ep, enter); !ok {
		t.Fatal("handleEventfdExit returned false")
	}
	return el, ep
}

// An ABI probe returns a version/errata number, not an fd: it must not
// overwrite the descriptor that happens to share that number.
func TestLandlockCreateRulesetProbeDoesNotRegisterFd(t *testing.T) {
	tests := []struct {
		name  string
		flags int32
		ret   int64
	}{
		{name: "version", flags: unix.LANDLOCK_CREATE_RULESET_VERSION, ret: 6},
		{name: "errata", flags: unix.LANDLOCK_CREATE_RULESET_ERRATA, ret: 6},
		{name: "version zero return", flags: unix.LANDLOCK_CREATE_RULESET_VERSION, ret: 0},
		{name: "unknown extra bit with version", flags: unix.LANDLOCK_CREATE_RULESET_VERSION | 0x8, ret: 6},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			el, ep := runLandlockCreateRuleset(t, tt.flags, tt.ret)
			verifyFileDescriptor(t, el, 90, 6, "/var/log/app.log")
			if tt.ret != 6 {
				verifyFdNotTracked(t, el, 90, int32(tt.ret))
			}
			want := landlockProbeName(tt.flags)
			if ep.File == nil || ep.File.Name() != want {
				t.Fatalf("pair file = %v, want %q", ep.File, want)
			}
		})
	}
}

// A regular ruleset creation (flags 0) still returns and registers an fd.
func TestLandlockCreateRulesetRegistersRulesetFd(t *testing.T) {
	el, ep := runLandlockCreateRuleset(t, 0, 7)
	verifyFileDescriptor(t, el, 90, 7, "landlockfd:0")
	verifyFileDescriptor(t, el, 90, 6, "/var/log/app.log")
	if ep.File == nil || ep.File.Name() != "landlockfd:0" {
		t.Fatalf("pair file = %v, want landlockfd:0", ep.File)
	}
}

// A failed probe (e.g. -EOPNOTSUPP when Landlock is disabled) records nothing.
func TestLandlockCreateRulesetFailedProbeLeavesFdTable(t *testing.T) {
	el, _ := runLandlockCreateRuleset(t, unix.LANDLOCK_CREATE_RULESET_VERSION, -int64(unix.EOPNOTSUPP))
	verifyFileDescriptor(t, el, 90, 6, "/var/log/app.log")
}

func TestIsLandlockRulesetProbe(t *testing.T) {
	tests := []struct {
		name    string
		traceID types.TraceId
		flags   int32
		want    bool
	}{
		{name: "version", traceID: types.SYS_ENTER_LANDLOCK_CREATE_RULESET, flags: 1, want: true},
		{name: "errata", traceID: types.SYS_ENTER_LANDLOCK_CREATE_RULESET, flags: 2, want: true},
		{name: "no flags", traceID: types.SYS_ENTER_LANDLOCK_CREATE_RULESET, flags: 0, want: false},
		{name: "unrelated bit", traceID: types.SYS_ENTER_LANDLOCK_CREATE_RULESET, flags: 4, want: false},
		{name: "other syscall with bit 0", traceID: types.SYS_ENTER_EVENTFD2, flags: 1, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isLandlockRulesetProbe(tt.traceID, tt.flags); got != tt.want {
				t.Fatalf("isLandlockRulesetProbe(%v, %d) = %v, want %v", tt.traceID, tt.flags, got, tt.want)
			}
		})
	}
}
