package internal

import (
	"encoding/binary"
	"syscall"
	"testing"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

func TestLegacyNamedEventfdPayloadUsesStableFallbackIdentity(t *testing.T) {
	tests := []struct {
		name    string
		enterID types.TraceId
		exitID  types.TraceId
		flags   int32
		want    string
	}{
		{name: "memfd_create", enterID: types.SYS_ENTER_MEMFD_CREATE, exitID: types.SYS_EXIT_MEMFD_CREATE, flags: 2, want: "memfd:2"},
		{name: "fsopen", enterID: types.SYS_ENTER_FSOPEN, exitID: types.SYS_EXIT_FSOPEN, flags: 4, want: "fsopenfd:4"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := make([]byte, 48)
			binary.LittleEndian.PutUint32(raw[0:4], uint32(types.ENTER_EVENTFD_EVENT))
			binary.LittleEndian.PutUint32(raw[4:8], uint32(tt.enterID))
			binary.LittleEndian.PutUint64(raw[8:16], 100)
			binary.LittleEndian.PutUint32(raw[16:20], 60)
			binary.LittleEndian.PutUint32(raw[20:24], 61)
			binary.LittleEndian.PutUint32(raw[24:28], uint32(tt.flags))
			binary.LittleEndian.PutUint64(raw[32:40], ^uint64(0))
			binary.LittleEndian.PutUint32(raw[40:44], ^uint32(0))
			enter := types.NewEventfdEventFast(raw)
			if enter == nil {
				t.Fatal("legacy eventfd payload did not decode")
			}
			defer enter.Recycle()

			el := mustNewEventLoop(t, eventLoopConfig{})
			exit := &types.EventfdEvent{EventType: types.EXIT_EVENTFD_EVENT, TraceId: tt.exitID, Time: 200, Pid: 60, Tid: 61, Ret: 40, Fd: -1}
			ep := &event.Pair{EnterEv: enter, ExitEv: exit}
			if ok := el.handleEventfdExit(ep, enter); !ok {
				t.Fatal("handleEventfdExit returned false")
			}
			if ep.File == nil || ep.File.Name() != tt.want {
				t.Fatalf("legacy identity = %v, want %q", ep.File, tt.want)
			}
		})
	}
}

func TestLegacyFsmountPayloadUsesStableFallbackIdentity(t *testing.T) {
	raw := make([]byte, 48)
	binary.LittleEndian.PutUint32(raw[0:4], uint32(types.ENTER_EVENTFD_EVENT))
	binary.LittleEndian.PutUint32(raw[4:8], uint32(types.SYS_ENTER_FSMOUNT))
	binary.LittleEndian.PutUint64(raw[8:16], 100)
	binary.LittleEndian.PutUint32(raw[16:20], 60)
	binary.LittleEndian.PutUint32(raw[20:24], 61)
	binary.LittleEndian.PutUint32(raw[24:28], 1)
	binary.LittleEndian.PutUint64(raw[32:40], ^uint64(0))
	binary.LittleEndian.PutUint32(raw[40:44], ^uint32(0))
	enter := types.NewEventfdEventFast(raw)
	if enter == nil {
		t.Fatal("legacy fsmount payload did not decode")
	}
	defer enter.Recycle()

	el := mustNewEventLoop(t, eventLoopConfig{})
	exit := &types.EventfdEvent{
		EventType: types.EXIT_EVENTFD_EVENT,
		TraceId:   types.SYS_EXIT_FSMOUNT,
		Time:      200,
		Pid:       60,
		Tid:       61,
		Ret:       40,
		Fd:        -1,
	}
	ep := &event.Pair{EnterEv: enter, ExitEv: exit}
	if ok := el.handleEventfdExit(ep, enter); !ok {
		t.Fatal("handleEventfdExit returned false")
	}
	if ep.File == nil || ep.File.Name() != "eventfd:1" {
		t.Fatalf("legacy fsmount identity = %v, want eventfd:1", ep.File)
	}
}

func TestLegacyMoveMountPayloadPreservesSourceFdAttribution(t *testing.T) {
	raw := make([]byte, 40)
	binary.LittleEndian.PutUint32(raw[0:4], uint32(types.ENTER_TWO_FD_EVENT))
	binary.LittleEndian.PutUint32(raw[4:8], uint32(types.SYS_ENTER_MOVE_MOUNT))
	binary.LittleEndian.PutUint64(raw[8:16], 100)
	binary.LittleEndian.PutUint32(raw[16:20], 62)
	binary.LittleEndian.PutUint32(raw[20:24], 63)
	binary.LittleEndian.PutUint32(raw[24:28], 41)
	binary.LittleEndian.PutUint32(raw[28:32], 42)
	enter := types.NewTwoFdEventFast(raw)
	if enter == nil {
		t.Fatal("legacy two_fd payload did not decode")
	}
	defer enter.Recycle()

	el := mustNewEventLoop(t, eventLoopConfig{})
	el.fdState().set(41, 62, file.NewFd(41, "/legacy/source", syscall.O_RDONLY))
	exit := &types.RetEvent{EventType: types.EXIT_RET_EVENT, TraceId: types.SYS_EXIT_MOVE_MOUNT, Time: 200, Pid: 62, Tid: 63, Ret: 0}
	ep := &event.Pair{EnterEv: enter, ExitEv: exit}
	if ok := el.handleTwoFdExit(ep, enter); !ok {
		t.Fatal("handleTwoFdExit returned false")
	}
	if ep.File == nil || ep.File.Name() != "/legacy/source" {
		t.Fatalf("legacy move_mount file = %v, want source fd identity", ep.File)
	}
}

func TestHandleMemfdCreateRegistersIdentifyingName(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	enter := &types.EventfdEvent{
		EventType:      types.ENTER_EVENTFD_EVENT,
		TraceId:        types.SYS_ENTER_MEMFD_CREATE,
		Time:           100,
		Pid:            70,
		Tid:            71,
		Flags:          1,
		Ret:            -1,
		Fd:             -1,
		FilenameStatus: types.PATH_READ_OK,
	}
	copy(enter.Filename[:], "ior-memfd")
	exit := &types.EventfdEvent{
		EventType: types.EXIT_EVENTFD_EVENT,
		TraceId:   types.SYS_EXIT_MEMFD_CREATE,
		Time:      200,
		Pid:       70,
		Tid:       71,
		Ret:       44,
		Fd:        -1,
	}
	ep := &event.Pair{EnterEv: enter, ExitEv: exit}

	if ok := el.handleEventfdExit(ep, enter); !ok {
		t.Fatal("handleEventfdExit returned false")
	}
	if ep.File == nil || ep.File.Name() != "memfd:ior-memfd" {
		t.Fatalf("memfd identity = %v, want memfd:ior-memfd", ep.File)
	}
	tracked, ok := el.fdState().files[fdKey(70, 44)]
	if !ok || tracked.Name() != "memfd:ior-memfd" {
		t.Fatalf("tracked memfd = %v, present=%v", tracked, ok)
	}
}

func TestFailedNamedEventfdRowsKeepCapturedIdentity(t *testing.T) {
	tests := []struct {
		name    string
		enterID types.TraceId
		exitID  types.TraceId
		value   string
		want    string
	}{
		{name: "memfd_create", enterID: types.SYS_ENTER_MEMFD_CREATE, exitID: types.SYS_EXIT_MEMFD_CREATE, value: "ior-memfd", want: "memfd:ior-memfd"},
		{name: "fsopen", enterID: types.SYS_ENTER_FSOPEN, exitID: types.SYS_EXIT_FSOPEN, value: "tmpfs", want: "fsopen:tmpfs"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			el := mustNewEventLoop(t, eventLoopConfig{filter: globalfilter.Filter{
				File: &globalfilter.StringFilter{Pattern: "^" + tt.want + "$"},
			}})
			enter := &types.EventfdEvent{
				EventType:      types.ENTER_EVENTFD_EVENT,
				TraceId:        tt.enterID,
				Time:           100,
				Pid:            70,
				Tid:            71,
				Flags:          1,
				Ret:            -1,
				Fd:             -1,
				FilenameStatus: types.PATH_READ_OK,
			}
			copy(enter.Filename[:], tt.value)
			exit := &types.EventfdEvent{
				EventType: types.EXIT_EVENTFD_EVENT,
				TraceId:   tt.exitID,
				Time:      200,
				Pid:       70,
				Tid:       71,
				Ret:       -int64(syscall.EPERM),
				Fd:        -1,
			}
			ep := &event.Pair{EnterEv: enter, ExitEv: exit}

			if ok := el.handleEventfdExit(ep, enter); !ok {
				t.Fatal("handleEventfdExit returned false")
			}
			if ep.File == nil || ep.File.Name() != tt.want || ep.File.FD() != -1 {
				t.Fatalf("failed-call identity = %v, want pathname %q", ep.File, tt.want)
			}
			if len(el.fdState().files) != 0 {
				t.Fatalf("failed call registered fd state: %v", el.fdState().files)
			}
		})
	}
}

func TestHandleFsmountCarriesFsopenIdentityToReturnedFd(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	el.fdState().set(41, 80, file.NewFd(41, "fsopen:tmpfs", syscall.O_RDWR))
	enter := &types.EventfdEvent{
		EventType: types.ENTER_EVENTFD_EVENT,
		TraceId:   types.SYS_ENTER_FSMOUNT,
		Time:      100,
		Pid:       80,
		Tid:       81,
		Flags:     1,
		Ret:       -1,
		Fd:        41,
	}
	exit := &types.EventfdEvent{
		EventType: types.EXIT_EVENTFD_EVENT,
		TraceId:   types.SYS_EXIT_FSMOUNT,
		Time:      200,
		Pid:       80,
		Tid:       81,
		Ret:       42,
		Fd:        -1,
	}
	ep := &event.Pair{EnterEv: enter, ExitEv: exit}

	if ok := el.handleEventfdExit(ep, enter); !ok {
		t.Fatal("handleEventfdExit returned false")
	}
	if ep.File == nil || ep.File.FD() != 42 || ep.File.Name() != "fsopen:tmpfs" {
		t.Fatalf("fsmount result = %v, want fd 42 with fsopen identity", ep.File)
	}
}

func TestHandleFsmountFallsBackWhenSourceIdentityCannotBeResolved(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	enter := &types.EventfdEvent{
		EventType: types.ENTER_EVENTFD_EVENT,
		TraceId:   types.SYS_ENTER_FSMOUNT,
		Time:      100,
		Pid:       ^uint32(0),
		Tid:       81,
		Flags:     1,
		Ret:       -1,
		Fd:        41,
	}
	exit := &types.EventfdEvent{
		EventType: types.EXIT_EVENTFD_EVENT,
		TraceId:   types.SYS_EXIT_FSMOUNT,
		Time:      200,
		Pid:       ^uint32(0),
		Tid:       81,
		Ret:       42,
		Fd:        -1,
	}
	ep := &event.Pair{EnterEv: enter, ExitEv: exit}

	if ok := el.handleEventfdExit(ep, enter); !ok {
		t.Fatal("handleEventfdExit returned false")
	}
	if ep.File == nil || ep.File.Name() != "eventfd:1" {
		t.Fatalf("fsmount fallback = %v, want eventfd:1", ep.File)
	}
}

func TestBpfCommandReturnsFDAllowlist(t *testing.T) {
	fdCommands := []uint32{
		bpfMapCreate, bpfProgLoad, bpfObjGet, bpfProgGetFdByID, bpfMapGetFdByID,
		bpfRawTracepointOpen, bpfBtfLoad, bpfBtfGetFdByID, bpfLinkCreate,
		bpfLinkGetFdByID, bpfEnableStats, bpfIterCreate, bpfTokenCreate,
	}
	for _, cmd := range fdCommands {
		if !bpfCommandReturnsFD(cmd) {
			t.Errorf("bpf command %d should be fd-producing", cmd)
		}
	}
	for _, cmd := range []uint32{10, 11, 12, 23, 31, 999} {
		if bpfCommandReturnsFD(cmd) {
			t.Errorf("bpf command %d must not be treated as fd-producing", cmd)
		}
	}
}

func TestInitRawHandlersRegistersBpfEvent(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	if _, ok := el.rawHandlers[types.ENTER_BPF_EVENT]; !ok {
		t.Fatal("ENTER_BPF_EVENT handler is not registered")
	}
}

func TestHandleBpfExitRegistersOnlySuccessfulFdCommands(t *testing.T) {
	tests := []struct {
		name        string
		cmd         uint32
		ret         int64
		wantTracked bool
		wantName    string
	}{
		{name: "map create", cmd: bpfMapCreate, ret: 63, wantTracked: true, wantName: "bpf:map_create"},
		{name: "enable stats", cmd: bpfEnableStats, ret: 62, wantTracked: true, wantName: "bpf:enable_stats"},
		{name: "fd command error", cmd: bpfMapCreate, ret: -int64(syscall.EPERM)},
		{name: "positive non-fd return", cmd: 10, ret: 7},
		{name: "unknown command fails closed", cmd: 999, ret: 7},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			el := mustNewEventLoop(t, eventLoopConfig{})
			enter := &types.BpfEvent{EventType: types.ENTER_BPF_EVENT, TraceId: types.SYS_ENTER_BPF, Time: 100, Pid: 90, Tid: 91, Cmd: tt.cmd}
			exit := &types.RetEvent{EventType: types.EXIT_RET_EVENT, TraceId: types.SYS_EXIT_BPF, Time: 200, Pid: 90, Tid: 91, Ret: tt.ret}
			ep := &event.Pair{EnterEv: enter, ExitEv: exit}

			if ok := el.handleBpfExit(ep, enter); !ok {
				t.Fatal("handleBpfExit returned false")
			}
			tracked, ok := el.fdState().files[fdKey(90, int32(tt.ret))]
			if ok != tt.wantTracked {
				t.Fatalf("tracked=%v, want %v", ok, tt.wantTracked)
			}
			if tt.wantTracked && (ep.File == nil || ep.File.Name() != tt.wantName || tracked.Name() != tt.wantName) {
				t.Fatalf("bpf identity pair=%v tracked=%v, want %q", ep.File, tracked, tt.wantName)
			}
		})
	}
}

func TestDroppedBpfRowStillRegistersReturnedFd(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{filter: globalfilter.Filter{
		Syscall: &globalfilter.StringFilter{Pattern: "openat"},
	}})
	enter := &types.BpfEvent{EventType: types.ENTER_BPF_EVENT, TraceId: types.SYS_ENTER_BPF, Time: 100, Pid: 92, Tid: 93, Cmd: bpfProgLoad}
	exit := &types.RetEvent{EventType: types.EXIT_RET_EVENT, TraceId: types.SYS_EXIT_BPF, Time: 200, Pid: 92, Tid: 93, Ret: 64}
	ep := &event.Pair{EnterEv: enter, ExitEv: exit}

	if ok := el.handleBpfExit(ep, enter); ok {
		t.Fatal("handleBpfExit should reject the row")
	}
	tracked, ok := el.fdState().files[fdKey(92, 64)]
	if !ok || tracked.Name() != "bpf:prog_load" {
		t.Fatalf("filtered bpf fd state = %v, present=%v", tracked, ok)
	}
}

func TestRecoveredFilenameAppliesToNamedEventfd(t *testing.T) {
	enter := &types.EventfdEvent{TraceId: types.SYS_ENTER_MEMFD_CREATE, FilenameStatus: types.PATH_READ_FAILED}
	fixup := &types.OpenNameFixupEvent{TraceId: types.SYS_ENTER_MEMFD_CREATE}
	copy(fixup.Filename[:], "recovered")

	applyRecoveredFilename(enter, fixup)

	if got := types.StringValue(enter.Filename[:]); got != "recovered" {
		t.Fatalf("recovered filename = %q", got)
	}
	if enter.FilenameStatus != types.PATH_READ_OK {
		t.Fatalf("filename status = %d, want PATH_READ_OK", enter.FilenameStatus)
	}
}
