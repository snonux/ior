package types

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
	"unsafe"
)

// rawBytes serializes ev and fails the test if that does not work. Writing it
// inline as `raw, _ := ev.Bytes()` discarded the error and handed the decoders
// a nil slice, turning a serialization failure into a confusing decode
// mismatch instead of naming the actual problem.
func rawBytes(t *testing.T, ev interface{ Bytes() ([]byte, error) }) []byte {
	t.Helper()
	raw, err := ev.Bytes()
	if err != nil {
		t.Fatalf("serialize %T: %v", ev, err)
	}
	return raw
}

func testFilename(value string) [MAX_FILENAME_LENGTH]byte {
	var filename [MAX_FILENAME_LENGTH]byte
	copy(filename[:], value)
	return filename
}

func TestFastDecodersMatchGeneratedDecoders(t *testing.T) {
	t.Run("OpenEvent", func(t *testing.T) {
		ev := &OpenEvent{EventType: ENTER_OPEN_EVENT, TraceId: SYS_ENTER_OPENAT, Time: 1, Pid: 2, Tid: 3, Dirfd: 5, Flags: 4, SchemaVersion: OPEN_EVENT_SCHEMA_VERSION}
		copy(ev.Filename[:], "a")
		copy(ev.Comm[:], "b")
		raw := rawBytes(t, ev)

		slow := NewOpenEvent(raw)
		fast := NewOpenEventFast(raw)
		defer slow.Recycle()
		defer fast.Recycle()
		if !slow.Equals(fast) {
			t.Fatalf("open decode mismatch")
		}
	})

	t.Run("OpenNameFixupEvent", func(t *testing.T) {
		ev := &OpenNameFixupEvent{EventType: OPEN_NAME_FIXUP_EVENT, TraceId: SYS_ENTER_OPENAT, Tid: 3}
		copy(ev.Filename[:], "recovered")
		raw := rawBytes(t, ev)

		slow := NewOpenNameFixupEvent(raw)
		fast := NewOpenNameFixupEventFast(raw)
		defer slow.Recycle()
		defer fast.Recycle()
		if !slow.Equals(fast) {
			t.Fatalf("open-name fixup decode mismatch")
		}
	})

	t.Run("ExecEvent", func(t *testing.T) {
		ev := &ExecEvent{EventType: ENTER_EXEC_EVENT, TraceId: SYS_ENTER_EXECVEAT, Time: 1, Pid: 2, Tid: 3, Dirfd: -100, Flags: 4,
			FilenameStatus: PATH_READ_FAILED, SchemaVersion: EXEC_EVENT_SCHEMA_VERSION}
		copy(ev.Filename[:], "a")
		copy(ev.Comm[:], "b")
		raw := rawBytes(t, ev)

		slow := NewExecEvent(raw)
		fast := NewExecEventFast(raw)
		defer slow.Recycle()
		defer fast.Recycle()
		if !slow.Equals(fast) || !ev.Equals(fast) {
			t.Fatalf("exec decode mismatch: %v", fast)
		}
	})

	t.Run("NullEvent", func(t *testing.T) {
		ev := &NullEvent{EventType: ENTER_NULL_EVENT, TraceId: SYS_ENTER_SYNC, Time: 1, Pid: 2, Tid: 3}
		raw := rawBytes(t, ev)

		slow := NewNullEvent(raw)
		fast := NewNullEventFast(raw)
		defer slow.Recycle()
		defer fast.Recycle()
		if !slow.Equals(fast) {
			t.Fatalf("null decode mismatch")
		}
	})

	t.Run("FdEvent", func(t *testing.T) {
		ev := &FdEvent{EventType: ENTER_FD_EVENT, TraceId: SYS_ENTER_READ, Time: 1, Pid: 2, Tid: 3, Fd: 4, SchemaVersion: FD_EVENT_SCHEMA_VERSION}
		raw := rawBytes(t, ev)

		slow := NewFdEvent(raw)
		fast := NewFdEventFast(raw)
		defer slow.Recycle()
		defer fast.Recycle()
		if !slow.Equals(fast) {
			t.Fatalf("fd decode mismatch")
		}
	})

	t.Run("RetEvent", func(t *testing.T) {
		ev := &RetEvent{EventType: EXIT_RET_EVENT, TraceId: SYS_EXIT_READ, Time: 1, Ret: 2, Pid: 3, Tid: 4, RetType: READ_CLASSIFIED}
		raw := rawBytes(t, ev)

		slow := NewRetEvent(raw)
		fast := NewRetEventFast(raw)
		defer slow.Recycle()
		defer fast.Recycle()
		if !slow.Equals(fast) {
			t.Fatalf("ret decode mismatch")
		}
	})

	t.Run("NameEvent", func(t *testing.T) {
		ev := &NameEvent{EventType: ENTER_NAME_EVENT, TraceId: SYS_ENTER_RENAME, Time: 1, Pid: 2, Tid: 3, Olddirfd: 4, Newdirfd: 5, SchemaVersion: NAME_EVENT_SCHEMA_VERSION}
		copy(ev.Oldname[:], "old")
		copy(ev.Newname[:], "new")
		raw := rawBytes(t, ev)

		slow := NewNameEvent(raw)
		fast := NewNameEventFast(raw)
		defer slow.Recycle()
		defer fast.Recycle()
		if !slow.Equals(fast) {
			t.Fatalf("name decode mismatch")
		}
	})

	t.Run("PathEvent", func(t *testing.T) {
		ev := &PathEvent{EventType: ENTER_PATH_EVENT, TraceId: SYS_ENTER_MKDIR, Time: 1, Pid: 2, Tid: 3, Dirfd: -100, SchemaVersion: PATH_EVENT_SCHEMA_VERSION}
		copy(ev.Pathname[:], "path")
		raw := rawBytes(t, ev)

		slow := NewPathEvent(raw)
		fast := NewPathEventFast(raw)
		defer slow.Recycle()
		defer fast.Recycle()
		if !slow.Equals(fast) {
			t.Fatalf("path decode mismatch")
		}
	})

	t.Run("FcntlEvent", func(t *testing.T) {
		ev := &FcntlEvent{EventType: ENTER_FCNTL_EVENT, TraceId: SYS_ENTER_FCNTL, Time: 1, Pid: 2, Tid: 3, Fd: 4, Cmd: 5, Arg: 6}
		raw := rawBytes(t, ev)

		slow := NewFcntlEvent(raw)
		fast := NewFcntlEventFast(raw)
		defer slow.Recycle()
		defer fast.Recycle()
		if !slow.Equals(fast) {
			t.Fatalf("fcntl decode mismatch")
		}
	})

	t.Run("Dup3Event", func(t *testing.T) {
		ev := &Dup3Event{EventType: ENTER_DUP3_EVENT, TraceId: SYS_ENTER_DUP3, Time: 1, Pid: 2, Tid: 3, Fd: 4, Flags: 5}
		raw := rawBytes(t, ev)

		slow := NewDup3Event(raw)
		fast := NewDup3EventFast(raw)
		defer slow.Recycle()
		defer fast.Recycle()
		if !slow.Equals(fast) {
			t.Fatalf("dup3 decode mismatch")
		}
	})

	t.Run("OpenByHandleAtEvent", func(t *testing.T) {
		ev := &OpenByHandleAtEvent{EventType: ENTER_OPEN_BY_HANDLE_AT_EVENT, TraceId: SYS_ENTER_OPEN_BY_HANDLE_AT, Time: 1, Pid: 2, Tid: 3, Flags: 4}
		raw := rawBytes(t, ev)

		slow := NewOpenByHandleAtEvent(raw)
		fast := NewOpenByHandleAtEventFast(raw)
		defer slow.Recycle()
		defer fast.Recycle()
		if !slow.Equals(fast) {
			t.Fatalf("open_by_handle_at decode mismatch")
		}
	})

	t.Run("SocketEvent", func(t *testing.T) {
		ev := &SocketEvent{EventType: ENTER_SOCKET_EVENT, TraceId: SYS_ENTER_SOCKET, Time: 1, Pid: 2, Tid: 3, Family: 1, Type: 2, Protocol: 3}
		raw := rawBytes(t, ev)

		slow := NewSocketEvent(raw)
		fast := NewSocketEventFast(raw)
		defer slow.Recycle()
		defer fast.Recycle()
		if !slow.Equals(fast) {
			t.Fatalf("socket decode mismatch")
		}
	})

	t.Run("SocketpairEvent", func(t *testing.T) {
		ev := &SocketpairEvent{EventType: ENTER_SOCKETPAIR_EVENT, TraceId: SYS_ENTER_SOCKETPAIR, Time: 1, Pid: 2, Tid: 3, Family: 1, Type: 2, Protocol: 0, Sv0: 10, Sv1: 11, Ret: -1}
		raw := rawBytes(t, ev)

		slow := NewSocketpairEvent(raw)
		fast := NewSocketpairEventFast(raw)
		defer slow.Recycle()
		defer fast.Recycle()
		if !slow.Equals(fast) {
			t.Fatalf("socketpair decode mismatch")
		}
	})

	t.Run("AcceptEvent", func(t *testing.T) {
		ev := &AcceptEvent{EventType: ENTER_ACCEPT_EVENT, TraceId: SYS_ENTER_ACCEPT4, Time: 1, Pid: 2, Tid: 3, Fd: 4, Ret: -1, Flags: 0x80800, SchemaVersion: ACCEPT_EVENT_SCHEMA_VERSION}
		raw := rawBytes(t, ev)

		slow := NewAcceptEvent(raw)
		fast := NewAcceptEventFast(raw)
		defer slow.Recycle()
		defer fast.Recycle()
		if !slow.Equals(fast) {
			t.Fatalf("accept decode mismatch")
		}
	})

	t.Run("PipeEvent", func(t *testing.T) {
		ev := &PipeEvent{EventType: ENTER_PIPE_EVENT, TraceId: SYS_ENTER_PIPE2, Time: 1, Pid: 2, Tid: 3, Flags: 0x80000, Fd0: -1, Fd1: -1, Ret: 0}
		raw := rawBytes(t, ev)

		slow := NewPipeEvent(raw)
		fast := NewPipeEventFast(raw)
		defer slow.Recycle()
		defer fast.Recycle()
		if !slow.Equals(fast) {
			t.Fatalf("pipe decode mismatch")
		}
	})

	t.Run("EventfdEvent", func(t *testing.T) {
		ev := &EventfdEvent{
			EventType:      ENTER_EVENTFD_EVENT,
			TraceId:        SYS_ENTER_MEMFD_CREATE,
			Time:           1,
			Pid:            2,
			Tid:            3,
			Flags:          0x800,
			Ret:            -1,
			Fd:             7,
			Filename:       testFilename("ior-memfd"),
			FilenameStatus: PATH_READ_OK,
			SchemaVersion:  EVENTFD_EVENT_SCHEMA_VERSION,
		}
		raw := rawBytes(t, ev)

		slow := NewEventfdEvent(raw)
		fast := NewEventfdEventFast(raw)
		defer slow.Recycle()
		defer fast.Recycle()
		if !slow.Equals(fast) {
			t.Fatalf("eventfd decode mismatch: slow=%#v fast=%#v", slow, fast)
		}
	})

	t.Run("EpollCtlEvent", func(t *testing.T) {
		ev := &EpollCtlEvent{EventType: ENTER_EPOLL_CTL_EVENT, TraceId: SYS_ENTER_EPOLL_CTL, Time: 1, Pid: 2, Tid: 3, Epfd: 10, Op: 1, Fd: 11, Events: 5}
		raw := rawBytes(t, ev)

		slow := NewEpollCtlEvent(raw)
		fast := NewEpollCtlEventFast(raw)
		defer slow.Recycle()
		defer fast.Recycle()
		if !slow.Equals(fast) {
			t.Fatalf("epoll_ctl decode mismatch")
		}
	})

	t.Run("TwoFdEvent", func(t *testing.T) {
		ev := &TwoFdEvent{
			EventType:     ENTER_TWO_FD_EVENT,
			TraceId:       SYS_ENTER_MOVE_MOUNT,
			Time:          1,
			Pid:           2,
			Tid:           3,
			FdA:           10,
			FdB:           11,
			Extra:         0x2,
			Oldname:       testFilename("source"),
			Newname:       testFilename("destination"),
			OldnameStatus: PATH_READ_OK,
			NewnameStatus: PATH_READ_OK,
			SchemaVersion: TWO_FD_EVENT_SCHEMA_VERSION,
		}
		raw := rawBytes(t, ev)

		slow := NewTwoFdEvent(raw)
		fast := NewTwoFdEventFast(raw)
		defer slow.Recycle()
		defer fast.Recycle()
		if !slow.Equals(fast) {
			t.Fatalf("two_fd decode mismatch")
		}
	})

	t.Run("PollEvent", func(t *testing.T) {
		ev := &PollEvent{EventType: ENTER_POLL_EVENT, TraceId: SYS_ENTER_EPOLL_WAIT, Time: 1, Pid: 2, Tid: 3, Nfds: 4, TimeoutNs: 5_000_000, Fd: 6, SchemaVersion: POLL_EVENT_SCHEMA_VERSION}
		raw := rawBytes(t, ev)

		slow := NewPollEvent(raw)
		fast := NewPollEventFast(raw)
		defer slow.Recycle()
		defer fast.Recycle()
		if !slow.Equals(fast) {
			t.Fatalf("poll decode mismatch")
		}
	})

	t.Run("MemEvent", func(t *testing.T) {
		ev := &MemEvent{
			EventType: ENTER_MEM_EVENT,
			TraceId:   SYS_ENTER_MREMAP,
			Time:      1,
			Pid:       2,
			Tid:       3,
			Addr:      0x1000,
			Length:    4096,
			Length2:   8192,
			Flags:     1,
		}
		raw := rawBytes(t, ev)

		slow := NewMemEvent(raw)
		fast := NewMemEventFast(raw)
		defer slow.Recycle()
		defer fast.Recycle()
		if !slow.Equals(fast) {
			t.Fatalf("mem decode mismatch")
		}
	})

	t.Run("MmapEvent", func(t *testing.T) {
		ev := &MmapEvent{
			EventType: ENTER_MMAP_EVENT,
			TraceId:   SYS_ENTER_MMAP,
			Time:      1,
			Pid:       2,
			Tid:       3,
			Addr:      0x1000,
			Length:    4096,
			Prot:      3,
			Flags:     0x22,
			Fd:        -1,
		}
		raw := rawBytes(t, ev)

		slow := NewMmapEvent(raw)
		fast := NewMmapEventFast(raw)
		defer slow.Recycle()
		defer fast.Recycle()
		if !slow.Equals(fast) {
			t.Fatalf("mmap decode mismatch")
		}
	})

	t.Run("SleepEvent", func(t *testing.T) {
		ev := &SleepEvent{
			EventType:   ENTER_SLEEP_EVENT,
			TraceId:     SYS_ENTER_NANOSLEEP,
			Time:        1,
			Pid:         2,
			Tid:         3,
			RequestedNs: 9_000_000,
		}
		raw := rawBytes(t, ev)

		slow := NewSleepEvent(raw)
		fast := NewSleepEventFast(raw)
		defer slow.Recycle()
		defer fast.Recycle()
		if !slow.Equals(fast) {
			t.Fatalf("sleep decode mismatch")
		}
	})

	t.Run("KeyctlEvent", func(t *testing.T) {
		ev := &KeyctlEvent{EventType: ENTER_KEYCTL_EVENT, TraceId: SYS_ENTER_KEYCTL, Time: 1, Pid: 2, Tid: 3, Option: 1, KeySerial: 2, Value: 3}
		raw := rawBytes(t, ev)

		slow := NewKeyctlEvent(raw)
		fast := NewKeyctlEventFast(raw)
		defer slow.Recycle()
		defer fast.Recycle()
		if !slow.Equals(fast) {
			t.Fatalf("keyctl decode mismatch")
		}
	})

	t.Run("PtraceEvent", func(t *testing.T) {
		ev := &PtraceEvent{EventType: ENTER_PTRACE_EVENT, TraceId: SYS_ENTER_PTRACE, Time: 1, Pid: 2, Tid: 3, Request: 4, TargetPid: 5, Data: 6}
		raw := rawBytes(t, ev)

		slow := NewPtraceEvent(raw)
		fast := NewPtraceEventFast(raw)
		defer slow.Recycle()
		defer fast.Recycle()
		if !slow.Equals(fast) {
			t.Fatalf("ptrace decode mismatch")
		}
	})

	t.Run("PerfOpenEvent", func(t *testing.T) {
		ev := &PerfOpenEvent{
			EventType: ENTER_PERF_OPEN_EVENT,
			TraceId:   SYS_ENTER_PERF_EVENT_OPEN,
			Time:      1,
			Pid:       2,
			Tid:       3,
			AttrType:  1,
			AttrSize:  64,
			Config:    5,
			TargetPid: 0,
			Cpu:       -1,
			GroupFd:   -1,
			Flags:     0,
		}
		raw := rawBytes(t, ev)

		slow := NewPerfOpenEvent(raw)
		fast := NewPerfOpenEventFast(raw)
		defer slow.Recycle()
		defer fast.Recycle()
		if !slow.Equals(fast) {
			t.Fatalf("perf_open decode mismatch")
		}
	})

	// ProcessExecEvent is not a syscall event: it is the sched_process_exec
	// control record that keeps the pid->comm cache correct across execve. It
	// belongs in this table for the same reason as the others - its fast path
	// only triggers on the exact kernel payload size, so a struct-layout drift
	// must show up as a decode mismatch here.
	t.Run("ProcessExecEvent", func(t *testing.T) {
		ev := &ProcessExecEvent{EventType: PROCESS_EXEC_EVENT, Time: 1, Pid: 2, Tid: 2, OldTid: 3, ExitUntraced: 1}
		copy(ev.Comm[:], "cat")
		raw := rawBytes(t, ev)

		slow := NewProcessExecEvent(raw)
		fast := NewProcessExecEventFast(raw)
		defer slow.Recycle()
		defer fast.Recycle()
		if !slow.Equals(fast) {
			t.Fatalf("process_exec decode mismatch")
		}
	})

	// ProcessExitEvent is the sibling control record (sched_process_exit)
	// that evicts a dead process's fdTracker entries. Same table membership
	// rationale as ProcessExecEvent above.
	t.Run("ProcessExitEvent", func(t *testing.T) {
		ev := &ProcessExitEvent{EventType: PROCESS_EXIT_EVENT, Time: 1, Pid: 2, Tid: 3, GroupDead: 1}
		raw := rawBytes(t, ev)

		slow := NewProcessExitEvent(raw)
		fast := NewProcessExitEventFast(raw)
		defer slow.Recycle()
		defer fast.Recycle()
		if !slow.Equals(fast) {
			t.Fatalf("process_exit decode mismatch")
		}
	})
}

// TestNewProcessExecEventFastKernelLayout pins the kernel byte offsets of
// struct process_exec_event, in particular old_tid at 40..44 behind the comm
// and exit_untraced at 44..48: the event loop re-keys a non-leader's parked
// execve enter from OldTid to Tid, and completes it from the record itself
// when ExitUntraced is set, so a misplaced field would pair nothing, move the
// wrong enter or complete an execve whose exit is still coming.
func TestNewProcessExecEventFastKernelLayout(t *testing.T) {
	raw := make([]byte, processExecEventSize)
	binary.LittleEndian.PutUint32(raw[0:4], uint32(PROCESS_EXEC_EVENT))
	binary.LittleEndian.PutUint64(raw[8:16], 7)
	binary.LittleEndian.PutUint32(raw[16:20], 100)
	binary.LittleEndian.PutUint32(raw[20:24], 100)
	copy(raw[24:40], "newprog")
	binary.LittleEndian.PutUint32(raw[40:44], 102)
	binary.LittleEndian.PutUint32(raw[44:48], 1)

	ev := NewProcessExecEventFast(raw)
	if ev == nil {
		t.Fatal("expected decoded process exec event for kernel layout payload")
	}
	defer ev.Recycle()
	if ev.EventType != PROCESS_EXEC_EVENT || ev.Time != 7 || ev.Pid != 100 || ev.Tid != 100 ||
		ev.OldTid != 102 || ev.ExitUntraced != 1 || StringValue(ev.Comm[:]) != "newprog" {
		t.Fatalf("unexpected process exec decode: %#v", ev)
	}
}

// TestNewProcessExecEventFastRejectsShortPayloads pins the negative path: a
// payload shorter than the old_tid layout - including the old 40-byte record -
// must fail to decode rather than read as an exec that kept its tid.
func TestNewProcessExecEventFastRejectsShortPayloads(t *testing.T) {
	for _, n := range []int{0, 24, 40, processExecEventSize - 1} {
		if ev := NewProcessExecEventFast(make([]byte, n)); ev != nil {
			ev.Recycle()
			t.Fatalf("NewProcessExecEventFast(%d bytes) decoded, want nil", n)
		}
	}
}

// TestNewProcessExitEventFastKernelLayout pins the kernel byte offsets of
// struct process_exit_event, in particular group_dead at 24..28: the event
// loop evicts a process's fd table only when it is set, so a misplaced field
// would either keep dead processes' descriptors or evict living ones.
func TestNewProcessExitEventFastKernelLayout(t *testing.T) {
	for _, tc := range []struct {
		name      string
		groupDead uint32
		want      bool
	}{
		{name: "thread exit", groupDead: 0, want: false},
		{name: "group dead", groupDead: 1, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := make([]byte, processExitEventSize)
			binary.LittleEndian.PutUint32(raw[0:4], uint32(PROCESS_EXIT_EVENT))
			binary.LittleEndian.PutUint64(raw[8:16], 7)
			binary.LittleEndian.PutUint32(raw[16:20], 100)
			binary.LittleEndian.PutUint32(raw[20:24], 101)
			binary.LittleEndian.PutUint32(raw[24:28], tc.groupDead)

			ev := NewProcessExitEventFast(raw)
			if ev == nil {
				t.Fatal("expected decoded process exit event for kernel layout payload")
			}
			defer ev.Recycle()
			if ev.EventType != PROCESS_EXIT_EVENT || ev.Time != 7 || ev.Pid != 100 || ev.Tid != 101 {
				t.Fatalf("unexpected process exit decode: %#v", ev)
			}
			if ev.IsGroupDead() != tc.want {
				t.Fatalf("IsGroupDead() = %v, want %v", ev.IsGroupDead(), tc.want)
			}
		})
	}
}

// TestNewProcessExitEventFastRejectsShortPayloads pins the negative path: a
// payload shorter than the group_dead layout - including the old 24-byte
// record - must fail to decode rather than read as a thread exit.
func TestNewProcessExitEventFastRejectsShortPayloads(t *testing.T) {
	for _, n := range []int{0, 23, 24, processExitEventSize - 1} {
		if ev := NewProcessExitEventFast(make([]byte, n)); ev != nil {
			ev.Recycle()
			t.Fatalf("NewProcessExitEventFast(%d bytes) decoded, want nil", n)
		}
	}
}

func TestNewSocketpairEventFastKernelLayout(t *testing.T) {
	raw := make([]byte, socketpairEventSize)
	binary.LittleEndian.PutUint32(raw[0:4], uint32(ENTER_SOCKETPAIR_EVENT))
	binary.LittleEndian.PutUint32(raw[4:8], uint32(SYS_ENTER_SOCKETPAIR))
	binary.LittleEndian.PutUint64(raw[8:16], 1)
	binary.LittleEndian.PutUint32(raw[16:20], 2)
	binary.LittleEndian.PutUint32(raw[20:24], 3)
	binary.LittleEndian.PutUint32(raw[24:28], uint32(1))
	binary.LittleEndian.PutUint32(raw[28:32], uint32(2))
	binary.LittleEndian.PutUint32(raw[32:36], uint32(0))
	binary.LittleEndian.PutUint32(raw[36:40], uint32(10))
	binary.LittleEndian.PutUint32(raw[40:44], uint32(11))
	binary.LittleEndian.PutUint64(raw[48:56], uint64(0))

	fast := NewSocketpairEventFast(raw)
	if fast == nil {
		t.Fatalf("expected decoded socketpair event for kernel layout payload")
	}
	defer fast.Recycle()

	if fast.EventType != ENTER_SOCKETPAIR_EVENT ||
		fast.TraceId != SYS_ENTER_SOCKETPAIR ||
		fast.Time != 1 ||
		fast.Pid != 2 ||
		fast.Tid != 3 ||
		fast.Family != 1 ||
		fast.Type != 2 ||
		fast.Protocol != 0 ||
		fast.Sv0 != 10 ||
		fast.Sv1 != 11 ||
		fast.Ret != 0 {
		t.Fatalf("unexpected socketpair decode: %#v", fast)
	}
}

func TestNewAcceptEventFastLegacyAndCurrentLayouts(t *testing.T) {
	acceptLayout := AcceptEvent{}
	if got := unsafe.Sizeof(acceptLayout); got != acceptEventSize {
		t.Fatalf("sizeof(AcceptEvent) = %d, want %d", got, acceptEventSize)
	}
	for field, offset := range map[string]struct {
		got  uintptr
		want uintptr
	}{
		"fd":             {unsafe.Offsetof(acceptLayout.Fd), 24},
		"ret":            {unsafe.Offsetof(acceptLayout.Ret), 32},
		"flags":          {unsafe.Offsetof(acceptLayout.Flags), 40},
		"schema_version": {unsafe.Offsetof(acceptLayout.SchemaVersion), 44},
	} {
		if offset.got != offset.want {
			t.Fatalf("AcceptEvent.%s offset = %d, want %d", field, offset.got, offset.want)
		}
	}
	if got := len(rawBytes(t, &AcceptEvent{})); got != acceptEventCompactSize {
		t.Fatalf("AcceptEvent.Bytes size = %d, want %d", got, acceptEventCompactSize)
	}

	tests := []struct {
		name          string
		size          int
		flags         int32
		schemaVersion uint32
	}{
		{name: "legacy compact", size: acceptEventLegacyCompactSize, flags: -1},
		{name: "legacy kernel", size: acceptEventLegacyKernelSize, flags: -1},
		{name: "current compact", size: acceptEventCompactSize, flags: 0x80800, schemaVersion: ACCEPT_EVENT_SCHEMA_VERSION},
		{name: "current kernel", size: acceptEventSize, flags: 0x80800, schemaVersion: ACCEPT_EVENT_SCHEMA_VERSION},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := make([]byte, tc.size)
			fillCommonHeader(raw, EXIT_ACCEPT_EVENT, SYS_EXIT_ACCEPT4)
			binary.LittleEndian.PutUint32(raw[24:28], uint32(10))
			retOffset := 28
			if tc.size == acceptEventLegacyKernelSize || tc.size == acceptEventSize {
				retOffset = 32
				// Legacy padding was never initialized. Poison it to prove the
				// decoder cannot reinterpret it as accept4 creation flags.
				binary.LittleEndian.PutUint32(raw[28:32], 0xdeadbeef)
			}
			binary.LittleEndian.PutUint64(raw[retOffset:retOffset+8], uint64(42))
			if tc.schemaVersion != 0 {
				binary.LittleEndian.PutUint32(raw[retOffset+8:retOffset+12], uint32(tc.flags))
				binary.LittleEndian.PutUint32(raw[retOffset+12:retOffset+16], tc.schemaVersion)
			}

			fast := NewAcceptEventFast(raw)
			if fast == nil {
				t.Fatal("expected decoded accept event")
			}
			defer fast.Recycle()
			if fast.Fd != 10 || fast.Ret != 42 || fast.Flags != tc.flags ||
				fast.SchemaVersion != tc.schemaVersion {
				t.Fatalf("unexpected accept decode: %#v", fast)
			}
		})
	}
}

func TestNewAcceptEventFastRejectsUnknownCurrentSchema(t *testing.T) {
	raw := make([]byte, acceptEventSize)
	fillCommonHeader(raw, ENTER_ACCEPT_EVENT, SYS_ENTER_ACCEPT4)
	binary.LittleEndian.PutUint32(raw[44:48], ACCEPT_EVENT_SCHEMA_VERSION+1)
	if got := NewAcceptEventFast(raw); got != nil {
		got.Recycle()
		t.Fatal("unknown accept schema decoded successfully")
	}
}

func TestNewPipeEventFastKernelLayout(t *testing.T) {
	raw := make([]byte, pipeEventSize)
	binary.LittleEndian.PutUint32(raw[0:4], uint32(EXIT_PIPE_EVENT))
	binary.LittleEndian.PutUint32(raw[4:8], uint32(SYS_EXIT_PIPE2))
	binary.LittleEndian.PutUint64(raw[8:16], 1)
	binary.LittleEndian.PutUint32(raw[16:20], 2)
	binary.LittleEndian.PutUint32(raw[20:24], 3)
	binary.LittleEndian.PutUint32(raw[24:28], uint32(0x80000))
	binary.LittleEndian.PutUint32(raw[28:32], uint32(10))
	binary.LittleEndian.PutUint32(raw[32:36], uint32(11))
	binary.LittleEndian.PutUint64(raw[40:48], uint64(0))

	fast := NewPipeEventFast(raw)
	if fast == nil {
		t.Fatalf("expected decoded pipe event for kernel layout payload")
	}
	defer fast.Recycle()

	if fast.EventType != EXIT_PIPE_EVENT ||
		fast.TraceId != SYS_EXIT_PIPE2 ||
		fast.Time != 1 ||
		fast.Pid != 2 ||
		fast.Tid != 3 ||
		fast.Flags != 0x80000 ||
		fast.Fd0 != 10 ||
		fast.Fd1 != 11 ||
		fast.Ret != 0 {
		t.Fatalf("unexpected pipe decode: %#v", fast)
	}
}

func TestNewEventfdEventFastKernelLayout(t *testing.T) {
	raw := make([]byte, eventfdNameEventSize)
	binary.LittleEndian.PutUint32(raw[0:4], uint32(EXIT_EVENTFD_EVENT))
	binary.LittleEndian.PutUint32(raw[4:8], uint32(SYS_EXIT_EVENTFD2))
	binary.LittleEndian.PutUint64(raw[8:16], 1)
	binary.LittleEndian.PutUint32(raw[16:20], 2)
	binary.LittleEndian.PutUint32(raw[20:24], 3)
	binary.LittleEndian.PutUint32(raw[24:28], uint32(0x800))
	binary.LittleEndian.PutUint64(raw[32:40], uint64(42))
	binary.LittleEndian.PutUint32(raw[40:44], uint32(17))
	copy(raw[44:300], "ior-memfd")
	binary.LittleEndian.PutUint32(raw[300:304], PATH_READ_OK)
	binary.LittleEndian.PutUint32(raw[304:308], EVENTFD_EVENT_SCHEMA_VERSION)

	fast := NewEventfdEventFast(raw)
	if fast == nil {
		t.Fatalf("expected decoded eventfd event for kernel layout payload")
	}
	defer fast.Recycle()

	if fast.EventType != EXIT_EVENTFD_EVENT ||
		fast.TraceId != SYS_EXIT_EVENTFD2 ||
		fast.Time != 1 ||
		fast.Pid != 2 ||
		fast.Tid != 3 ||
		fast.Flags != 0x800 ||
		fast.Ret != 42 ||
		fast.Fd != 17 ||
		fast.Filename != testFilename("ior-memfd") ||
		fast.FilenameStatus != PATH_READ_OK ||
		fast.SchemaVersion != EVENTFD_EVENT_SCHEMA_VERSION {
		t.Fatalf("unexpected eventfd decode: %#v", fast)
	}
}

func TestNewEventfdEventFastLegacyKernelLayout(t *testing.T) {
	raw := make([]byte, eventfdEventSizeV2)
	binary.LittleEndian.PutUint32(raw[0:4], uint32(EXIT_EVENTFD_EVENT))
	binary.LittleEndian.PutUint32(raw[4:8], uint32(SYS_EXIT_EVENTFD2))
	binary.LittleEndian.PutUint64(raw[8:16], 1)
	binary.LittleEndian.PutUint32(raw[16:20], 2)
	binary.LittleEndian.PutUint32(raw[20:24], 3)
	binary.LittleEndian.PutUint32(raw[24:28], uint32(0x800))
	binary.LittleEndian.PutUint64(raw[32:40], uint64(42))

	fast := NewEventfdEventFast(raw)
	if fast == nil {
		t.Fatalf("expected decoded legacy eventfd event")
	}
	defer fast.Recycle()

	if fast.Ret != 42 || fast.Fd != -1 {
		t.Fatalf("unexpected legacy eventfd decode: %#v", fast)
	}
}

func TestNewPollEventFastKernelLayout(t *testing.T) {
	raw := make([]byte, pollEventSize)
	binary.LittleEndian.PutUint32(raw[0:4], uint32(ENTER_POLL_EVENT))
	binary.LittleEndian.PutUint32(raw[4:8], uint32(SYS_ENTER_POLL))
	binary.LittleEndian.PutUint64(raw[8:16], 1)
	binary.LittleEndian.PutUint32(raw[16:20], 2)
	binary.LittleEndian.PutUint32(raw[20:24], 3)
	binary.LittleEndian.PutUint32(raw[24:28], uint32(8))
	binary.LittleEndian.PutUint64(raw[32:40], uint64(75_000_000))
	binary.LittleEndian.PutUint32(raw[40:44], uint32(9))
	binary.LittleEndian.PutUint32(raw[44:48], POLL_EVENT_SCHEMA_VERSION)

	fast := NewPollEventFast(raw)
	if fast == nil {
		t.Fatalf("expected decoded poll event for kernel layout payload")
	}
	defer fast.Recycle()

	if fast.EventType != ENTER_POLL_EVENT ||
		fast.TraceId != SYS_ENTER_POLL ||
		fast.Time != 1 ||
		fast.Pid != 2 ||
		fast.Tid != 3 ||
		fast.Nfds != 8 ||
		fast.TimeoutNs != 75_000_000 ||
		fast.Fd != 9 ||
		fast.SchemaVersion != POLL_EVENT_SCHEMA_VERSION {
		t.Fatalf("unexpected poll decode: %#v", fast)
	}
}

func TestNewPollEventFastLayoutsAndSchema(t *testing.T) {
	tests := []struct {
		name          string
		size          int
		timeoutOffset int
		current       bool
	}{
		{name: "legacy compact", size: pollEventLegacyCompactSize, timeoutOffset: 28},
		{name: "legacy kernel", size: pollEventLegacyKernelSize, timeoutOffset: 32},
		{name: "current compact", size: pollEventCompactSize, timeoutOffset: 28, current: true},
		{name: "current kernel", size: pollEventSize, timeoutOffset: 32, current: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := make([]byte, tc.size)
			binary.LittleEndian.PutUint32(raw[0:4], uint32(ENTER_POLL_EVENT))
			binary.LittleEndian.PutUint32(raw[4:8], uint32(SYS_ENTER_EPOLL_WAIT))
			binary.LittleEndian.PutUint32(raw[24:28], 4)
			binary.LittleEndian.PutUint64(raw[tc.timeoutOffset:tc.timeoutOffset+8], 250_000_000)
			if tc.current {
				binary.LittleEndian.PutUint32(raw[tc.timeoutOffset+8:tc.timeoutOffset+12], 7)
				binary.LittleEndian.PutUint32(raw[tc.timeoutOffset+12:tc.timeoutOffset+16], POLL_EVENT_SCHEMA_VERSION)
			}

			ev := NewPollEventFast(raw)
			if ev == nil {
				t.Fatal("NewPollEventFast returned nil")
			}
			defer ev.Recycle()
			wantFD := int32(-1)
			var wantSchema uint32
			if tc.current {
				wantFD = 7
				wantSchema = POLL_EVENT_SCHEMA_VERSION
			}
			if ev.Nfds != 4 || ev.TimeoutNs != 250_000_000 || ev.Fd != wantFD || ev.SchemaVersion != wantSchema {
				t.Fatalf("decoded poll event = %#v, want nfds=4 timeout=250ms fd=%d schema=%d", ev, wantFD, wantSchema)
			}
		})
	}

	badSchema := make([]byte, pollEventCompactSize)
	binary.LittleEndian.PutUint32(badSchema[40:44], POLL_EVENT_SCHEMA_VERSION+1)
	if got := NewPollEventFast(badSchema); got != nil {
		got.Recycle()
		t.Fatal("current poll payload with unknown schema must be rejected")
	}
	if got := NewPollEventFast(make([]byte, pollEventLegacyCompactSize+1)); got != nil {
		got.Recycle()
		t.Fatal("unknown poll payload size must be rejected")
	}
}

func TestNewPollEventFastLegacyResetsAppendedPooledFields(t *testing.T) {
	current := make([]byte, pollEventCompactSize)
	binary.LittleEndian.PutUint32(current[36:40], 17)
	binary.LittleEndian.PutUint32(current[40:44], POLL_EVENT_SCHEMA_VERSION)
	ev := NewPollEventFast(current)
	if ev == nil {
		t.Fatal("decode current poll payload")
	}
	ev.Recycle()

	legacy := make([]byte, pollEventLegacyCompactSize)
	got := NewPollEventFast(legacy)
	if got == nil {
		t.Fatal("decode legacy poll payload")
	}
	defer got.Recycle()
	if got.Fd != -1 || got.SchemaVersion != 0 {
		t.Fatalf("legacy appended fields = fd %d schema %d, want -1/0", got.Fd, got.SchemaVersion)
	}
}

func TestNewTwoFdEventFastKernelLayout(t *testing.T) {
	raw := make([]byte, twoFdNamesEventSize)
	binary.LittleEndian.PutUint32(raw[0:4], uint32(ENTER_TWO_FD_EVENT))
	binary.LittleEndian.PutUint32(raw[4:8], uint32(SYS_ENTER_MOVE_MOUNT))
	binary.LittleEndian.PutUint64(raw[8:16], 1)
	binary.LittleEndian.PutUint32(raw[16:20], 2)
	binary.LittleEndian.PutUint32(raw[20:24], 3)
	binary.LittleEndian.PutUint32(raw[24:28], uint32(10))
	binary.LittleEndian.PutUint32(raw[28:32], uint32(11))
	binary.LittleEndian.PutUint64(raw[32:40], uint64(0x80))
	copy(raw[40:296], "source")
	copy(raw[296:552], "destination")
	binary.LittleEndian.PutUint32(raw[552:556], PATH_READ_OK)
	binary.LittleEndian.PutUint32(raw[556:560], PATH_READ_OK)
	binary.LittleEndian.PutUint32(raw[560:564], TWO_FD_EVENT_SCHEMA_VERSION)

	fast := NewTwoFdEventFast(raw)
	if fast == nil {
		t.Fatalf("expected decoded two_fd event for kernel layout payload")
	}
	defer fast.Recycle()

	if fast.EventType != ENTER_TWO_FD_EVENT ||
		fast.TraceId != SYS_ENTER_MOVE_MOUNT ||
		fast.Time != 1 ||
		fast.Pid != 2 ||
		fast.Tid != 3 ||
		fast.FdA != 10 ||
		fast.FdB != 11 ||
		fast.Extra != 0x80 ||
		fast.Oldname != testFilename("source") ||
		fast.Newname != testFilename("destination") ||
		fast.OldnameStatus != PATH_READ_OK ||
		fast.NewnameStatus != PATH_READ_OK ||
		fast.SchemaVersion != TWO_FD_EVENT_SCHEMA_VERSION {
		t.Fatalf("unexpected two_fd decode: %#v", fast)
	}
}

func TestTwoFdCodecsAcceptOnlyReviewedLayouts(t *testing.T) {
	current := make([]byte, twoFdNamesEventSize)
	binary.LittleEndian.PutUint32(current[0:4], uint32(ENTER_TWO_FD_EVENT))
	binary.LittleEndian.PutUint32(current[4:8], uint32(SYS_ENTER_MOVE_MOUNT))
	binary.LittleEndian.PutUint64(current[8:16], 10)
	binary.LittleEndian.PutUint32(current[16:20], 20)
	binary.LittleEndian.PutUint32(current[20:24], 21)
	binary.LittleEndian.PutUint32(current[24:28], 30)
	binary.LittleEndian.PutUint32(current[28:32], 31)
	binary.LittleEndian.PutUint64(current[32:40], 0x80)
	copy(current[40:296], "source")
	copy(current[296:552], "destination")
	binary.LittleEndian.PutUint32(current[552:556], PATH_READ_OK)
	binary.LittleEndian.PutUint32(current[556:560], PATH_READ_OK)
	binary.LittleEndian.PutUint32(current[560:564], TWO_FD_EVENT_SCHEMA_VERSION)

	legacy := append([]byte(nil), current[:twoFdLegacySize]...)
	decoders := []struct {
		name string
		fn   func([]byte) *TwoFdEvent
	}{
		{name: "generated", fn: NewTwoFdEvent},
		{name: "fast", fn: NewTwoFdEventFast},
	}
	for _, decoder := range decoders {
		for _, size := range []int{twoFdNamesCompactSize, twoFdNamesEventSize} {
			t.Run(decoder.name+"/current/"+fmt.Sprint(size), func(t *testing.T) {
				ev := decoder.fn(current[:size])
				if ev == nil {
					t.Fatalf("current %d-byte payload did not decode", size)
				}
				defer ev.Recycle()
				if ev.Oldname != testFilename("source") || ev.Newname != testFilename("destination") ||
					ev.SchemaVersion != TWO_FD_EVENT_SCHEMA_VERSION {
					t.Fatalf("unexpected current decode: %#v", ev)
				}
			})
		}

		for _, size := range []int{twoFdNamesCompactSize, twoFdNamesEventSize} {
			t.Run(decoder.name+"/pre-kcmp-owner/"+fmt.Sprint(size), func(t *testing.T) {
				raw := append([]byte(nil), current[:size]...)
				binary.LittleEndian.PutUint32(raw[560:564], TWO_FD_EVENT_PRE_KCMP_OWNER_SCHEMA_VERSION)
				ev := decoder.fn(raw)
				if ev == nil {
					t.Fatalf("pre-owner schema %d-byte payload did not decode", size)
				}
				defer ev.Recycle()
				if ev.SchemaVersion != TWO_FD_EVENT_PRE_KCMP_OWNER_SCHEMA_VERSION {
					t.Fatalf("unexpected pre-owner decode: %#v", ev)
				}
			})
		}

		t.Run(decoder.name+"/legacy", func(t *testing.T) {
			ev := decoder.fn(legacy)
			if ev == nil {
				t.Fatal("legacy payload did not decode")
			}
			defer ev.Recycle()
			if ev.FdA != 30 || ev.FdB != 31 || ev.Extra != 0x80 ||
				ev.Oldname != ([MAX_FILENAME_LENGTH]byte{}) || ev.Newname != ([MAX_FILENAME_LENGTH]byte{}) ||
				ev.OldnameStatus != PATH_READ_NULL || ev.NewnameStatus != PATH_READ_NULL || ev.SchemaVersion != 0 {
				t.Fatalf("unexpected legacy decode: %#v", ev)
			}
		})

		for _, size := range []int{39, 41, 563, 565, 566, 567, 569} {
			t.Run(decoder.name+"/malformed/"+fmt.Sprint(size), func(t *testing.T) {
				raw := make([]byte, size)
				if ev := decoder.fn(raw); ev != nil {
					ev.Recycle()
					t.Fatalf("malformed %d-byte payload decoded", size)
				}
			})
		}

		for _, size := range []int{twoFdNamesCompactSize, twoFdNamesEventSize} {
			t.Run(decoder.name+"/wrong-schema/"+fmt.Sprint(size), func(t *testing.T) {
				raw := append([]byte(nil), current[:size]...)
				binary.LittleEndian.PutUint32(raw[560:564], TWO_FD_EVENT_SCHEMA_VERSION+1)
				if ev := decoder.fn(raw); ev != nil {
					ev.Recycle()
					t.Fatalf("wrong-schema %d-byte payload decoded", size)
				}
			})
		}
	}
}

func TestNewSleepEventFastKernelLayout(t *testing.T) {
	raw := make([]byte, sleepEventSize)
	binary.LittleEndian.PutUint32(raw[0:4], uint32(ENTER_SLEEP_EVENT))
	binary.LittleEndian.PutUint32(raw[4:8], uint32(SYS_ENTER_CLOCK_NANOSLEEP))
	binary.LittleEndian.PutUint64(raw[8:16], 1)
	binary.LittleEndian.PutUint32(raw[16:20], 2)
	binary.LittleEndian.PutUint32(raw[20:24], 3)
	binary.LittleEndian.PutUint64(raw[24:32], uint64(125_000_000))

	fast := NewSleepEventFast(raw)
	if fast == nil {
		t.Fatalf("expected decoded sleep event for kernel layout payload")
	}
	defer fast.Recycle()

	if fast.EventType != ENTER_SLEEP_EVENT ||
		fast.TraceId != SYS_ENTER_CLOCK_NANOSLEEP ||
		fast.Time != 1 ||
		fast.Pid != 2 ||
		fast.Tid != 3 ||
		fast.RequestedNs != 125_000_000 {
		t.Fatalf("unexpected sleep decode: %#v", fast)
	}
}

// fillCommonHeader writes the shared 24-byte event prefix
// (event_type, trace_id, time, pid, tid) into raw.
func fillCommonHeader(raw []byte, et EventType, tid TraceId) {
	binary.LittleEndian.PutUint32(raw[0:4], uint32(et))
	binary.LittleEndian.PutUint32(raw[4:8], uint32(tid))
	binary.LittleEndian.PutUint64(raw[8:16], 111)
	binary.LittleEndian.PutUint32(raw[16:20], 22)
	binary.LittleEndian.PutUint32(raw[20:24], 33)
}

// The five tests below feed the *padded* kernel payload (sizeof(struct ...)
// reserved by bpf_ringbuf_reserve, which Go's binary.Write does NOT emit) and
// assert the fast path decodes it correctly. They guard against the regression
// where the fast-size gate used the field-sum size and silently dropped to the
// slow binary.Read path on the hottest events (open/read/write/ret).

func TestNewOpenEventFastLegacyAndCurrentLayouts(t *testing.T) {
	flags := int32(-7)
	openLayout := OpenEvent{}
	if got := unsafe.Sizeof(OpenEvent{}); got != openEventSize {
		t.Fatalf("sizeof(OpenEvent) = %d, want %d", got, openEventSize)
	}
	for field, offset := range map[string]struct {
		got  uintptr
		want uintptr
	}{
		"flags":           {unsafe.Offsetof(openLayout.Flags), 24},
		"filename":        {unsafe.Offsetof(openLayout.Filename), 28},
		"comm":            {unsafe.Offsetof(openLayout.Comm), 284},
		"dirfd":           {unsafe.Offsetof(openLayout.Dirfd), 300},
		"schema_version":  {unsafe.Offsetof(openLayout.SchemaVersion), 304},
		"filename_status": {unsafe.Offsetof(openLayout.FilenameStatus), 308},
		"schema_reserved": {unsafe.Offsetof(openLayout.SchemaReserved), 312},
	} {
		if offset.got != offset.want {
			t.Fatalf("OpenEvent.%s offset = %d, want %d", field, offset.got, offset.want)
		}
	}
	if got := len(rawBytes(t, &OpenEvent{})); got != openEventCompactSize {
		t.Fatalf("OpenEvent.Bytes size = %d, want %d", got, openEventCompactSize)
	}

	tests := []struct {
		name          string
		size          int
		dirfd         int32
		schemaVersion uint32
		status        uint32
	}{
		{name: "legacy compact", size: openEventLegacyCompactSize, dirfd: legacyPathDirfd},
		{name: "legacy kernel", size: openEventLegacyKernelSize, dirfd: legacyPathDirfd},
		{name: "v3 compact ok", size: openEventCompactSize, dirfd: 9, schemaVersion: 3},
		{name: "v3 kernel null", size: openEventSize, dirfd: 9, schemaVersion: 3, status: PATH_READ_NULL},
		{name: "v3 kernel failed", size: openEventSize, dirfd: 9, schemaVersion: 3, status: PATH_READ_FAILED},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := make([]byte, tc.size)
			fillCommonHeader(raw, ENTER_OPEN_EVENT, SYS_ENTER_OPENAT)
			binary.LittleEndian.PutUint32(raw[24:28], uint32(flags))
			copy(raw[28:284], "path")
			copy(raw[284:300], "comm")
			if tc.size == openEventCompactSize || tc.size == openEventSize {
				binary.LittleEndian.PutUint32(raw[300:304], uint32(tc.dirfd))
				binary.LittleEndian.PutUint32(raw[304:308], tc.schemaVersion)
			}
			if tc.size >= openEventCompactSize {
				binary.LittleEndian.PutUint32(raw[308:312], tc.status)
			}

			fast := NewOpenEventFast(raw)
			if fast == nil {
				t.Fatal("expected open payload to decode")
			}
			defer fast.Recycle()
			if fast.Flags != flags || fast.Dirfd != tc.dirfd || fast.SchemaVersion != tc.schemaVersion ||
				fast.FilenameStatus != tc.status || fast.SchemaReserved != 0 ||
				StringValue(fast.Filename[:]) != "path" || StringValue(fast.Comm[:]) != "comm" {
				t.Fatalf("unexpected open decode: %#v", fast)
			}
		})
	}
	for _, size := range []int{308, 312} {
		if got := NewOpenEventFast(make([]byte, size)); got != nil {
			got.Recycle()
			t.Fatalf("intermediate %d-byte open layout decoded", size)
		}
	}
	badSchema := make([]byte, openEventCompactSize)
	binary.LittleEndian.PutUint32(badSchema[304:308], OPEN_EVENT_SCHEMA_VERSION+1)
	if got := NewOpenEventFast(badSchema); got != nil {
		got.Recycle()
		t.Fatal("current-size open layout with wrong schema decoded")
	}
}

func TestNewNameEventFastLegacyAndCurrentLayouts(t *testing.T) {
	nameLayout := NameEvent{}
	if got := unsafe.Sizeof(NameEvent{}); got != nameEventSize {
		t.Fatalf("sizeof(NameEvent) = %d, want %d", got, nameEventSize)
	}
	for field, offset := range map[string]struct {
		got  uintptr
		want uintptr
	}{
		"oldname":        {unsafe.Offsetof(nameLayout.Oldname), 24},
		"newname":        {unsafe.Offsetof(nameLayout.Newname), 280},
		"olddirfd":       {unsafe.Offsetof(nameLayout.Olddirfd), 536},
		"newdirfd":       {unsafe.Offsetof(nameLayout.Newdirfd), 540},
		"oldname_status": {unsafe.Offsetof(nameLayout.OldnameStatus), 544},
		"newname_status": {unsafe.Offsetof(nameLayout.NewnameStatus), 548},
		"flags":          {unsafe.Offsetof(nameLayout.Flags), 552},
		"schema_version": {unsafe.Offsetof(nameLayout.SchemaVersion), 556},
	} {
		if offset.got != offset.want {
			t.Fatalf("NameEvent.%s offset = %d, want %d", field, offset.got, offset.want)
		}
	}
	if got := len(rawBytes(t, &NameEvent{})); got != nameEventSize {
		t.Fatalf("NameEvent.Bytes size = %d, want %d", got, nameEventSize)
	}

	tests := []struct {
		name          string
		size          int
		oldDirfd      int32
		newDirfd      int32
		oldStatus     uint32
		newStatus     uint32
		flags         uint32
		schemaVersion uint32
	}{
		{name: "legacy", size: nameEventLegacySize, oldDirfd: legacyPathDirfd, newDirfd: legacyPathDirfd},
		{name: "current", size: nameEventSize, oldDirfd: 7, newDirfd: 8,
			oldStatus: PATH_READ_FAILED, newStatus: PATH_READ_NULL, flags: 0x1000, schemaVersion: 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := make([]byte, tc.size)
			fillCommonHeader(raw, ENTER_NAME_EVENT, SYS_ENTER_RENAMEAT)
			if tc.size == nameEventSize {
				binary.LittleEndian.PutUint32(raw[536:540], uint32(tc.oldDirfd))
				binary.LittleEndian.PutUint32(raw[540:544], uint32(tc.newDirfd))
				binary.LittleEndian.PutUint32(raw[544:548], tc.oldStatus)
				binary.LittleEndian.PutUint32(raw[548:552], tc.newStatus)
				binary.LittleEndian.PutUint32(raw[552:556], tc.flags)
				binary.LittleEndian.PutUint32(raw[556:560], tc.schemaVersion)
			}

			fast := NewNameEventFast(raw)
			if fast == nil {
				t.Fatal("expected name payload to decode")
			}
			defer fast.Recycle()
			if fast.Olddirfd != tc.oldDirfd || fast.Newdirfd != tc.newDirfd ||
				fast.OldnameStatus != tc.oldStatus || fast.NewnameStatus != tc.newStatus ||
				fast.Flags != tc.flags || fast.SchemaVersion != tc.schemaVersion {
				t.Fatalf("unexpected name decode: %#v", fast)
			}
		})
	}
	for _, size := range []int{544, 552} {
		if got := NewNameEventFast(make([]byte, size)); got != nil {
			got.Recycle()
			t.Fatalf("intermediate %d-byte name layout decoded", size)
		}
	}
	badSchema := make([]byte, nameEventSize)
	binary.LittleEndian.PutUint32(badSchema[556:560], NAME_EVENT_SCHEMA_VERSION+1)
	if got := NewNameEventFast(badSchema); got != nil {
		got.Recycle()
		t.Fatal("current-size name layout with wrong schema decoded")
	}
}

func TestNewPathEventFastLegacyAndCurrentLayouts(t *testing.T) {
	pathLayout := PathEvent{}
	if got := unsafe.Sizeof(PathEvent{}); got != pathEventSize {
		t.Fatalf("sizeof(PathEvent) = %d, want %d", got, pathEventSize)
	}
	for field, offset := range map[string]struct {
		got  uintptr
		want uintptr
	}{
		"pathname":        {unsafe.Offsetof(pathLayout.Pathname), 24},
		"dirfd":           {unsafe.Offsetof(pathLayout.Dirfd), 280},
		"pathname_status": {unsafe.Offsetof(pathLayout.PathnameStatus), 284},
		"flags":           {unsafe.Offsetof(pathLayout.Flags), 288},
		"schema_version":  {unsafe.Offsetof(pathLayout.SchemaVersion), 292},
		"target_status":   {unsafe.Offsetof(pathLayout.TargetStatus), 296},
		"size_valid":      {unsafe.Offsetof(pathLayout.SizeValid), 300},
		"size":            {unsafe.Offsetof(pathLayout.Size), 304},
	} {
		if offset.got != offset.want {
			t.Fatalf("PathEvent.%s offset = %d, want %d", field, offset.got, offset.want)
		}
	}
	if got := len(rawBytes(t, &PathEvent{})); got != pathEventCompactSize {
		t.Fatalf("PathEvent.Bytes size = %d, want %d", got, pathEventCompactSize)
	}

	tests := []struct {
		name          string
		size          int
		dirfd         int32
		status        uint32
		flags         uint32
		schemaVersion uint32
		targetStatus  uint32
		sizeValid     uint32
		requestedSize uint64
	}{
		{name: "legacy", size: pathEventLegacySize, dirfd: legacyPathDirfd},
		{name: "v3 compact", size: pathEventV3CompactSize, dirfd: 9, status: PATH_READ_FAILED, flags: 0x1000, schemaVersion: 3, targetStatus: PATH_TARGET_UNKNOWN},
		{name: "v3 kernel", size: pathEventV3KernelSize, dirfd: 9, status: PATH_READ_NULL, flags: 0x1000, schemaVersion: 3, targetStatus: PATH_TARGET_SKIPPED},
		{name: "current", size: pathEventSize, dirfd: 9, status: PATH_READ_OK, flags: 0x2000, schemaVersion: PATH_EVENT_SCHEMA_VERSION, targetStatus: PATH_TARGET_REQUIRED, sizeValid: 1, requestedSize: 4096},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := make([]byte, tc.size)
			fillCommonHeader(raw, ENTER_PATH_EVENT, SYS_ENTER_STATX)
			if tc.size != pathEventLegacySize {
				binary.LittleEndian.PutUint32(raw[280:284], uint32(tc.dirfd))
				binary.LittleEndian.PutUint32(raw[284:288], tc.status)
				binary.LittleEndian.PutUint32(raw[288:292], tc.flags)
				binary.LittleEndian.PutUint32(raw[292:296], tc.schemaVersion)
				binary.LittleEndian.PutUint32(raw[296:300], tc.targetStatus)
			}
			if tc.size == pathEventSize {
				binary.LittleEndian.PutUint32(raw[300:304], tc.sizeValid)
				binary.LittleEndian.PutUint64(raw[304:312], tc.requestedSize)
			}

			fast := NewPathEventFast(raw)
			if fast == nil {
				t.Fatal("expected path payload to decode")
			}
			defer fast.Recycle()
			if fast.Dirfd != tc.dirfd || fast.PathnameStatus != tc.status || fast.Flags != tc.flags ||
				fast.SchemaVersion != tc.schemaVersion || fast.TargetStatus != tc.targetStatus ||
				fast.SizeValid != tc.sizeValid || fast.Size != tc.requestedSize {
				t.Fatalf("unexpected path decode: %#v", fast)
			}
		})
	}
	for _, size := range []int{284, 288, 296, 308} {
		if got := NewPathEventFast(make([]byte, size)); got != nil {
			got.Recycle()
			t.Fatalf("ambiguous intermediate %d-byte path layout decoded", size)
		}
	}
	badSchema := make([]byte, pathEventCompactSize)
	binary.LittleEndian.PutUint32(badSchema[292:296], PATH_EVENT_SCHEMA_VERSION+1)
	if got := NewPathEventFast(badSchema); got != nil {
		got.Recycle()
		t.Fatal("current-size path layout with wrong schema decoded")
	}

	// A recycled current record must not leak its target status or requested
	// size into a legacy payload, whose absent fields receive compatibility
	// defaults.
	current := make([]byte, pathEventCompactSize)
	binary.LittleEndian.PutUint32(current[292:296], PATH_EVENT_SCHEMA_VERSION)
	binary.LittleEndian.PutUint32(current[296:300], PATH_TARGET_UNKNOWN)
	binary.LittleEndian.PutUint32(current[300:304], 1)
	binary.LittleEndian.PutUint64(current[304:312], 4096)
	decodedCurrent := NewPathEventFast(current)
	if decodedCurrent == nil {
		t.Fatal("current path payload did not decode")
	}
	decodedCurrent.Recycle()
	legacy := NewPathEventFast(make([]byte, pathEventLegacySize))
	if legacy == nil {
		t.Fatal("legacy path payload did not decode")
	}
	defer legacy.Recycle()
	if legacy.TargetStatus != PATH_TARGET_REQUIRED || legacy.SizeValid != 0 || legacy.Size != 0 {
		t.Fatalf("legacy metadata leaked from recycled current payload: %#v", legacy)
	}
}

func TestNewOpenNameFixupEventFastCompactKernelLayout(t *testing.T) {
	if got := unsafe.Sizeof(OpenNameFixupEvent{}); got != openNameFixupEventSize {
		t.Fatalf("sizeof(OpenNameFixupEvent) = %d, want %d", got, openNameFixupEventSize)
	}
	if got := unsafe.Sizeof(OpenEvent{}); got != openEventSize {
		t.Fatalf("sizeof(OpenEvent) = %d, want %d", got, openEventSize)
	}
	if got := openEventSize - openNameFixupEventSize; got != 52 {
		t.Fatalf("compact fixup saves %d bytes over an open event, want 52", got)
	}

	raw := make([]byte, openNameFixupEventSize)
	binary.LittleEndian.PutUint32(raw[0:4], uint32(OPEN_NAME_FIXUP_EVENT))
	binary.LittleEndian.PutUint32(raw[4:8], uint32(SYS_ENTER_OPENAT))
	binary.LittleEndian.PutUint32(raw[8:12], 33)
	copy(raw[12:268], "recovered")

	fast := NewOpenNameFixupEventFast(raw)
	if fast == nil {
		t.Fatal("expected decoded open-name fixup event for compact kernel payload")
	}
	defer fast.Recycle()
	if fast.EventType != OPEN_NAME_FIXUP_EVENT || fast.TraceId != SYS_ENTER_OPENAT ||
		fast.Tid != 33 || StringValue(fast.Filename[:]) != "recovered" {
		t.Fatalf("unexpected open-name fixup decode: %#v", fast)
	}
}

func TestNewOpenNameFixupEventFastLegacyOpenEventLayout(t *testing.T) {
	for _, size := range []int{openEventLegacyCompactSize, openEventLegacyKernelSize} {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			raw := make([]byte, size)
			fillCommonHeader(raw, OPEN_NAME_FIXUP_EVENT, SYS_ENTER_OPENAT)
			copy(raw[28:284], "legacy-recovered")

			fixup := NewOpenNameFixupEventFast(raw)
			if fixup == nil {
				t.Fatal("expected legacy open-event fixup payload to decode")
			}
			defer fixup.Recycle()
			if fixup.Tid != 33 || StringValue(fixup.Filename[:]) != "legacy-recovered" {
				t.Fatalf("unexpected legacy fixup decode: %#v", fixup)
			}
		})
	}
}

func TestNewOpenNameFixupEventFastRejectsUnknownLayout(t *testing.T) {
	if got := NewOpenNameFixupEventFast(make([]byte, openNameFixupEventSize+1)); got != nil {
		got.Recycle()
		t.Fatal("unexpected fixup layout decoded instead of being rejected")
	}
}

func TestNewFdEventFastLegacyAndCurrentLayouts(t *testing.T) {
	fdLayout := FdEvent{}
	if got := unsafe.Sizeof(fdLayout); got != fdEventLegacyKernelSize {
		t.Fatalf("sizeof(FdEvent) = %d, want %d", got, fdEventLegacyKernelSize)
	}
	if got := len(rawBytes(t, &fdLayout)); got != fdEventSize {
		t.Fatalf("FdEvent.Bytes size = %d, want %d", got, fdEventSize)
	}

	tests := []struct {
		name          string
		payloadSize   int
		sizeOffset    int
		requestedSize uint64
		sizeValid     uint32
	}{
		{name: "lean compact", payloadSize: fdEventCompactSize},
		{name: "lean kernel", payloadSize: fdEventSize},
		{name: "wide compact", payloadSize: fdEventLegacyCompactSize, sizeOffset: 28, requestedSize: 4096, sizeValid: 1},
		{name: "wide kernel", payloadSize: fdEventLegacyKernelSize, sizeOffset: 32, requestedSize: 8192, sizeValid: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := make([]byte, tc.payloadSize)
			fillCommonHeader(raw, ENTER_FD_EVENT, SYS_ENTER_READ)
			binary.LittleEndian.PutUint32(raw[24:28], uint32(int32(9)))
			if tc.sizeOffset != 0 {
				binary.LittleEndian.PutUint64(raw[tc.sizeOffset:tc.sizeOffset+8], tc.requestedSize)
				binary.LittleEndian.PutUint32(raw[tc.sizeOffset+8:tc.sizeOffset+12], tc.sizeValid)
				binary.LittleEndian.PutUint32(raw[tc.sizeOffset+12:tc.sizeOffset+16], FD_EVENT_SCHEMA_VERSION)
			}

			fast := NewFdEventFast(raw)
			if fast == nil {
				t.Fatal("expected fd payload to decode")
			}
			defer fast.Recycle()
			regular := NewFdEvent(raw)
			if regular == nil || !fast.Equals(regular) {
				t.Fatalf("regular constructor disagrees with fast decoder: %#v / %#v", regular, fast)
			}
			defer regular.Recycle()
			if fast.Time != 111 || fast.Pid != 22 || fast.Tid != 33 || fast.Fd != 9 ||
				fast.Size != tc.requestedSize || fast.SizeValid != tc.sizeValid {
				t.Fatalf("unexpected fd decode: %#v", fast)
			}
		})
	}
}

func TestSplitPayloadFastDecoders(t *testing.T) {
	t.Run("fd size", func(t *testing.T) {
		raw := make([]byte, fdSizeEventSize)
		fillCommonHeader(raw, ENTER_FD_SIZE_EVENT, SYS_ENTER_FGETXATTR)
		binary.LittleEndian.PutUint32(raw[24:28], 7)
		binary.LittleEndian.PutUint64(raw[32:40], 4096)
		binary.LittleEndian.PutUint32(raw[40:44], 1)
		binary.LittleEndian.PutUint32(raw[44:48], FD_SIZE_EVENT_SCHEMA_VERSION)
		ev := NewFdSizeEventFast(raw)
		if ev == nil || ev.Fd != 7 || ev.Size != 4096 || ev.SizeValid != 1 {
			t.Fatalf("fd size decode = %#v", ev)
		}
		ev.Recycle()
		regular := NewFdSizeEvent(raw)
		if regular == nil || regular.Fd != 7 || regular.Size != 4096 || regular.SizeValid != 1 {
			t.Fatalf("regular fd size decode = %#v", regular)
		}
		encoded, err := regular.Bytes()
		regular.Recycle()
		if err != nil || !bytes.Equal(encoded, raw) {
			t.Fatalf("fd size encode = %x, %v; want %x", encoded, err, raw)
		}
		binary.LittleEndian.PutUint32(raw[44:48], FD_SIZE_EVENT_SCHEMA_VERSION+1)
		if ev := NewFdSizeEventFast(raw); ev != nil {
			ev.Recycle()
			t.Fatal("accepted wrong fd-size schema")
		}
		if ev := NewFdSizeEventFast(raw[:47]); ev != nil {
			ev.Recycle()
			t.Fatal("accepted truncated fd-size record")
		}
		if ev := NewFdSizeEvent(raw); ev != nil {
			ev.Recycle()
			t.Fatal("regular decoder accepted wrong fd-size schema")
		}
		if ev := NewFdSizeEvent(raw[:47]); ev != nil {
			ev.Recycle()
			t.Fatal("regular decoder accepted truncated fd-size record")
		}
	})
	t.Run("eventfd name", func(t *testing.T) {
		raw := make([]byte, eventfdNameEventSize)
		fillCommonHeader(raw, ENTER_EVENTFD_NAME_EVENT, SYS_ENTER_MEMFD_CREATE)
		copy(raw[44:300], "named-memfd")
		binary.LittleEndian.PutUint32(raw[304:308], EVENTFD_NAME_EVENT_SCHEMA_VERSION)
		ev := NewEventfdNameEventFast(raw)
		if ev == nil || StringValue(ev.Filename[:]) != "named-memfd" {
			t.Fatalf("eventfd name decode = %#v", ev)
		}
		ev.Recycle()
		binary.LittleEndian.PutUint32(raw[304:308], EVENTFD_NAME_EVENT_SCHEMA_VERSION+1)
		if ev := NewEventfdNameEventFast(raw); ev != nil {
			ev.Recycle()
			t.Fatal("accepted wrong eventfd-name schema")
		}
		if ev := NewEventfdNameEventFast(raw[:311]); ev != nil {
			ev.Recycle()
			t.Fatal("accepted truncated eventfd-name record")
		}
	})
	t.Run("two fd names", func(t *testing.T) {
		raw := make([]byte, twoFdNamesEventSize)
		fillCommonHeader(raw, ENTER_TWO_FD_NAMES_EVENT, SYS_ENTER_MOVE_MOUNT)
		copy(raw[40:296], "/source")
		copy(raw[296:552], "/target")
		binary.LittleEndian.PutUint32(raw[560:564], TWO_FD_EVENT_SCHEMA_VERSION)
		ev := NewTwoFdNamesEventFast(raw)
		if ev == nil || StringValue(ev.Oldname[:]) != "/source" || StringValue(ev.Newname[:]) != "/target" {
			t.Fatalf("two-fd names decode = %#v", ev)
		}
		ev.Recycle()
		binary.LittleEndian.PutUint32(raw[560:564], TWO_FD_EVENT_SCHEMA_VERSION+1)
		if ev := NewTwoFdNamesEventFast(raw); ev != nil {
			ev.Recycle()
			t.Fatal("accepted wrong two-fd-names schema")
		}
		if ev := NewTwoFdNamesEventFast(raw[:567]); ev != nil {
			ev.Recycle()
			t.Fatal("accepted truncated two-fd-names record")
		}
	})
	t.Run("empty two fd names retain wide layout", func(t *testing.T) {
		ev := &TwoFdEvent{
			EventType:     ENTER_TWO_FD_NAMES_EVENT,
			TraceId:       SYS_ENTER_MOVE_MOUNT,
			SchemaVersion: TWO_FD_EVENT_SCHEMA_VERSION,
		}
		raw, err := ev.Bytes()
		if err != nil || len(raw) != twoFdNamesEventSize {
			t.Fatalf("two-fd named encode size = %d, %v", len(raw), err)
		}
		decoded := NewTwoFdNamesEventFast(raw)
		if decoded == nil {
			t.Fatal("named decoder rejected empty-name record")
		}
		decoded.Recycle()
	})
	t.Run("lean two fd keeps lean layout", func(t *testing.T) {
		ev := &TwoFdEvent{
			EventType:     ENTER_TWO_FD_EVENT,
			TraceId:       SYS_ENTER_CLOSE_RANGE,
			OldnameStatus: PATH_READ_NULL,
			NewnameStatus: PATH_READ_NULL,
			SchemaVersion: TWO_FD_EVENT_SCHEMA_VERSION,
		}
		raw, err := ev.Bytes()
		if err != nil || len(raw) != twoFdEventSize {
			t.Fatalf("two-fd lean encode size = %d, %v", len(raw), err)
		}
	})
	t.Run("legacy two fd preserves failed empty name", func(t *testing.T) {
		raw := make([]byte, twoFdNamesEventSize)
		fillCommonHeader(raw, ENTER_TWO_FD_EVENT, SYS_ENTER_MOVE_MOUNT)
		binary.LittleEndian.PutUint32(raw[552:556], PATH_READ_FAILED)
		binary.LittleEndian.PutUint32(raw[556:560], PATH_READ_OK)
		binary.LittleEndian.PutUint32(raw[560:564], TWO_FD_EVENT_SCHEMA_VERSION)
		ev := NewTwoFdEvent(raw)
		if ev == nil {
			t.Fatal("legacy named record rejected")
		}
		encoded, err := ev.Bytes()
		ev.Recycle()
		if err != nil || !bytes.Equal(encoded, raw) {
			t.Fatalf("legacy named roundtrip = %x, %v; want %x", encoded, err, raw)
		}
	})
}

func TestNewRetEventFastKernelLayout(t *testing.T) {
	raw := make([]byte, retEventSize) // 40: sizeof(struct ret_event)
	fillCommonHeader(raw, EXIT_RET_EVENT, SYS_EXIT_READ)
	// ret_event has Ret before Pid/Tid; rewrite pid/tid at their real offsets.
	ret := int64(-5)
	binary.LittleEndian.PutUint64(raw[16:24], uint64(ret))
	binary.LittleEndian.PutUint32(raw[24:28], 22)
	binary.LittleEndian.PutUint32(raw[28:32], 33)
	binary.LittleEndian.PutUint32(raw[32:36], READ_CLASSIFIED)

	fast := NewRetEventFast(raw)
	if fast == nil {
		t.Fatalf("expected decoded ret event for padded kernel payload")
	}
	defer fast.Recycle()
	if fast.Time != 111 || fast.Ret != -5 || fast.Pid != 22 || fast.Tid != 33 ||
		fast.RetType != READ_CLASSIFIED {
		t.Fatalf("unexpected ret decode: %#v", fast)
	}
}

func TestNewSocketEventFastKernelLayout(t *testing.T) {
	raw := make([]byte, socketEventSize) // 40: sizeof(struct socket_event)
	fillCommonHeader(raw, ENTER_SOCKET_EVENT, SYS_ENTER_SOCKET)
	binary.LittleEndian.PutUint32(raw[24:28], uint32(int32(2)))
	binary.LittleEndian.PutUint32(raw[28:32], uint32(int32(1)))
	binary.LittleEndian.PutUint32(raw[32:36], uint32(int32(6)))

	fast := NewSocketEventFast(raw)
	if fast == nil {
		t.Fatalf("expected decoded socket event for padded kernel payload")
	}
	defer fast.Recycle()
	if fast.Time != 111 || fast.Family != 2 || fast.Type != 1 || fast.Protocol != 6 {
		t.Fatalf("unexpected socket decode: %#v", fast)
	}
}

func TestNewOpenByHandleAtEventFastKernelLayout(t *testing.T) {
	raw := make([]byte, openByHandleAtEventSize) // 32: sizeof(struct open_by_handle_at_event)
	fillCommonHeader(raw, ENTER_OPEN_BY_HANDLE_AT_EVENT, SYS_ENTER_OPEN_BY_HANDLE_AT)
	binary.LittleEndian.PutUint32(raw[24:28], uint32(int32(3)))

	fast := NewOpenByHandleAtEventFast(raw)
	if fast == nil {
		t.Fatalf("expected decoded open_by_handle_at event for padded kernel payload")
	}
	defer fast.Recycle()
	if fast.Time != 111 || fast.Pid != 22 || fast.Tid != 33 || fast.Flags != 3 {
		t.Fatalf("unexpected open_by_handle_at decode: %#v", fast)
	}
}

func TestNewMmapEventFastKernelLayout(t *testing.T) {
	ev := &MmapEvent{
		EventType: ENTER_MMAP_EVENT,
		TraceId:   SYS_ENTER_MMAP,
		Time:      111,
		Pid:       22,
		Tid:       33,
		Addr:      0x1000,
		Length:    4096,
		Prot:      3,
		Flags:     0x22,
		Fd:        -1,
	}
	raw := rawBytes(t, ev)
	raw = append(raw, 0, 0, 0, 0)
	if len(raw) != mmapEventSize {
		t.Fatalf("padded mmap payload size = %d, want %d", len(raw), mmapEventSize)
	}

	fast := NewMmapEventFast(raw)
	if fast == nil {
		t.Fatal("expected decoded mmap event for padded kernel payload")
	}
	defer fast.Recycle()
	if !ev.Equals(fast) {
		t.Fatalf("unexpected mmap decode: %#v", fast)
	}
}

// TestExecEventFastSchemaCompatibility pins the exec_event v1 layout (task
// 9p2): the filename read status and schema word follow comm, the released
// 304-byte layout still decodes as a successful read, and every other size
// or schema version fails closed instead of misreading the status.
func TestExecEventFastSchemaCompatibility(t *testing.T) {
	current := &ExecEvent{EventType: ENTER_EXEC_EVENT, TraceId: SYS_ENTER_EXECVEAT, Time: 1, Pid: 2, Tid: 3,
		Dirfd: 7, Flags: 0x1000, FilenameStatus: PATH_READ_NULL, SchemaVersion: EXEC_EVENT_SCHEMA_VERSION}
	copy(current.Filename[:], "prog")
	copy(current.Comm[:], "sh")
	raw := rawBytes(t, current)
	if len(raw) != execEventSize {
		t.Fatalf("exec_event v1 encodes to %d bytes, want %d", len(raw), execEventSize)
	}

	t.Run("current", func(t *testing.T) {
		fast := NewExecEventFast(raw)
		if fast == nil || !current.Equals(fast) {
			t.Fatalf("decoded %v, want %v", fast, current)
		}
		fast.Recycle()
	})
	t.Run("legacy 304-byte layout reads as PATH_READ_OK", func(t *testing.T) {
		fast := NewExecEventFast(raw[:execEventLegacySize])
		if fast == nil {
			t.Fatal("legacy exec_event rejected")
		}
		defer fast.Recycle()
		want := *current
		want.FilenameStatus, want.SchemaVersion = PATH_READ_OK, 0
		if !want.Equals(fast) {
			t.Fatalf("decoded %v, want %v", fast, want)
		}
	})
	for _, version := range []uint32{0, EXEC_EVENT_SCHEMA_VERSION + 1} {
		// Version 0 is what a 312-byte record with an unwritten schema word
		// would carry; only the legacy 304-byte layout implies it.
		t.Run(fmt.Sprintf("schema version %d fails closed", version), func(t *testing.T) {
			bad := append([]byte(nil), raw...)
			binary.LittleEndian.PutUint32(bad[308:312], version)
			if fast := NewExecEventFast(bad); fast != nil {
				t.Fatalf("decoded unknown schema: %v", fast)
			}
		})
	}
	for _, size := range []int{execEventLegacySize + 4, execEventSize + 4, execEventSize + 8} {
		t.Run(fmt.Sprintf("size %d fails closed", size), func(t *testing.T) {
			if fast := NewExecEventFast(append(raw, make([]byte, 8)...)[:size]); fast != nil {
				t.Fatalf("decoded %d-byte payload: %v", size, fast)
			}
		})
	}
}

func TestFastDecodersReturnNilOnShortPayload(t *testing.T) {
	cases := []struct {
		name   string
		decode func([]byte) bool
	}{
		{name: "OpenEvent", decode: func(raw []byte) bool { return NewOpenEventFast(raw) == nil }},
		{name: "OpenNameFixupEvent", decode: func(raw []byte) bool { return NewOpenNameFixupEventFast(raw) == nil }},
		{name: "ExecEvent", decode: func(raw []byte) bool { return NewExecEventFast(raw) == nil }},
		{name: "NullEvent", decode: func(raw []byte) bool { return NewNullEventFast(raw) == nil }},
		{name: "FdEvent", decode: func(raw []byte) bool { return NewFdEventFast(raw) == nil }},
		{name: "RetEvent", decode: func(raw []byte) bool { return NewRetEventFast(raw) == nil }},
		{name: "NameEvent", decode: func(raw []byte) bool { return NewNameEventFast(raw) == nil }},
		{name: "PathEvent", decode: func(raw []byte) bool { return NewPathEventFast(raw) == nil }},
		{name: "FcntlEvent", decode: func(raw []byte) bool { return NewFcntlEventFast(raw) == nil }},
		{name: "Dup3Event", decode: func(raw []byte) bool { return NewDup3EventFast(raw) == nil }},
		{name: "OpenByHandleAtEvent", decode: func(raw []byte) bool { return NewOpenByHandleAtEventFast(raw) == nil }},
		{name: "SocketEvent", decode: func(raw []byte) bool { return NewSocketEventFast(raw) == nil }},
		{name: "SocketpairEvent", decode: func(raw []byte) bool { return NewSocketpairEventFast(raw) == nil }},
		{name: "AcceptEvent", decode: func(raw []byte) bool { return NewAcceptEventFast(raw) == nil }},
		{name: "PipeEvent", decode: func(raw []byte) bool { return NewPipeEventFast(raw) == nil }},
		{name: "EventfdEvent", decode: func(raw []byte) bool { return NewEventfdEventFast(raw) == nil }},
		{name: "EpollCtlEvent", decode: func(raw []byte) bool { return NewEpollCtlEventFast(raw) == nil }},
		{name: "TwoFdEvent", decode: func(raw []byte) bool { return NewTwoFdEventFast(raw) == nil }},
		{name: "PollEvent", decode: func(raw []byte) bool { return NewPollEventFast(raw) == nil }},
		{name: "SleepEvent", decode: func(raw []byte) bool { return NewSleepEventFast(raw) == nil }},
		{name: "KeyctlEvent", decode: func(raw []byte) bool { return NewKeyctlEventFast(raw) == nil }},
		{name: "PtraceEvent", decode: func(raw []byte) bool { return NewPtraceEventFast(raw) == nil }},
		{name: "PerfOpenEvent", decode: func(raw []byte) bool { return NewPerfOpenEventFast(raw) == nil }},
		{name: "MemEvent", decode: func(raw []byte) bool { return NewMemEventFast(raw) == nil }},
		{name: "MmapEvent", decode: func(raw []byte) bool { return NewMmapEventFast(raw) == nil }},
		{name: "ProcessExecEvent", decode: func(raw []byte) bool { return NewProcessExecEventFast(raw) == nil }},
		{name: "ProcessExitEvent", decode: func(raw []byte) bool { return NewProcessExitEventFast(raw) == nil }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.decode([]byte{1}) {
				t.Fatalf("expected nil for short payload")
			}
		})
	}
}
