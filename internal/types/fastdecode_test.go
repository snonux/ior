package types

import (
	"encoding/binary"
	"testing"
)

func TestFastDecodersMatchGeneratedDecoders(t *testing.T) {
	t.Run("OpenEvent", func(t *testing.T) {
		ev := &OpenEvent{EventType: ENTER_OPEN_EVENT, TraceId: SYS_ENTER_OPENAT, Time: 1, Pid: 2, Tid: 3, Flags: 4}
		copy(ev.Filename[:], "a")
		copy(ev.Comm[:], "b")
		raw, _ := ev.Bytes()

		slow := NewOpenEvent(raw)
		fast := NewOpenEventFast(raw)
		defer slow.Recycle()
		defer fast.Recycle()
		if !slow.Equals(fast) {
			t.Fatalf("open decode mismatch")
		}
	})

	t.Run("NullEvent", func(t *testing.T) {
		ev := &NullEvent{EventType: ENTER_NULL_EVENT, TraceId: SYS_ENTER_SYNC, Time: 1, Pid: 2, Tid: 3}
		raw, _ := ev.Bytes()

		slow := NewNullEvent(raw)
		fast := NewNullEventFast(raw)
		defer slow.Recycle()
		defer fast.Recycle()
		if !slow.Equals(fast) {
			t.Fatalf("null decode mismatch")
		}
	})

	t.Run("FdEvent", func(t *testing.T) {
		ev := &FdEvent{EventType: ENTER_FD_EVENT, TraceId: SYS_ENTER_READ, Time: 1, Pid: 2, Tid: 3, Fd: 4}
		raw, _ := ev.Bytes()

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
		raw, _ := ev.Bytes()

		slow := NewRetEvent(raw)
		fast := NewRetEventFast(raw)
		defer slow.Recycle()
		defer fast.Recycle()
		if !slow.Equals(fast) {
			t.Fatalf("ret decode mismatch")
		}
	})

	t.Run("NameEvent", func(t *testing.T) {
		ev := &NameEvent{EventType: ENTER_NAME_EVENT, TraceId: SYS_ENTER_RENAME, Time: 1, Pid: 2, Tid: 3}
		copy(ev.Oldname[:], "old")
		copy(ev.Newname[:], "new")
		raw, _ := ev.Bytes()

		slow := NewNameEvent(raw)
		fast := NewNameEventFast(raw)
		defer slow.Recycle()
		defer fast.Recycle()
		if !slow.Equals(fast) {
			t.Fatalf("name decode mismatch")
		}
	})

	t.Run("PathEvent", func(t *testing.T) {
		ev := &PathEvent{EventType: ENTER_PATH_EVENT, TraceId: SYS_ENTER_MKDIR, Time: 1, Pid: 2, Tid: 3}
		copy(ev.Pathname[:], "path")
		raw, _ := ev.Bytes()

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
		raw, _ := ev.Bytes()

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
		raw, _ := ev.Bytes()

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
		raw, _ := ev.Bytes()

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
		raw, _ := ev.Bytes()

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
		raw, _ := ev.Bytes()

		slow := NewSocketpairEvent(raw)
		fast := NewSocketpairEventFast(raw)
		defer slow.Recycle()
		defer fast.Recycle()
		if !slow.Equals(fast) {
			t.Fatalf("socketpair decode mismatch")
		}
	})

	t.Run("AcceptEvent", func(t *testing.T) {
		ev := &AcceptEvent{EventType: ENTER_ACCEPT_EVENT, TraceId: SYS_ENTER_ACCEPT4, Time: 1, Pid: 2, Tid: 3, Fd: 4, Ret: -1}
		raw, _ := ev.Bytes()

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
		raw, _ := ev.Bytes()

		slow := NewPipeEvent(raw)
		fast := NewPipeEventFast(raw)
		defer slow.Recycle()
		defer fast.Recycle()
		if !slow.Equals(fast) {
			t.Fatalf("pipe decode mismatch")
		}
	})

	t.Run("EventfdEvent", func(t *testing.T) {
		ev := &EventfdEvent{EventType: ENTER_EVENTFD_EVENT, TraceId: SYS_ENTER_EVENTFD2, Time: 1, Pid: 2, Tid: 3, Flags: 0x800, Ret: -1}
		raw, _ := ev.Bytes()

		slow := NewEventfdEvent(raw)
		fast := NewEventfdEventFast(raw)
		defer slow.Recycle()
		defer fast.Recycle()
		if !slow.Equals(fast) {
			t.Fatalf("eventfd decode mismatch")
		}
	})

	t.Run("EpollCtlEvent", func(t *testing.T) {
		ev := &EpollCtlEvent{EventType: ENTER_EPOLL_CTL_EVENT, TraceId: SYS_ENTER_EPOLL_CTL, Time: 1, Pid: 2, Tid: 3, Epfd: 10, Op: 1, Fd: 11, Events: 5}
		raw, _ := ev.Bytes()

		slow := NewEpollCtlEvent(raw)
		fast := NewEpollCtlEventFast(raw)
		defer slow.Recycle()
		defer fast.Recycle()
		if !slow.Equals(fast) {
			t.Fatalf("epoll_ctl decode mismatch")
		}
	})

	t.Run("TwoFdEvent", func(t *testing.T) {
		ev := &TwoFdEvent{EventType: ENTER_TWO_FD_EVENT, TraceId: SYS_ENTER_MOVE_MOUNT, Time: 1, Pid: 2, Tid: 3, FdA: 10, FdB: 11, Extra: 0x2}
		raw, _ := ev.Bytes()

		slow := NewTwoFdEvent(raw)
		fast := NewTwoFdEventFast(raw)
		defer slow.Recycle()
		defer fast.Recycle()
		if !slow.Equals(fast) {
			t.Fatalf("two_fd decode mismatch")
		}
	})

	t.Run("PollEvent", func(t *testing.T) {
		ev := &PollEvent{EventType: ENTER_POLL_EVENT, TraceId: SYS_ENTER_POLL, Time: 1, Pid: 2, Tid: 3, Nfds: 4, TimeoutNs: 5_000_000}
		raw, _ := ev.Bytes()

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
		raw, _ := ev.Bytes()

		slow := NewMemEvent(raw)
		fast := NewMemEventFast(raw)
		defer slow.Recycle()
		defer fast.Recycle()
		if !slow.Equals(fast) {
			t.Fatalf("mem decode mismatch")
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
		raw, _ := ev.Bytes()

		slow := NewSleepEvent(raw)
		fast := NewSleepEventFast(raw)
		defer slow.Recycle()
		defer fast.Recycle()
		if !slow.Equals(fast) {
			t.Fatalf("sleep decode mismatch")
		}
	})
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

func TestNewAcceptEventFastKernelLayout(t *testing.T) {
	raw := make([]byte, acceptEventSize)
	binary.LittleEndian.PutUint32(raw[0:4], uint32(EXIT_ACCEPT_EVENT))
	binary.LittleEndian.PutUint32(raw[4:8], uint32(SYS_EXIT_ACCEPT4))
	binary.LittleEndian.PutUint64(raw[8:16], 1)
	binary.LittleEndian.PutUint32(raw[16:20], 2)
	binary.LittleEndian.PutUint32(raw[20:24], 3)
	binary.LittleEndian.PutUint32(raw[24:28], uint32(10))
	binary.LittleEndian.PutUint64(raw[32:40], uint64(42))

	fast := NewAcceptEventFast(raw)
	if fast == nil {
		t.Fatalf("expected decoded accept event for kernel layout payload")
	}
	defer fast.Recycle()

	if fast.EventType != EXIT_ACCEPT_EVENT ||
		fast.TraceId != SYS_EXIT_ACCEPT4 ||
		fast.Time != 1 ||
		fast.Pid != 2 ||
		fast.Tid != 3 ||
		fast.Fd != 10 ||
		fast.Ret != 42 {
		t.Fatalf("unexpected accept decode: %#v", fast)
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
	raw := make([]byte, eventfdEventSize)
	binary.LittleEndian.PutUint32(raw[0:4], uint32(EXIT_EVENTFD_EVENT))
	binary.LittleEndian.PutUint32(raw[4:8], uint32(SYS_EXIT_EVENTFD2))
	binary.LittleEndian.PutUint64(raw[8:16], 1)
	binary.LittleEndian.PutUint32(raw[16:20], 2)
	binary.LittleEndian.PutUint32(raw[20:24], 3)
	binary.LittleEndian.PutUint32(raw[24:28], uint32(0x800))
	binary.LittleEndian.PutUint64(raw[32:40], uint64(42))

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
		fast.Ret != 42 {
		t.Fatalf("unexpected eventfd decode: %#v", fast)
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
		fast.TimeoutNs != 75_000_000 {
		t.Fatalf("unexpected poll decode: %#v", fast)
	}
}

func TestNewTwoFdEventFastKernelLayout(t *testing.T) {
	raw := make([]byte, twoFdEventSize)
	binary.LittleEndian.PutUint32(raw[0:4], uint32(ENTER_TWO_FD_EVENT))
	binary.LittleEndian.PutUint32(raw[4:8], uint32(SYS_ENTER_MOVE_MOUNT))
	binary.LittleEndian.PutUint64(raw[8:16], 1)
	binary.LittleEndian.PutUint32(raw[16:20], 2)
	binary.LittleEndian.PutUint32(raw[20:24], 3)
	binary.LittleEndian.PutUint32(raw[24:28], uint32(10))
	binary.LittleEndian.PutUint32(raw[28:32], uint32(11))
	binary.LittleEndian.PutUint64(raw[32:40], uint64(0x80))

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
		fast.Extra != 0x80 {
		t.Fatalf("unexpected two_fd decode: %#v", fast)
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

func TestFastDecodersReturnNilOnShortPayload(t *testing.T) {
	cases := []struct {
		name   string
		decode func([]byte) bool
	}{
		{name: "OpenEvent", decode: func(raw []byte) bool { return NewOpenEventFast(raw) == nil }},
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
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.decode([]byte{1}) {
				t.Fatalf("expected nil for short payload")
			}
		})
	}
}
