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
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.decode([]byte{1}) {
				t.Fatalf("expected nil for short payload")
			}
		})
	}
}
