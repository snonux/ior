package types

import "testing"

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
}
