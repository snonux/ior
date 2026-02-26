package eventstream

import (
	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/types"
	"testing"
)

func TestNewStreamEventPopulatesFields(t *testing.T) {
	enter := &types.OpenEvent{TraceId: types.SYS_ENTER_OPENAT, Time: 1234, Pid: 42, Tid: 84}
	exit := &types.RetEvent{TraceId: types.SYS_EXIT_OPENAT, Time: 1300, Ret: -2, Pid: 42, Tid: 84}
	pair := event.NewPair(enter)
	pair.ExitEv = exit
	pair.File = file.NewFd(7, "/tmp/test.txt", 0)
	pair.Comm = "cat"
	pair.Duration = 66
	pair.DurationToPrev = 19
	pair.Bytes = 512

	got := NewStreamEvent(9, pair)

	if got.Seq != 9 {
		t.Fatalf("Seq = %d, want 9", got.Seq)
	}
	if got.TimeNs != 1234 {
		t.Fatalf("TimeNs = %d, want 1234", got.TimeNs)
	}
	if got.Syscall != "openat" {
		t.Fatalf("Syscall = %q, want openat", got.Syscall)
	}
	if got.Comm != "cat" {
		t.Fatalf("Comm = %q, want cat", got.Comm)
	}
	if got.PID != 42 || got.TID != 84 {
		t.Fatalf("PID/TID = %d/%d, want 42/84", got.PID, got.TID)
	}
	if got.FileName != "/tmp/test.txt" {
		t.Fatalf("FileName = %q, want /tmp/test.txt", got.FileName)
	}
	if got.DurationNs != 66 || got.GapNs != 19 || got.Bytes != 512 {
		t.Fatalf("DurationNs/GapNs/Bytes = %d/%d/%d, want 66/19/512", got.DurationNs, got.GapNs, got.Bytes)
	}
	if got.FD != 7 {
		t.Fatalf("FD = %d, want 7", got.FD)
	}
	if got.RetVal != -2 {
		t.Fatalf("RetVal = %d, want -2", got.RetVal)
	}
	if !got.IsError {
		t.Fatalf("IsError = false, want true")
	}
}

func TestNewStreamEventCopiesBeforeRecycle(t *testing.T) {
	enter := &types.OpenEvent{TraceId: types.SYS_ENTER_READ, Time: 2000, Pid: 1, Tid: 2}
	exit := &types.RetEvent{TraceId: types.SYS_EXIT_READ, Time: 2010, Ret: 8, Pid: 1, Tid: 2}
	pair := event.NewPair(enter)
	pair.ExitEv = exit
	pair.File = file.NewFd(3, "/tmp/in.txt", 0)
	pair.Comm = "reader"
	pair.Duration = 10
	pair.DurationToPrev = 5
	pair.Bytes = 8

	got := NewStreamEvent(1, pair)
	pair.Recycle()

	if got.Syscall != "read" || got.Comm != "reader" || got.FileName != "/tmp/in.txt" {
		t.Fatalf("event changed after recycle: %+v", got)
	}
	if got.RetVal != 8 || got.IsError {
		t.Fatalf("RetVal/IsError = %d/%v, want 8/false", got.RetVal, got.IsError)
	}
	if got.FD != 3 {
		t.Fatalf("FD = %d, want 3", got.FD)
	}
}

func TestNewStreamEventWithoutRetEvent(t *testing.T) {
	enter := &types.NullEvent{TraceId: types.SYS_ENTER_SYNC, Time: 10, Pid: 1, Tid: 1}
	exit := &types.NullEvent{TraceId: types.SYS_EXIT_SYNC, Time: 11, Pid: 1, Tid: 1}
	pair := event.NewPair(enter)
	pair.ExitEv = exit

	got := NewStreamEvent(3, pair)
	if got.RetVal != 0 {
		t.Fatalf("RetVal = %d, want 0", got.RetVal)
	}
	if got.IsError {
		t.Fatalf("IsError = true, want false")
	}
	if got.FD != UnknownFD {
		t.Fatalf("FD = %d, want %d", got.FD, UnknownFD)
	}
}
