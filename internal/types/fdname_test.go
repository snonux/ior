package types

import (
	"encoding/binary"
	"strings"
	"testing"
)

// fd_name_event (task xz2) is the record close sends in place of its
// fd_event when the file it releases has a last path component: fd_event's
// 32 bytes, name_len at 32 and the name at 36, 104 bytes in all. It decodes
// into FdEvent. These tests pin the layout against the generated struct of
// the C record, what LeafName makes of the two fields, and that the name of
// one record never reaches the next user of the pooled struct.

// fdNamePayload builds the record of a close of descriptor 9, file identity
// testFileIdent, with the name bytes and the given name_len.
func fdNamePayload(t *testing.T, nameLen uint32, name string) []byte {
	t.Helper()
	ev := FdNameEvent{EventType: ENTER_FD_NAME_EVENT, TraceId: SYS_ENTER_CLOSE, Time: 77, Pid: 11, Tid: 12,
		Fd: 9, FileIdent: testFileIdent, NameLen: nameLen}
	copy(ev.Name[:], name)
	return rawBytes(t, &ev)
}

func TestFdNameEventDecodesIntoAnFdEvent(t *testing.T) {
	raw := fdNamePayload(t, 7, "foo.log")
	if len(raw) != fdNameEventSize || fdNameEventSize != 104 {
		t.Fatalf("record is %d bytes, decoder expects %d, the C layout is 104", len(raw), fdNameEventSize)
	}
	ev := NewFdNameEventFast(raw)
	if ev == nil {
		t.Fatal("payload did not decode")
	}
	defer ev.Recycle()
	want := FdEvent{EventType: ENTER_FD_NAME_EVENT, TraceId: SYS_ENTER_CLOSE, Time: 77, Pid: 11, Tid: 12,
		Fd: 9, FileIdent: testFileIdent, NameLen: 7}
	copy(want.Name[:], "foo.log")
	if *ev != want {
		t.Fatalf("decoded %+v\nwant    %+v", *ev, want)
	}
	if name, cut := ev.LeafName(); name != "foo.log" || cut {
		t.Fatalf("LeafName() = %q, cut %v; want foo.log, not cut", name, cut)
	}
}

func TestFdNameEventOfAnotherSizeDoesNotDecode(t *testing.T) {
	raw := fdNamePayload(t, 7, "foo.log")
	for _, size := range []int{fdEventSize, fdNameEventNameOffset, fdNameEventSize - 1} {
		if ev := NewFdNameEventFast(raw[:size]); ev != nil {
			t.Errorf("a %d-byte payload decoded: %+v", size, *ev)
		}
	}
	if ev := NewFdNameEventFast(append(raw, 0)); ev != nil {
		t.Errorf("a %d-byte payload decoded: %+v", len(raw)+1, *ev)
	}
	// The plain decoder must not take the wide record for an fd_event either.
	if ev := NewFdEventFast(raw); ev != nil {
		t.Errorf("NewFdEventFast decoded the 104-byte record: %+v", *ev)
	}
}

func TestLeafName(t *testing.T) {
	long := strings.Repeat("n", IOR_FD_NAME_LENGTH-1)
	tests := []struct {
		name     string
		nameLen  uint32
		bytes    string
		wantName string
		wantCut  bool
	}{
		{name: "whole name", nameLen: 3, bytes: "a.b", wantName: "a.b"},
		{name: "name that fills the field", nameLen: IOR_FD_NAME_LENGTH - 1, bytes: long, wantName: long},
		{name: "cut name", nameLen: 200, bytes: long, wantName: long, wantCut: true},
		{name: "stale bytes behind the terminator", nameLen: 3, bytes: "a.b\x00stale", wantName: "a.b"},
		{name: "shortest cut name", nameLen: IOR_FD_NAME_LENGTH, bytes: long, wantName: long, wantCut: true},
		// A close that raced a rename: the terminator comes before the length
		// the record reports. The name is whole, not cut.
		{name: "terminator before the reported length", nameLen: 40, bytes: "a.b\x00stale", wantName: "a.b"},
		{name: "unread name", nameLen: 0, bytes: "stale"},
		{name: "empty name", nameLen: 5, bytes: "\x00tale"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev := NewFdNameEventFast(fdNamePayload(t, tc.nameLen, tc.bytes))
			defer ev.Recycle()
			name, cut := ev.LeafName()
			if name != tc.wantName || cut != tc.wantCut {
				t.Fatalf("LeafName() = %q, cut %v; want %q, cut %v", name, cut, tc.wantName, tc.wantCut)
			}
		})
	}
}

// TestFdEventDecoderClearsAPooledName: a read decoded into the struct a
// named close used before must not report that close's file.
func TestFdEventDecoderClearsAPooledName(t *testing.T) {
	ev := decodeAfterIdent(t,
		func() *FdEvent { return NewFdNameEventFast(fdNamePayload(t, 7, "foo.log")) },
		func(ev *FdEvent) { ev.Recycle() },
		func() *FdEvent { return NewFdEventFast(fdPayload(fdEventSize, testFileIdent)) })
	defer ev.Recycle()
	if name, _ := ev.LeafName(); name != "" || ev.NameLen != 0 || ev.Name != [IOR_FD_NAME_LENGTH]byte{} {
		t.Fatalf("plain record decoded with name %q, NameLen %d, Name % x", name, ev.NameLen, ev.Name)
	}
}

// TestFdNameEventDecoderReplacesAPooledName: a shorter name does not keep the
// tail of a longer one in front of its terminator, and the wide-record fields
// of an earlier user are cleared.
func TestFdNameEventDecoderReplacesAPooledName(t *testing.T) {
	ev := decodeAfterIdent(t,
		func() *FdEvent {
			seed := NewFdNameEventFast(fdNamePayload(t, 11, "longer-name"))
			seed.Flags, seed.Size, seed.SizeValid, seed.SchemaVersion = 1, 2, 3, 4
			return seed
		},
		func(ev *FdEvent) { ev.Recycle() },
		func() *FdEvent { return NewFdNameEventFast(fdNamePayload(t, 1, "x")) })
	defer ev.Recycle()
	if name, cut := ev.LeafName(); name != "x" || cut {
		t.Fatalf("LeafName() = %q, cut %v; want x", name, cut)
	}
	if ev.Flags != 0 || ev.Size != 0 || ev.SizeValid != 0 || ev.SchemaVersion != 0 {
		t.Fatalf("wide fields survived the pool: %+v", *ev)
	}
}

func TestFdEventBytesWritesTheNameRecord(t *testing.T) {
	want := fdNamePayload(t, 7, "foo.log")
	ev := NewFdNameEventFast(want)
	defer ev.Recycle()
	got := rawBytes(t, ev)
	if string(got) != string(want) {
		t.Fatalf("Bytes() = % x\nwant      % x", got, want)
	}
	if binary.LittleEndian.Uint32(got[32:36]) != 7 || string(got[36:43]) != "foo.log" {
		t.Fatalf("name_len/name are not at offsets 32 and 36: % x", got)
	}
}
