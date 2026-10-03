package types

import (
	"encoding/binary"
	"testing"
)

// The file identity word (task 603) sits in the last four bytes of the lean
// fd_event (28..32) and of ret_event (36..40), which were tail padding, and
// after the flags of dup3_event (32..36), which grew for it (task d23). These
// tests pin where the decoders read it, that the layouts without the word
// decode with 0 - never with the bytes another field owns at that offset or
// with what a pooled struct held before - and that Bytes writes it back.

const testFileIdent = 0xa1b2c3d4

// fdPayload builds an fd record of size bytes for descriptor 9 whose bytes
// 28..32, when it has them, are word.
func fdPayload(size int, word uint32) []byte {
	raw := make([]byte, size)
	fillCommonHeader(raw, ENTER_FD_EVENT, SYS_ENTER_READ)
	binary.LittleEndian.PutUint32(raw[24:28], 9)
	if size >= 32 {
		binary.LittleEndian.PutUint32(raw[28:32], word)
	}
	if size >= fdEventLegacyCompactSize {
		binary.LittleEndian.PutUint32(raw[size-4:size], FD_EVENT_SCHEMA_VERSION)
	}
	return raw
}

func TestFdEventCarriesTheFileIdentInItsLastWord(t *testing.T) {
	tests := []struct {
		name string
		size int
		want uint32
	}{
		{name: "lean kernel record", size: fdEventSize, want: testFileIdent},
		{name: "compact record has no such word", size: fdEventCompactSize, want: 0},
		// Offset 28 of the wide layouts is the size field or padding.
		{name: "wide compact record", size: fdEventLegacyCompactSize, want: 0},
		{name: "wide kernel record", size: fdEventLegacyKernelSize, want: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev := NewFdEventFast(fdPayload(tc.size, testFileIdent))
			if ev == nil {
				t.Fatal("payload did not decode")
			}
			defer ev.Recycle()
			if ev.FileIdent != tc.want || ev.Fd != 9 || ev.Flags != 0 {
				t.Fatalf("FileIdent=%#x Fd=%d Flags=%#x, want FileIdent=%#x Fd=9 Flags=0", ev.FileIdent, ev.Fd, ev.Flags, tc.want)
			}
		})
	}
}

// TestFdSizeEventHasNoFileIdent pins the other owner of offset 28: an
// fd_size_event carries the recv flags there, and they must not be taken for
// an identity.
func TestFdSizeEventHasNoFileIdent(t *testing.T) {
	raw := make([]byte, fdSizeEventSize)
	fillCommonHeader(raw, ENTER_FD_SIZE_EVENT, SYS_ENTER_RECVMSG)
	binary.LittleEndian.PutUint32(raw[28:32], testFileIdent)
	binary.LittleEndian.PutUint32(raw[44:48], FD_SIZE_EVENT_SCHEMA_VERSION)
	ev := NewFdSizeEventFast(raw)
	if ev == nil {
		t.Fatal("payload did not decode")
	}
	defer ev.Recycle()
	if ev.Flags != testFileIdent {
		t.Fatalf("Flags = %#x, want the word at offset 28", ev.Flags)
	}
}

// decodeAfterIdent decodes a record that carries an identity, recycles it and
// decodes raw with decode until the pool hands the same struct back, so a
// decoder that leaves the field alone is caught with what the struct held.
func decodeAfterIdent[T any](t *testing.T, seed func() *T, recycle func(*T), decode func() *T) *T {
	t.Helper()
	for range 64 {
		first := seed()
		recycle(first)
		second := decode()
		if second == first {
			return second
		}
		recycle(second)
	}
	t.Skip("the pool never handed the seeded struct back")
	return nil
}

func TestFdEventDecoderClearsAPooledFileIdent(t *testing.T) {
	ev := decodeAfterIdent(t,
		func() *FdEvent { return NewFdEventFast(fdPayload(fdEventSize, testFileIdent)) },
		func(ev *FdEvent) { ev.Recycle() },
		func() *FdEvent { return NewFdEventFast(fdPayload(fdEventCompactSize, 0)) })
	defer ev.Recycle()
	if ev.FileIdent != 0 {
		t.Fatalf("FileIdent = %#x after a record without the word, want 0", ev.FileIdent)
	}
}

func TestFdEventBytesWritesTheFileIdent(t *testing.T) {
	raw := rawBytes(t, &FdEvent{EventType: ENTER_FD_EVENT, TraceId: SYS_ENTER_READ, Fd: 9, FileIdent: testFileIdent})
	if len(raw) != fdEventSize || binary.LittleEndian.Uint32(raw[28:32]) != testFileIdent {
		t.Fatalf("lean record = % x, want 32 bytes ending in the identity", raw)
	}
	// The wide record has the flags word there, whatever FileIdent holds.
	wide := rawBytes(t, &FdEvent{EventType: ENTER_FD_SIZE_EVENT, Fd: 9, FileIdent: testFileIdent, Flags: 0x22})
	if len(wide) != fdSizeEventSize || binary.LittleEndian.Uint32(wide[28:32]) != 0x22 {
		t.Fatalf("wide record = % x, want 48 bytes with the flags at offset 28", wide)
	}
}

// retPayload builds a ret record of size bytes whose bytes 36..40, when it
// has them, are word.
func retPayload(size int, word uint32) []byte {
	raw := make([]byte, size)
	fillCommonHeader(raw, EXIT_RET_EVENT, SYS_EXIT_OPENAT)
	binary.LittleEndian.PutUint64(raw[16:24], 5)
	binary.LittleEndian.PutUint32(raw[24:28], 22)
	binary.LittleEndian.PutUint32(raw[28:32], 33)
	binary.LittleEndian.PutUint32(raw[32:36], UNCLASSIFIED)
	if size >= retEventSize {
		binary.LittleEndian.PutUint32(raw[36:40], word)
	}
	return raw
}

func TestRetEventCarriesTheFileIdentInItsLastWord(t *testing.T) {
	ev := NewRetEventFast(retPayload(retEventSize, testFileIdent))
	if ev == nil {
		t.Fatal("kernel payload did not decode")
	}
	defer ev.Recycle()
	if ev.FileIdent != testFileIdent || ev.Ret != 5 || ev.Pid != 22 || ev.Tid != 33 || ev.RetType != UNCLASSIFIED {
		t.Fatalf("decoded %+v, want the identity and the fields before it", ev)
	}
	raw := rawBytes(t, ev)
	if len(raw) != retEventSize || binary.LittleEndian.Uint32(raw[36:40]) != testFileIdent {
		t.Fatalf("Bytes = % x, want 40 bytes ending in the identity", raw)
	}
}

func TestRetEventWithoutTheWordDecodesWithNoFileIdent(t *testing.T) {
	ev := decodeAfterIdent(t,
		func() *RetEvent { return NewRetEventFast(retPayload(retEventSize, testFileIdent)) },
		func(ev *RetEvent) { ev.Recycle() },
		func() *RetEvent { return NewRetEventFast(retPayload(retEventSizeV1, 0)) })
	defer ev.Recycle()
	if ev.FileIdent != 0 || ev.Ret != 5 {
		t.Fatalf("FileIdent=%#x Ret=%d for a 36-byte record, want 0 and 5", ev.FileIdent, ev.Ret)
	}
}

// dup3Payload builds a dup3 record of size bytes for old descriptor 9 with
// flags 0x80000 whose bytes 32..36, when it has them, are word.
func dup3Payload(size int, word uint32) []byte {
	raw := make([]byte, size)
	fillCommonHeader(raw, ENTER_DUP3_EVENT, SYS_ENTER_DUP3)
	binary.LittleEndian.PutUint32(raw[24:28], 9)
	binary.LittleEndian.PutUint32(raw[28:32], 0x80000)
	if size >= dup3EventCompactSize {
		binary.LittleEndian.PutUint32(raw[32:36], word)
	}
	return raw
}

// TestDup3EventCarriesTheFileIdentAfterTheFlags pins the word dup3_event
// grew for the old descriptor (task d23): read at 32..36 from the kernel's
// padded record and from binary.Write's compact one, 0 for the 32-byte record
// of an object built before it.
func TestDup3EventCarriesTheFileIdentAfterTheFlags(t *testing.T) {
	tests := []struct {
		name string
		size int
		want uint32
	}{
		{name: "kernel record", size: dup3EventSize, want: testFileIdent},
		{name: "compact record", size: dup3EventCompactSize, want: testFileIdent},
		{name: "legacy record has no such word", size: dup3EventLegacySize, want: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev := NewDup3EventFast(dup3Payload(tc.size, testFileIdent))
			if ev == nil {
				t.Fatal("payload did not decode")
			}
			defer ev.Recycle()
			if ev.FileIdent != tc.want || ev.Fd != 9 || ev.Flags != 0x80000 {
				t.Fatalf("FileIdent=%#x Fd=%d Flags=%#x, want FileIdent=%#x Fd=9 Flags=0x80000",
					ev.FileIdent, ev.Fd, ev.Flags, tc.want)
			}
		})
	}
}

// TestDup3EventRejectsSizesBetweenTheLayouts keeps the decoder from reading
// a truncated record as one of the known layouts.
func TestDup3EventRejectsSizesBetweenTheLayouts(t *testing.T) {
	for _, size := range []int{28, 31, 33, 35, 37, 39} {
		if ev := NewDup3EventFast(dup3Payload(dup3EventSize, testFileIdent)[:size]); ev != nil {
			t.Errorf("decoded a %d-byte payload: %v", size, ev)
		}
	}
}

func TestDup3EventDecoderClearsAPooledFileIdent(t *testing.T) {
	ev := decodeAfterIdent(t,
		func() *Dup3Event { return NewDup3EventFast(dup3Payload(dup3EventSize, testFileIdent)) },
		func(ev *Dup3Event) { ev.Recycle() },
		func() *Dup3Event { return NewDup3EventFast(dup3Payload(dup3EventLegacySize, 0)) })
	defer ev.Recycle()
	if ev.FileIdent != 0 {
		t.Fatalf("FileIdent = %#x after a legacy dup3 record, want 0", ev.FileIdent)
	}
}

func TestDup3EventBytesWritesTheFileIdent(t *testing.T) {
	raw := rawBytes(t, &Dup3Event{EventType: ENTER_DUP3_EVENT, TraceId: SYS_ENTER_DUP3, Fd: 9, FileIdent: testFileIdent})
	if len(raw) != dup3EventCompactSize || binary.LittleEndian.Uint32(raw[32:36]) != testFileIdent {
		t.Fatalf("record = % x, want 36 bytes ending in the identity", raw)
	}
}
