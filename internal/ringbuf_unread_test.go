package internal

import (
	"errors"
	"strings"
	"testing"
	"unsafe"
)

// ringBytes returns a doubled ring data area of 2*size bytes, 8-byte aligned
// as the kernel's page mapping is (the atomic header loads need it).
func ringBytes(size int) []byte {
	words := make([]uint64, 2*size/8)
	return unsafe.Slice((*byte)(unsafe.Pointer(&words[0])), 2*size)
}

// putRecord writes a record header for a payload of length at pos in both
// halves of the doubled mapping (as the hardware mirror does) and returns the
// position after it.
func putRecord(data []byte, pos uint64, length uint32, state uint32) uint64 {
	size := uint64(len(data) / 2)
	hdr := length | state
	for _, off := range []uint64{pos & (size - 1), pos&(size-1) + size} {
		*(*uint32)(unsafe.Pointer(&data[off])) = hdr
	}
	return pos + uint64((length+ringbufHdrSize+7)&^7)
}

func TestCountUnreadRingRecordsWalksCommittedRecords(t *testing.T) {
	data := ringBytes(4096)
	pos := uint64(0)
	pos = putRecord(data, pos, 56, 0)                 // 64 bytes with its header
	pos = putRecord(data, pos, 13, 0)                 // 21 -> 24 bytes
	pos = putRecord(data, pos, 40, ringbufDiscardBit) // space, not a record
	pos = putRecord(data, pos, 8, 0)                  // 16 bytes
	got := countUnreadRingRecords(0, pos, data)
	if got.records != 3 || got.bytes != 64+24+48+16 {
		t.Fatalf("unread = %+v, want 3 records in 152 bytes", got)
	}
}

func TestCountUnreadRingRecordsStartsAtTheConsumerPosition(t *testing.T) {
	data := ringBytes(4096)
	first := putRecord(data, 0, 56, 0)
	end := putRecord(data, first, 56, 0)
	if got := countUnreadRingRecords(first, end, data); got.records != 1 || got.bytes != 64 {
		t.Fatalf("unread after consuming one = %+v, want 1 record in 64 bytes", got)
	}
	if got := countUnreadRingRecords(end, end, data); got != (ringbufUnread{}) {
		t.Fatalf("a caught-up consumer has %+v unread, want nothing", got)
	}
}

func TestCountUnreadRingRecordsStopsAtABusyRecord(t *testing.T) {
	data := ringBytes(4096)
	pos := putRecord(data, 0, 56, 0)
	pos = putRecord(data, pos, 56, ringbufBusyBit) // reserved, not committed
	end := putRecord(data, pos, 56, 0)             // behind the busy one: not readable yet
	if got := countUnreadRingRecords(0, end, data); got.records != 1 {
		t.Fatalf("unread = %+v, want only the record before the busy one", got)
	}
}

func TestCountUnreadRingRecordsFollowsTheWrap(t *testing.T) {
	const size = 4096
	data := ringBytes(size)
	start := uint64(3 * size) // positions grow monotonically; the ring is addressed modulo size
	pos := start + size - 64
	pos = putRecord(data, pos, 56, 0)  // last slot before the wrap
	end := putRecord(data, pos, 56, 0) // first slot after it
	if got := countUnreadRingRecords(start+size-64, end, data); got.records != 2 || got.bytes != 128 {
		t.Fatalf("unread across the wrap = %+v, want 2 records in 128 bytes", got)
	}
}

type fakeRingUnread struct {
	unread ringbufUnread
	err    error
}

func (f fakeRingUnread) Unread() (ringbufUnread, error) { return f.unread, f.err }

// TestStopReportsRecordsLeftInTheKernelRing is the task us2 accounting: a
// consumer that lagged leaves committed records in the kernel ring, and the
// stop reports them in the statistics and as a warning instead of letting
// "ring buffer drops: 0" read as complete.
func TestStopReportsRecordsLeftInTheKernelRing(t *testing.T) {
	el := newPairEvictionEventLoop(t)
	var warnings []string
	el.SetWarningCallback(func(msg string) { warnings = append(warnings, msg) })
	el.ringUnread = fakeRingUnread{unread: ringbufUnread{records: 18000, bytes: 1 << 20}}

	el.countKernelRingLeftAtStop()

	if el.numLeftInKernelRing != 18000 {
		t.Fatalf("numLeftInKernelRing = %d, want 18000", el.numLeftInKernelRing)
	}
	if line := el.leftInKernelRingStatLine(); !strings.Contains(line, "left in the kernel ring buffer at stop: 18000") {
		t.Fatalf("stat line = %q", line)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "18000 records were still in the kernel ring buffer") {
		t.Fatalf("warnings = %q", warnings)
	}
}

func TestStopSaysNothingWhenTheConsumerKeptUp(t *testing.T) {
	el := newPairEvictionEventLoop(t)
	var warnings []string
	el.SetWarningCallback(func(msg string) { warnings = append(warnings, msg) })
	el.ringUnread = fakeRingUnread{}
	el.countKernelRingLeftAtStop()
	if el.leftInKernelRingStatLine() != "" || len(warnings) != 0 {
		t.Fatalf("empty ring: line %q, warnings %q; want neither", el.leftInKernelRingStatLine(), warnings)
	}
	(&eventLoop{}).countKernelRingLeftAtStop() // no reader: nothing to do, no panic
}

func TestStopWarnsWhenTheRingBacklogCannotBeRead(t *testing.T) {
	el := newPairEvictionEventLoop(t)
	var warnings []string
	el.SetWarningCallback(func(msg string) { warnings = append(warnings, msg) })
	el.ringUnread = fakeRingUnread{err: errors.New("mmap failed")}
	el.countKernelRingLeftAtStop()
	if len(warnings) != 1 || !strings.Contains(warnings[0], "could not read the kernel ring buffer backlog") || el.numLeftInKernelRing != 0 {
		t.Fatalf("warnings = %q, left = %d", warnings, el.numLeftInKernelRing)
	}
}
