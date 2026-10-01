package internal

import (
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"syscall"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
)

// Task us2: records that are still in the kernel's BPF ring buffer when the
// trace stops. The libbpfgo poller feeds rawCh ahead of the decoder and blocks
// when it is full, so a lagging consumer leaves records in the kernel ring;
// RingBuffer.Stop abandons them. They are in neither "tracepoints" (never
// decoded) nor "ring buffer drops" (the kernel did not drop them), nor in
// "discarded at stop" (that counts only what had reached rawCh), so "drops: 0"
// overstated completeness. This file reads how much the consumer left behind
// straight from the ring's own bookkeeping, so the end-of-run statistics can
// say so.

// ringbufUnread is what the kernel ring buffer still holds, as seen at one
// moment: the committed records (a discarded record counts as space only) and
// the bytes they occupy, headers and padding included.
type ringbufUnread struct {
	records uint64
	bytes   uint64
}

// ringbufUnreadSource reads the unconsumed part of the event ring buffer. It
// is implemented by kernelRingUnread over the live map and stubbed in tests.
type ringbufUnreadSource interface {
	Unread() (ringbufUnread, error)
}

// The kernel's ring buffer record header (include/linux/bpf_ringbuf / kernel/
// bpf/ringbuf.c): the first word of each record carries its length and two
// state bits, the second the page offset the record was reserved at. Records
// are 8-byte aligned and include the 8-byte header.
const (
	ringbufBusyBit    = 1 << 31 // reserved, not yet committed or discarded
	ringbufDiscardBit = 1 << 30 // committed as discarded: space, no record
	ringbufHdrSize    = 8
)

// countUnreadRingRecords walks the records between consumerPos and producerPos
// the way libbpf's consumer does. data is the ring's data area as mapped by
// userspace: the ring (size, a power of two) mapped twice back to back, so a
// header never straddles the wrap. It stops at the first record that is still
// busy (reserved but not committed): the consumer cannot get past it either, so
// what follows is not "left behind" by a lagging consumer but not readable yet.
func countUnreadRingRecords(consumerPos, producerPos uint64, data []byte) ringbufUnread {
	mask := uint64(len(data)/2) - 1
	var unread ringbufUnread
	for pos := consumerPos; pos < producerPos; {
		hdr := atomic.LoadUint32((*uint32)(unsafe.Pointer(&data[pos&mask])))
		if hdr&ringbufBusyBit != 0 {
			break
		}
		length := uint64(hdr &^ (ringbufBusyBit | ringbufDiscardBit))
		span := (length + ringbufHdrSize + 7) &^ 7
		if hdr&ringbufDiscardBit == 0 {
			unread.records++
		}
		unread.bytes += span
		pos += span
	}
	return unread
}

// kernelRingUnread maps the event ring buffer read-only, reads its two
// positions and counts what lies between them. It maps on every call and
// unmaps again: it runs once, at stop, while the BPF module is still open (the
// caller's teardown order), and holding no mapping keeps Close of the module
// free of any ordering rule.
type kernelRingUnread struct {
	fd   int
	size int // ring size in bytes: the map's max_entries
}

// newKernelRingUnread binds to the module's event_map ring buffer.
func newKernelRingUnread(module *bpf.Module) (*kernelRingUnread, error) {
	if module == nil {
		return nil, errors.New("nil bpf module")
	}
	eventMap, err := module.GetMap("event_map")
	if err != nil {
		return nil, fmt.Errorf("get event_map: %w", err)
	}
	if eventMap.Type() != bpf.MapTypeRingbuf {
		return nil, fmt.Errorf("event_map is %v, not a ring buffer", eventMap.Type())
	}
	size := int(eventMap.MaxEntries())
	if size <= 0 || size&(size-1) != 0 {
		return nil, fmt.Errorf("event_map size %d is not a power of two", size)
	}
	return &kernelRingUnread{fd: eventMap.FileDescriptor(), size: size}, nil
}

// Unread reads the consumer and producer positions and counts the committed
// records between them. libbpf maps the consumer page at offset 0 and the
// producer page plus the doubled data area from offset one page; read-only
// mappings of both are allowed.
func (r *kernelRingUnread) Unread() (ringbufUnread, error) {
	if r == nil {
		return ringbufUnread{}, nil
	}
	page := os.Getpagesize()
	consumer, err := syscall.Mmap(r.fd, 0, page, syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		return ringbufUnread{}, fmt.Errorf("map the ring buffer consumer page: %w", err)
	}
	defer syscall.Munmap(consumer) //nolint:errcheck // nothing to do about a failed unmap of a read-only view
	producer, err := syscall.Mmap(r.fd, int64(page), page+2*r.size, syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		return ringbufUnread{}, fmt.Errorf("map the ring buffer producer page and data: %w", err)
	}
	defer syscall.Munmap(producer) //nolint:errcheck // as above
	consumerPos := atomic.LoadUint64((*uint64)(unsafe.Pointer(&consumer[0])))
	producerPos := atomic.LoadUint64((*uint64)(unsafe.Pointer(&producer[0])))
	return countUnreadRingRecords(consumerPos, producerPos, producer[page:]), nil
}

// attachRingbufUnreadReader wires the unread-ring reader into the event loop.
// Like the drop counter it is deliberately non-fatal: without it only the
// end-of-run line about records left in the kernel ring is missing.
func attachRingbufUnreadReader(el *eventLoop, bpfModule *bpf.Module, warnSetup func(...any)) {
	reader, err := newKernelRingUnread(bpfModule)
	if err != nil {
		warnSetup("Ring-buffer backlog reader unavailable (records left in the kernel ring at stop will not be reported):", err)
		return
	}
	el.ringUnread = reader
}
