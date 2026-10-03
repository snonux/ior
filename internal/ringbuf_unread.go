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
// trace stops (read before the stop-time drain, see backlogAtStop). The
// libbpfgo poller feeds rawCh ahead of the decoder and blocks when it is
// full, so a lagging consumer leaves records in the kernel ring;
// RingBuffer.Stop abandons them. They are in neither "tracepoints" (never
// decoded) nor "ring buffer drops" (the kernel did not drop them), nor in
// "discarded at stop" (that counts only what was in rawCh at the stop), so
// "drops: 0" overstated completeness. This file reads how much the consumer
// left behind straight from the ring's own bookkeeping, so the end-of-run
// statistics can say so.

// ringbufUnread is what the kernel ring buffer still holds, as seen at one
// moment: the committed records (a discarded record counts as space only) and
// the bytes they occupy, headers and padding included. busy says the count
// ended at a record that was still being written, before the producer
// position: records committed behind it by other CPUs are not in the count.
type ringbufUnread struct {
	records uint64
	bytes   uint64
	busy    bool
}

// ringbufPositions are the ring's two positions as seen at one moment, in
// bytes since the ring was created: the consumer has read everything before
// consumer, the kernel has reserved everything before producer.
type ringbufPositions struct {
	consumer, producer uint64
}

// empty reports that the consumer has read all the kernel reserved.
func (p ringbufPositions) empty() bool {
	return p.consumer >= p.producer
}

// ringbufUnreadSource reads the unconsumed part of the event ring buffer. It
// is implemented by kernelRingUnread over the live map and stubbed in tests.
// Positions is the cheap look (two words, whatever the ring holds); Unread
// counts the records, which costs a walk over all of them.
type ringbufUnreadSource interface {
	Positions() (ringbufPositions, error)
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
// busy (reserved but not committed) and says so: the consumer cannot get past
// it either, but what other CPUs committed behind it becomes readable the
// moment it is committed, so the caller decides whether to look again
// (countRingAtStop).
func countUnreadRingRecords(consumerPos, producerPos uint64, data []byte) ringbufUnread {
	mask := uint64(len(data)/2) - 1
	var unread ringbufUnread
	for pos := consumerPos; pos < producerPos; {
		hdr := atomic.LoadUint32((*uint32)(unsafe.Pointer(&data[pos&mask])))
		if hdr&ringbufBusyBit != 0 {
			unread.busy = true
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

// kernelRingUnread maps the event ring buffer read-only and reads its two
// positions (Positions) or counts what lies between them (Unread). It maps on
// every call and unmaps again: it is used a few times, at stop, while the BPF
// module is still open (the caller's teardown order), and holding no mapping
// keeps Close of the module free of any ordering rule.
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

// ringMapping is one read-only view of the ring buffer map: the consumer
// page and, behind the producer page, as much of the data area as was asked
// for. libbpf maps the consumer page at offset 0 and the producer page plus
// the doubled data area from offset one page; read-only mappings of both are
// allowed.
type ringMapping struct {
	consumer, producer []byte
	page               int
}

// mapRing maps the two position pages and dataLen bytes of the data area (0:
// none of it; 2*size: all of it, as Unread needs).
func (r *kernelRingUnread) mapRing(dataLen int) (*ringMapping, error) {
	page := os.Getpagesize()
	consumer, err := syscall.Mmap(r.fd, 0, page, syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("map the ring buffer consumer page: %w", err)
	}
	producer, err := syscall.Mmap(r.fd, int64(page), page+dataLen, syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		_ = syscall.Munmap(consumer) // as in unmap
		return nil, fmt.Errorf("map the ring buffer producer page and data: %w", err)
	}
	return &ringMapping{consumer: consumer, producer: producer, page: page}, nil
}

// unmap drops the view. There is nothing to do about a failed unmap of a
// read-only view.
func (m *ringMapping) unmap() {
	_ = syscall.Munmap(m.consumer)
	_ = syscall.Munmap(m.producer)
}

// positions reads the two positions, the consumer's first: an empty answer
// then means every record produced up to that read had been consumed (the
// producer position only grows), which backlogAtStop relies on.
func (m *ringMapping) positions() ringbufPositions {
	consumer := atomic.LoadUint64((*uint64)(unsafe.Pointer(&m.consumer[0])))
	producer := atomic.LoadUint64((*uint64)(unsafe.Pointer(&m.producer[0])))
	return ringbufPositions{consumer: consumer, producer: producer}
}

// Positions reads the consumer and producer positions and nothing else: two
// one-page mappings, however much the ring holds. backlogAtStop waits for the
// poller on it.
func (r *kernelRingUnread) Positions() (ringbufPositions, error) {
	if r == nil {
		return ringbufPositions{}, nil
	}
	m, err := r.mapRing(0)
	if err != nil {
		return ringbufPositions{}, err
	}
	defer m.unmap()
	return m.positions(), nil
}

// Unread reads the two positions and counts the committed records between
// them. It maps the whole doubled data area and reads the header of every
// unread record, so its cost grows with what the ring holds: about 30 ms per
// million records, most of it the page faults of the fresh mapping (measured
// for the whole snapshot of a lagging stop: 4 to 6 ms with 0.1 to 0.25
// million records left in a 16 MiB ring, 31 to 40 ms with 1.2 million in a
// 256 MiB one). That is why the stop calls it once, and only for a ring that
// is not empty.
func (r *kernelRingUnread) Unread() (ringbufUnread, error) {
	if r == nil {
		return ringbufUnread{}, nil
	}
	m, err := r.mapRing(2 * r.size)
	if err != nil {
		return ringbufUnread{}, err
	}
	defer m.unmap()
	positions := m.positions()
	return countUnreadRingRecords(positions.consumer, positions.producer, m.producer[m.page:]), nil
}

// attachRingbufUnreadReader wires the unread-ring reader into the event loop.
// Like the drop counter it is deliberately non-fatal: without it only the
// end-of-run line about records left in the kernel ring is missing.
func attachRingbufUnreadReader(el *eventLoop, bpfModule *bpf.Module, warnSetup func(...any)) {
	if bpfModule == nil {
		return // no module: attachRingbufDropCounter already warned about it
	}
	reader, err := newKernelRingUnread(bpfModule)
	if err != nil {
		warnSetup("Ring-buffer backlog reader unavailable (records left in the kernel ring at stop will not be reported):", err)
		return
	}
	el.ringUnread = reader
}
