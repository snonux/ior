package main

import (
	"fmt"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// io_uring ABI of the submission path (<linux/io_uring.h>): two request
// opcodes, the enter flag that waits for completions and the mmap offsets of
// the three ring mappings.
const (
	ioringOpOpenat       = 18 // IORING_OP_OPENAT
	ioringOpClose        = 19 // IORING_OP_CLOSE
	ioringEnterGetevents = 1  // IORING_ENTER_GETEVENTS
	ioringOffSqRing      = 0
	ioringOffCqRing      = 0x8000000
	ioringOffSqes        = 0x10000000
)

// ioUringSqOffsets and ioUringCqOffsets are struct io_sqring_offsets and
// struct io_cqring_offsets: where the ring words sit inside the mappings.
type ioUringSqOffsets struct {
	head, tail, ringMask, ringEntries, flags, dropped, array, resv1 uint32
	userAddr                                                        uint64
}

type ioUringCqOffsets struct {
	head, tail, ringMask, ringEntries, overflow, cqes, flags, resv1 uint32
	userAddr                                                        uint64
}

// ioUringParamsLayout is struct io_uring_params (ioUringParamsSize bytes).
type ioUringParamsLayout struct {
	sqEntries, cqEntries, flags, sqThreadCPU, sqThreadIdle, features, wqFd uint32
	resv                                                                   [3]uint32
	sqOff                                                                  ioUringSqOffsets
	cqOff                                                                  ioUringCqOffsets
}

// ioUringSqe is the part of struct io_uring_sqe (64 bytes) the two opcodes
// use: for OPENAT fd is the directory, addr the pathname, length the mode and
// opFlags the open flags; for CLOSE only fd is set.
type ioUringSqe struct {
	opcode, flags uint8
	ioprio        uint16
	fd            int32
	off, addr     uint64
	length        uint32
	opFlags       uint32
	userData      uint64
	pad           [3]uint64
}

// ioUringCqe is struct io_uring_cqe; res is the request's result, the value
// the equivalent syscall would have returned.
type ioUringCqe struct {
	userData uint64
	res      int32
	flags    uint32
}

// miniRing is an io_uring instance with its three mappings, enough to submit
// one request at a time and wait for its completion.
type miniRing struct {
	fd           int
	params       ioUringParamsLayout
	sq, cq, sqes []byte
}

// newMiniRing creates a ring of entries submission slots and maps it.
func newMiniRing(entries uint32) (*miniRing, error) {
	r := &miniRing{}
	fd, _, errno := syscall.Syscall(sysIoUringSetup, uintptr(entries), uintptr(unsafe.Pointer(&r.params)), 0)
	if errno != 0 {
		return nil, fmt.Errorf("io_uring_setup: %w", errno)
	}
	r.fd = int(fd)
	p := &r.params
	maps := []struct {
		dst    *[]byte
		offset int64
		size   uint32
	}{
		{&r.sq, ioringOffSqRing, p.sqOff.array + p.sqEntries*4},
		{&r.cq, ioringOffCqRing, p.cqOff.cqes + p.cqEntries*uint32(unsafe.Sizeof(ioUringCqe{}))},
		{&r.sqes, ioringOffSqes, p.sqEntries * uint32(unsafe.Sizeof(ioUringSqe{}))},
	}
	for _, m := range maps {
		mapped, err := syscall.Mmap(r.fd, m.offset, int(m.size), syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
		if err != nil {
			r.close()
			return nil, fmt.Errorf("mmap io_uring ring at %#x: %w", m.offset, err)
		}
		*m.dst = mapped
	}
	return r, nil
}

// close unmaps and closes the ring.
func (r *miniRing) close() {
	for _, mapped := range [][]byte{r.sq, r.cq, r.sqes} {
		if mapped != nil {
			syscall.Munmap(mapped)
		}
	}
	syscall.Close(r.fd)
}

// ringWord returns the 32-bit word at offset off of a ring mapping.
func ringWord(mapped []byte, off uint32) *uint32 {
	return (*uint32)(unsafe.Pointer(&mapped[off]))
}

// submit queues sqe, enters the kernel for it and waits for its completion,
// whose result it returns. The ring never holds more than this one request.
func (r *miniRing) submit(sqe ioUringSqe) (int32, error) {
	sqOff, cqOff := r.params.sqOff, r.params.cqOff
	tail := ringWord(r.sq, sqOff.tail)
	index := *tail & *ringWord(r.sq, sqOff.ringMask)
	*(*ioUringSqe)(unsafe.Pointer(&r.sqes[uintptr(index)*unsafe.Sizeof(sqe)])) = sqe
	*ringWord(r.sq, sqOff.array+index*4) = index
	atomic.StoreUint32(tail, *tail+1)

	_, _, errno := syscall.Syscall6(sysIoUringEnter, uintptr(r.fd), 1, 1, ioringEnterGetevents, 0, 0)
	if errno != 0 {
		return 0, fmt.Errorf("io_uring_enter: %w", errno)
	}
	head := ringWord(r.cq, cqOff.head)
	if *head == atomic.LoadUint32(ringWord(r.cq, cqOff.tail)) {
		return 0, fmt.Errorf("io_uring_enter returned without a completion")
	}
	slot := *head & *ringWord(r.cq, cqOff.ringMask)
	cqe := *(*ioUringCqe)(unsafe.Pointer(&r.cq[cqOff.cqes+slot*uint32(unsafe.Sizeof(ioUringCqe{}))]))
	atomic.StoreUint32(head, *head+1)
	return cqe.res, nil
}

// File names and read sizes of iouring-reopen. The integration test tells the
// reads before the reopen from those after it by their size.
const (
	iouringReopenFirst      = "iouring-reopen-first.txt"
	iouringReopenSecond     = "iouring-reopen-second.txt"
	iouringReopenFirstRead  = 3
	iouringReopenSecondRead = 5
)

// iouringReopenSettle is how long iouring-reopen keeps the rebound descriptor
// open after reading it. ior learns from the reads' records that the number
// names another file than the one it traced the open of, and can then only
// ask procfs for the name - when it gets to the rows, which lags the
// syscalls. The pause lets that happen while the second file is still there;
// without it the number is already free or reused (the scenario's own cleanup
// opens the directory on it) and the rows are, correctly, left unnamed.
const iouringReopenSettle = 500 * time.Millisecond

// iouringReopen rebinds a descriptor without any syscall the tracer could
// attribute to it (task 603): it opens the first file with openat(2) and
// reads it, then closes that descriptor with IORING_OP_CLOSE and opens the
// second file with IORING_OP_OPENAT, which lands on the number just freed,
// and reads again. ior sees an openat of the first file and reads on one
// number throughout; only the identity of the file behind the number says
// that the later reads, and the final close(2), are on the second file. The
// close waits iouringReopenSettle, so ior can still look the second file up.
func iouringReopen() error {
	dir, cleanup, err := makeTempDir("iouring-reopen")
	if err != nil {
		return err
	}
	defer cleanup()
	first, second := filepath.Join(dir, iouringReopenFirst), filepath.Join(dir, iouringReopenSecond)
	for path, content := range map[string]string{first: "first-file-content", second: "second-file-content"} {
		if err := writeWholeFile(path, content); err != nil {
			return err
		}
	}
	fd, err := syscall.Open(first, syscall.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", first, err)
	}
	if err := preadPrefix(fd, "first-file-content", iouringReopenFirstRead, 2); err != nil {
		return err
	}
	if err := reopenThroughRing(fd, second); err != nil {
		return err
	}
	if err := preadPrefix(fd, "second-file-content", iouringReopenSecondRead, 3); err != nil {
		return err
	}
	time.Sleep(iouringReopenSettle)
	return syscall.Close(fd)
}

// writeWholeFile creates path with content.
func writeWholeFile(path, content string) error {
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer syscall.Close(fd)
	if _, err := syscall.Write(fd, []byte(content)); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// preadPrefix reads the first size bytes of fd times times and requires them
// to be the start of content: the kernel's own word on which file fd names.
func preadPrefix(fd int, content string, size, times int) error {
	buf := make([]byte, size)
	for range times {
		n, err := syscall.Pread(fd, buf, 0)
		if err != nil {
			return fmt.Errorf("pread fd %d: %w", fd, err)
		}
		if n != size || string(buf) != content[:size] {
			return fmt.Errorf("pread fd %d read %q, want %q", fd, buf[:n], content[:size])
		}
	}
	return nil
}

// reopenThroughRing closes fd and opens path on the same number, both through
// io_uring requests instead of close(2) and openat(2).
func reopenThroughRing(fd int, path string) error {
	ring, err := newMiniRing(4)
	if err != nil {
		return err
	}
	defer ring.close()
	res, err := ring.submit(ioUringSqe{opcode: ioringOpClose, fd: int32(fd)})
	if err != nil || res != 0 {
		return fmt.Errorf("IORING_OP_CLOSE of fd %d: result %d, %v", fd, res, err)
	}
	name, err := syscall.BytePtrFromString(path)
	if err != nil {
		return err
	}
	atFdCwd := int32(-100)
	res, err = ring.submit(ioUringSqe{opcode: ioringOpOpenat, fd: atFdCwd,
		addr: uint64(uintptr(unsafe.Pointer(name))), opFlags: syscall.O_RDONLY})
	runtime.KeepAlive(name)
	if err != nil || int(res) != fd {
		return fmt.Errorf("IORING_OP_OPENAT of %s: result %d (%v), want the freed fd %d", path, res, err, fd)
	}
	return nil
}
