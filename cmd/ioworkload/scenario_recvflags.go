package main

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

// Datagram lengths of the recv-flags scenario. Each receive returns a distinct
// value so the integration test can tell the calls apart by their return
// value alone (the Parquet row keeps ret and the byte count side by side).
const (
	recvflagsPeekLen      = 100 // recvfrom MSG_PEEK, then a real recvfrom
	recvflagsTruncLen     = 300 // recvfrom MSG_TRUNC into a short buffer
	recvflagsNetlinkLen   = 200 // recvmsg PEEK|TRUNC size probe, then a real recvmsg
	recvflagsTruncMsgLen  = 400 // recvmsg MSG_TRUNC into two short iovecs
	recvflagsManyIovLen   = 90  // recvmsg MSG_TRUNC with more iovecs than BPF sums
	recvflagsShortBuf     = 10  // capacity of the short recvfrom buffer
	recvflagsIovA         = 25  // the two iovec lengths of the short recvmsg
	recvflagsIovB         = 15  //
	recvflagsManyIovCount = 9   // one more than IOR_RECVMSG_MAX_IOV
)

// recvFlagsScenario makes recvfrom and recvmsg run with the flags whose
// return value is not the number of bytes consumed by the caller:
//
//   - MSG_PEEK leaves the datagram queued, so a following plain receive
//     returns the same length again;
//   - MSG_TRUNC returns the datagram's real length even when it did not fit;
//   - recvmsg(fd, {iov_len=0}, MSG_PEEK|MSG_TRUNC) followed by a plain
//     recvmsg is the size-then-read idiom of every netlink client (iproute2,
//     libnl, sd-netlink).
//
// The tracer must count only the bytes that were actually received.
func recvFlagsScenario() error {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("socketpair: %w", err)
	}
	defer syscall.Close(fds[0])
	defer syscall.Close(fds[1])

	steps := []func(tx, rx int) error{
		recvflagsPeekThenRead,
		recvflagsTruncatedRecvfrom,
		recvflagsNetlinkIdiom,
		recvflagsTruncatedRecvmsg,
		recvflagsManyIovecs,
	}
	for _, step := range steps {
		if err := step(fds[0], fds[1]); err != nil {
			return err
		}
	}
	return nil
}

// recvflagsSend queues one datagram of n bytes on tx.
func recvflagsSend(tx, n int) error {
	if _, err := syscall.SendmsgN(tx, make([]byte, n), nil, nil, 0); err != nil {
		return fmt.Errorf("send %d bytes: %w", n, err)
	}
	return nil
}

// recvflagsRecvfrom is recvfrom(rx, buf, len(buf), flags) with the raw syscall
// so the flags reach the kernel exactly as given.
func recvflagsRecvfrom(rx int, buf []byte, flags int) (int, error) {
	n, _, errno := syscall.Syscall6(syscall.SYS_RECVFROM, uintptr(rx),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(flags), 0, 0)
	runtime.KeepAlive(buf)
	if errno != 0 {
		return 0, errno
	}
	return int(n), nil
}

// recvflagsRecvmsg is recvmsg(rx, {iov}, flags) over the given buffers; a nil
// buffer becomes a zero-length iovec, as netlink clients pass for the size
// probe.
func recvflagsRecvmsg(rx int, bufs [][]byte, flags int) (int, error) {
	iovs := make([]syscall.Iovec, len(bufs))
	for i, buf := range bufs {
		iovs[i].Len = uint64(len(buf))
		if len(buf) > 0 {
			iovs[i].Base = &buf[0]
		}
	}
	var msg syscall.Msghdr
	msg.Iov = &iovs[0]
	msg.Iovlen = uint64(len(iovs))
	n, _, errno := syscall.Syscall(syscall.SYS_RECVMSG, uintptr(rx), uintptr(unsafe.Pointer(&msg)), uintptr(flags))
	runtime.KeepAlive(bufs)
	runtime.KeepAlive(iovs)
	if errno != 0 {
		return 0, errno
	}
	return int(n), nil
}

// recvflagsExpect fails when a receive did not return the length the scenario
// relies on to keep its calls distinguishable in the trace.
func recvflagsExpect(what string, got int, err error, want int) error {
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	if got != want {
		return fmt.Errorf("%s returned %d, want %d", what, got, want)
	}
	return nil
}

func recvflagsPeekThenRead(tx, rx int) error {
	if err := recvflagsSend(tx, recvflagsPeekLen); err != nil {
		return err
	}
	buf := make([]byte, 4096)
	n, err := recvflagsRecvfrom(rx, buf, syscall.MSG_PEEK)
	if err := recvflagsExpect("recvfrom MSG_PEEK", n, err, recvflagsPeekLen); err != nil {
		return err
	}
	n, err = recvflagsRecvfrom(rx, buf, 0)
	return recvflagsExpect("recvfrom", n, err, recvflagsPeekLen)
}

func recvflagsTruncatedRecvfrom(tx, rx int) error {
	if err := recvflagsSend(tx, recvflagsTruncLen); err != nil {
		return err
	}
	n, err := recvflagsRecvfrom(rx, make([]byte, recvflagsShortBuf), syscall.MSG_TRUNC)
	return recvflagsExpect("recvfrom MSG_TRUNC", n, err, recvflagsTruncLen)
}

func recvflagsNetlinkIdiom(tx, rx int) error {
	if err := recvflagsSend(tx, recvflagsNetlinkLen); err != nil {
		return err
	}
	n, err := recvflagsRecvmsg(rx, [][]byte{nil}, syscall.MSG_PEEK|syscall.MSG_TRUNC)
	if err := recvflagsExpect("recvmsg PEEK|TRUNC", n, err, recvflagsNetlinkLen); err != nil {
		return err
	}
	n, err = recvflagsRecvmsg(rx, [][]byte{make([]byte, recvflagsNetlinkLen)}, 0)
	return recvflagsExpect("recvmsg", n, err, recvflagsNetlinkLen)
}

func recvflagsTruncatedRecvmsg(tx, rx int) error {
	if err := recvflagsSend(tx, recvflagsTruncMsgLen); err != nil {
		return err
	}
	bufs := [][]byte{make([]byte, recvflagsIovA), make([]byte, recvflagsIovB)}
	n, err := recvflagsRecvmsg(rx, bufs, syscall.MSG_TRUNC)
	return recvflagsExpect("recvmsg MSG_TRUNC", n, err, recvflagsTruncMsgLen)
}

// recvflagsManyIovecs receives with more iovecs than the BPF handler sums, so
// its capacity is reported as unknown. The datagram fits, so nothing is
// truncated and the return value is the exact byte count either way.
func recvflagsManyIovecs(tx, rx int) error {
	if err := recvflagsSend(tx, recvflagsManyIovLen); err != nil {
		return err
	}
	bufs := make([][]byte, recvflagsManyIovCount)
	for i := range bufs {
		bufs[i] = make([]byte, recvflagsManyIovLen/recvflagsManyIovCount)
	}
	n, err := recvflagsRecvmsg(rx, bufs, syscall.MSG_TRUNC)
	return recvflagsExpect("recvmsg MSG_TRUNC many iovecs", n, err, recvflagsManyIovLen)
}
