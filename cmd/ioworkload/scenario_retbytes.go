package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

const (
	sysProcessVMReadv  = 310
	sysProcessVMWritev = 311
	sysSendmmsg        = 307
	retbytesPayloadLen = 18
)

type mmsghdr struct {
	hdr syscall.Msghdr
	len uint32
	_   uint32
}

// retbytesPhaseA exercises byte-classified syscalls that use generic ret_event exits.
func retbytesPhaseA() error {
	if err := retbytesSocketIO(); err != nil {
		return err
	}
	if err := retbytesBatchSocketIO(); err != nil {
		return err
	}
	if err := retbytesSendfile(); err != nil {
		return err
	}
	if err := retbytesSplice(); err != nil {
		return err
	}
	if err := retbytesTee(); err != nil {
		return err
	}
	if err := retbytesGetdents(); err != nil {
		return err
	}
	if err := retbytesReadlinkat(); err != nil {
		return err
	}
	return retbytesProcessVM()
}

// retbytesGetdents opens a non-empty directory and reads its entries via
// getdents64(2). getdents/getdents64 are READ_CLASSIFIED, so a successful call
// on a populated directory returns ctx->ret > 0 (bytes filled into the dirent
// buffer). This drives the exit byte-count assertion in TestRetbytesPhaseA.
func retbytesGetdents() error {
	dir, cleanup, err := makeTempDir("retbytes-getdents")
	if err != nil {
		return err
	}
	defer cleanup()

	// Create several files so getdents64 has substantial dirent data to return,
	// guaranteeing a strictly positive byte count.
	for i := 0; i < 4; i++ {
		filePath := filepath.Join(dir, fmt.Sprintf("getdents-file-%d.txt", i))
		fd, openErr := syscall.Open(filePath, syscall.O_RDWR|syscall.O_CREAT, 0o644)
		if openErr != nil {
			return fmt.Errorf("open file: %w", openErr)
		}
		syscall.Close(fd)
	}

	dirFD, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("open dir: %w", err)
	}
	defer syscall.Close(dirFD)

	// Re-issue getdents64 in a short window so ior has enough time to attach and
	// capture an enter/exit pair under high parallel integration load. Each call
	// rewinds via lseek so the directory keeps returning entries.
	buf := make([]byte, 4096)
	for i := 0; i < 40; i++ {
		if _, err := syscall.Seek(dirFD, 0, 0); err != nil {
			return fmt.Errorf("seek dir: %w", err)
		}
		n, _, errno := syscall.Syscall(syscall.SYS_GETDENTS64, uintptr(dirFD), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
		runtime.KeepAlive(buf)
		if errno != 0 {
			return fmt.Errorf("getdents64: %w", errno)
		}
		if n == 0 {
			return fmt.Errorf("getdents64 returned 0 bytes on a non-empty directory")
		}
		time.Sleep(25 * time.Millisecond)
	}
	return nil
}

// retbytesReadlinkat creates a symlink with a known non-empty target and reads
// it back via readlinkat(2). readlinkat is READ_CLASSIFIED, so a successful
// call returns ctx->ret > 0: the byte length of the target string copied into
// the caller's buffer. This drives the exit byte-count assertion in
// TestRetbytesPhaseA.
func retbytesReadlinkat() error {
	dir, cleanup, err := makeTempDir("retbytes-readlinkat")
	if err != nil {
		return err
	}
	defer cleanup()

	// Point the symlink at an absolute path inside the temp dir. The target is
	// deliberately non-empty so readlinkat reports a strictly positive byte
	// count (the length of this target string).
	target := filepath.Join(dir, "retbytes-readlinkat-target.txt")
	linkPath := filepath.Join(dir, "retbytes-readlinkat-link.txt")
	if err := syscall.Symlink(target, linkPath); err != nil {
		return fmt.Errorf("symlink: %w", err)
	}

	dirFD, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("open dir: %w", err)
	}
	defer syscall.Close(dirFD)

	linkName, err := syscall.BytePtrFromString("retbytes-readlinkat-link.txt")
	if err != nil {
		return fmt.Errorf("link name bytes: %w", err)
	}

	// Re-issue readlinkat in a short window so ior has enough time to attach and
	// capture an enter/exit pair under high parallel integration load. Each call
	// re-resolves the same symlink, so ctx->ret stays equal to the target length.
	buf := make([]byte, 256)
	for i := 0; i < 40; i++ {
		n, _, errno := syscall.Syscall6(
			syscall.SYS_READLINKAT,
			uintptr(dirFD),
			uintptr(unsafe.Pointer(linkName)),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			0, 0,
		)
		runtime.KeepAlive(linkName)
		runtime.KeepAlive(buf)
		if errno != 0 {
			return fmt.Errorf("readlinkat: %w", errno)
		}
		if n == 0 {
			return fmt.Errorf("readlinkat returned 0 bytes for a non-empty link target")
		}
		time.Sleep(25 * time.Millisecond)
	}
	return nil
}

func retbytesSocketIO() error {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return fmt.Errorf("socketpair: %w", err)
	}
	defer syscall.Close(fds[0])
	defer syscall.Close(fds[1])

	payload := []byte("phase-a-send-recv!")
	if err := syscall.Sendto(fds[0], payload, 0, nil); err != nil {
		return fmt.Errorf("sendto: %w", err)
	}
	buf := make([]byte, len(payload))
	n, _, err := syscall.Recvfrom(fds[1], buf, 0)
	if err != nil {
		return fmt.Errorf("recvfrom: %w", err)
	}
	if n != len(payload) {
		return fmt.Errorf("recvfrom read %d bytes, want %d", n, len(payload))
	}

	if n, err := syscall.SendmsgN(fds[0], payload, nil, nil, 0); err != nil {
		return fmt.Errorf("sendmsg: %w", err)
	} else if n != len(payload) {
		return fmt.Errorf("sendmsg wrote %d bytes, want %d", n, len(payload))
	}
	n, _, _, _, err = syscall.Recvmsg(fds[1], buf, nil, 0)
	if err != nil {
		return fmt.Errorf("recvmsg: %w", err)
	}
	if n != len(payload) {
		return fmt.Errorf("recvmsg read %d bytes, want %d", n, len(payload))
	}
	return nil
}

func retbytesBatchSocketIO() error {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("batch socketpair: %w", err)
	}
	defer syscall.Close(fds[0])
	defer syscall.Close(fds[1])

	payloadA := []byte("batch-one")
	payloadB := []byte("batch-two")
	sendMsgs := mmsgSlice(payloadA, payloadB)
	n, _, errno := syscall.Syscall6(sysSendmmsg, uintptr(fds[0]), uintptr(unsafe.Pointer(&sendMsgs[0])), uintptr(len(sendMsgs)), 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("sendmmsg: %w", errno)
	}
	if n != uintptr(len(sendMsgs)) {
		return fmt.Errorf("sendmmsg sent %d messages, want %d", n, len(sendMsgs))
	}
	runtime.KeepAlive(payloadA)
	runtime.KeepAlive(payloadB)
	runtime.KeepAlive(sendMsgs)

	recvA := make([]byte, len(payloadA))
	recvB := make([]byte, len(payloadB))
	recvMsgs := mmsgSlice(recvA, recvB)
	n, _, errno = syscall.Syscall6(syscall.SYS_RECVMMSG, uintptr(fds[1]), uintptr(unsafe.Pointer(&recvMsgs[0])), uintptr(len(recvMsgs)), 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("recvmmsg: %w", errno)
	}
	if n != uintptr(len(recvMsgs)) {
		return fmt.Errorf("recvmmsg received %d messages, want %d", n, len(recvMsgs))
	}
	runtime.KeepAlive(recvA)
	runtime.KeepAlive(recvB)
	runtime.KeepAlive(recvMsgs)
	return nil
}

func retbytesSendfile() error {
	dir, cleanup, err := makeTempDir("retbytes-sendfile")
	if err != nil {
		return err
	}
	defer cleanup()

	src, dst, err := openTransferFiles(dir, "sendfilesrc.txt", "sendfiledst.txt")
	if err != nil {
		return err
	}
	defer syscall.Close(src)
	defer syscall.Close(dst)

	n, err := syscall.Sendfile(dst, src, nil, retbytesPayloadLen)
	if err != nil {
		return fmt.Errorf("sendfile: %w", err)
	}
	if n != retbytesPayloadLen {
		return fmt.Errorf("sendfile copied %d bytes, want %d", n, retbytesPayloadLen)
	}
	return nil
}

func retbytesSplice() error {
	dir, cleanup, err := makeTempDir("retbytes-splice")
	if err != nil {
		return err
	}
	defer cleanup()

	src, err := openPayloadFile(filepath.Join(dir, "splicesrc.txt"))
	if err != nil {
		return err
	}
	defer syscall.Close(src)

	pipe := make([]int, 2)
	if err := syscall.Pipe2(pipe, syscall.O_CLOEXEC); err != nil {
		return fmt.Errorf("pipe2: %w", err)
	}
	defer syscall.Close(pipe[0])
	defer syscall.Close(pipe[1])

	n, err := syscall.Splice(src, nil, pipe[1], nil, retbytesPayloadLen, 0)
	if err != nil {
		return fmt.Errorf("splice: %w", err)
	}
	if n != retbytesPayloadLen {
		return fmt.Errorf("splice copied %d bytes, want %d", n, retbytesPayloadLen)
	}
	return nil
}

func retbytesTee() error {
	pipeA := make([]int, 2)
	if err := syscall.Pipe2(pipeA, syscall.O_CLOEXEC); err != nil {
		return fmt.Errorf("pipe2 source: %w", err)
	}
	defer syscall.Close(pipeA[0])
	defer syscall.Close(pipeA[1])

	pipeB := make([]int, 2)
	if err := syscall.Pipe2(pipeB, syscall.O_CLOEXEC); err != nil {
		return fmt.Errorf("pipe2 dest: %w", err)
	}
	defer syscall.Close(pipeB[0])
	defer syscall.Close(pipeB[1])

	payload := []byte("phase-a-tee-bytes!")
	if _, err := syscall.Write(pipeA[1], payload); err != nil {
		return fmt.Errorf("write pipe: %w", err)
	}
	n, err := syscall.Tee(pipeA[0], pipeB[1], len(payload), 0)
	if err != nil {
		return fmt.Errorf("tee: %w", err)
	}
	if n != int64(len(payload)) {
		return fmt.Errorf("tee copied %d bytes, want %d", n, len(payload))
	}
	return nil
}

func retbytesProcessVM() error {
	src := []byte("phase-a-process-vm")
	dst := make([]byte, len(src))
	if n, err := processVMWritev(os.Getpid(), dst, src); err != nil {
		return err
	} else if n != len(src) {
		return fmt.Errorf("process_vm_writev wrote %d bytes, want %d", n, len(src))
	}

	readBuf := make([]byte, len(dst))
	if n, err := processVMReadv(os.Getpid(), readBuf, dst); err != nil {
		return err
	} else if n != len(dst) {
		return fmt.Errorf("process_vm_readv read %d bytes, want %d", n, len(dst))
	}
	runtime.KeepAlive(src)
	runtime.KeepAlive(dst)
	runtime.KeepAlive(readBuf)
	return nil
}

func openTransferFiles(dir, srcName, dstName string) (int, int, error) {
	src, err := openPayloadFile(filepath.Join(dir, srcName))
	if err != nil {
		return 0, 0, err
	}
	dstPath := filepath.Join(dir, dstName)
	dst, err := syscall.Open(dstPath, syscall.O_RDWR|syscall.O_CREAT|syscall.O_TRUNC, 0o644)
	if err != nil {
		syscall.Close(src)
		return 0, 0, fmt.Errorf("open destination: %w", err)
	}
	return src, dst, nil
}

func openPayloadFile(path string) (int, error) {
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_TRUNC, 0o644)
	if err != nil {
		return 0, fmt.Errorf("open payload: %w", err)
	}
	if _, err := syscall.Write(fd, []byte("phase-a-ret-bytes!")); err != nil {
		syscall.Close(fd)
		return 0, fmt.Errorf("write payload: %w", err)
	}
	if _, err := syscall.Seek(fd, 0, 0); err != nil {
		syscall.Close(fd)
		return 0, fmt.Errorf("seek payload: %w", err)
	}
	return fd, nil
}

func mmsgSlice(bufs ...[]byte) []mmsghdr {
	msgs := make([]mmsghdr, len(bufs))
	iovs := make([]syscall.Iovec, len(bufs))
	for i := range bufs {
		iovs[i] = syscall.Iovec{Base: &bufs[i][0], Len: uint64(len(bufs[i]))}
		msgs[i].hdr.Iov = &iovs[i]
		msgs[i].hdr.Iovlen = 1
	}
	return msgs
}

func processVMReadv(pid int, local, remote []byte) (int, error) {
	localIov := syscall.Iovec{Base: &local[0], Len: uint64(len(local))}
	remoteIov := syscall.Iovec{Base: &remote[0], Len: uint64(len(remote))}
	n, _, errno := syscall.Syscall6(
		sysProcessVMReadv,
		uintptr(pid),
		uintptr(unsafe.Pointer(&localIov)),
		1,
		uintptr(unsafe.Pointer(&remoteIov)),
		1,
		0,
	)
	runtime.KeepAlive(local)
	runtime.KeepAlive(remote)
	if errno != 0 {
		return 0, fmt.Errorf("process_vm_readv: %w", errno)
	}
	return int(n), nil
}

func processVMWritev(pid int, remote, local []byte) (int, error) {
	localIov := syscall.Iovec{Base: &local[0], Len: uint64(len(local))}
	remoteIov := syscall.Iovec{Base: &remote[0], Len: uint64(len(remote))}
	n, _, errno := syscall.Syscall6(
		sysProcessVMWritev,
		uintptr(pid),
		uintptr(unsafe.Pointer(&localIov)),
		1,
		uintptr(unsafe.Pointer(&remoteIov)),
		1,
		0,
	)
	runtime.KeepAlive(local)
	runtime.KeepAlive(remote)
	if errno != 0 {
		return 0, fmt.Errorf("process_vm_writev: %w", errno)
	}
	return int(n), nil
}
