package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	sysProcessVMReadv  = 310
	sysProcessVMWritev = 311
	retbytesPayloadLen = 18
)

// retbytesPhaseA exercises byte-classified syscalls that use generic ret_event exits.
func retbytesPhaseA() error {
	if err := retbytesSocketIO(); err != nil {
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
	return retbytesProcessVM()
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
