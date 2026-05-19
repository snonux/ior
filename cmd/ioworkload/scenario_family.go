package main

import (
	"fmt"
	"path/filepath"
	"syscall"
)

// familyMixed emits representative syscalls from multiple broad families so
// integration tests can verify family tagging and aggregation from a real trace.
func familyMixed() error {
	if err := familyMixedFS(); err != nil {
		return err
	}
	if err := familyMixedMemory(); err != nil {
		return err
	}
	if err := familyMixedIPC(); err != nil {
		return err
	}
	if err := familyMixedNetwork(); err != nil {
		return err
	}
	if err := familyMixedProcessSchedTime(); err != nil {
		return err
	}
	return nil
}

func familyMixedFS() error {
	dir, cleanup, err := makeTempDir("family-mixed")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "family-file.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("open family file: %w", err)
	}
	defer syscall.Close(fd)
	if _, err := syscall.Write(fd, []byte("family")); err != nil {
		return fmt.Errorf("write family file: %w", err)
	}
	return nil
}

func familyMixedMemory() error {
	mapped, err := syscall.Mmap(-1, 0, 4096, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANON)
	if err != nil {
		return fmt.Errorf("mmap anonymous page: %w", err)
	}
	defer syscall.Munmap(mapped)
	mapped[0] = 1
	return nil
}

func familyMixedIPC() error {
	var pipe [2]int
	if err := syscall.Pipe2(pipe[:], syscall.O_CLOEXEC); err != nil {
		return fmt.Errorf("pipe2: %w", err)
	}
	defer syscall.Close(pipe[0])
	defer syscall.Close(pipe[1])
	return nil
}

func familyMixedNetwork() error {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("socketpair: %w", err)
	}
	defer syscall.Close(fds[0])
	defer syscall.Close(fds[1])
	return nil
}

func familyMixedProcessSchedTime() error {
	if _, _, errno := syscall.RawSyscall(syscall.SYS_GETPID, 0, 0, 0); errno != 0 {
		return fmt.Errorf("getpid: %w", errno)
	}
	if _, _, errno := syscall.RawSyscall(syscall.SYS_SCHED_YIELD, 0, 0, 0); errno != 0 {
		return fmt.Errorf("sched_yield: %w", errno)
	}
	if err := syscall.Nanosleep(&syscall.Timespec{Nsec: 1000}, nil); err != nil {
		return fmt.Errorf("nanosleep: %w", err)
	}
	return nil
}
