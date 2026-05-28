package main

import (
	"fmt"
	"path/filepath"
	"syscall"
)

const sysCloseRange = 436

// closeBasic opens multiple files and closes them.
func closeBasic() error {
	dir, cleanup, err := makeTempDir("close-basic")
	if err != nil {
		return err
	}
	defer cleanup()

	var fds []int
	for i := range 3 {
		path := filepath.Join(dir, fmt.Sprintf("closefile-%d.txt", i))
		fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
		if err != nil {
			return fmt.Errorf("open %d: %w", i, err)
		}
		fds = append(fds, fd)
	}
	for _, fd := range fds {
		if err := syscall.Close(fd); err != nil {
			return fmt.Errorf("close fd %d: %w", fd, err)
		}
	}
	return nil
}

// closeRange opens multiple files and closes a range of them via close_range(2).
func closeRange() error {
	dir, cleanup, err := makeTempDir("close-range")
	if err != nil {
		return err
	}
	defer cleanup()

	var fds []int
	for i := range 3 {
		path := filepath.Join(dir, fmt.Sprintf("closerangefile-%d.txt", i))
		fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
		if err != nil {
			return fmt.Errorf("open %d: %w", i, err)
		}
		fds = append(fds, fd)
	}

	if fds[2]-fds[0] != 2 {
		return fmt.Errorf("fds not contiguous: %v", fds)
	}

	first := uintptr(fds[0])
	last := uintptr(fds[len(fds)-1])
	_, _, errno := syscall.Syscall(sysCloseRange, first, last, 0)
	if errno != 0 {
		return fmt.Errorf("close_range: %w", errno)
	}
	return nil
}

// closeRangeBounded opens a contiguous block of low fds plus one higher fd,
// then closes only the low block via close_range(first, last, 0) where last is
// strictly below the higher fd. It writes to the higher fd afterwards to prove
// it stayed open. This exercises close_range's upper-bound handling end to end:
// ior must keep the higher fd tracked rather than evicting everything >= first.
func closeRangeBounded() error {
	dir, cleanup, err := makeTempDir("close-range-bounded")
	if err != nil {
		return err
	}
	defer cleanup()

	var lowFds []int
	for i := range 3 {
		path := filepath.Join(dir, fmt.Sprintf("closerangelow-%d.txt", i))
		fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
		if err != nil {
			return fmt.Errorf("open low %d: %w", i, err)
		}
		lowFds = append(lowFds, fd)
	}

	highPath := filepath.Join(dir, "closerangehigh.txt")
	highFd, err := syscall.Open(highPath, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open high: %w", err)
	}
	defer syscall.Close(highFd)

	if highFd <= lowFds[len(lowFds)-1] {
		return fmt.Errorf("high fd %d not above low fds %v", highFd, lowFds)
	}

	first := uintptr(lowFds[0])
	last := uintptr(lowFds[len(lowFds)-1])
	if _, _, errno := syscall.Syscall(sysCloseRange, first, last, 0); errno != 0 {
		return fmt.Errorf("close_range: %w", errno)
	}

	// highFd is above last, so it must still be open and usable.
	if _, err := syscall.Write(highFd, []byte("still-open")); err != nil {
		return fmt.Errorf("write high fd: %w", err)
	}
	return nil
}

// closeInvalidFd attempts to close a very high fd number that is not open.
// The close fails with EBADF, but ior should capture the enter_close tracepoint
// because arguments are read on syscall entry before the kernel returns an error.
func closeInvalidFd() error {
	err := syscall.Close(99999)
	if err == nil {
		return fmt.Errorf("expected close of invalid fd to fail")
	}
	return nil
}

// closeDoubleClose opens a file, closes it normally, then closes the same fd again.
// The second close fails with EBADF, but ior should capture both enter_close
// tracepoints because arguments are read on syscall entry.
func closeDoubleClose() error {
	dir, cleanup, err := makeTempDir("close-double-close")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "doubleclosefile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}

	if err := syscall.Close(fd); err != nil {
		return fmt.Errorf("first close: %w", err)
	}

	err = syscall.Close(fd)
	if err == nil {
		return fmt.Errorf("expected second close of same fd to fail")
	}
	return nil
}

// closeRangeEmpty calls close_range(2) with a range of very high fd numbers
// (9000–9999) where no fds are open. The syscall succeeds (empty range is valid),
// and ior should capture the enter_close_range tracepoint.
func closeRangeEmpty() error {
	// Retry a few times to reduce event-loss flakiness under heavy test load.
	for i := 0; i < 5; i++ {
		_, _, errno := syscall.Syscall(sysCloseRange, 9000, 9999, 0)
		if errno != 0 {
			return fmt.Errorf("close_range: %w", errno)
		}
	}
	return nil
}
