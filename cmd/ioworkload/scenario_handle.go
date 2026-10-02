package main

import (
	"fmt"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

// handleRounds is how often the handle scenarios repeat their sequence, so a
// single dropped event cannot fail a test.
const handleRounds = 5

// handleSettle is how long openByHandleAtReusedNumber keeps its decoy
// descriptors open after the last round: long enough for a tracer to have
// processed every record of the scenario while each reused number still shows
// the decoy in /proc/<pid>/fd.
const handleSettle = 300 * time.Millisecond

// openByHandleAtReusedNumber opens a file by handle, closes the descriptor and
// at once opens another file - the decoy - with the same flags, which takes
// over the number and keeps it until the scenario ends.
//
// It pins the case task k03 was filed for. ior used to name an
// open_by_handle_at by looking at /proc/<pid>/fd/<fd> when it handled the
// exit record, and believed what it saw whenever that descriptor had the
// call's fixed flags: here that is the decoy, opened O_RDONLY like the handle,
// on the handle's number, and still open. The row and the fd table entry were
// then named after the decoy. With the handle bytes in the records the row is
// named after the file the handle belongs to, whatever holds the number.
// Requires root (CAP_DAC_READ_SEARCH).
func openByHandleAtReusedNumber() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	dir, cleanup, err := makeTempDir("open-by-handle-at-reuse")
	if err != nil {
		return err
	}
	defer cleanup()

	for i := 0; i < handleRounds; i++ {
		decoyFD, err := openHandleThenReuseItsNumber(dir, i)
		if err != nil {
			return err
		}
		defer syscall.Close(decoyFD)
	}
	time.Sleep(handleSettle)
	return nil
}

// openHandleThenReuseItsNumber runs one round of openByHandleAtReusedNumber
// and returns the decoy descriptor that now holds the handle's number.
func openHandleThenReuseItsNumber(dir string, round int) (int, error) {
	name := fmt.Sprintf("handle-reuse-%d.txt", round)
	decoy := filepath.Join(dir, fmt.Sprintf("decoy-%d.txt", round))
	for _, path := range []string{filepath.Join(dir, name), decoy} {
		if err := createEmptyFile(path); err != nil {
			return -1, err
		}
	}
	handle, mountFD, err := nameToHandleAt(dir, name)
	if err != nil {
		return -1, fmt.Errorf("name_to_handle_at: %w", err)
	}
	defer syscall.Close(mountFD)

	fd, err := openByHandleAtSyscall(mountFD, handle, syscall.O_RDONLY)
	if err != nil {
		return -1, fmt.Errorf("open_by_handle_at: %w", err)
	}
	if err := syscall.Close(fd); err != nil {
		return -1, fmt.Errorf("close: %w", err)
	}
	decoyFD, err := syscall.Open(decoy, syscall.O_RDONLY, 0)
	if err != nil {
		return -1, fmt.Errorf("open decoy: %w", err)
	}
	if decoyFD != fd {
		syscall.Close(decoyFD)
		return -1, fmt.Errorf("decoy got descriptor %d, want the handle's number %d", decoyFD, fd)
	}
	return decoyFD, nil
}

// takenHandle is a file handle one thread hands to another.
type takenHandle struct {
	handle  []byte
	mountFD int
	tid     int
	err     error
}

// openByHandleAtAcrossThreads takes file handles on one OS thread and opens
// them on another, which is what the API is for: a handle is valid
// system-wide. Each handle is opened twice by the second thread - once with
// mount_fd -1, which fails with EBADF, and once for real - so both a failed
// and a successful row exist for a thread that never called
// name_to_handle_at. ior used to keep the pathname per thread and could name
// neither from it. Requires root (CAP_DAC_READ_SEARCH).
func openByHandleAtAcrossThreads() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	dir, cleanup, err := makeTempDir("open-by-handle-at-threads")
	if err != nil {
		return err
	}
	defer cleanup()

	for i := 0; i < handleRounds; i++ {
		name := fmt.Sprintf("handle-thread-%d.txt", i)
		if err := createEmptyFile(filepath.Join(dir, name)); err != nil {
			return err
		}
		taken := takeHandleOnAnotherThread(dir, name)
		if taken.err != nil {
			return taken.err
		}
		if err := openTakenHandle(taken); err != nil {
			return err
		}
	}
	return nil
}

// takeHandleOnAnotherThread calls name_to_handle_at on an OS thread of its
// own. The goroutine never unlocks the thread, so the thread ends with it and
// cannot be the caller's.
func takeHandleOnAnotherThread(dir, name string) takenHandle {
	result := make(chan takenHandle, 1)
	go func() {
		runtime.LockOSThread()
		handle, mountFD, err := nameToHandleAt(dir, name)
		if err != nil {
			err = fmt.Errorf("name_to_handle_at: %w", err)
		}
		result <- takenHandle{handle: handle, mountFD: mountFD, tid: syscall.Gettid(), err: err}
	}()
	return <-result
}

// openTakenHandle opens a handle another thread took: first failing with
// EBADF, then successfully.
func openTakenHandle(taken takenHandle) error {
	defer syscall.Close(taken.mountFD)
	if tid := syscall.Gettid(); tid == taken.tid {
		return fmt.Errorf("handle was taken on the opening thread %d", tid)
	}
	if err := expectOpenByHandleAtErrno(-1, taken.handle, syscall.EBADF); err != nil {
		return err
	}
	fd, err := openByHandleAtSyscall(taken.mountFD, taken.handle, syscall.O_RDONLY)
	if err != nil {
		return fmt.Errorf("open_by_handle_at: %w", err)
	}
	return syscall.Close(fd)
}

// openByHandleAtEbadfOlderHandle takes the handles of two files on one thread
// and then fails to open the OLDER one (mount_fd -1, EBADF). A failed call
// has no descriptor ior could look at, so while the pathname was kept per
// thread the row could only be named after the thread's last
// name_to_handle_at - the newer file, the wrong one.
func openByHandleAtEbadfOlderHandle(dir string) error {
	handles := make([][]byte, 0, 2)
	for _, name := range []string{"handle-older.txt", "handle-newer.txt"} {
		if err := createEmptyFile(filepath.Join(dir, name)); err != nil {
			return err
		}
		handle, mountFD, err := nameToHandleAt(dir, name)
		if err != nil {
			return fmt.Errorf("name_to_handle_at: %w", err)
		}
		syscall.Close(mountFD)
		handles = append(handles, handle)
	}
	if err := expectOpenByHandleAtErrno(-1, handles[0], syscall.EBADF); err != nil {
		return fmt.Errorf("older handle: %w", err)
	}
	return nil
}
