package main

import (
	"fmt"
	"path/filepath"
	"syscall"
)

// syncBasic opens a file, writes data, and fsyncs it.
func syncBasic() error {
	dir, cleanup, err := makeTempDir("sync-basic")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "syncfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	if _, err := syscall.Write(fd, []byte("sync me")); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return syscall.Fsync(fd)
}

// syncFdatasync opens a file, writes data, and fdatasyncs it.
func syncFdatasync() error {
	dir, cleanup, err := makeTempDir("sync-fdatasync")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "fdatasyncfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	if _, err := syscall.Write(fd, []byte("fdatasync me")); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return syscall.Fdatasync(fd)
}

// syncSync calls sync(2) to flush all filesystem caches.
// sync is a null_event with no file arguments.
func syncSync() error {
	syscall.Sync()
	return nil
}

// syncSyncFileRange opens a file, writes data, then calls sync_file_range(2).
func syncSyncFileRange() error {
	dir, cleanup, err := makeTempDir("sync-sync-file-range")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "syncrangefile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	data := []byte("sync file range data")
	if _, err := syscall.Write(fd, data); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return syscall.SyncFileRange(fd, 0, int64(len(data)), 0)
}

// syncSyncFileRangeToEOF calls sync_file_range(2) with nbytes=0.
// Per sync_file_range(2), nbytes=0 means "sync from offset through end-of-file".
func syncSyncFileRangeToEOF() error {
	dir, cleanup, err := makeTempDir("sync-sync-file-range-to-eof")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "syncrangeeoffile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	if _, err := syscall.Write(fd, []byte("sync file range to eof")); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	return syscall.SyncFileRange(fd, 0, 0, 0)
}

// syncFsyncEbadf calls fsync on an invalid fd.
// The syscall fails with EBADF, but ior captures the enter_fsync tracepoint.
func syncFsyncEbadf() error {
	for i := 0; i < 5; i++ {
		_, _, errno := syscall.Syscall(syscall.SYS_FSYNC, 99999, 0, 0)
		if errno == 0 {
			return fmt.Errorf("expected EBADF, but fsync succeeded")
		}
	}
	return nil
}

// syncFdatasyncEbadf calls fdatasync on an invalid fd.
// The syscall fails with EBADF, but ior captures the enter_fdatasync tracepoint.
func syncFdatasyncEbadf() error {
	for i := 0; i < 5; i++ {
		_, _, errno := syscall.Syscall(syscall.SYS_FDATASYNC, 99999, 0, 0)
		if errno == 0 {
			return fmt.Errorf("expected EBADF, but fdatasync succeeded")
		}
	}
	return nil
}

// syncFileRangeEbadf calls sync_file_range on an invalid fd.
// The syscall fails with EBADF, but ior captures the enter_sync_file_range tracepoint.
func syncFileRangeEbadf() error {
	for i := 0; i < 5; i++ {
		_, _, errno := syscall.Syscall6(syscall.SYS_SYNC_FILE_RANGE, 99999, 0, 0, 0, 0, 0)
		if errno == 0 {
			return fmt.Errorf("expected EBADF, but sync_file_range succeeded")
		}
	}
	return nil
}
