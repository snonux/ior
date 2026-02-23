package main

import (
	"fmt"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	sysRenameat2       = 316 // SYS_RENAMEAT2 on amd64
	renameNoreplaceFlag = 1  // RENAME_NOREPLACE
)

// renameBasic creates a file and renames it via rename(2).
// Uses raw SYS_RENAME because Go's syscall.Rename wraps renameat on amd64.
func renameBasic() error {
	dir, cleanup, err := makeTempDir("rename-basic")
	if err != nil {
		return err
	}
	defer cleanup()

	oldPath := filepath.Join(dir, "oldname.txt")
	newPath := filepath.Join(dir, "newname.txt")

	fd, err := syscall.Open(oldPath, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	if err := syscall.Close(fd); err != nil {
		return fmt.Errorf("close: %w", err)
	}

	oldBytes, err := syscall.BytePtrFromString(oldPath)
	if err != nil {
		return fmt.Errorf("old path bytes: %w", err)
	}
	newBytes, err := syscall.BytePtrFromString(newPath)
	if err != nil {
		return fmt.Errorf("new path bytes: %w", err)
	}

	_, _, errno := syscall.Syscall(
		syscall.SYS_RENAME,
		uintptr(unsafe.Pointer(oldBytes)),
		uintptr(unsafe.Pointer(newBytes)),
		0,
	)
	runtime.KeepAlive(oldBytes)
	runtime.KeepAlive(newBytes)
	if errno != 0 {
		return fmt.Errorf("rename: %w", errno)
	}
	return nil
}

// renameRenameat creates a file and renames it via renameat(2).
func renameRenameat() error {
	dir, cleanup, err := makeTempDir("rename-renameat")
	if err != nil {
		return err
	}
	defer cleanup()

	oldName := "renameat-old.txt"
	newName := "renameat-new.txt"
	path := filepath.Join(dir, oldName)

	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	if err := syscall.Close(fd); err != nil {
		return fmt.Errorf("close: %w", err)
	}

	dirFD, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("open dir: %w", err)
	}
	defer syscall.Close(dirFD)

	oldBytes, err := syscall.BytePtrFromString(oldName)
	if err != nil {
		return fmt.Errorf("old name bytes: %w", err)
	}
	newBytes, err := syscall.BytePtrFromString(newName)
	if err != nil {
		return fmt.Errorf("new name bytes: %w", err)
	}

	_, _, errno := syscall.Syscall6(
		syscall.SYS_RENAMEAT,
		uintptr(dirFD),
		uintptr(unsafe.Pointer(oldBytes)),
		uintptr(dirFD),
		uintptr(unsafe.Pointer(newBytes)),
		0, 0,
	)
	runtime.KeepAlive(oldBytes)
	runtime.KeepAlive(newBytes)
	if errno != 0 {
		return fmt.Errorf("renameat: %w", errno)
	}
	return nil
}

// renameRenameat2 creates a file and renames it via renameat2(2) with no flags.
func renameRenameat2() error {
	dir, cleanup, err := makeTempDir("rename-renameat2")
	if err != nil {
		return err
	}
	defer cleanup()

	oldName := "renameat2-old.txt"
	newName := "renameat2-new.txt"
	path := filepath.Join(dir, oldName)

	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	if err := syscall.Close(fd); err != nil {
		return fmt.Errorf("close: %w", err)
	}

	dirFD, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("open dir: %w", err)
	}
	defer syscall.Close(dirFD)

	oldBytes, err := syscall.BytePtrFromString(oldName)
	if err != nil {
		return fmt.Errorf("old name bytes: %w", err)
	}
	newBytes, err := syscall.BytePtrFromString(newName)
	if err != nil {
		return fmt.Errorf("new name bytes: %w", err)
	}

	_, _, errno := syscall.Syscall6(
		sysRenameat2,
		uintptr(dirFD),
		uintptr(unsafe.Pointer(oldBytes)),
		uintptr(dirFD),
		uintptr(unsafe.Pointer(newBytes)),
		0, // flags=0: plain rename
		0,
	)
	runtime.KeepAlive(oldBytes)
	runtime.KeepAlive(newBytes)
	if errno != 0 {
		return fmt.Errorf("renameat2: %w", errno)
	}
	return nil
}

// renameEnoent attempts to rename a nonexistent file via raw SYS_RENAME.
// The syscall fails with ENOENT, but ior captures the tracepoint on entry.
func renameEnoent() error {
	dir, cleanup, err := makeTempDir("rename-enoent")
	if err != nil {
		return err
	}
	defer cleanup()

	oldPath := filepath.Join(dir, "rename-enoent-missing.txt")
	newPath := filepath.Join(dir, "rename-enoent-new.txt")

	oldBytes, err := syscall.BytePtrFromString(oldPath)
	if err != nil {
		return fmt.Errorf("old path bytes: %w", err)
	}
	newBytes, err := syscall.BytePtrFromString(newPath)
	if err != nil {
		return fmt.Errorf("new path bytes: %w", err)
	}

	for i := 0; i < 5; i++ {
		_, _, errno := syscall.Syscall(
			syscall.SYS_RENAME,
			uintptr(unsafe.Pointer(oldBytes)),
			uintptr(unsafe.Pointer(newBytes)),
			0,
		)
		runtime.KeepAlive(oldBytes)
		runtime.KeepAlive(newBytes)
		if errno == 0 {
			return fmt.Errorf("expected ENOENT, but rename succeeded")
		}
	}
	return nil
}

// renameNoreplace creates two files, then attempts renameat2 with
// RENAME_NOREPLACE. Because the target already exists, the syscall fails
// with EEXIST, but ior captures the tracepoint on entry.
func renameNoreplace() error {
	dir, cleanup, err := makeTempDir("rename-noreplace")
	if err != nil {
		return err
	}
	defer cleanup()

	srcName := "noreplace-src.txt"
	dstName := "noreplace-dst.txt"

	for _, name := range []string{srcName, dstName} {
		path := filepath.Join(dir, name)
		fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
		if err != nil {
			return fmt.Errorf("create %s: %w", name, err)
		}
		if err := syscall.Close(fd); err != nil {
			return fmt.Errorf("close %s: %w", name, err)
		}
	}

	dirFD, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("open dir: %w", err)
	}
	defer syscall.Close(dirFD)

	srcBytes, err := syscall.BytePtrFromString(srcName)
	if err != nil {
		return fmt.Errorf("src name bytes: %w", err)
	}
	dstBytes, err := syscall.BytePtrFromString(dstName)
	if err != nil {
		return fmt.Errorf("dst name bytes: %w", err)
	}

	_, _, errno := syscall.Syscall6(
		sysRenameat2,
		uintptr(dirFD),
		uintptr(unsafe.Pointer(srcBytes)),
		uintptr(dirFD),
		uintptr(unsafe.Pointer(dstBytes)),
		renameNoreplaceFlag,
		0,
	)
	runtime.KeepAlive(srcBytes)
	runtime.KeepAlive(dstBytes)
	if errno == 0 {
		return fmt.Errorf("expected EEXIST, but renameat2 NOREPLACE succeeded")
	}
	return nil
}
