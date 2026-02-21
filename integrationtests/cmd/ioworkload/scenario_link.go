package main

import (
	"fmt"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"
)

// linkBasic creates a file, hard links it via link(2), symlinks it via
// symlink(2), and reads the symlink via readlink(2).
// Uses raw SYS_LINK, SYS_SYMLINK, SYS_READLINK because Go's syscall wrappers
// delegate to linkat/symlinkat/readlinkat on amd64.
func linkBasic() error {
	dir, cleanup, err := makeTempDir("link-basic")
	if err != nil {
		return err
	}
	defer cleanup()

	origPath := filepath.Join(dir, "original.txt")
	fd, err := syscall.Open(origPath, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	if err := syscall.Close(fd); err != nil {
		return fmt.Errorf("close: %w", err)
	}

	if err := rawLink(origPath, filepath.Join(dir, "hardlink.txt")); err != nil {
		return err
	}

	symPath := filepath.Join(dir, "symlink.txt")
	if err := rawSymlink(origPath, symPath); err != nil {
		return err
	}

	return rawReadlink(symPath)
}

// linkLinkat creates a file and hard links it via linkat(2).
func linkLinkat() error {
	dir, cleanup, err := makeTempDir("link-linkat")
	if err != nil {
		return err
	}
	defer cleanup()

	origName := "linkat-original.txt"
	origPath := filepath.Join(dir, origName)
	fd, err := syscall.Open(origPath, syscall.O_RDWR|syscall.O_CREAT, 0o644)
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

	hardName := "linkat-hard.txt"
	oldBytes, err := syscall.BytePtrFromString(origName)
	if err != nil {
		return fmt.Errorf("old name bytes: %w", err)
	}
	newBytes, err := syscall.BytePtrFromString(hardName)
	if err != nil {
		return fmt.Errorf("new name bytes: %w", err)
	}

	_, _, errno := syscall.Syscall6(
		syscall.SYS_LINKAT,
		uintptr(dirFD),
		uintptr(unsafe.Pointer(oldBytes)),
		uintptr(dirFD),
		uintptr(unsafe.Pointer(newBytes)),
		0, // flags
		0,
	)
	runtime.KeepAlive(oldBytes)
	runtime.KeepAlive(newBytes)
	if errno != 0 {
		return fmt.Errorf("linkat: %w", errno)
	}
	return nil
}

// linkSymlinkat creates a symlink via symlinkat(2).
func linkSymlinkat() error {
	dir, cleanup, err := makeTempDir("link-symlinkat")
	if err != nil {
		return err
	}
	defer cleanup()

	origPath := filepath.Join(dir, "symlinkat-original.txt")
	fd, err := syscall.Open(origPath, syscall.O_RDWR|syscall.O_CREAT, 0o644)
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

	targetBytes, err := syscall.BytePtrFromString(origPath)
	if err != nil {
		return fmt.Errorf("target bytes: %w", err)
	}
	linkName := "symlinkat-link.txt"
	linkBytes, err := syscall.BytePtrFromString(linkName)
	if err != nil {
		return fmt.Errorf("link name bytes: %w", err)
	}

	_, _, errno := syscall.Syscall(
		syscall.SYS_SYMLINKAT,
		uintptr(unsafe.Pointer(targetBytes)),
		uintptr(dirFD),
		uintptr(unsafe.Pointer(linkBytes)),
	)
	runtime.KeepAlive(targetBytes)
	runtime.KeepAlive(linkBytes)
	if errno != 0 {
		return fmt.Errorf("symlinkat: %w", errno)
	}
	return nil
}

// linkReadlinkat creates a symlink, then reads it via readlinkat(2).
func linkReadlinkat() error {
	dir, cleanup, err := makeTempDir("link-readlinkat")
	if err != nil {
		return err
	}
	defer cleanup()

	origPath := filepath.Join(dir, "readlinkat-original.txt")
	fd, err := syscall.Open(origPath, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	if err := syscall.Close(fd); err != nil {
		return fmt.Errorf("close: %w", err)
	}

	// Create symlink using raw SYS_SYMLINK so we don't mix tracepoints.
	linkPath := filepath.Join(dir, "readlinkat-link.txt")
	if err := rawSymlink(origPath, linkPath); err != nil {
		return err
	}

	// Read via readlinkat(2).
	dirFD, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("open dir: %w", err)
	}
	defer syscall.Close(dirFD)

	linkName := "readlinkat-link.txt"
	nameBytes, err := syscall.BytePtrFromString(linkName)
	if err != nil {
		return fmt.Errorf("link name bytes: %w", err)
	}
	buf := make([]byte, 256)
	_, _, errno := syscall.Syscall6(
		syscall.SYS_READLINKAT,
		uintptr(dirFD),
		uintptr(unsafe.Pointer(nameBytes)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		0, 0,
	)
	runtime.KeepAlive(nameBytes)
	runtime.KeepAlive(buf)
	if errno != 0 {
		return fmt.Errorf("readlinkat: %w", errno)
	}
	return nil
}

// linkEnoent attempts to hard link a nonexistent source via raw SYS_LINK.
// The syscall fails with ENOENT, but ior captures the enter_link tracepoint
// because arguments are read on syscall entry.
func linkEnoent() error {
	dir, cleanup, err := makeTempDir("link-enoent")
	if err != nil {
		return err
	}
	defer cleanup()

	srcPath := filepath.Join(dir, "link-enoent-missing.txt")
	dstPath := filepath.Join(dir, "link-enoent-dst.txt")

	srcBytes, err := syscall.BytePtrFromString(srcPath)
	if err != nil {
		return fmt.Errorf("src path bytes: %w", err)
	}
	dstBytes, err := syscall.BytePtrFromString(dstPath)
	if err != nil {
		return fmt.Errorf("dst path bytes: %w", err)
	}

	_, _, errno := syscall.Syscall(
		syscall.SYS_LINK,
		uintptr(unsafe.Pointer(srcBytes)),
		uintptr(unsafe.Pointer(dstBytes)),
		0,
	)
	runtime.KeepAlive(srcBytes)
	runtime.KeepAlive(dstBytes)
	if errno == 0 {
		return fmt.Errorf("expected ENOENT, but link succeeded")
	}
	return nil
}

// linkSymlinkEexist creates a regular file, then attempts to create a symlink
// at the same path via raw SYS_SYMLINK. The syscall fails with EEXIST because
// the link path already exists, but ior captures the enter_symlink tracepoint.
func linkSymlinkEexist() error {
	dir, cleanup, err := makeTempDir("link-symlink-eexist")
	if err != nil {
		return err
	}
	defer cleanup()

	existingPath := filepath.Join(dir, "symlink-eexist.txt")
	fd, err := syscall.Open(existingPath, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	if err := syscall.Close(fd); err != nil {
		return fmt.Errorf("close: %w", err)
	}

	targetBytes, err := syscall.BytePtrFromString("/tmp/dummy-target")
	if err != nil {
		return fmt.Errorf("target bytes: %w", err)
	}
	linkBytes, err := syscall.BytePtrFromString(existingPath)
	if err != nil {
		return fmt.Errorf("link path bytes: %w", err)
	}

	_, _, errno := syscall.Syscall(
		syscall.SYS_SYMLINK,
		uintptr(unsafe.Pointer(targetBytes)),
		uintptr(unsafe.Pointer(linkBytes)),
		0,
	)
	runtime.KeepAlive(targetBytes)
	runtime.KeepAlive(linkBytes)
	if errno == 0 {
		return fmt.Errorf("expected EEXIST, but symlink succeeded")
	}
	return nil
}

// linkReadlinkatEinval creates a regular file and calls readlinkat(2) on it.
// The syscall fails with EINVAL because the path is not a symlink, but ior
// captures the enter_readlinkat tracepoint on syscall entry.
func linkReadlinkatEinval() error {
	dir, cleanup, err := makeTempDir("link-readlinkat-einval")
	if err != nil {
		return err
	}
	defer cleanup()

	regularFile := "readlinkat-einval.txt"
	regularPath := filepath.Join(dir, regularFile)
	fd, err := syscall.Open(regularPath, syscall.O_RDWR|syscall.O_CREAT, 0o644)
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

	nameBytes, err := syscall.BytePtrFromString(regularFile)
	if err != nil {
		return fmt.Errorf("name bytes: %w", err)
	}
	buf := make([]byte, 256)
	_, _, errno := syscall.Syscall6(
		syscall.SYS_READLINKAT,
		uintptr(dirFD),
		uintptr(unsafe.Pointer(nameBytes)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		0, 0,
	)
	runtime.KeepAlive(nameBytes)
	runtime.KeepAlive(buf)
	if errno == 0 {
		return fmt.Errorf("expected EINVAL, but readlinkat succeeded")
	}
	return nil
}

// rawLink calls link(2) via raw SYS_LINK.
func rawLink(oldPath, newPath string) error {
	oldBytes, err := syscall.BytePtrFromString(oldPath)
	if err != nil {
		return fmt.Errorf("old path bytes: %w", err)
	}
	newBytes, err := syscall.BytePtrFromString(newPath)
	if err != nil {
		return fmt.Errorf("new path bytes: %w", err)
	}
	_, _, errno := syscall.Syscall(
		syscall.SYS_LINK,
		uintptr(unsafe.Pointer(oldBytes)),
		uintptr(unsafe.Pointer(newBytes)),
		0,
	)
	runtime.KeepAlive(oldBytes)
	runtime.KeepAlive(newBytes)
	if errno != 0 {
		return fmt.Errorf("link: %w", errno)
	}
	return nil
}

// rawSymlink calls symlink(2) via raw SYS_SYMLINK.
func rawSymlink(target, linkPath string) error {
	targetBytes, err := syscall.BytePtrFromString(target)
	if err != nil {
		return fmt.Errorf("target path bytes: %w", err)
	}
	linkBytes, err := syscall.BytePtrFromString(linkPath)
	if err != nil {
		return fmt.Errorf("link path bytes: %w", err)
	}
	_, _, errno := syscall.Syscall(
		syscall.SYS_SYMLINK,
		uintptr(unsafe.Pointer(targetBytes)),
		uintptr(unsafe.Pointer(linkBytes)),
		0,
	)
	runtime.KeepAlive(targetBytes)
	runtime.KeepAlive(linkBytes)
	if errno != 0 {
		return fmt.Errorf("symlink: %w", errno)
	}
	return nil
}

// rawReadlink calls readlink(2) via raw SYS_READLINK.
func rawReadlink(path string) error {
	pathBytes, err := syscall.BytePtrFromString(path)
	if err != nil {
		return fmt.Errorf("path bytes: %w", err)
	}
	buf := make([]byte, 256)
	_, _, errno := syscall.Syscall(
		syscall.SYS_READLINK,
		uintptr(unsafe.Pointer(pathBytes)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	runtime.KeepAlive(pathBytes)
	runtime.KeepAlive(buf)
	if errno != 0 {
		return fmt.Errorf("readlink: %w", errno)
	}
	return nil
}
