package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// scenarios maps scenario names to their execution functions.
var scenarios = map[string]func() error{
	"open-basic":      openBasic,
	"open-creat":      openCreat,
	"readwrite-basic": readwriteBasic,
	"close-basic":     closeBasic,
	"dup-basic":       dupBasic,
	"fcntl-dupfd":     fcntlDupfd,
	"rename-basic":    renameBasic,
	"link-basic":      linkBasic,
	"unlink-basic":    unlinkBasic,
	"dir-basic":       dirBasic,
	"stat-basic":      statBasic,
	"sync-basic":      syncBasic,
	"truncate-basic":  truncateBasic,
}

func makeTempDir(prefix string) (string, func(), error) {
	dir, err := os.MkdirTemp("", fmt.Sprintf("ioworkload-%s-", prefix))
	if err != nil {
		return "", nil, fmt.Errorf("create temp dir: %w", err)
	}
	cleanup := func() { os.RemoveAll(dir) }
	return dir, cleanup, nil
}

// openBasic opens a file with O_RDWR|O_CREAT, then closes it.
func openBasic() error {
	dir, cleanup, err := makeTempDir("open-basic")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "testfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	return syscall.Close(fd)
}

// openCreat uses the creat syscall to create a file.
func openCreat() error {
	dir, cleanup, err := makeTempDir("open-creat")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "creatfile.txt")
	fd, err := syscall.Creat(path, 0o644)
	if err != nil {
		return fmt.Errorf("creat: %w", err)
	}
	return syscall.Close(fd)
}

// readwriteBasic opens a file, writes data, seeks to start, reads it back.
func readwriteBasic() error {
	dir, cleanup, err := makeTempDir("readwrite-basic")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "rwfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	data := []byte("hello from ioworkload")
	if _, err := syscall.Write(fd, data); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	if _, err := syscall.Seek(fd, 0, 0); err != nil {
		return fmt.Errorf("seek: %w", err)
	}

	buf := make([]byte, len(data))
	if _, err := syscall.Read(fd, buf); err != nil {
		return fmt.Errorf("read: %w", err)
	}
	return nil
}

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

// dupBasic opens a file, dups the fd, writes via the dup, closes both.
func dupBasic() error {
	dir, cleanup, err := makeTempDir("dup-basic")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "dupfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	newFd, err := syscall.Dup(fd)
	if err != nil {
		return fmt.Errorf("dup: %w", err)
	}
	defer syscall.Close(newFd)

	if _, err := syscall.Write(newFd, []byte("via dup")); err != nil {
		return fmt.Errorf("write via dup: %w", err)
	}
	return nil
}

// fcntlDupfd uses fcntl F_DUPFD to duplicate a file descriptor.
func fcntlDupfd() error {
	dir, cleanup, err := makeTempDir("fcntl-dupfd")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "fcntlfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	newFd, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_DUPFD, 0)
	if errno != 0 {
		return fmt.Errorf("fcntl F_DUPFD: %w", errno)
	}
	defer syscall.Close(int(newFd))

	if _, err := syscall.Write(int(newFd), []byte("via fcntl")); err != nil {
		return fmt.Errorf("write via fcntl dup: %w", err)
	}
	return nil
}

// renameBasic creates a file and renames it.
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

	return syscall.Rename(oldPath, newPath)
}

// linkBasic creates a file, hard links it, and symlinks it.
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

	hardPath := filepath.Join(dir, "hardlink.txt")
	if err := syscall.Link(origPath, hardPath); err != nil {
		return fmt.Errorf("link: %w", err)
	}

	symPath := filepath.Join(dir, "symlink.txt")
	if err := syscall.Symlink(origPath, symPath); err != nil {
		return fmt.Errorf("symlink: %w", err)
	}

	buf := make([]byte, 256)
	if _, err := syscall.Readlink(symPath, buf); err != nil {
		return fmt.Errorf("readlink: %w", err)
	}
	return nil
}

// unlinkBasic creates a file and unlinks it.
func unlinkBasic() error {
	dir, cleanup, err := makeTempDir("unlink-basic")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "unlinkme.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	if err := syscall.Close(fd); err != nil {
		return fmt.Errorf("close: %w", err)
	}

	return syscall.Unlink(path)
}

// dirBasic creates a directory, checks access, then removes it.
func dirBasic() error {
	dir, cleanup, err := makeTempDir("dir-basic")
	if err != nil {
		return err
	}
	defer cleanup()

	subDir := filepath.Join(dir, "subdir")
	if err := syscall.Mkdir(subDir, 0o755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	if err := syscall.Access(subDir, syscall.F_OK); err != nil {
		return fmt.Errorf("access: %w", err)
	}
	return syscall.Rmdir(subDir)
}

// statBasic creates a file and stats it.
func statBasic() error {
	dir, cleanup, err := makeTempDir("stat-basic")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "statfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("fstat: %w", err)
	}
	if err := syscall.Stat(path, &stat); err != nil {
		return fmt.Errorf("stat: %w", err)
	}
	return nil
}

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

// truncateBasic opens a file, writes data, and truncates it.
func truncateBasic() error {
	dir, cleanup, err := makeTempDir("truncate-basic")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "truncfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	if _, err := syscall.Write(fd, []byte("truncate this content")); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return syscall.Ftruncate(fd, 5)
}
