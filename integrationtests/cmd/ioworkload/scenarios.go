package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"
)

// scenarios maps scenario names to their execution functions.
var scenarios = map[string]func() error{
	"crash":               crash,
	"open-basic":          openBasic,
	"open-creat":          openCreat,
	"open-by-handle-at":   openByHandleAt,
	"readwrite-basic":   readwriteBasic,
	"readwrite-pread":   readwritePread,
	"readwrite-pwrite":  readwritePwrite,
	"readwrite-readv":   readwriteReadv,
	"readwrite-writev":  readwriteWritev,
	"close-basic":     closeBasic,
	"close-range":     closeRange,
	"dup-basic":       dupBasic,
	"dup-dup2":        dupDup2,
	"dup-dup3":        dupDup3,
	"fcntl-dupfd":          fcntlDupfd,
	"fcntl-setfl":          fcntlSetfl,
	"fcntl-dupfd-cloexec":  fcntlDupfdCloexec,
	"rename-basic":         renameBasic,
	"rename-renameat":      renameRenameat,
	"rename-renameat2":     renameRenameat2,
	"link-basic":      linkBasic,
	"link-linkat":     linkLinkat,
	"link-symlinkat":  linkSymlinkat,
	"link-readlinkat": linkReadlinkat,
	"unlink-basic":    unlinkBasic,
	"unlink-unlinkat": unlinkUnlinkat,
	"unlink-rmdir":    unlinkRmdir,
	"dir-basic":       dirBasic,
	"dir-mkdirat":     dirMkdirat,
	"dir-chdir":       dirChdir,
	"dir-getdents":    dirGetdents,
	"stat-basic":      statBasic,
	"stat-fstat":      statFstat,
	"stat-lstat":      statLstat,
	"stat-newfstatat": statNewfstatat,
	"stat-statx":      statStatx,
	"stat-access":     statAccess,
	"stat-faccessat":  statFaccessat,
	"sync-basic":            syncBasic,
	"sync-fdatasync":        syncFdatasync,
	"sync-sync":             syncSync,
	"sync-sync-file-range":  syncSyncFileRange,
	"truncate-basic":      truncateBasic,
	"truncate-ftruncate":  truncateFtruncate,
	"iouring-setup":       iouringSetup,
	"iouring-enter":       iouringEnter,
	"iouring-register":    iouringRegister,
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

// openCreat creates a file via raw SYS_CREAT.
// Go's syscall.Creat wraps Open which delegates to openat on amd64,
// so we use the raw syscall to actually exercise the creat tracepoint.
func openCreat() error {
	dir, cleanup, err := makeTempDir("open-creat")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "creatfile.txt")
	pathBytes, err := syscall.BytePtrFromString(path)
	if err != nil {
		return fmt.Errorf("path bytes: %w", err)
	}
	fd, _, errno := syscall.Syscall(syscall.SYS_CREAT, uintptr(unsafe.Pointer(pathBytes)), 0o644, 0)
	runtime.KeepAlive(pathBytes)
	if errno != 0 {
		return fmt.Errorf("creat: %w", errno)
	}
	return syscall.Close(int(fd))
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

// readwritePread opens a file, writes data, then reads it back via pread64.
func readwritePread() error {
	dir, cleanup, err := makeTempDir("readwrite-pread")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "preadfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	data := []byte("pread test data")
	if _, err := syscall.Write(fd, data); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	buf := make([]byte, len(data))
	if _, err := syscall.Pread(fd, buf, 0); err != nil {
		return fmt.Errorf("pread: %w", err)
	}
	return nil
}

// readwritePwrite opens a file and writes data via pwrite64.
func readwritePwrite() error {
	dir, cleanup, err := makeTempDir("readwrite-pwrite")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "pwritefile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	if _, err := syscall.Pwrite(fd, []byte("pwrite test data"), 0); err != nil {
		return fmt.Errorf("pwrite: %w", err)
	}
	return nil
}

// readwriteReadv opens a file, writes data, then reads it back via readv.
func readwriteReadv() error {
	dir, cleanup, err := makeTempDir("readwrite-readv")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "readvfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	data := []byte("readv test data here")
	if _, err := syscall.Write(fd, data); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	if _, err := syscall.Seek(fd, 0, 0); err != nil {
		return fmt.Errorf("seek: %w", err)
	}

	buf1 := make([]byte, 5)
	buf2 := make([]byte, 15)
	iovs := []syscall.Iovec{
		{Base: &buf1[0], Len: uint64(len(buf1))},
		{Base: &buf2[0], Len: uint64(len(buf2))},
	}
	_, _, errno := syscall.Syscall(syscall.SYS_READV, uintptr(fd), uintptr(unsafe.Pointer(&iovs[0])), uintptr(len(iovs)))
	runtime.KeepAlive(buf1)
	runtime.KeepAlive(buf2)
	if errno != 0 {
		return fmt.Errorf("readv: %w", errno)
	}
	return nil
}

// readwriteWritev opens a file and writes data via writev.
func readwriteWritev() error {
	dir, cleanup, err := makeTempDir("readwrite-writev")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "writevfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	buf1 := []byte("writev ")
	buf2 := []byte("test data")
	iovs := []syscall.Iovec{
		{Base: &buf1[0], Len: uint64(len(buf1))},
		{Base: &buf2[0], Len: uint64(len(buf2))},
	}
	_, _, errno := syscall.Syscall(syscall.SYS_WRITEV, uintptr(fd), uintptr(unsafe.Pointer(&iovs[0])), uintptr(len(iovs)))
	runtime.KeepAlive(buf1)
	runtime.KeepAlive(buf2)
	if errno != 0 {
		return fmt.Errorf("writev: %w", errno)
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

const sysCloseRange = 436

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

// dupDup2 opens a file and duplicates the fd onto a specific target fd via dup2.
func dupDup2() error {
	dir, cleanup, err := makeTempDir("dup-dup2")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "dup2file.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	// Use a high fd number to avoid collisions.
	targetFd := 500
	if err := syscall.Dup2(fd, targetFd); err != nil {
		return fmt.Errorf("dup2: %w", err)
	}
	defer syscall.Close(targetFd)

	if _, err := syscall.Write(targetFd, []byte("via dup2")); err != nil {
		return fmt.Errorf("write via dup2: %w", err)
	}
	return nil
}

// dupDup3 opens a file and duplicates the fd onto a specific target fd via dup3
// with O_CLOEXEC flag.
func dupDup3() error {
	dir, cleanup, err := makeTempDir("dup-dup3")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "dup3file.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	// Use a high fd number to avoid collisions.
	targetFd := 501
	if err := syscall.Dup3(fd, targetFd, syscall.O_CLOEXEC); err != nil {
		return fmt.Errorf("dup3: %w", err)
	}
	defer syscall.Close(targetFd)

	if _, err := syscall.Write(targetFd, []byte("via dup3")); err != nil {
		return fmt.Errorf("write via dup3: %w", err)
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

// fcntlSetfl uses fcntl F_GETFL/F_SETFL to read and modify file status flags.
func fcntlSetfl() error {
	dir, cleanup, err := makeTempDir("fcntl-setfl")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "fcntlsetflfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFL, 0)
	if errno != 0 {
		return fmt.Errorf("fcntl F_GETFL: %w", errno)
	}

	_, _, errno = syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_SETFL, flags|syscall.O_APPEND)
	if errno != 0 {
		return fmt.Errorf("fcntl F_SETFL: %w", errno)
	}

	if _, err := syscall.Write(fd, []byte("appended via fcntl setfl")); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return nil
}

// fcntlDupfdCloexec uses fcntl F_DUPFD_CLOEXEC to duplicate a file descriptor
// with the close-on-exec flag set.
func fcntlDupfdCloexec() error {
	dir, cleanup, err := makeTempDir("fcntl-dupfd-cloexec")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "fcntlcloexecfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	newFd, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_DUPFD_CLOEXEC, 0)
	if errno != 0 {
		return fmt.Errorf("fcntl F_DUPFD_CLOEXEC: %w", errno)
	}
	defer syscall.Close(int(newFd))

	if _, err := syscall.Write(int(newFd), []byte("via fcntl dupfd cloexec")); err != nil {
		return fmt.Errorf("write via fcntl dup cloexec: %w", err)
	}
	return nil
}

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

const sysRenameat2 = 316 // SYS_RENAMEAT2 on amd64

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

	// Hard link via raw SYS_LINK.
	hardPath := filepath.Join(dir, "hardlink.txt")
	origBytes, err := syscall.BytePtrFromString(origPath)
	if err != nil {
		return fmt.Errorf("orig path bytes: %w", err)
	}
	hardBytes, err := syscall.BytePtrFromString(hardPath)
	if err != nil {
		return fmt.Errorf("hard path bytes: %w", err)
	}
	_, _, errno := syscall.Syscall(
		syscall.SYS_LINK,
		uintptr(unsafe.Pointer(origBytes)),
		uintptr(unsafe.Pointer(hardBytes)),
		0,
	)
	runtime.KeepAlive(origBytes)
	runtime.KeepAlive(hardBytes)
	if errno != 0 {
		return fmt.Errorf("link: %w", errno)
	}

	// Symlink via raw SYS_SYMLINK.
	symPath := filepath.Join(dir, "symlink.txt")
	targetBytes, err := syscall.BytePtrFromString(origPath)
	if err != nil {
		return fmt.Errorf("target path bytes: %w", err)
	}
	symBytes, err := syscall.BytePtrFromString(symPath)
	if err != nil {
		return fmt.Errorf("sym path bytes: %w", err)
	}
	_, _, errno = syscall.Syscall(
		syscall.SYS_SYMLINK,
		uintptr(unsafe.Pointer(targetBytes)),
		uintptr(unsafe.Pointer(symBytes)),
		0,
	)
	runtime.KeepAlive(targetBytes)
	runtime.KeepAlive(symBytes)
	if errno != 0 {
		return fmt.Errorf("symlink: %w", errno)
	}

	// Readlink via raw SYS_READLINK.
	symBytes2, err := syscall.BytePtrFromString(symPath)
	if err != nil {
		return fmt.Errorf("sym path bytes: %w", err)
	}
	buf := make([]byte, 256)
	_, _, errno = syscall.Syscall(
		syscall.SYS_READLINK,
		uintptr(unsafe.Pointer(symBytes2)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	runtime.KeepAlive(symBytes2)
	runtime.KeepAlive(buf)
	if errno != 0 {
		return fmt.Errorf("readlink: %w", errno)
	}
	return nil
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
	targetBytes, err := syscall.BytePtrFromString(origPath)
	if err != nil {
		return fmt.Errorf("target bytes: %w", err)
	}
	linkPathBytes, err := syscall.BytePtrFromString(linkPath)
	if err != nil {
		return fmt.Errorf("link path bytes: %w", err)
	}
	_, _, errno := syscall.Syscall(
		syscall.SYS_SYMLINK,
		uintptr(unsafe.Pointer(targetBytes)),
		uintptr(unsafe.Pointer(linkPathBytes)),
		0,
	)
	runtime.KeepAlive(targetBytes)
	runtime.KeepAlive(linkPathBytes)
	if errno != 0 {
		return fmt.Errorf("symlink: %w", errno)
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
	_, _, errno = syscall.Syscall6(
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

// unlinkBasic creates a file and unlinks it via raw SYS_UNLINK.
// We use the raw syscall because Go's syscall.Unlink wraps unlinkat on amd64.
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

	pathBytes, err := syscall.BytePtrFromString(path)
	if err != nil {
		return fmt.Errorf("path bytes: %w", err)
	}
	_, _, errno := syscall.Syscall(syscall.SYS_UNLINK, uintptr(unsafe.Pointer(pathBytes)), 0, 0)
	runtime.KeepAlive(pathBytes)
	if errno != 0 {
		return fmt.Errorf("unlink: %w", errno)
	}
	return nil
}

// unlinkUnlinkat creates a file and unlinks it via unlinkat(2).
func unlinkUnlinkat() error {
	dir, cleanup, err := makeTempDir("unlink-unlinkat")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "unlinkat-file.txt")
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

	nameBytes, err := syscall.BytePtrFromString("unlinkat-file.txt")
	if err != nil {
		return fmt.Errorf("name bytes: %w", err)
	}
	_, _, errno := syscall.Syscall(syscall.SYS_UNLINKAT, uintptr(dirFD), uintptr(unsafe.Pointer(nameBytes)), 0)
	runtime.KeepAlive(nameBytes)
	if errno != 0 {
		return fmt.Errorf("unlinkat: %w", errno)
	}
	return nil
}

// unlinkRmdir creates a directory and removes it via raw SYS_RMDIR.
// We use the raw syscall because Go's syscall.Rmdir wraps unlinkat on amd64.
func unlinkRmdir() error {
	dir, cleanup, err := makeTempDir("unlink-rmdir")
	if err != nil {
		return err
	}
	defer cleanup()

	subDir := filepath.Join(dir, "rmdir-me")
	if err := syscall.Mkdir(subDir, 0o755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	pathBytes, err := syscall.BytePtrFromString(subDir)
	if err != nil {
		return fmt.Errorf("path bytes: %w", err)
	}
	_, _, errno := syscall.Syscall(syscall.SYS_RMDIR, uintptr(unsafe.Pointer(pathBytes)), 0, 0)
	runtime.KeepAlive(pathBytes)
	if errno != 0 {
		return fmt.Errorf("rmdir: %w", errno)
	}
	return nil
}

// dirBasic creates a directory via raw SYS_MKDIR, checks access, then removes it
// via raw SYS_RMDIR. We use raw syscalls because Go's syscall.Mkdir wraps mkdirat
// and syscall.Rmdir wraps unlinkat on amd64.
func dirBasic() error {
	dir, cleanup, err := makeTempDir("dir-basic")
	if err != nil {
		return err
	}
	defer cleanup()

	subDir := filepath.Join(dir, "subdir")
	pathBytes, err := syscall.BytePtrFromString(subDir)
	if err != nil {
		return fmt.Errorf("path bytes: %w", err)
	}
	_, _, errno := syscall.Syscall(syscall.SYS_MKDIR, uintptr(unsafe.Pointer(pathBytes)), 0o755, 0)
	runtime.KeepAlive(pathBytes)
	if errno != 0 {
		return fmt.Errorf("mkdir: %w", errno)
	}

	if err := syscall.Access(subDir, syscall.F_OK); err != nil {
		return fmt.Errorf("access: %w", err)
	}

	pathBytes2, err := syscall.BytePtrFromString(subDir)
	if err != nil {
		return fmt.Errorf("path bytes: %w", err)
	}
	_, _, errno = syscall.Syscall(syscall.SYS_RMDIR, uintptr(unsafe.Pointer(pathBytes2)), 0, 0)
	runtime.KeepAlive(pathBytes2)
	if errno != 0 {
		return fmt.Errorf("rmdir: %w", errno)
	}
	return nil
}

// dirMkdirat creates a directory via mkdirat(2) using Go's syscall.Mkdir
// which wraps mkdirat with AT_FDCWD on amd64.
func dirMkdirat() error {
	dir, cleanup, err := makeTempDir("dir-mkdirat")
	if err != nil {
		return err
	}
	defer cleanup()

	subDir := filepath.Join(dir, "mkdirat-subdir")
	if err := syscall.Mkdir(subDir, 0o755); err != nil {
		return fmt.Errorf("mkdirat: %w", err)
	}
	return nil
}

// dirChdir creates a temp directory, then changes to it via chdir(2).
// Restores the original working directory afterward.
func dirChdir() error {
	origDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("getwd: %w", err)
	}

	dir, cleanup, err := makeTempDir("dir-chdir")
	if err != nil {
		return err
	}
	defer cleanup()
	defer syscall.Chdir(origDir)

	if err := syscall.Chdir(dir); err != nil {
		return fmt.Errorf("chdir: %w", err)
	}
	return nil
}

// dirGetdents opens a directory and reads its entries via getdents64(2).
func dirGetdents() error {
	dir, cleanup, err := makeTempDir("dir-getdents")
	if err != nil {
		return err
	}
	defer cleanup()

	// Create a file so getdents has something to return.
	filePath := filepath.Join(dir, "getdents-file.txt")
	fd, err := syscall.Open(filePath, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open file: %w", err)
	}
	syscall.Close(fd)

	dirFD, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("open dir: %w", err)
	}
	defer syscall.Close(dirFD)

	buf := make([]byte, 4096)
	_, _, errno := syscall.Syscall(syscall.SYS_GETDENTS64, uintptr(dirFD), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	runtime.KeepAlive(buf)
	if errno != 0 {
		return fmt.Errorf("getdents64: %w", errno)
	}
	return nil
}

// statBasic creates a file and stats it via raw SYS_STAT (newstat).
// We use the raw syscall because Go's syscall.Stat wraps newfstatat on amd64.
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
	syscall.Close(fd)

	var stat syscall.Stat_t
	pathBytes, err := syscall.BytePtrFromString(path)
	if err != nil {
		return fmt.Errorf("path bytes: %w", err)
	}
	_, _, errno := syscall.Syscall(syscall.SYS_STAT, uintptr(unsafe.Pointer(pathBytes)), uintptr(unsafe.Pointer(&stat)), 0)
	runtime.KeepAlive(pathBytes)
	runtime.KeepAlive(&stat)
	if errno != 0 {
		return fmt.Errorf("stat: %w", errno)
	}
	return nil
}

// statFstat creates a file and stats it via raw SYS_FSTAT (newfstat).
// This is an fd_event, so ior resolves the path via its fd lookup table.
func statFstat() error {
	dir, cleanup, err := makeTempDir("stat-fstat")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "fstatfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	var stat syscall.Stat_t
	_, _, errno := syscall.Syscall(syscall.SYS_FSTAT, uintptr(fd), uintptr(unsafe.Pointer(&stat)), 0)
	runtime.KeepAlive(&stat)
	if errno != 0 {
		return fmt.Errorf("fstat: %w", errno)
	}
	return nil
}

// statLstat creates a file and stats it via raw SYS_LSTAT (newlstat).
// We use the raw syscall because Go's syscall.Lstat wraps newfstatat on amd64.
func statLstat() error {
	dir, cleanup, err := makeTempDir("stat-lstat")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "lstatfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	syscall.Close(fd)

	var stat syscall.Stat_t
	pathBytes, err := syscall.BytePtrFromString(path)
	if err != nil {
		return fmt.Errorf("path bytes: %w", err)
	}
	_, _, errno := syscall.Syscall(syscall.SYS_LSTAT, uintptr(unsafe.Pointer(pathBytes)), uintptr(unsafe.Pointer(&stat)), 0)
	runtime.KeepAlive(pathBytes)
	runtime.KeepAlive(&stat)
	if errno != 0 {
		return fmt.Errorf("lstat: %w", errno)
	}
	return nil
}

// statNewfstatat creates a file and stats it via Go's syscall.Stat, which
// wraps SYS_NEWFSTATAT (fstatat with AT_FDCWD) on amd64.
func statNewfstatat() error {
	dir, cleanup, err := makeTempDir("stat-newfstatat")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "fstatatfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	syscall.Close(fd)

	var stat syscall.Stat_t
	if err := syscall.Stat(path, &stat); err != nil {
		return fmt.Errorf("newfstatat: %w", err)
	}
	return nil
}

const (
	sysStatx       = 332
	rOK            = 0x4   // R_OK
	statxBasicMask = 0x07ff // STATX_BASIC_STATS
)

const atFDCwd = -100 // AT_FDCWD

// statStatx creates a file and stats it via raw statx(2) syscall.
func statStatx() error {
	dir, cleanup, err := makeTempDir("stat-statx")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "statxfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	syscall.Close(fd)

	pathBytes, err := syscall.BytePtrFromString(path)
	if err != nil {
		return fmt.Errorf("path bytes: %w", err)
	}
	var buf [256]byte // statx struct is ~256 bytes
	_, _, errno := syscall.Syscall6(
		sysStatx,
		^uintptr(99), // AT_FDCWD (-100)
		uintptr(unsafe.Pointer(pathBytes)),
		0,
		statxBasicMask,
		uintptr(unsafe.Pointer(&buf[0])),
		0,
	)
	runtime.KeepAlive(pathBytes)
	runtime.KeepAlive(buf)
	if errno != 0 {
		return fmt.Errorf("statx: %w", errno)
	}
	return nil
}

// statAccess creates a file and checks access via raw SYS_ACCESS.
// We use the raw syscall because Go's syscall.Access wraps faccessat on amd64.
func statAccess() error {
	dir, cleanup, err := makeTempDir("stat-access")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "accessfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	syscall.Close(fd)

	pathBytes, err := syscall.BytePtrFromString(path)
	if err != nil {
		return fmt.Errorf("path bytes: %w", err)
	}
	_, _, errno := syscall.Syscall(syscall.SYS_ACCESS, uintptr(unsafe.Pointer(pathBytes)), rOK, 0)
	runtime.KeepAlive(pathBytes)
	if errno != 0 {
		return fmt.Errorf("access: %w", errno)
	}
	return nil
}

// statFaccessat creates a file and checks access via faccessat(2).
// Go's syscall.Faccessat wraps SYS_FACCESSAT.
func statFaccessat() error {
	dir, cleanup, err := makeTempDir("stat-faccessat")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "faccessatfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	syscall.Close(fd)

	if err := syscall.Faccessat(atFDCwd, path, uint32(rOK), 0); err != nil {
		return fmt.Errorf("faccessat: %w", err)
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

// truncateBasic opens a file, writes data, then truncates it via
// syscall.Truncate which uses SYS_TRUNCATE directly on amd64 (path-based).
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

	if _, err := syscall.Write(fd, []byte("truncate this content")); err != nil {
		syscall.Close(fd)
		return fmt.Errorf("write: %w", err)
	}
	syscall.Close(fd)

	return syscall.Truncate(path, 5)
}

// truncateFtruncate opens a file, writes data, then truncates it via
// syscall.Ftruncate which uses SYS_FTRUNCATE directly on amd64 (fd-based).
func truncateFtruncate() error {
	dir, cleanup, err := makeTempDir("truncate-ftruncate")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "ftruncfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	if _, err := syscall.Write(fd, []byte("ftruncate this content")); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return syscall.Ftruncate(fd, 5)
}

// openByHandleAt creates a file, resolves its handle via name_to_handle_at,
// then opens it via open_by_handle_at. Requires root (CAP_DAC_READ_SEARCH).
// LockOSThread prevents goroutine migration between the two syscalls so that
// ior sees the same TID for both and can correlate the path.
func openByHandleAt() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	dir, cleanup, err := makeTempDir("open-by-handle-at")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "handlefile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	if err := syscall.Close(fd); err != nil {
		return fmt.Errorf("close: %w", err)
	}

	handle, mountFD, err := nameToHandleAt(dir, "handlefile.txt")
	if err != nil {
		return fmt.Errorf("name_to_handle_at: %w", err)
	}
	defer syscall.Close(mountFD)

	fd2, err := openByHandleAtSyscall(mountFD, handle, syscall.O_RDONLY)
	if err != nil {
		return fmt.Errorf("open_by_handle_at: %w", err)
	}
	return syscall.Close(fd2)
}

// fileHandle matches the kernel's struct file_handle layout.
type fileHandle struct {
	Size uint32
	Type int32
	// Handle bytes follow immediately after.
}

const (
	sysNameToHandleAt = 303
	sysOpenByHandleAt = 304
)

// nameToHandleAt calls name_to_handle_at(2) and returns the file handle
// and the directory fd. The caller can pass this dirFD as the mount_fd
// argument to open_by_handle_at since any fd on the same filesystem works.
func nameToHandleAt(dirPath, name string) ([]byte, int, error) {
	dirFD, err := syscall.Open(dirPath, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, 0, fmt.Errorf("open dir: %w", err)
	}

	nameBytes, err := syscall.BytePtrFromString(name)
	if err != nil {
		syscall.Close(dirFD)
		return nil, 0, fmt.Errorf("name bytes: %w", err)
	}

	// Start with a buffer large enough for most handles.
	buf := make([]byte, unsafe.Sizeof(fileHandle{})+128)
	fh := (*fileHandle)(unsafe.Pointer(&buf[0]))
	fh.Size = uint32(len(buf) - int(unsafe.Sizeof(fileHandle{})))

	var mountID int32
	_, _, errno := syscall.Syscall6(
		sysNameToHandleAt,
		uintptr(dirFD),
		uintptr(unsafe.Pointer(nameBytes)),
		uintptr(unsafe.Pointer(fh)),
		uintptr(unsafe.Pointer(&mountID)),
		0, 0,
	)
	if errno != 0 {
		syscall.Close(dirFD)
		return nil, 0, fmt.Errorf("syscall: %w", errno)
	}

	handleLen := int(unsafe.Sizeof(fileHandle{})) + int(fh.Size)
	handle := make([]byte, handleLen)
	copy(handle, buf[:handleLen])

	return handle, dirFD, nil
}

// openByHandleAtSyscall calls open_by_handle_at(2).
func openByHandleAtSyscall(mountFD int, handle []byte, flags int) (int, error) {
	fd, _, errno := syscall.Syscall(
		sysOpenByHandleAt,
		uintptr(mountFD),
		uintptr(unsafe.Pointer(&handle[0])),
		uintptr(flags),
	)
	if errno != 0 {
		return 0, fmt.Errorf("syscall: %w", errno)
	}
	return int(fd), nil
}

const (
	sysIoUringSetup    = 425
	sysIoUringEnter    = 426
	sysIoUringRegister = 427

	// io_uring_params struct size: 10 x uint32 + io_sqring_offsets(40) + io_cqring_offsets(40) = 120 bytes.
	ioUringParamsSize = 120

	ioringRegisterProbe = 8 // IORING_REGISTER_PROBE
)

// iouringSetup creates an io_uring instance via io_uring_setup(2) and closes the fd.
func iouringSetup() error {
	fd, err := ioUringSetupRing(1)
	if err != nil {
		return err
	}
	return syscall.Close(fd)
}

// iouringEnter creates an io_uring instance, then calls io_uring_enter(2)
// with zero submissions/completions to exercise the enter tracepoint.
func iouringEnter() error {
	fd, err := ioUringSetupRing(1)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	_, _, errno := syscall.Syscall6(
		sysIoUringEnter,
		uintptr(fd),
		0, // to_submit
		0, // min_complete
		0, // flags
		0, // sig
		0, // sz
	)
	if errno != 0 {
		return fmt.Errorf("io_uring_enter: %w", errno)
	}
	return nil
}

// iouringRegister creates an io_uring instance, then calls io_uring_register(2)
// with IORING_REGISTER_PROBE to exercise the register tracepoint.
func iouringRegister() error {
	fd, err := ioUringSetupRing(1)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	// io_uring_probe header is 16 bytes; we don't need probe_op entries.
	var probeBuf [16]byte
	_, _, errno := syscall.Syscall6(
		sysIoUringRegister,
		uintptr(fd),
		ioringRegisterProbe,
		uintptr(unsafe.Pointer(&probeBuf[0])),
		0, // nr_args (0 ops requested)
		0, 0,
	)
	runtime.KeepAlive(probeBuf)
	if errno != 0 {
		return fmt.Errorf("io_uring_register: %w", errno)
	}
	return nil
}

// ioUringSetupRing calls io_uring_setup(2) and returns the ring fd.
func ioUringSetupRing(entries uint32) (int, error) {
	var params [ioUringParamsSize]byte
	fd, _, errno := syscall.Syscall(
		sysIoUringSetup,
		uintptr(entries),
		uintptr(unsafe.Pointer(&params[0])),
		0,
	)
	runtime.KeepAlive(params)
	if errno != 0 {
		return 0, fmt.Errorf("io_uring_setup: %w", errno)
	}
	return int(fd), nil
}

// crash simulates a workload that fails with a non-zero exit code.
// Used to verify the test harness handles workload failures gracefully.
func crash() error {
	return fmt.Errorf("intentional crash for testing")
}
