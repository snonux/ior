package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// fanotifyMarks uses three distinct targets so tracing can prove absolute,
// dirfd-relative, and NULL pathname semantics independently. No events need
// reading, and closing the group removes every mark.
func fanotifyMarks() error {
	dir, cleanup, err := makeTempDir("fanotify")
	if err != nil {
		return err
	}
	defer cleanup()
	for _, name := range []string{"absolute", "relative", "null-target"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("ior"), 0o600); err != nil {
			return fmt.Errorf("create fanotify target: %w", err)
		}
	}
	group, err := unix.FanotifyInit(unix.FAN_CLASS_NOTIF|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK, unix.O_RDONLY)
	if err != nil {
		return fmt.Errorf("fanotify_init (requires CAP_SYS_ADMIN): %w", err)
	}
	defer syscall.Close(group)
	dirfd, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("open fanotify directory: %w", err)
	}
	defer syscall.Close(dirfd)
	target, err := syscall.Open(filepath.Join(dir, "null-target"), syscall.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("open fanotify NULL target: %w", err)
	}
	defer syscall.Close(target)
	return exerciseFanotifyMarks(group, dirfd, target, dir)
}

func exerciseFanotifyMarks(group, dirfd, target int, dir string) error {
	absPath, relative, empty, ignored := filepath.Join(dir, "absolute"), "relative", "", "ignored-flush-target"
	for _, call := range []struct {
		name  string
		flags uint
		dfd   int
		path  *string
		want  syscall.Errno
	}{
		{name: "absolute", flags: unix.FAN_MARK_ADD, dfd: -1, path: &absPath},
		{name: "relative", flags: unix.FAN_MARK_ADD, dfd: dirfd, path: &relative},
		{name: "NULL", flags: unix.FAN_MARK_ADD, dfd: target},
		{name: "empty", flags: unix.FAN_MARK_ADD, dfd: target, path: &empty, want: syscall.ENOENT},
		{name: "NULL AT_FDCWD", flags: unix.FAN_MARK_ADD, dfd: unix.AT_FDCWD, want: syscall.EBADF},
		{name: "flush", flags: unix.FAN_MARK_FLUSH, dfd: dirfd, path: &ignored},
	} {
		var pathname *byte
		if call.path != nil {
			var err error
			pathname, err = syscall.BytePtrFromString(*call.path)
			if err != nil {
				return fmt.Errorf("fanotify %s pathname: %w", call.name, err)
			}
		}
		mask := uintptr(unix.FAN_OPEN)
		if call.flags == unix.FAN_MARK_FLUSH {
			mask = 0
		}
		_, _, errno := syscall.Syscall6(unix.SYS_FANOTIFY_MARK, uintptr(group), uintptr(call.flags), mask,
			uintptr(call.dfd), uintptr(unsafe.Pointer(pathname)), 0)
		if errno != call.want {
			return fmt.Errorf("fanotify_mark %s: got %v, want %v", call.name, errno, call.want)
		}
	}
	return nil
}
