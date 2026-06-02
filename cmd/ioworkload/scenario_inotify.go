package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// inotifyBasic exercises the inotify IPC family end-to-end:
// inotify_init1(IN_CLOEXEC) creates the inotify instance fd (registered as an
// eventfd-kind descriptor, exit ret UNCLASSIFIED, path label "inotifyfd:"),
// inotify_add_watch registers a watch on a file under a temp dir and returns a
// watch descriptor (NOT a tracked fd; exit ret UNCLASSIFIED), inotify_rm_watch
// removes that watch by descriptor, and close releases the instance fd.
//
// It is deliberately non-blocking: it only registers and removes the watch and
// never reads pending events, so the workload returns promptly regardless of
// filesystem activity. The watched path lives under a temp dir that is removed
// on return.
func inotifyBasic() error {
	dir, cleanup, err := makeTempDir("inotify")
	if err != nil {
		return err
	}
	defer cleanup()

	// Create a concrete file to watch so the path resolves to a real inode.
	watched := filepath.Join(dir, "watched")
	if err := os.WriteFile(watched, []byte("ior"), 0o600); err != nil {
		return fmt.Errorf("create watched file: %w", err)
	}

	// inotify_init1 with IN_CLOEXEC; returns the inotify instance fd.
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC)
	if err != nil {
		return fmt.Errorf("inotify_init1: %w", err)
	}
	defer syscall.Close(fd)

	// inotify_add_watch on the instance fd; returns a watch descriptor (wd),
	// which is NOT a file descriptor and must not be registered as a tracked fd.
	mask := uint32(unix.IN_CREATE | unix.IN_DELETE | unix.IN_MODIFY)
	wd, err := unix.InotifyAddWatch(fd, watched, mask)
	if err != nil {
		return fmt.Errorf("inotify_add_watch: %w", err)
	}

	// inotify_rm_watch removes the watch by descriptor on the instance fd.
	if _, err := unix.InotifyRmWatch(fd, uint32(wd)); err != nil {
		return fmt.Errorf("inotify_rm_watch: %w", err)
	}

	return nil
}
