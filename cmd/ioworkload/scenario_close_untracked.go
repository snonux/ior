package main

import (
	"fmt"
	"path/filepath"
	"syscall"
	"time"
)

// closeUntrackedFiles is how many descriptors close-untracked opens before ior
// attaches. Each close races ior's processing of its row against the pipe(2)
// that reuses the number, so one iteration would make the regression check a
// coin flip; with 64 the pre-fix resolver (which read /proc/<pid>/fd after the
// close and named about a quarter of the rows after the reusing pipe) fails
// the integration test reliably.
const closeUntrackedFiles = 64

// closeUntrackedSettle is how long close-untracked waits between its write to
// the first descriptor and the closes. ior resolves that descriptor through
// procfs when it processes the write row, which lags the syscall; the pause
// lets that read happen while the file is still open, so the close row has a
// pre-close answer to use. Without it the read can land after the close and
// the reusing pipe, and the close row is (correctly) left unnamed.
const closeUntrackedSettle = 500 * time.Millisecond

// closeUntrackedState carries the descriptors close-untracked opened in its
// prestart hook over to the scenario proper.
var closeUntrackedState struct {
	fds     []int
	cleanup func()
}

// openUntrackedFiles is close-untracked's prestart hook: it runs before the
// PID is announced, i.e. before ior starts, so ior never sees these opens and
// its fd table does not know the descriptors.
func openUntrackedFiles() error {
	dir, cleanup, err := makeTempDir("close-untracked")
	if err != nil {
		return err
	}
	closeUntrackedState.cleanup = cleanup
	for i := range closeUntrackedFiles {
		path := filepath.Join(dir, fmt.Sprintf("closeuntracked-%d.txt", i))
		fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
		if err != nil {
			cleanup()
			return fmt.Errorf("open %d: %w", i, err)
		}
		closeUntrackedState.fds = append(closeUntrackedState.fds, fd)
	}
	return nil
}

// closeUntracked closes the descriptors opened before ior attached (task
// jr2). The first one is written to first, and closeUntrackedSettle later, so
// ior resolves it through procfs while it is open and can name its close.
// Every close is followed at once by a pipe(2), which takes the lowest free
// number, i.e. the one just closed; the pipes stay open until the process
// exits, so a resolver that reads /proc/<pid>/fd after the close sees the pipe
// there instead of the file.
func closeUntracked() error {
	defer closeUntrackedState.cleanup()
	fds := closeUntrackedState.fds
	if _, err := syscall.Write(fds[0], []byte("named-before-close")); err != nil {
		return fmt.Errorf("write fd %d: %w", fds[0], err)
	}
	time.Sleep(closeUntrackedSettle)
	for _, fd := range fds {
		if err := syscall.Close(fd); err != nil {
			return fmt.Errorf("close fd %d: %w", fd, err)
		}
		var pipefd [2]int
		if err := syscall.Pipe2(pipefd[:], syscall.O_CLOEXEC); err != nil {
			return fmt.Errorf("pipe2 after closing fd %d: %w", fd, err)
		}
		if pipefd[0] != fd {
			return fmt.Errorf("pipe2 after closing fd %d got %v, not the closed number", fd, pipefd)
		}
	}
	return nil
}
