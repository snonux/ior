package common

import (
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"

	tea "charm.land/bubbletea/v2"
)

// execState records the child process a tea.Exec currently runs in the
// foreground, so the process-level signal watcher (internal/tui/signals.go)
// can tell "an editor owns the terminal" from "the dashboard does" and can
// terminate that child. There is one terminal and Bubble Tea runs an
// ExecCommand inside its event loop (blocking it), so at most one exec is ever
// active and process-wide state is accurate rather than a shortcut.
var execState struct {
	mu     sync.Mutex
	active bool
	proc   *os.Process // nil until the child has started
}

// ExecActive reports whether a child started through ExecProcess is running.
//
// Bubble Tea itself ignored SIGINT/SIGTERM while an exec ran (it sets
// ignoreSignals around ReleaseTerminal): in the cooked-mode editor a Ctrl+C is
// delivered to the whole foreground process group, so it reaches ior too, but
// it is the editor's key, not a request to quit. ior turned Bubble Tea's
// handler off (see internal/tui/signals.go), so the watcher needs this to
// keep that behaviour.
func ExecActive() bool {
	execState.mu.Lock()
	defer execState.mu.Unlock()
	return execState.active
}

// SignalExec sends sig to the running exec child. It does nothing when no
// exec is active or the child has not started, and ignores a child that
// already exited.
func SignalExec(sig syscall.Signal) {
	execState.mu.Lock()
	proc := execState.proc
	execState.mu.Unlock()
	if proc != nil {
		_ = proc.Signal(sig)
	}
}

// ExecProcess is tea.ExecProcess with ExecActive/SignalExec bookkeeping: it
// runs c in the foreground with the terminal released, calling fn with the
// result. Use it instead of tea.ExecProcess for any child that owns the
// terminal, so termination signals are handled correctly meanwhile.
func ExecProcess(c *exec.Cmd, fn tea.ExecCallback) tea.Cmd {
	return tea.Exec(&trackedExec{Cmd: c}, fn)
}

// trackedExec is Bubble Tea's own exec.Cmd adapter plus the state above.
type trackedExec struct{ *exec.Cmd }

// Run marks the exec active before the child starts (so a signal in the
// start-up window is already recognised), runs it to completion and clears
// the state afterwards on every path.
func (t *trackedExec) Run() error {
	execState.mu.Lock()
	execState.active = true
	execState.mu.Unlock()
	defer func() {
		execState.mu.Lock()
		execState.active, execState.proc = false, nil
		execState.mu.Unlock()
	}()

	if err := t.Start(); err != nil {
		return err
	}
	execState.mu.Lock()
	execState.proc = t.Process
	execState.mu.Unlock()
	return t.Wait()
}

// The setters mirror Bubble Tea's unexported adapter: they only fill streams
// the caller left unset, so a command with its own redirections keeps them.

// SetStdin gives the child the terminal's input unless it has its own.
func (t *trackedExec) SetStdin(r io.Reader) {
	if t.Stdin == nil {
		t.Stdin = r
	}
}

// SetStdout gives the child the terminal's output unless it has its own.
func (t *trackedExec) SetStdout(w io.Writer) {
	if t.Stdout == nil {
		t.Stdout = w
	}
}

// SetStderr gives the child stderr unless it has its own.
func (t *trackedExec) SetStderr(w io.Writer) {
	if t.Stderr == nil {
		t.Stderr = w
	}
}
