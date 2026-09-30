package probes

import (
	"errors"

	"ior/internal/probemanager"
	"ior/internal/types"

	tea "charm.land/bubbletea/v2"
)

// FamilyBatchProgressMsg reports the progress of a running family attach or
// detach (Families view). Completed and Total count probes, not tracepoints.
// The TUI must hand it to Model.Update even while the modal is hidden or has
// been rebuilt: the returned command waits for the next update, so dropping
// the message would stop the TUI from ever seeing the batch finish.
type FamilyBatchProgressMsg struct {
	Family    types.SyscallFamily
	Attach    bool
	Completed int
	Total     int
	run       *familyBatchRun
}

// FamilyToggledMsg reports the end of a family attach or detach. Err is a
// failure of the batch as a whole (no manager); per-syscall failures are in
// Result.Errors, with every other probe of the family changed regardless.
type FamilyToggledMsg struct {
	Family types.SyscallFamily
	Attach bool
	Result probemanager.BatchResult
	Err    error
}

// familyBatchRun connects one family batch, running on its own goroutine, to
// the Bubble Tea command chain that reports it. Attaching a family walks
// dozens of tracepoints and takes seconds, so the batch must not run inside
// the command that the TUI waits on for each update: the command only waits
// for the next progress update or the final result (next).
//
// progress holds at most the latest update: report replaces an unread one
// instead of blocking, so a slow renderer never slows the attach down and
// nothing is left blocked if the TUI stops waiting. done is buffered for the
// same reason.
type familyBatchRun struct {
	family   types.SyscallFamily
	attach   bool
	progress chan [2]int
	done     chan FamilyToggledMsg
}

// familyBatchCmd starts attaching (attach) or detaching every probe of family
// through manager and returns its first progress update (or the result).
func familyBatchCmd(manager Manager, family types.SyscallFamily, attach bool) tea.Cmd {
	return func() tea.Msg {
		if manager == nil {
			return FamilyToggledMsg{Family: family, Attach: attach, Err: errors.New("probe manager unavailable")}
		}
		run := &familyBatchRun{
			family:   family,
			attach:   attach,
			progress: make(chan [2]int, 1),
			done:     make(chan FamilyToggledMsg, 1),
		}
		go run.execute(manager)
		return run.next()
	}
}

// execute runs the batch and publishes its result.
func (r *familyBatchRun) execute(manager Manager) {
	operation := manager.DetachFamily
	if r.attach {
		operation = manager.AttachFamily
	}
	result, err := operation(r.family, r.report)
	r.done <- FamilyToggledMsg{Family: r.family, Attach: r.attach, Result: result, Err: err}
}

// report publishes a progress update, replacing an unread older one. The
// batch goroutine is the only sender, so after the drain the send cannot
// block.
func (r *familyBatchRun) report(completed, total int) {
	select {
	case <-r.progress:
	default:
	}
	r.progress <- [2]int{completed, total}
}

// next blocks until the batch has progressed or finished and returns the
// corresponding message. A progress update still unread when the batch ends
// may be delivered before the result; it is simply superseded by it.
func (r *familyBatchRun) next() tea.Msg {
	select {
	case msg := <-r.done:
		return msg
	case p := <-r.progress:
		return FamilyBatchProgressMsg{Family: r.family, Attach: r.attach, Completed: p[0], Total: p[1], run: r}
	}
}

// waitCmd returns the command that waits for the next update of the batch
// behind msg, or nil for a message that was not produced by a batch.
func (msg FamilyBatchProgressMsg) waitCmd() tea.Cmd {
	if msg.run == nil {
		return nil
	}
	return msg.run.next
}
