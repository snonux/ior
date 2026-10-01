package probes

import (
	"context"
	"errors"

	"ior/internal/probemanager"
	"ior/internal/types"

	tea "charm.land/bubbletea/v2"
)

// FamilyBatchRequestMsg asks the TUI to attach (Attach) or detach a whole
// family. The modal only requests the batch: the TUI owns the run - it keeps
// the one-batch-at-a-time guard across modal rebuilds, records the intended
// probe set for trace restarts and numbers the run - and starts it with
// StartFamilyBatch.
type FamilyBatchRequestMsg struct {
	Family types.SyscallFamily
	Attach bool
}

// FamilyBatchProgressMsg reports the progress of the family batch numbered
// Run. Completed and Total count probes, not tracepoints. Whoever receives it
// must return Next() to keep following the batch to its FamilyToggledMsg.
type FamilyBatchProgressMsg struct {
	Run       uint64
	Family    types.SyscallFamily
	Attach    bool
	Completed int
	Total     int
	run       *familyBatchRun
}

// FamilyToggledMsg reports the end of the family batch numbered Run. Err is a
// failure of the batch as a whole (no manager); per-syscall failures are in
// Result.Errors, with every other probe of the family changed regardless.
type FamilyToggledMsg struct {
	Run    uint64
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
// same reason; next also uses its slot to hold the result back behind a
// still-unread update, so that update is never lost to the result.
type familyBatchRun struct {
	id       uint64
	family   types.SyscallFamily
	attach   bool
	progress chan [2]int
	done     chan FamilyToggledMsg
}

// StartFamilyBatch starts attaching (attach) or detaching every probe of
// family through manager as run number run, and returns a command yielding
// its first progress update (or its result).
//
// ctx bounds the batch: the TUI passes the context of the trace session that
// owns manager, so ending that session (restart, stop, quit) stops the batch
// between two probes instead of letting it attach the rest of the family to
// a module that is about to close. The batch then still ends with a
// FamilyToggledMsg, whose Err is the context's error.
func StartFamilyBatch(ctx context.Context, manager Manager, run uint64, family types.SyscallFamily, attach bool) tea.Cmd {
	return func() tea.Msg {
		if manager == nil {
			return FamilyToggledMsg{Run: run, Family: family, Attach: attach, Err: errors.New("probe manager unavailable")}
		}
		r := newFamilyBatchRun(run, family, attach)
		go r.execute(ctx, manager)
		return r.next()
	}
}

// newFamilyBatchRun returns the not yet started run number run of the batch
// attaching (attach) or detaching family, with the one-slot channels the
// type's comment explains.
func newFamilyBatchRun(run uint64, family types.SyscallFamily, attach bool) *familyBatchRun {
	return &familyBatchRun{
		id:       run,
		family:   family,
		attach:   attach,
		progress: make(chan [2]int, 1),
		done:     make(chan FamilyToggledMsg, 1),
	}
}

// Next returns the command that waits for the next update of the batch
// behind msg, or nil for a message that was not produced by a batch.
func (msg FamilyBatchProgressMsg) Next() tea.Cmd {
	if msg.run == nil {
		return nil
	}
	return msg.run.next
}

// execute runs the batch and publishes its result. done is buffered, so the
// goroutine ends even when nobody waits for the result any more (a stale
// run whose chain the TUI stopped following).
func (r *familyBatchRun) execute(ctx context.Context, manager Manager) {
	operation := manager.DetachFamily
	if r.attach {
		operation = manager.AttachFamily
	}
	result, err := operation(ctx, r.family, r.report)
	r.done <- FamilyToggledMsg{Run: r.id, Family: r.family, Attach: r.attach, Result: result, Err: err}
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
// corresponding message.
//
// Ordering contract: the latest progress update reported before the batch
// ended is always delivered before its FamilyToggledMsg. Older updates can
// still be coalesced away (report keeps only the latest), which is fine for
// a progress bar. A plain select over done and progress cannot keep that
// promise: when the batch finishes before the TUI asks for the next update
// (a fast or tiny family), both channels are ready and Go picks one at
// random, so about half of those runs skipped the last update - the cause of
// the flaky TestFamilyToggleAttachesWholeFamilyWithProgress (task gs2). So a
// result is held back while a progress update is pending: execute sends
// every update before the result on the same goroutine, so once the result
// has been received any earlier update is already buffered and the
// non-blocking check below sees it deterministically. The result goes back
// into done, whose one-slot buffer was just emptied and which has no other
// sender, so that send cannot block, and the following next returns it (no
// update can follow the result).
func (r *familyBatchRun) next() tea.Msg {
	select {
	case msg := <-r.done:
		select {
		case p := <-r.progress:
			r.done <- msg
			return r.progressMsg(p)
		default:
			return msg
		}
	case p := <-r.progress:
		return r.progressMsg(p)
	}
}

// progressMsg wraps the update p (completed, total) of this batch in the
// message the TUI renders and follows with Next.
func (r *familyBatchRun) progressMsg(p [2]int) FamilyBatchProgressMsg {
	return FamilyBatchProgressMsg{Run: r.id, Family: r.family, Attach: r.attach, Completed: p[0], Total: p[1], run: r}
}
