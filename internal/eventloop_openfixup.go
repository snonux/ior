package internal

import (
	"ior/internal/types"
)

// handleOpenNameFixupEvent splices a recovered open filename into the enter
// event that is still waiting for its exit.
//
// Why the name can be missing in the first place: bpf_probe_read_user_str() is
// a nofault read, so at sys_enter it returns -EFAULT and leaves the buffer
// untouched whenever the path string's page is not resident - routinely the
// case for the first open a program makes through a freshly mmap'ed library.
// The kernel's own getname() faults that page in as part of servicing the
// call, so the identical read succeeds at sys_exit; the generated exit handler
// re-reads it there and publishes it as this OPEN_NAME_FIXUP_EVENT control
// record (ior_take_pending_filename / ior_emit_open_name_fixup in
// internal/c/filter.c).
//
// Ordering is what makes the splice safe. The kernel reserves the fixup record
// before the exit record of the same syscall, the BPF ring buffer preserves
// reservation order, and this event loop has a single consumer goroutine - so
// the fixup is always applied while the enter event is still pending and
// unpaired. A record lost to ring-buffer backpressure simply never arrives and
// the row keeps its empty name, exactly as before this mechanism existed.
//
// The one residual case is a tid whose pending open enter never got its exit
// (its exit record was itself lost to backpressure): a later open on the same
// tid can then splice its name onto that orphan. It takes a counted drop to
// reach, and the orphan can only ever be emitted by being mispaired with a
// later exit - which is already broken with or without this splice - so it is
// left to the drop counter rather than to extra per-record identity state.
//
// Like every control record it never becomes a row, and it owns the event it is
// handed, so it must recycle it.
func (e *eventLoop) handleOpenNameFixupEvent(ev *types.OpenNameFixupEvent) {
	defer ev.Recycle()
	pair, ok := e.pairs.pending(ev.Tid)
	if !ok {
		return
	}
	applyRecoveredFilename(pair.EnterEv, ev)
}

func applyRecoveredFilename(enterEv any, fixup *types.OpenNameFixupEvent) {
	switch typed := enterEv.(type) {
	case *types.OpenEvent:
		applyRecoveredOpenFilename(typed, fixup)
	case *types.EventfdEvent:
		applyRecoveredEventfdFilename(typed, fixup)
	}
}

func applyRecoveredOpenFilename(openEv *types.OpenEvent, ev *types.OpenNameFixupEvent) {
	// The kernel stamps the fixup with the enter trace ID it recovered the name
	// for, and only after checking that the per-tid enter state still belongs
	// to that syscall. Re-checking it here closes the userspace half of the
	// same hazard: a fixup must never graft a path onto some *other* pending
	// open of the same tid.
	if openEv.GetTraceId() != ev.GetTraceId() {
		return
	}
	// Only a failed non-NULL enter-side read can have stashed a pointer for the
	// exit helper. Requiring that state prevents a synthetic or stale control
	// record from turning a genuine NULL argument into a valid empty path.
	if openEv.FilenameStatus != types.PATH_READ_FAILED {
		return
	}
	// Never overwrite a name the enter side captured itself. That read is the
	// authoritative one - it saw the caller's buffer at the moment of the call,
	// while this one saw it after the kernel had already copied it in.
	if types.StringValue(openEv.Filename[:]) != "" {
		return
	}
	copy(openEv.Filename[:], ev.Filename[:])
	// A submitted fixup is proof that the non-NULL pointer which failed at
	// sys_enter was read successfully at sys_exit. That includes a return of 1
	// for a valid empty C string, whose all-zero payload must remain
	// distinguishable from receiving no control record at all.
	openEv.FilenameStatus = types.PATH_READ_OK
}

func applyRecoveredEventfdFilename(eventfdEv *types.EventfdEvent, ev *types.OpenNameFixupEvent) {
	if eventfdEv.GetTraceId() != ev.GetTraceId() || eventfdEv.FilenameStatus != types.PATH_READ_FAILED {
		return
	}
	if types.StringValue(eventfdEv.Filename[:]) != "" {
		return
	}
	copy(eventfdEv.Filename[:], ev.Filename[:])
	eventfdEv.FilenameStatus = types.PATH_READ_OK
}
