package internal

import (
	"ior/internal/types"
)

// handleOpenNameFixupEvent splices a recovered path into the enter event that
// is still waiting for its exit: the filename of an open, the pathname of a
// stat/access/unlink/inotify_add_watch, or the oldname/newname of a
// rename/link or the from/to pathname of a move_mount (the record's slot says
// which).
//
// Why the name can be missing in the first place: bpf_probe_read_user_str() is
// a nofault read, so at sys_enter it returns -EFAULT and the handler leaves an
// empty name whenever the path string's page is not resident - routinely the
// case for the first open a program makes through a freshly mmap'ed library,
// and for any path argument living in never-touched memory.
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
// The one residual case is a tid whose pending enter never got its exit
// (its exit record was itself lost to backpressure): a later recovering call
// on the same tid can then splice its name onto that orphan. It takes a counted drop to
// reach, and the orphan can only ever be emitted by being mispaired with a
// later exit - which is already broken with or without this splice - so it is
// left to the drop counter rather than to extra per-record identity state.
//
// The same record also carries the path getcwd returned to its caller, read by
// the exit handler from the output buffer after a successful return; that one
// lands on the pair rather than in the enter event (applyCapturedOutputPath).
//
// Like every control record it never becomes a row, and it owns the event it is
// handed, so it must recycle it.
func (e *eventLoop) handleOpenNameFixupEvent(ev *types.OpenNameFixupEvent) {
	defer ev.Recycle()
	pair, ok := e.pairs.pending(ev.Tid)
	if !ok {
		return
	}
	if applyCapturedOutputPath(pair, ev) {
		return
	}
	applyRecoveredFilename(pair.EnterEv, ev)
}

// applyRecoveredFilename splices the recovered string into the path field of
// the pending enter event that the fixup's slot names.
func applyRecoveredFilename(enterEv any, fixup *types.OpenNameFixupEvent) {
	switch typed := enterEv.(type) {
	case *types.OpenEvent:
		applyRecoveredOpenFilename(typed, fixup)
	case *types.EventfdEvent:
		applyRecoveredEventfdFilename(typed, fixup)
	case *types.PathEvent:
		if fixup.Slot == types.OPEN_NAME_FIXUP_SLOT_FIRST {
			spliceRecoveredPath(typed.GetTraceId(), &typed.Pathname, &typed.PathnameStatus, fixup)
		}
	case *types.FdPathEvent:
		if fixup.Slot == types.OPEN_NAME_FIXUP_SLOT_FIRST {
			spliceRecoveredPath(typed.GetTraceId(), &typed.Pathname, &typed.PathnameStatus, fixup)
		}
	case *types.NameEvent:
		applyRecoveredNameEvent(typed, fixup)
	case *types.TwoFdEvent:
		applyRecoveredTwoFdNames(typed, fixup)
	}
}

func applyRecoveredOpenFilename(openEv *types.OpenEvent, ev *types.OpenNameFixupEvent) {
	if ev.Slot != types.OPEN_NAME_FIXUP_SLOT_FIRST {
		return
	}
	spliceRecoveredPath(openEv.GetTraceId(), &openEv.Filename, &openEv.FilenameStatus, ev)
}

func applyRecoveredEventfdFilename(eventfdEv *types.EventfdEvent, ev *types.OpenNameFixupEvent) {
	if ev.Slot != types.OPEN_NAME_FIXUP_SLOT_FIRST {
		return
	}
	spliceRecoveredPath(eventfdEv.GetTraceId(), &eventfdEv.Filename, &eventfdEv.FilenameStatus, ev)
}

// applyRecoveredNameEvent picks the rename/link name the fixup's slot belongs
// to: the first slot is oldname, the second newname. The two are recovered
// independently - either read can fault while the other succeeds - so a slot
// only ever touches its own field, and one recovered name can never stand in
// for the other.
func applyRecoveredNameEvent(nameEv *types.NameEvent, ev *types.OpenNameFixupEvent) {
	switch ev.Slot {
	case types.OPEN_NAME_FIXUP_SLOT_FIRST:
		spliceRecoveredPath(nameEv.GetTraceId(), &nameEv.Oldname, &nameEv.OldnameStatus, ev)
	case types.OPEN_NAME_FIXUP_SLOT_SECOND:
		spliceRecoveredPath(nameEv.GetTraceId(), &nameEv.Newname, &nameEv.NewnameStatus, ev)
	}
}

// applyRecoveredTwoFdNames is applyRecoveredNameEvent for move_mount, whose
// two_fd_names_event decodes into a types.TwoFdEvent (decodeTwoFdNamesEvent)
// carrying from_pathname as Oldname and to_pathname as Newname. The lean
// two_fd_event of close_range and kcmp decodes into the same Go type with
// zeroed names and statuses; it never stashes a pointer, and a stray record
// for one is still refused by spliceRecoveredPath's trace-ID and
// PATH_READ_FAILED guards, so the type switch needs no extra kind check.
func applyRecoveredTwoFdNames(twoFdEv *types.TwoFdEvent, ev *types.OpenNameFixupEvent) {
	switch ev.Slot {
	case types.OPEN_NAME_FIXUP_SLOT_FIRST:
		spliceRecoveredPath(twoFdEv.GetTraceId(), &twoFdEv.Oldname, &twoFdEv.OldnameStatus, ev)
	case types.OPEN_NAME_FIXUP_SLOT_SECOND:
		spliceRecoveredPath(twoFdEv.GetTraceId(), &twoFdEv.Newname, &twoFdEv.NewnameStatus, ev)
	}
}

// spliceRecoveredPath copies the fixup's string into one captured path field
// of an enter event, under the three guards every recovering kind shares.
func spliceRecoveredPath(enterTrace types.TraceId, name *[types.MAX_FILENAME_LENGTH]byte,
	status *uint32, ev *types.OpenNameFixupEvent) {
	// The kernel stamps the fixup with the enter trace ID it recovered the name
	// for, and only after checking that the per-tid enter state still belongs
	// to that syscall. Re-checking it here closes the userspace half of the
	// same hazard: a fixup must never graft a path onto some *other* pending
	// syscall of the same tid.
	if enterTrace != ev.GetTraceId() {
		return
	}
	// Only a failed non-NULL enter-side read can have stashed a pointer for the
	// exit helper. Requiring that state prevents a synthetic or stale control
	// record from turning a genuine NULL argument into a valid empty path.
	if *status != types.PATH_READ_FAILED {
		return
	}
	// Never overwrite a name the enter side captured itself. That read is the
	// authoritative one - it saw the caller's buffer at the moment of the call,
	// while this one saw it after the kernel had already copied it in.
	if types.StringValue(name[:]) != "" {
		return
	}
	copy(name[:], ev.Filename[:])
	// A submitted fixup is proof that the non-NULL pointer which failed at
	// sys_enter was read successfully at sys_exit. That includes a return of 1
	// for a valid empty C string, whose all-zero payload must remain
	// distinguishable from receiving no control record at all.
	*status = types.PATH_READ_OK
}
