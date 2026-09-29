package internal

import (
	"ior/internal/event"
	"ior/internal/types"
)

const kcmpFileComparison = uint32(0)

func (e *eventLoop) applyKcmpFile(ep *event.Pair, ev *types.TwoFdEvent) {
	// Schema 3 is the first producer that packs the proven host owner in
	// Extra's high word.
	// Older producers copied the raw 64-bit type argument, whose ignored upper
	// bits are not a safe owner discriminator.
	if ev.SchemaVersion != types.TWO_FD_EVENT_SCHEMA_VERSION ||
		uint32(ev.Extra) != kcmpFileComparison || ev.FdA < 0 {
		return
	}

	// The producer proves pid1 is the caller in its PID namespace at sys_enter
	// and packs the stable host TGID. Do not repeat that proof through /proc at
	// event-processing time: a short-lived caller may already be gone, or its
	// host PID may have been reused. Foreign PIDs and non-leader TIDs remain
	// un-attributed because their fdTracker entries cannot be kept coherent by
	// the caller-TGID event stream.
	ownerPID := uint32(ev.Extra >> 32)
	if ownerPID == 0 || ownerPID != ev.Pid {
		return
	}
	// A live procfs fallback is unsafe here even after the entry-time ownership
	// proof: the caller can exit before ring consumption and its numeric host
	// PID can be reused. KCMP attribution therefore uses only descriptor state
	// captured earlier in this trace and stays nil on a miss.
	if captured, ok := e.fdState().get(ev.FdA, ownerPID); ok {
		ep.File = captured
	}
}
