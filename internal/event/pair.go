package event

import (
	"fmt"
	"strconv"
	"strings"

	"ior/internal/file"
	"ior/internal/types"
)

// Pair represents a matched syscall enter/exit pair together with derived metadata.
//
// Timing semantics for Duration (durationNs) and DurationToPrev (durationToPrevNs),
// mirroring the README:
//   - Duration is the syscall runtime on the same thread: exit(current) - enter(current).
//   - DurationToPrev is the inter-syscall gap on the same thread: enter(current) - exit(previous).
//   - DurationToPrev is tracked per TID; the first observed Pair for a TID has DurationToPrev == 0.
//   - The inter-syscall gap is attributed to the current Pair (the one whose enter closes the gap).
//   - There is no separate "idle" pseudo-event bucket; aggregated views should use DurationToPrev
//     when they want to emphasize inter-syscall time.
type Pair struct {
	EnterEv, ExitEv Event
	File            file.File
	Comm            string
	Duration        uint64
	DurationToPrev  uint64
	Bytes           uint64 // Number of bytes transferred (read/write/transfer syscalls only)
}

func NewPair(enterEv Event) *Pair {
	e := poolOfEventPairs.Get().(*Pair)
	// Zero all fields via struct literal to prevent stale data from previous pool reuse.
	*e = Pair{EnterEv: enterEv}
	return e
}

func (e *Pair) CalculateDurations(prevPairTime uint64) {
	exitTime := e.ExitEv.GetTime()
	enterTime := e.EnterEv.GetTime()

	// Guard against uint64 underflow caused by non-monotonic BPF timestamps
	// (e.g. cross-CPU clock skew or NTP adjustments). When exit < enter the
	// syscall duration cannot be measured reliably; treat it as zero rather
	// than wrapping around to an astronomically large value.
	if exitTime >= enterTime {
		e.Duration = exitTime - enterTime
	} else {
		e.Duration = 0
	}

	if prevPairTime > 0 {
		// DurationToPrev is the inter-syscall gap on the same TID:
		// enter(current) - exit(previous).
		// Apply the same underflow guard: if the previous exit timestamp
		// is ahead of this enter (clock skew), clamp the gap to zero.
		if enterTime >= prevPairTime {
			e.DurationToPrev = enterTime - prevPairTime
		} else {
			e.DurationToPrev = 0
		}
	}
}

func (e *Pair) Is(id types.TraceId) bool {
	return e.EnterEv.GetTraceId() == id
}

const EventStreamHeader = "durationToPrevNs,durationNs,comm,pid.tid,name,ret,notice,file"

func (e *Pair) String() string {
	var sb strings.Builder

	_, _ = fmt.Fprintf(&sb, "%08d,%08d", e.DurationToPrev, e.Duration)

	sb.WriteString(",")
	sb.WriteString(e.Comm)

	sb.WriteString("@")
	sb.WriteString(strconv.FormatInt(int64(e.EnterEv.GetPid()), 10))
	sb.WriteString(".")
	sb.WriteString(strconv.FormatInt(int64(e.EnterEv.GetTid()), 10))

	sb.WriteString(",")
	sb.WriteString(e.EnterEv.GetTraceId().Name())

	sb.WriteString("=>")
	if retEv, ok := e.ExitEv.(*types.RetEvent); ok {
		sb.WriteString(strconv.FormatInt(int64(retEv.Ret), 10))
	}

	sb.WriteString(",")
	if e.File == nil {
		sb.WriteString("N:file")
	} else {
		sb.WriteString(e.File.String())
	}

	return sb.String()
}

func (e *Pair) Flags() file.Flags {
	if e.File == nil {
		return file.Flags(0)
	}
	return e.File.Flags()
}

func (e *Pair) FileName() string {
	if e.File == nil {
		return "N:file"
	}
	return e.File.Name()
}

// FileDescriptor returns the associated file descriptor when available.
func (e *Pair) FileDescriptor() (int32, bool) {
	if e.File == nil {
		return 0, false
	}
	fd := e.File.FD()
	if fd < 0 {
		return 0, false
	}
	return fd, true
}

func (e *Pair) Dump() string {
	return fmt.Sprintf("%v with enterEv(%v) and exitEv(%v)", e, e.EnterEv, e.ExitEv)
}

func (e *Pair) Recycle() {
	if e.EnterEv != nil {
		e.EnterEv.Recycle()
	}
	if e.ExitEv != nil {
		e.ExitEv.Recycle()
	}
	// Zero all fields via struct literal to prevent stale data on pool reuse.
	*e = Pair{}
	poolOfEventPairs.Put(e)
}
