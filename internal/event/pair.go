package event

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

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
	// AddressSpaceBytes tracks memory-region extent for memory syscalls
	// (e.g. munmap/mremap) and is intentionally separate from I/O bytes.
	AddressSpaceBytes uint64
	// RequestedSleepNs tracks requested sleep duration for nanosleep-style syscalls.
	RequestedSleepNs int64
	// Epoll carries epoll_ctl control metadata (op, target fd, requested event
	// mask). It is only populated for epoll_ctl pairs; HasEpoll reports whether
	// it is set. The Pair-level File still resolves to the epoll instance (epfd);
	// Epoll.TargetFD is the descriptor being registered/modified/removed.
	Epoll    EpollCtl
	HasEpoll bool
	// Oldname holds the source/old path for rename-family (rename/renameat/
	// renameat2) and link-family (link/linkat/symlink/symlinkat) syscalls. The
	// Pair-level File resolves to the "new" path (File.Name() == newname), so
	// Oldname is the only place the captured source path (BPF name_event.oldname,
	// at args[1] for the AT-variants after a dirfd) reaches the output schema.
	// Empty for every other syscall.
	Oldname string
}

// EpollCtl holds the decoded epoll_ctl arguments surfaced from the BPF
// EpollCtlEvent: the operation (EPOLL_CTL_ADD/MOD/DEL), the target fd
// (args[2]), and the requested epoll event mask (args[3]->events).
type EpollCtl struct {
	Op       int32
	TargetFD int32
	Events   uint32
}

// Linux epoll_ctl op values from <sys/epoll.h>.
const (
	epollCtlAdd = 1
	epollCtlDel = 2
	epollCtlMod = 3
)

// OpName renders the epoll_ctl operation as a human-readable token
// (ADD/DEL/MOD). Unknown values fall back to their decimal form so the
// raw op is never lost.
func (c EpollCtl) OpName() string {
	switch c.Op {
	case epollCtlAdd:
		return "ADD"
	case epollCtlDel:
		return "DEL"
	case epollCtlMod:
		return "MOD"
	default:
		return strconv.FormatInt(int64(c.Op), 10)
	}
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

// EventStreamHeader is the CSV header line printed once by -plain mode.
// Each row rendered by Pair.String() carries exactly these columns, in this
// order. This is the reduced plain-mode schema; the full per-event schema
// (timestamp, bytes, requested_sleep_ns, ...) is available via the TUI stream
// CSV export and the headless Parquet output.
const EventStreamHeader = "durationToPrevNs,durationNs,comm,pid.tid,name,ret,file"

// quoteCSVField quotes field for RFC 4180 CSV output, byte-identical to
// encoding/csv.Writer for the default comma: quotes fields containing a comma,
// double quote, carriage return, or line feed, fields whose first rune is a
// Unicode space, and the literal `\.`; embedded double quotes are doubled.
// Bytes are copied verbatim (not runes) so non-UTF-8 filenames round-trip
// unchanged. Fields that need no quoting are returned unchanged so the hot
// plain-mode path stays allocation-free for the common case.
func quoteCSVField(field string) string {
	if !csvFieldNeedsQuotes(field) {
		return field
	}
	var sb strings.Builder
	// Worst case doubles every byte plus two delimiters; Grow is a hint.
	sb.Grow(2*len(field) + 2)
	sb.WriteByte('"')
	for i := 0; i < len(field); i++ {
		if field[i] == '"' {
			sb.WriteString(`""`)
			continue
		}
		sb.WriteByte(field[i])
	}
	sb.WriteByte('"')
	return sb.String()
}

// csvFieldNeedsQuotes mirrors encoding/csv.Writer.fieldNeedsQuotes for the
// default comma so quoteCSVField stays byte-identical to the stdlib writer:
// empty fields are never quoted, the Postgres `\.` terminator always is, and
// fields containing the comma/quote/CR/LF bytes or starting with a Unicode
// space must be quoted.
func csvFieldNeedsQuotes(field string) bool {
	if field == "" {
		return false
	}
	if field == `\.` {
		return true
	}
	for i := 0; i < len(field); i++ {
		switch field[i] {
		case '\n', '\r', '"', ',':
			return true
		}
	}
	r1, _ := utf8.DecodeRuneInString(field)
	return unicode.IsSpace(r1)
}

// String renders the Pair as one CSV row matching EventStreamHeader: seven
// columns (durationToPrevNs,durationNs,comm,pid.tid,name,ret,file). Free-text
// columns (comm, name, file) are quoted per RFC 4180 so embedded commas —
// e.g. the fd/flags decoration inside the file column — stay inside their
// field and the row stays machine-parseable with any CSV reader. The ret
// column is empty when no return value was captured.
func (e *Pair) String() string {
	var sb strings.Builder

	_, _ = fmt.Fprintf(&sb, "%08d,%08d,", e.DurationToPrev, e.Duration)

	sb.WriteString(quoteCSVField(e.Comm))

	sb.WriteString(",")
	sb.WriteString(strconv.FormatInt(int64(e.EnterEv.GetPid()), 10))
	sb.WriteString(".")
	sb.WriteString(strconv.FormatInt(int64(e.EnterEv.GetTid()), 10))

	sb.WriteString(",")
	sb.WriteString(quoteCSVField(e.EnterEv.GetTraceId().Name()))

	sb.WriteString(",")
	// Every exit event carrying a ret field feeds this column, not just the
	// generic *types.RetEvent: the kind-specific exits (accept/accept4,
	// pipe/pipe2, socketpair, eventfd/pidfd) carry one too.
	if retEv, ok := e.ExitEv.(RetCarrier); ok {
		sb.WriteString(strconv.FormatInt(retEv.GetRet(), 10))
	}

	sb.WriteString(",")
	if e.File == nil {
		sb.WriteString("N:file")
	} else {
		sb.WriteString(quoteCSVField(e.File.String()))
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
