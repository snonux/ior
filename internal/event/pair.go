package event

import (
	"fmt"
	"math"
	"slices"
	"strconv"
	"unicode"
	"unicode/utf8"

	"ior/internal/file"
	"ior/internal/types"
)

// NoFileName is the placeholder a pair renders in its file column (-plain
// output, FileName, the stream tab's File cell) when it carries no file. It
// is display text only. Data files never store it: the stream CSV export, the
// Parquet recorder (streamrow Row.FileValue) and the .ior.zst flamegraph record
// (Pair.FileValue, task pq2) all write an empty file for such a row, so a
// non-empty file selects the rows that have a file. Only the -plain stdout CSV
// (appendCSVFile) prints the placeholder, since it is a display stream.
// The global filter's file dimension likewise sees such a pair, and the
// stream row built from it, as the empty value (globalfilter
// pairCandidate.FileValue, streamrow Row.FileValue, which keys off the row's
// explicit NoFile flag rather than this text). A real file literally named
// "N:file" therefore still filters and persists by its real name on both
// paths. The Files tab ranking (statsengine rankablePath) decides the same
// way, on File == nil rather than on the text, so it ranks a real "N:file"
// too (task ks2).
const NoFileName = "N:file"

// Pair represents a matched syscall enter/exit pair together with derived metadata.
//
// Timing semantics for Duration (durationNs) and DurationToPrev (durationToPrevNs),
// mirroring the README:
//   - Duration is the syscall runtime on the same thread: exit(current) - enter(current).
//     For a call interrupted with -516 and resumed through restart_syscall, the event loop
//     folds the continuation into the pair (task fs2, internal/eventloop_restart.go): ExitEv
//     then carries the final return and time, so Duration spans the whole call, stopped
//     time included.
//     Restarts counts the continuations folded that way (task 203).
//   - DurationToPrev is the inter-syscall gap on the same thread: enter(current) - exit(previous).
//   - DurationToPrev is tracked per TID; the first observed Pair for a TID has DurationToPrev == 0
//     and FirstOnTID set, so aggregations can tell "no previous pair" from a measured 0ns gap.
//   - The previous pair is the previous EMITTED pair of the TID: calls the tracer did not emit
//     (sampled out, filtered, or only counted in kernel-side aggregates) fall inside the gap.
//   - The inter-syscall gap is attributed to the current Pair (the one whose enter closes the gap).
//   - There is no separate "idle" pseudo-event bucket; aggregated views should use DurationToPrev
//     when they want to emphasize inter-syscall time.
type Pair struct {
	EnterEv, ExitEv Event
	File            file.File
	Comm            string
	Duration        uint64
	DurationToPrev  uint64
	// FirstOnTID reports that no previous pair was known for the TID when the
	// durations were calculated, so DurationToPrev is 0 by definition rather
	// than a measured gap. Consumers that average or bucket gaps skip it.
	FirstOnTID bool
	// NoReturn marks the row of a syscall that never returns to its caller
	// (exit, exit_group, rt_sigreturn; types.TraceId.NoReturn): its sys_exit
	// tracepoint never fires, so the event loop completes the pair at enter
	// (completeNoReturnEnter in internal/eventloop_noreturn.go). ExitEv is
	// then a synthetic *types.NullEvent stamped with the enter's time and
	// tid; it carries no return value (it is not a RetCarrier, so the -plain
	// ret column is empty and ret filters see 0), and Duration is 0 because
	// there is no latency to measure, not because the call took no time.
	// Latency aggregates count such a pair as untimed (statsengine).
	// DurationToPrev is a real gap, measured to the enter like any pair's.
	NoReturn bool
	// Restarts counts the kernel restarts the event loop folded into this pair
	// (task 203; foldRestartExit in internal/eventloop_restart.go): one for
	// each restart_syscall continuation of a call stopped with -516 and one for
	// each re-execution after -512/-513/-514. Such a pair shows the call's
	// final return only, so this is the one place that says it was interrupted
	// at all. 0 for every other pair, including one that kept its restart code
	// because the fold was refused, and for the continuation's own pair then.
	// It saturates at 255 (NoteRestart).
	Restarts uint8
	Bytes    uint64 // Number of bytes transferred (read/write/transfer syscalls only)
	// AddressSpaceBytes is the virtual address space a memory syscall added,
	// removed or moved, in whole host pages: the page-rounded length of
	// mmap/munmap, the larger of the old and new size for mremap, and how far
	// the program break moved for brk (0 for a process's first brk seen and for
	// brk(0) queries). msync/mprotect/madvise/mlock change no extent and report
	// 0, as do failed calls. Intentionally separate from I/O bytes. See
	// eventloop_addrspace.go.
	AddressSpaceBytes uint64
	// RequestedSleepNs tracks requested sleep duration for nanosleep-style
	// syscalls. -1 means unknown (null/unreadable or kernel-invalid timespec,
	// or an absolute TIMER_ABSTIME sleep); a valid request too large for int64
	// nanoseconds (e.g. `sleep infinity`) is saturated to math.MaxInt64 in BPF.
	// The kernel similarly clamps to KTIME_MAX, but from tv_sec >=
	// KTIME_SEC_MAX, so values within ~1s of the boundary may differ.
	RequestedSleepNs int64
	// Nfds and TimeoutNs carry poll/select readiness metadata. For epoll waits,
	// Nfds is maxevents. TimeoutNs uses -1 for an infinite wait and -2 when a
	// timeout is unreadable, invalid, or unrepresentable; both are zero for
	// unrelated syscalls.
	Nfds      int32
	TimeoutNs int64
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

// NewPair takes ownership of enterEv and wraps it in a fresh pooled Pair
// with every other field zeroed, ready for the matching exit event.
func NewPair(enterEv Event) *Pair {
	e := poolOfEventPairs.Get().(*Pair)
	// Zero all fields via struct literal to prevent stale data from previous pool reuse.
	*e = Pair{EnterEv: enterEv}
	return e
}

// CalculateDurations derives the pair's latency (exit minus enter time) and
// its inter-syscall gap (enter minus prevPairTime, the same TID's previous
// exit), clamping both to zero on non-monotonic BPF timestamps. A zero
// prevPairTime means the TID has no previous pair: the gap stays 0 and
// FirstOnTID is set.
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

	e.FirstOnTID = prevPairTime == 0
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

// NoteRestart counts one kernel restart folded into the pair (Restarts). The
// count stays at 255 once it is there: a call restarted more often than that
// (a sleep stopped and continued in a loop) must not wrap around to a small
// number, least of all to the 0 that means "never interrupted".
func (e *Pair) NoteRestart() {
	if e.Restarts < math.MaxUint8 {
		e.Restarts++
	}
}

// Is reports whether the pair's enter event carries the given trace ID, the
// idiomatic check for dispatching on the syscall kind.
func (e *Pair) Is(id types.TraceId) bool {
	return e.EnterEv.GetTraceId() == id
}

// EventStreamHeader is the CSV header line printed once by -plain mode.
// Each row rendered by Pair.String() carries exactly these columns, in this
// order. This is the reduced plain-mode schema; the full per-event schema
// (timestamp, bytes, old_file, address_space_bytes, epoll_*, ...) is available
// via the TUI stream CSV export and the headless Parquet output.
const EventStreamHeader = "durationToPrevNs,durationNs,comm,pid.tid,name,ret,file"

// quoteCSVField quotes field for RFC 4180 CSV output, byte-identical to
// encoding/csv.Writer for the default comma: quotes fields containing a comma,
// double quote, carriage return, or line feed, fields whose first rune is a
// Unicode space, and the literal `\.`; embedded double quotes are doubled.
// Bytes are copied verbatim (not runes) so non-UTF-8 filenames round-trip
// unchanged. Fields that need no quoting are returned unchanged. The -plain
// hot path uses appendCSVText / quoteInPlace instead, which write into a
// reused buffer; this string form remains the reference the tests compare
// them against.
func quoteCSVField(field string) string {
	if !csvFieldNeedsQuotes(field) {
		return field
	}
	return string(appendQuoted(make([]byte, 0, 2*len(field)+2), field))
}

// appendQuoted appends field to dst as a quoted CSV field, doubling embedded
// double quotes and copying bytes verbatim.
func appendQuoted(dst []byte, field string) []byte {
	dst = append(dst, '"')
	for i := 0; i < len(field); i++ {
		if field[i] == '"' {
			dst = append(dst, '"')
		}
		dst = append(dst, field[i])
	}
	return append(dst, '"')
}

// appendCSVText appends one free-text CSV column to dst: escaped by escape
// (when non-nil) and then quoted per RFC 4180 only when it needs quoting, so
// the common clean field is a plain append.
func appendCSVText(dst []byte, field string, escape func(string) string) []byte {
	if escape != nil {
		field = escape(field)
	}
	if !csvFieldNeedsQuotes(field) {
		return append(dst, field...)
	}
	return appendQuoted(dst, field)
}

// quoteInPlace RFC 4180 quotes the field already appended to dst[start:],
// when it needs quoting, without a second buffer: it grows dst by the two
// delimiters plus one byte per embedded quote and then moves the field
// right-to-left into place, doubling the quotes as it goes. Walking backwards
// is what makes the overlapping move safe: the write index stays strictly
// ahead of the read index, so no byte is overwritten before it is read.
func quoteInPlace(dst []byte, start int) []byte {
	field := dst[start:]
	if !csvFieldNeedsQuotes(field) {
		return dst
	}
	quotes := 0
	for _, c := range field {
		if c == '"' {
			quotes++
		}
	}
	end := len(dst)
	dst = slices.Grow(dst, quotes+2)[:end+quotes+2]
	if quotes == 0 {
		// Common case (every fd-backed file: the "%(fd,flags)" comma forces
		// quoting): nothing to double, so one memmove shifts the field.
		copy(dst[start+1:], dst[start:end])
		dst[start] = '"'
		dst[len(dst)-1] = '"'
		return dst
	}

	w := len(dst) - 1
	dst[w] = '"'
	w--
	for r := end - 1; r >= start; r-- {
		c := dst[r]
		dst[w] = c
		w--
		if c == '"' {
			dst[w] = '"'
			w--
		}
	}
	dst[start] = '"' // w == start here: the opening delimiter
	return dst
}

// csvFieldNeedsQuotes mirrors encoding/csv.Writer.fieldNeedsQuotes for the
// default comma so the quoting helpers stay byte-identical to the stdlib
// writer: empty fields are never quoted, the Postgres `\.` terminator always
// is, and fields containing the comma/quote/CR/LF bytes or starting with a
// Unicode space must be quoted. It is generic over string and []byte so the
// in-place path can test the bytes it just appended without converting them.
func csvFieldNeedsQuotes[S ~string | ~[]byte](field S) bool {
	if len(field) == 0 {
		return false
	}
	if len(field) == 2 && field[0] == '\\' && field[1] == '.' {
		return true
	}
	for i := 0; i < len(field); i++ {
		switch field[i] {
		case '\n', '\r', '"', ',':
			return true
		}
	}
	// Only the first rune matters, and it lies within the first UTFMax bytes.
	var lead [utf8.UTFMax]byte
	n := copy(lead[:], field)
	r1, _ := utf8.DecodeRune(lead[:n])
	return unicode.IsSpace(r1)
}

// String renders the Pair as one raw CSV row matching EventStreamHeader; it
// is CSVRow(nil). Traced text is written byte for byte, which is right for
// files and pipes but not for a terminal: see CSVRow.
func (e *Pair) String() string {
	return e.CSVRow(nil)
}

// csvDurationWidth is the zero-padded width of the two duration columns.
const csvDurationWidth = 8

// csvZeros supplies the padding for appendZeroPadded.
const csvZeros = "00000000"

// appendZeroPadded appends v in decimal, left-padded with zeros to at least
// width digits (width <= len(csvZeros)); it is fmt's "%08d" for unsigned
// values without the formatter's allocations.
func appendZeroPadded(dst []byte, v uint64, width int) []byte {
	start := len(dst)
	dst = strconv.AppendUint(dst, v, 10)
	digits := len(dst) - start
	if digits >= width {
		return dst
	}
	pad := width - digits
	dst = append(dst, csvZeros[:pad]...)           // grow by pad bytes
	copy(dst[start+pad:], dst[start:start+digits]) // shift the digits right
	copy(dst[start:start+pad], csvZeros[:pad])     // zero the vacated prefix
	return dst
}

// CSVRow renders the Pair as one CSV row; see AppendCSVRow for the format.
// It allocates the row string, so the -plain hot path uses AppendCSVRow into
// a reused buffer instead.
func (e *Pair) CSVRow(escape func(string) string) string {
	return string(e.AppendCSVRow(make([]byte, 0, 160), escape))
}

// AppendCSVRow appends the Pair as one CSV row (without the trailing line
// feed) matching EventStreamHeader to dst and returns the extended slice:
// seven columns (durationToPrevNs,durationNs,comm,pid.tid,name,ret,file).
// Free-text columns (comm, name, file) are quoted per RFC 4180 so embedded
// commas - e.g. the fd/flags decoration inside the file column - stay inside
// their field and the row stays machine-parseable with any CSV reader. The
// ret column is empty when no return value was captured.
//
// escape, when non-nil, is applied to each free-text column before quoting.
// -plain passes textsafe.Escape when stdout is a terminal, because comm and
// file names are attacker-controlled and could otherwise carry ESC/BEL/C1
// sequences (spoofed OSC 8 links, hidden SGR text, bidi overrides) or
// blank-rendering lookalikes of a space (no-break space, Braille blank) into
// the operator's terminal. Escaping first keeps the row valid CSV: the escape
// notation adds no delimiter, quote or line break. A nil escape keeps the
// exact bytes for machine consumers.
//
// The row is built with strconv.Append* and direct appends rather than
// fmt.Fprintf and strings.Builder: -plain formats one row per syscall, and
// with a reused dst a clean row costs no allocation at all.
func (e *Pair) AppendCSVRow(dst []byte, escape func(string) string) []byte {
	dst = appendZeroPadded(dst, e.DurationToPrev, csvDurationWidth)
	dst = append(dst, ',')
	dst = appendZeroPadded(dst, e.Duration, csvDurationWidth)
	dst = append(dst, ',')

	dst = appendCSVText(dst, e.Comm, escape)

	dst = append(dst, ',')
	dst = strconv.AppendInt(dst, int64(e.EnterEv.GetPid()), 10)
	dst = append(dst, '.')
	dst = strconv.AppendInt(dst, int64(e.EnterEv.GetTid()), 10)

	dst = append(dst, ',')
	dst = appendCSVText(dst, e.EnterEv.GetTraceId().Name(), escape)

	dst = append(dst, ',')
	// Every exit event carrying a ret field feeds this column, not just the
	// generic *types.RetEvent: the kind-specific exits (accept/accept4,
	// pipe/pipe2, socketpair, eventfd/pidfd) carry one too.
	if retEv, ok := e.ExitEv.(RetCarrier); ok {
		dst = strconv.AppendInt(dst, retEv.GetRet(), 10)
	}

	dst = append(dst, ',')
	return e.appendCSVFile(dst, escape)
}

// appendCSVFile appends the file column. Files that implement
// file.StringAppender (every file in this codebase) are rendered straight
// into dst - only their traced path components pass through escape - and are
// then quoted in place; anything else falls back to String().
func (e *Pair) appendCSVFile(dst []byte, escape func(string) string) []byte {
	if e.File == nil {
		return append(dst, NoFileName...)
	}
	appender, ok := e.File.(file.StringAppender)
	if !ok {
		return appendCSVText(dst, e.File.String(), escape)
	}
	start := len(dst)
	dst = appender.AppendString(dst, escape)
	return quoteInPlace(dst, start)
}

// Flags returns the open flags of the pair's associated file, or zero when
// no file is attached.
func (e *Pair) Flags() file.Flags {
	if e.File == nil {
		return file.Flags(0)
	}
	return e.File.Flags()
}

// FileName returns the associated file's path, or the NoFileName placeholder
// when the pair carries no file. Use it for display; data files use FileValue.
func (e *Pair) FileName() string {
	if e.File == nil {
		return NoFileName
	}
	return e.File.Name()
}

// FileValue returns the associated file's path, or "" when the pair carries
// no file. It is the value persisted into data files (the .ior.zst flamegraph
// record, task pq2): the decision is File == nil, not a comparison of the text
// with NoFileName, so a real file literally named "N:file" keeps its name
// (the same rule as streamrow Row.FileValue for the Parquet and CSV exports).
func (e *Pair) FileValue() string {
	if e.File == nil {
		return ""
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

// Dump renders the pair for debugging: the CSV row plus both raw events.
func (e *Pair) Dump() string {
	return fmt.Sprintf("%v with enterEv(%v) and exitEv(%v)", e, e.EnterEv, e.ExitEv)
}

// Recycle returns the pair and both of its events to their pools. Every
// code path that drops a pair must go through here; a leaked pool object is
// a silent allocation regression on the hot path.
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
