package internal

import (
	"io"
	"os"
	"time"

	"ior/internal/event"
	"ior/internal/textsafe"
)

// plainFlushBytes is the buffered output size that triggers a write. One
// write(2) then carries several hundred rows instead of one, which took the
// syscall out of the -plain per-row cost.
const plainFlushBytes = 64 << 10

// plainFlushInterval bounds how long a buffered row waits for company: the
// event loop flushes this long after the first row of a batch, busy or idle.
// It is short enough for `ior -plain | tail -f`-style consumers to see output
// live, and long enough that a loaded loop still batches tens of rows per
// write. It is a variable only so tests can stretch it to prove that a flush
// came from the shutdown path rather than the timer; nothing else writes it.
var plainFlushInterval = 20 * time.Millisecond

// pairFlusher is what the event loop needs from a buffered pair sink.
type pairFlusher interface {
	// Flush writes out everything buffered.
	Flush() error
	// Pending reports whether rows are buffered and not yet written.
	Pending() bool
}

// plainSink is the default pair sink, which -plain mode keeps: each pair is
// appended to a buffer as one CSV row (event.Pair.AppendCSVRow), recycled, and
// the buffer is written to w in large chunks. The escaper is chosen once, in
// newPlainSink, by mode.Escaper: with the default auto mode a terminal gets
// the attacker-controlled comm/name/file columns escaped with
// textsafe.Escape, so a traced file name cannot inject escape sequences into
// the operator's terminal, while piped or redirected rows keep the exact
// traced bytes for machine consumers. -escape=always covers pipes that still
// end in a terminal (| less -R, | tee); -escape=never forces raw output.
//
// Buffering: writing each row with its own write(2) cost about as much as
// formatting it. A terminal is the exception, because it is interactive and
// its rendering, not the write, is the bottleneck: rows to a terminal are
// written as they are produced. For everything else Print only appends; the
// buffer is written when it reaches plainFlushBytes, by the event loop within
// plainFlushInterval of the first buffered row, and when the loop stops.
//
// Accepted trade-off: buffering means rows can be lost on an exit that does not
// run the event loop's defers. The flush on loop stop covers a normal exit,
// ctx cancellation (SIGINT/SIGTERM) and even a panic unwinding through run, but
// not a crash in another goroutine, SIGHUP, SIGQUIT or SIGKILL: up to
// plainFlushInterval of rows, or plainFlushBytes, are then lost, where the old
// row-per-write writer lost nothing. That is the price of the ~2x throughput,
// and a process dying that way is already not producing a complete trace.
//
// A plainSink is used from the event-loop goroutine only and needs no lock.
type plainSink struct {
	w           io.Writer
	escape      func(string) string
	interactive bool
	buf         []byte
	// err is the first write error. Rows of a failed write are dropped and
	// later rows are still attempted, as the unbuffered fmt.Fprintln did, so
	// a transient failure loses only the affected rows; Err lets the caller
	// surface it. A partial write (n < len, err != nil) drops the whole
	// buffer too, including the n bytes that did get out: the unwritten tail
	// is not retried, because a retry could duplicate or tear a row. Err is
	// what the -plain write-error task (tr2) consumes to report lost rows.
	err error
}

func newPlainSink(w io.Writer, mode textsafe.EscapeMode) *plainSink {
	return &plainSink{
		w:           w,
		escape:      mode.Escaper(w),
		interactive: textsafe.IsTerminal(w),
		buf:         make([]byte, 0, plainFlushBytes+4<<10),
	}
}

// Print appends the pair's row and recycles the pair.
func (s *plainSink) Print(ep *event.Pair) {
	s.buf = ep.AppendCSVRow(s.buf, s.escape)
	s.buf = append(s.buf, '\n')
	ep.Recycle()
	if s.interactive || len(s.buf) >= plainFlushBytes {
		_ = s.Flush() // recorded in s.err
	}
}

// Flush writes the buffered rows to w. The buffer is emptied even when the
// write fails, so a persistently failing writer cannot grow it without bound.
func (s *plainSink) Flush() error {
	if len(s.buf) == 0 {
		return nil
	}
	_, err := s.w.Write(s.buf)
	s.buf = s.buf[:0]
	if err != nil && s.err == nil {
		s.err = err
	}
	return err
}

// Pending implements pairFlusher.
func (s *plainSink) Pending() bool { return len(s.buf) > 0 }

// Err returns the first write error, or nil.
func (s *plainSink) Err() error { return s.err }

// plainStdoutSink is the eventLoop's default sink: a plainSink bound to
// os.Stdout with the -escape mode. The binding (and with it the terminal
// check) happens on the first pair rather than when the loop is built, so the
// sink writes to whatever os.Stdout is once events flow, as the fmt.Println it
// replaced did (tests swap os.Stdout after constructing the loop).
type plainStdoutSink struct {
	mode textsafe.EscapeMode
	sink *plainSink
}

func newPlainStdoutSink(mode textsafe.EscapeMode) *plainStdoutSink {
	return &plainStdoutSink{mode: mode}
}

// Print implements the printCb contract, binding os.Stdout on first use.
func (s *plainStdoutSink) Print(ep *event.Pair) {
	if s.sink == nil {
		s.sink = newPlainSink(os.Stdout, s.mode)
	}
	s.sink.Print(ep)
}

// Flush implements pairFlusher; before the first pair there is nothing to flush.
func (s *plainStdoutSink) Flush() error {
	if s.sink == nil {
		return nil
	}
	return s.sink.Flush()
}

// Pending implements pairFlusher.
func (s *plainStdoutSink) Pending() bool { return s.sink != nil && s.sink.Pending() }

// Err returns the first stdout write error, or nil (also before the first
// pair). It is the accessor through which the -plain write-error handling
// (task tr2) learns that rows were lost; nothing consumes it yet.
func (s *plainStdoutSink) Err() error {
	if s.sink == nil {
		return nil
	}
	return s.sink.Err()
}

// flushTimer schedules the event loop's flush of a buffered sink: it is armed
// when rows first become pending and fires plainFlushInterval later, so the
// wait is bounded whether the loop is busy or idle. A nil *flushTimer (no
// buffered sink) is valid and does nothing; C then blocks forever, which
// disables the select case.
type flushTimer struct {
	sink  pairFlusher
	timer *time.Timer
	armed bool
}

func newFlushTimer(sink pairFlusher) *flushTimer {
	if sink == nil {
		return nil
	}
	t := time.NewTimer(plainFlushInterval)
	t.Stop()
	return &flushTimer{sink: sink, timer: t}
}

// armIfPending starts the countdown when rows are buffered and none runs.
func (t *flushTimer) armIfPending() {
	if t == nil || t.armed || !t.sink.Pending() {
		return
	}
	t.timer.Reset(plainFlushInterval)
	t.armed = true
}

// C is the channel to select on; nil while the timer is not armed.
func (t *flushTimer) C() <-chan time.Time {
	if t == nil || !t.armed {
		return nil
	}
	return t.timer.C
}

// fire flushes the sink after C delivered.
func (t *flushTimer) fire() {
	t.armed = false
	_ = t.sink.Flush() // the sink records the error
}

// stop releases the timer when the loop ends.
func (t *flushTimer) stop() {
	if t != nil {
		t.timer.Stop()
	}
}
