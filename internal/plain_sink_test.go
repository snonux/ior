package internal

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/textsafe"
	"ior/internal/types"
)

// recordingWriter is a goroutine-safe io.Writer that remembers every Write,
// so tests can count the write(2) calls the sink would have made and read the
// output while the event loop is still running.
type recordingWriter struct {
	mu     sync.Mutex
	writes []string
	failN  int // fail the first failN writes
	err    error
}

func (w *recordingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.failN > 0 {
		w.failN--
		return 0, w.err
	}
	w.writes = append(w.writes, string(p))
	return len(p), nil
}

func (w *recordingWriter) snapshot() (writes int, out string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.writes), strings.Join(w.writes, "")
}

// plainTestPair is a small clean pair (no hostile bytes).
func plainTestPair(pid uint32) *event.Pair {
	pair := event.NewPair(&types.OpenEvent{TraceId: types.SYS_ENTER_OPENAT, Pid: pid, Tid: pid})
	pair.ExitEv = &types.RetEvent{TraceId: types.SYS_EXIT_OPENAT, Pid: pid, Tid: pid, Ret: 3}
	pair.Comm = "dd"
	pair.File = file.NewFd(3, "/tmp/x", 0)
	pair.Duration, pair.DurationToPrev = 7, 9
	return pair
}

// TestPlainSinkBatchesWrites: rows to a pipe or file are buffered, written
// only on Flush or once plainFlushBytes accumulate, and the bytes written are
// exactly the rows CSVRow renders, in order.
func TestPlainSinkBatchesWrites(t *testing.T) {
	w := &recordingWriter{}
	sink := newPlainSink(w, textsafe.EscapeAuto)

	var want strings.Builder
	sink.Print(plainTestPair(1))
	want.WriteString("00000009,00000007,dd,1.1,openat,3,\"/tmp/x%(3,O_RDONLY)\"\n")
	if n, _ := w.snapshot(); n != 0 || !sink.Pending() {
		t.Fatalf("one buffered row: %d writes, pending %v; want 0 writes and pending", n, sink.Pending())
	}
	if err := sink.Flush(); err != nil {
		t.Fatal(err)
	}
	if n, out := w.snapshot(); n != 1 || out != want.String() || sink.Pending() {
		t.Fatalf("after Flush: %d writes, out %q, pending %v", n, out, sink.Pending())
	}

	// Enough rows to cross the threshold: far fewer writes than rows.
	rows := 3 * plainFlushBytes / len(want.String())
	for i := 0; i < rows; i++ {
		sink.Print(plainTestPair(1))
		want.WriteString("00000009,00000007,dd,1.1,openat,3,\"/tmp/x%(3,O_RDONLY)\"\n")
	}
	if err := sink.Flush(); err != nil {
		t.Fatal(err)
	}
	n, out := w.snapshot()
	if out != want.String() {
		t.Fatalf("output differs from the expected rows (%d bytes vs %d)", len(out), want.Len())
	}
	if n < 2 || n > rows/10 {
		t.Fatalf("%d rows took %d writes, want batching (a few writes, more than one)", rows, n)
	}
}

// TestPlainSinkTerminalWritesEveryRow: a terminal is interactive, so a row
// is written immediately, never held back.
func TestPlainSinkTerminalWritesEveryRow(t *testing.T) {
	tty := newTTYBuffer(t)
	sink := newPlainSink(tty, textsafe.EscapeNever)
	sink.Print(plainTestPair(1))
	if sink.Pending() || tty.Len() == 0 {
		t.Fatalf("terminal row was buffered: pending %v, written %d bytes", sink.Pending(), tty.Len())
	}
}

// TestPlainSinkWriteError: a failed write is recorded, drops only the rows
// of that write (the buffer does not grow without bound) and later rows are
// still attempted, as the unbuffered writer behaved.
func TestPlainSinkWriteError(t *testing.T) {
	boom := errors.New("disk full")
	w := &recordingWriter{failN: 1, err: boom}
	sink := newPlainSink(w, textsafe.EscapeAuto)

	sink.Print(plainTestPair(1))
	if err := sink.Flush(); !errors.Is(err, boom) {
		t.Fatalf("Flush error = %v, want %v", err, boom)
	}
	if sink.Pending() {
		t.Fatal("failed rows stayed buffered")
	}
	sink.Print(plainTestPair(2))
	if err := sink.Flush(); err != nil {
		t.Fatalf("second Flush: %v", err)
	}
	if n, out := w.snapshot(); n != 1 || !strings.Contains(out, ",2.2,") || strings.Contains(out, ",1.1,") {
		t.Fatalf("after the failure: %d writes, out %q; want only the second row", n, out)
	}
	if !errors.Is(sink.Err(), boom) {
		t.Fatalf("Err = %v, want the first write error", sink.Err())
	}
}

// TestFlushTimerNilIsInert: loops without a buffered sink pass a nil timer;
// every method must be a no-op and C must never fire.
func TestFlushTimerNilIsInert(t *testing.T) {
	timer := newFlushTimer(nil)
	timer.armIfPending()
	timer.stop()
	if timer.C() != nil {
		t.Fatal("nil timer exposes a channel")
	}
}

// runPlainLoop starts an event loop whose printCb is a plainSink on w and
// returns the raw channel and a stop function that waits for the loop.
func runPlainLoop(t *testing.T, w *recordingWriter) (chan<- []byte, *eventLoop, func()) {
	t.Helper()
	el := mustNewEventLoop(t, eventLoopConfig{commResolver: newHermeticCommResolver()})
	t.Cleanup(el.commResolver.shutdown)
	sink := newPlainSink(w, textsafe.EscapeNever)
	el.printCb, el.flusher = sink.Print, sink

	ctx, cancel := context.WithCancel(context.Background())
	rawCh := make(chan []byte)
	go el.run(ctx, rawCh)
	stop := func() {
		cancel()
		waitForEventLoopDone(t, el, 5*time.Second)
	}
	t.Cleanup(cancel)
	return rawCh, el, stop
}

// sendOpenPair feeds one openat enter/exit pair, which completes one row.
func sendOpenPair(t *testing.T, rawCh chan<- []byte, at uint64) {
	t.Helper()
	_, enter := makeEnterOpenEvent(t, at, defaultPid, defaultTid)
	_, exit := makeExitOpenEvent(t, at+100, defaultPid, defaultTid)
	rawCh <- enter
	rawCh <- exit
}

// TestEventLoopFlushesBufferedRowsWhileRunning: a lone row must reach the
// writer within the flush interval even though the loop is still running and
// idle (the `tail -f` case), not only at shutdown.
func TestEventLoopFlushesBufferedRowsWhileRunning(t *testing.T) {
	w := &recordingWriter{}
	rawCh, _, stop := runPlainLoop(t, w)
	defer stop()

	sendOpenPair(t, rawCh, defaulTime)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if n, out := w.snapshot(); n > 0 {
			if !strings.HasSuffix(out, "\n") || strings.Count(out, "\n") != 1 {
				t.Fatalf("flushed %q, want exactly one complete row", out)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("buffered row was not flushed while the loop was idle")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestEventLoopFlushesOnShutdown proves the shutdown flush independently of
// the timer: the interval is stretched to an hour, so the row can only reach
// the writer through the flush in run's exit path.
func TestEventLoopFlushesOnShutdown(t *testing.T) {
	old := plainFlushInterval
	plainFlushInterval = time.Hour
	t.Cleanup(func() { plainFlushInterval = old })

	w := &recordingWriter{}
	rawCh, _, stop := runPlainLoop(t, w)
	sendOpenPair(t, rawCh, defaulTime)
	// The loop handles records in order, so once it takes this second pair
	// the first is already emitted (buffered).
	sendOpenPair(t, rawCh, defaulTime+1000)
	if n, _ := w.snapshot(); n != 0 {
		t.Fatalf("rows were written before shutdown (%d writes) although the timer is an hour", n)
	}
	stop()
	if _, out := w.snapshot(); strings.Count(out, "\n") != 2 {
		t.Fatalf("after shutdown output = %q, want both rows flushed", out)
	}
}

// TestSetPrintCallbackDropsFlusher: replacing the callback (TUI, parquet)
// must also drop the plain sink's flusher, so the loop does not flush a sink
// that is no longer fed.
func TestSetPrintCallbackDropsFlusher(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{commResolver: newHermeticCommResolver()})
	t.Cleanup(el.commResolver.shutdown)
	if el.flusher == nil {
		t.Fatal("default loop has no flusher for its buffered -plain sink")
	}
	el.SetPrintCallback(func(ep *event.Pair) { ep.Recycle() })
	if el.flusher != nil {
		t.Fatal("SetPrintCallback kept the flusher")
	}
}

// BenchmarkPlainSinkPrint is the -plain per-row cost with the buffered sink
// writing to /dev/null. BenchmarkPlainUnbufferedFprintln is the previous
// design (CSVRow string + one write(2) per row) on the same target.
func BenchmarkPlainSinkPrint(b *testing.B) {
	devNull := openDevNull(b)
	sink := newPlainSink(devNull, textsafe.EscapeNever)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sink.Print(plainTestPair(1))
	}
	_ = sink.Flush()
}

func BenchmarkPlainUnbufferedFprintln(b *testing.B) {
	devNull := openDevNull(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ep := plainTestPair(1)
		_, _ = fmt.Fprintln(devNull, ep.CSVRow(nil))
		ep.Recycle()
	}
}

func openDevNull(b *testing.B) *os.File {
	b.Helper()
	f, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = f.Close() })
	return f
}
