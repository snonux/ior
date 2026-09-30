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
	"ior/internal/flags"
	"ior/internal/probemanager"
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
	// partial, when > 0, makes the first failing write accept only that many
	// bytes (recorded) before returning err, like a write(2) cut short by
	// ENOSPC or EPIPE. It applies to writes counted by failN.
	partial int
}

func (w *recordingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.failN > 0 {
		w.failN--
		n := min(w.partial, len(p))
		if n > 0 {
			w.writes = append(w.writes, string(p[:n]))
		}
		return n, w.err
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

// TestSetPrintCallbackDropsFlusher: a mode that replaces the callback (TUI,
// parquet, flamegraph, pprof) must also drop the plain sink's flusher, so the
// loop does not flush a sink that is no longer fed. Only WrapPrintCallback,
// whose wrapper still feeds the previous callback, keeps it (see
// TestWrapPrintCallbackKeepsFlusher).
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

// TestWrapPrintCallbackKeepsFlusher: wrapping the default callback keeps the
// flusher and still routes pairs through the wrapper into the original sink.
func TestWrapPrintCallbackKeepsFlusher(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{commResolver: newHermeticCommResolver()})
	t.Cleanup(el.commResolver.shutdown)
	sink := el.flusher
	wrapped := 0
	el.WrapPrintCallback(func(next func(*event.Pair)) func(*event.Pair) {
		return func(ep *event.Pair) { wrapped++; next(ep) }
	})
	if el.flusher != sink {
		t.Fatal("WrapPrintCallback dropped or replaced the flusher")
	}
	pipeR, pipeW := swapStdoutPipe(t)
	el.emit(plainTestPair(1))
	if wrapped != 1 || !el.flusher.Pending() {
		t.Fatalf("wrapper calls %d, pending %v; want the pair to pass the wrapper into the sink", wrapped, el.flusher.Pending())
	}
	el.flushOutput()
	_ = pipeW.Close()
	if out := readAll(t, pipeR); strings.Count(out, "\n") != 1 {
		t.Fatalf("flushed %q, want one row", out)
	}
}

// swapStdoutPipe replaces os.Stdout with the write end of a real pipe (a
// non-terminal, so the -plain sink buffers) for the rest of the test and
// returns both ends. The caller closes the write end before reading to EOF.
func swapStdoutPipe(t *testing.T) (r, w *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	t.Cleanup(func() {
		os.Stdout = old
		_ = w.Close()
		_ = r.Close()
	})
	return r, w
}

func readAll(t *testing.T, r *os.File) string {
	t.Helper()
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			return sb.String()
		}
	}
}

// plainTraceInfra builds the traceInfra runTraceLoop drives in a real -plain
// run: the default event loop (buffered stdout sink), a probe manager with
// openat active, and a raw channel the test feeds. os.Stdout is a real pipe,
// so a row visible on the read end has really gone through write(2).
func plainTraceInfra(t *testing.T) (infra *traceInfra, rawCh chan []byte, pipeR *os.File) {
	t.Helper()
	pipeR, _ = swapStdoutPipe(t)
	el := mustNewEventLoop(t, eventLoopConfig{plainMode: true, commResolver: newHermeticCommResolver()})
	t.Cleanup(el.commResolver.shutdown)

	mgr := probemanager.NewManager(&fakeProbeAttacher{prog: &fakeProbeProgram{link: &fakeProbeLink{}}})
	mgr.Register("openat", probemanager.TracepointPair{Enter: "sys_enter_openat", Exit: "sys_exit_openat"})
	if err := mgr.Attach("openat"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	profiling, err := setupProfiling(ctx, flags.NewFlags(), nil)
	if err != nil {
		t.Fatal(err)
	}
	rawCh = make(chan []byte)
	return &traceInfra{ch: rawCh, ctx: ctx, cancel: cancel, profiling: profiling, el: el, mgr: mgr}, rawCh, pipeR
}

// runTraceLoopAsync runs runTraceLoop with configure == nil, the -plain
// wiring, and returns a stop func that cancels the trace and waits for it.
func runTraceLoopAsync(t *testing.T, infra *traceInfra) (stop func()) {
	t.Helper()
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		runTraceLoop(infra, false, nil, func(...any) {})
	}()
	return func() {
		infra.cancel()
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			t.Fatal("runTraceLoop did not return after cancellation")
		}
	}
}

// TestPlainRunTimerFlushThroughTraceWiring is the end-to-end -plain check the
// hand-wired loop tests missed: through runTraceLoop and
// configureEventLoopOutput (the active-probe wrapper) a lone row must show up
// on a real pipe within about plainFlushInterval, far below plainFlushBytes,
// while the loop keeps running. The interval is stretched to 200ms so that a
// row-per-write regression cannot pass for a timer flush either.
func TestPlainRunTimerFlushThroughTraceWiring(t *testing.T) {
	old := plainFlushInterval
	plainFlushInterval = 200 * time.Millisecond
	t.Cleanup(func() { plainFlushInterval = old })

	infra, rawCh, pipeR := plainTraceInfra(t)
	stop := runTraceLoopAsync(t, infra)
	defer stop()

	start := time.Now()
	sendOpenPair(t, rawCh, defaulTime)

	rowCh := make(chan string, 1)
	go func() {
		line := make([]byte, 0, 256)
		b := make([]byte, 1)
		for {
			if _, err := pipeR.Read(b); err != nil {
				return
			}
			line = append(line, b[0])
			// The header line is written directly by run; the row is the
			// second line.
			if b[0] == '\n' && strings.Count(string(line), "\n") == 2 {
				rowCh <- string(line)
				return
			}
		}
	}()
	select {
	case got := <-rowCh:
		if elapsed := time.Since(start); elapsed < plainFlushInterval/2 {
			t.Fatalf("row arrived after %v, before the flush timer could have fired: not batched", elapsed)
		}
		if !strings.Contains(got, ",openat,") {
			t.Fatalf("got %q, want the openat row", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("buffered row never reached the pipe: the flush timer is not active behind runTraceLoop")
	}
}

// TestPlainRunShutdownFlushThroughTraceWiring: with the timer stretched to an
// hour, the rows can only leave through the flush on the loop's exit path,
// which requires configureEventLoopOutput to have kept the flusher.
func TestPlainRunShutdownFlushThroughTraceWiring(t *testing.T) {
	old := plainFlushInterval
	plainFlushInterval = time.Hour
	t.Cleanup(func() { plainFlushInterval = old })

	infra, rawCh, pipeR := plainTraceInfra(t)
	stop := runTraceLoopAsync(t, infra)
	sendOpenPair(t, rawCh, defaulTime)
	sendOpenPair(t, rawCh, defaulTime+1000)
	stop()

	// runTraceLoop has returned, so the loop has flushed; close the write end
	// (os.Stdout) and read what really went through the pipe.
	_ = os.Stdout.Close()
	out := readAll(t, pipeR)
	if rows := strings.Count(out, ",openat,"); rows != 2 {
		t.Fatalf("pipe holds %q, want both rows flushed at shutdown", out)
	}
}

// TestPlainRunActiveProbeFilterStillApplies: the wrapper that keeps the
// flusher must still drop pairs of inactive probes.
func TestPlainRunActiveProbeFilterStillApplies(t *testing.T) {
	infra, rawCh, pipeR := plainTraceInfra(t)
	infra.mgr = probemanager.NewManager(&fakeProbeAttacher{prog: &fakeProbeProgram{link: &fakeProbeLink{}}})
	stop := runTraceLoopAsync(t, infra)
	sendOpenPair(t, rawCh, defaulTime)
	stop()
	_ = os.Stdout.Close()
	if out := readAll(t, pipeR); strings.Contains(out, ",openat,") {
		t.Fatalf("row of an inactive probe was printed: %q", out)
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

// TestPlainSinkPartialWrite: a write that accepts n < len bytes and errors
// loses the rest of that buffer (it is not retried, so no row is duplicated or
// torn a second time), records the error, does not keep the buffer pending,
// and later rows still go out whole.
func TestPlainSinkPartialWrite(t *testing.T) {
	boom := errors.New("no space left on device")
	w := &recordingWriter{failN: 1, err: boom, partial: 10}
	sink := newPlainSink(w, textsafe.EscapeNever)

	sink.Print(plainTestPair(1))
	sink.Print(plainTestPair(2))
	if err := sink.Flush(); !errors.Is(err, boom) {
		t.Fatalf("Flush error = %v, want %v", err, boom)
	}
	if n, out := w.snapshot(); n != 1 || len(out) != 10 {
		t.Fatalf("partial write recorded %d writes / %d bytes, want 1 write of 10 bytes", n, len(out))
	}
	if sink.Pending() {
		t.Fatal("the unwritten tail stayed buffered; it would be retried and could duplicate rows")
	}
	if !errors.Is(sink.Err(), boom) {
		t.Fatalf("Err = %v, want the write error", sink.Err())
	}

	sink.Print(plainTestPair(3))
	if err := sink.Flush(); err != nil {
		t.Fatalf("Flush after the failure: %v", err)
	}
	_, out := w.snapshot()
	tail := out[10:]
	if !strings.HasPrefix(tail, "00000009,00000007,dd,3.3,") || strings.Count(tail, "\n") != 1 {
		t.Fatalf("row after the partial write = %q, want exactly one whole row of pid 3", tail)
	}
	// Err keeps the first error; a later success does not clear it.
	if !errors.Is(sink.Err(), boom) {
		t.Fatalf("Err cleared by a later successful write: %v", sink.Err())
	}
}

// TestPlainStdoutSinkErr: the wrapper exposes the inner sink's error (the
// accessor task tr2 consumes) and is nil before it is bound.
func TestPlainStdoutSinkErr(t *testing.T) {
	s := newPlainStdoutSink(textsafe.EscapeNever)
	if s.Err() != nil {
		t.Fatal("Err before the first pair is non-nil")
	}
	r, _ := swapStdoutPipe(t)
	_ = r.Close() // reader gone: writes fail with EPIPE
	s.Print(plainTestPair(1))
	if err := s.Flush(); err == nil || s.Err() == nil {
		t.Fatalf("Flush error %v, Err %v; want the closed-pipe error on both", err, s.Err())
	}
}
