package internal

import (
	"errors"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"ior/internal/event"
	"ior/internal/textsafe"
)

// TestPlainSinkReportsDroppedRows: onErr fires once per failed write with the
// error and the number of rows that write dropped, and never on success.
func TestPlainSinkReportsDroppedRows(t *testing.T) {
	boom := errors.New("no space left on device")
	w := &recordingWriter{failN: 2, err: boom}
	sink := newPlainSink(w, textsafe.EscapeNever)
	var dropped []int
	sink.onErr = func(err error, n int) {
		if !errors.Is(err, boom) {
			t.Errorf("onErr error = %v, want %v", err, boom)
		}
		dropped = append(dropped, n)
	}

	sink.Print(plainTestPair(1))
	sink.Print(plainTestPair(2))
	_ = sink.Flush() // first failure: two rows
	sink.Print(plainTestPair(3))
	_ = sink.Flush() // second failure: one row, the counter restarted
	sink.Print(plainTestPair(4))
	if err := sink.Flush(); err != nil {
		t.Fatalf("Flush after the failures: %v", err)
	}
	if len(dropped) != 2 || dropped[0] != 2 || dropped[1] != 1 {
		t.Fatalf("dropped rows per failed write = %v, want [2 1] and no call for the successful write", dropped)
	}
}

// TestPlainSinkFlushWithoutRowsIsNotAnError: an empty Flush writes nothing, so
// it can neither fail nor call onErr.
func TestPlainSinkFlushWithoutRowsIsNotAnError(t *testing.T) {
	sink := newPlainSink(&recordingWriter{failN: 1, err: errors.New("boom")}, textsafe.EscapeNever)
	sink.onErr = func(error, int) { t.Error("onErr called for a Flush with nothing buffered") }
	if err := sink.Flush(); err != nil {
		t.Fatalf("empty Flush: %v", err)
	}
}

// TestPlainStdoutSinkForwardsOnErr: the onErr handed to the stdout wrapper
// reaches the sink it binds on the first pair.
func TestPlainStdoutSinkForwardsOnErr(t *testing.T) {
	r, _ := swapStdoutPipe(t)
	_ = r.Close() // reader gone: the write fails with EPIPE (fd is not 1, so no SIGPIPE death)
	s := newPlainStdoutSink(textsafe.EscapeNever)
	var got error
	var rows int
	s.onErr = func(err error, n int) { got, rows = err, n }
	s.Print(plainTestPair(1))
	_ = s.Flush()
	if !errors.Is(got, syscall.EPIPE) || rows != 1 {
		t.Fatalf("onErr got (%v, %d), want (EPIPE, 1)", got, rows)
	}
}

// TestOutputFailedStopsTraceOnce: the first failure records the error, warns
// and stops the trace exactly once; later failures only add to the lost rows.
func TestOutputFailedStopsTraceOnce(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{commResolver: newHermeticCommResolver()})
	t.Cleanup(el.commResolver.shutdown)
	var warnings []string
	el.SetWarningCallback(func(m string) { warnings = append(warnings, m) })
	stops := 0
	el.stopTrace = func() { stops++ }

	if el.outputError() != nil || el.outputLossStatLine() != "" {
		t.Fatal("a healthy loop reports an output error or lost rows")
	}
	first := syscall.ENOSPC
	el.outputFailed(first, 3)
	el.outputFailed(errors.New("later"), 4)

	if stops != 1 || len(warnings) != 1 || !strings.Contains(warnings[0], first.Error()) {
		t.Fatalf("stops %d, warnings %q; want one stop and one warning naming %q", stops, warnings, first)
	}
	err := el.outputError()
	if !errors.Is(err, first) || !strings.Contains(err.Error(), "up to 7 rows lost") {
		t.Fatalf("outputError = %v, want the first error and 7 lost rows", err)
	}
	if line := el.outputLossStatLine(); !strings.Contains(line, "up to 7") {
		t.Fatalf("stat line %q does not report the 7 lost rows", line)
	}
}

// TestPlainRunStopsOnUnwritableStdout drives the real -plain wiring
// (runTraceLoop, default stdout sink) and lets the reader go away after the
// header. The next row's write fails, so the loop must end the trace by
// itself - nothing here cancels the context - and report the error, instead
// of tracing on with every row going nowhere.
func TestPlainRunStopsOnUnwritableStdout(t *testing.T) {
	infra, rawCh, pipeR, _ := plainTraceInfra(t)
	var mu sync.Mutex
	var warnings []string
	infra.el.SetWarningCallback(func(m string) {
		mu.Lock()
		defer mu.Unlock()
		warnings = append(warnings, m)
	})

	finished := make(chan struct{})
	go func() {
		defer close(finished)
		runTraceLoop(infra, false, nil, func(...any) {})
	}()
	if got := readPipeFor(t, pipeR, time.Second); !strings.Contains(got, event.EventStreamHeader) {
		t.Fatalf("no header reached the pipe, got %q", got)
	}
	_ = pipeR.Close()

	sendOpenPair(t, rawCh, defaulTime)
	select {
	case <-finished:
	case <-time.After(10 * time.Second):
		infra.cancel()
		t.Fatal("the trace kept running after stdout became unwritable")
	}
	err := infra.el.outputError()
	if !errors.Is(err, syscall.EPIPE) {
		t.Fatalf("outputError = %v, want EPIPE", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(warnings) != 1 || !strings.Contains(warnings[0], "stdout failed") {
		t.Fatalf("warnings = %q, want exactly one stdout-failure warning", warnings)
	}
	if infra.el.rowsLost < 1 {
		t.Fatalf("rowsLost = %d, want the dropped row counted", infra.el.rowsLost)
	}
}

// TestPlainRunStopsOnFullDisk is the reported case: stdout is /dev/full, so
// even the CSV header write fails with ENOSPC. The trace must stop and the
// error must reach the caller (runTraceWithContext joins it into its result).
func TestPlainRunStopsOnFullDisk(t *testing.T) {
	full, err := os.OpenFile("/dev/full", os.O_WRONLY, 0)
	if err != nil {
		t.Skipf("/dev/full unavailable: %v", err)
	}
	t.Cleanup(func() { _ = full.Close() })
	infra, _, _, _ := plainTraceInfra(t) // installs its own pipe; replace it
	old := os.Stdout
	os.Stdout = full
	t.Cleanup(func() { os.Stdout = old })
	infra.el.SetWarningCallback(func(string) {})

	finished := make(chan struct{})
	go func() {
		defer close(finished)
		runTraceLoop(infra, false, nil, func(...any) {})
	}()
	select {
	case <-finished:
	case <-time.After(10 * time.Second):
		infra.cancel()
		t.Fatal("the trace kept running although stdout is full")
	}
	if err := infra.el.outputError(); !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("outputError = %v, want ENOSPC", err)
	}
}
