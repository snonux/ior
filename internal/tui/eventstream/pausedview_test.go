package eventstream

import (
	"strings"
	"testing"
)

// pausedFD7Model returns a model paused on a view that still shows five fd-7
// rows of pid 100, after the live ring has been flooded with enough newer
// events to evict every one of them. The ring then holds only rows the paused
// view does not show, which is what separates "the paused snapshot" from "the
// live ring" in the operations under test (task 2r2). The selection is left on
// the last visible fd-7 row.
func pausedFD7Model(t *testing.T) (*Model, *RingBuffer) {
	t.Helper()
	rb := NewRingBuffer()
	for i := 0; i < 5; i++ {
		rb.Push(StreamEvent{Seq: uint64(100 + i), Syscall: "read", Comm: "proc", PID: 100, FD: 7, FileName: "/tmp/fd7"})
	}
	model := NewModel(rb)
	m := &model
	m.SetViewport(160, 40)
	m.Refresh()
	if !pressLocal(t, m, "space") || !m.Paused() {
		t.Fatalf("expected space to pause the stream")
	}
	m.selectedIdx = len(m.filtered) - 1

	for i := 0; i < ringBufferCapacity; i++ {
		rb.Push(StreamEvent{Seq: uint64(1000 + i), Syscall: "write", Comm: "flood", PID: 200, FD: 9, FileName: "/tmp/flood"})
	}
	for _, ev := range rb.Snapshot() {
		if ev.FD == 7 {
			t.Fatalf("setup: live ring still holds fd 7 (seq %d); eviction did not happen", ev.Seq)
		}
	}
	return m, rb
}

// T on a still-visible row must trace from the paused snapshot. Before the fix
// it re-read the live ring, found nothing for fd 7 and silently did nothing.
func TestFDTraceWhilePausedUsesPausedSnapshotNotLiveRing(t *testing.T) {
	m, _ := pausedFD7Model(t)
	if !pressLocal(t, m, "T") || !m.FDTraceVisible() {
		t.Fatalf("T on a visible fd-7 row did not open the overlay (status %q)", m.statusMessage)
	}
	if got := len(m.fdTraceView.events); got != 5 {
		t.Fatalf("fd trace has %d events, want the 5 paused fd-7 rows", got)
	}
	for _, ev := range m.fdTraceView.events {
		if ev.PID != 100 || ev.FD != 7 {
			t.Fatalf("fd trace contains foreign row %+v", ev)
		}
	}
}

// A fileless row has no descriptor to trace: the key is consumed and the
// footer says why, instead of the key vanishing.
func TestFDTraceOnRowWithoutDescriptorSetsStatus(t *testing.T) {
	rb := NewRingBuffer()
	rb.Push(StreamEvent{Seq: 1, Syscall: "sched_yield", Comm: "proc", PID: 100, FD: UnknownFD})
	model := NewModel(rb)
	m := &model
	m.SetViewport(160, 40)
	m.Refresh()
	pressLocal(t, m, "space")
	if !pressLocal(t, m, "T") {
		t.Fatalf("T on an fd-less row must be consumed")
	}
	if m.FDTraceVisible() {
		t.Fatalf("overlay opened for a row without a descriptor")
	}
	if !strings.Contains(m.statusMessage, "no file descriptor") {
		t.Fatalf("status = %q, want a no-file-descriptor message", m.statusMessage)
	}
}

// T while live stays unhandled: the trace is a paused-view operation.
func TestFDTraceWhileLiveIsNotHandled(t *testing.T) {
	m, _ := pausedFD7Model(t)
	pressLocal(t, m, "space") // resume
	if pressLocal(t, m, "T") || m.FDTraceVisible() {
		t.Fatalf("T must not open the overlay while the stream is live")
	}
}

// The two export paths differ on purpose (task 364, README, AGENTS.md): the
// dashboard-wide 'e' (ExportInputs) writes a fresh snapshot of the live ring
// even while paused, while the stream tab's x writes the frozen paused rows.
// Task 2r2 confirmed this as intended behaviour and left it alone; this test
// pins both halves so neither drifts into the other unnoticed.
func TestExportInputsStayLiveWhilePaused(t *testing.T) {
	m, rb := pausedFD7Model(t)
	src, filter, _ := m.ExportInputs()
	if src != Source(rb) {
		t.Fatalf("paused ExportInputs source = %T, want the live ring buffer", src)
	}
	ePath, err := exportSnapshotToCSV(src, filter, t.TempDir(), "e.csv")
	if err != nil {
		t.Fatalf("e export: %v", err)
	}
	eRows := readCSVRecords(t, ePath)
	if len(eRows) != 1+ringBufferCapacity || eRows[1][0] != "1000" {
		t.Fatalf("e exported %d data rows (first seq %s), want the %d live flood rows", len(eRows)-1, eRows[1][0], ringBufferCapacity)
	}

	m.exportEnabled = true
	m.exportDir = t.TempDir()
	if !pressLocal(t, m, "x") || m.lastExportPath == "" {
		t.Fatalf("x did not export: %q", m.statusMessage)
	}
	xRows := readCSVRecords(t, m.lastExportPath)
	if len(xRows) != 1+5 || xRows[1][0] != "100" {
		t.Fatalf("x exported %d data rows (first seq %s), want the 5 paused rows", len(xRows)-1, xRows[1][0])
	}
}
