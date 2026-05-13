package streamrow

import (
	"sync"
	"testing"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/types"
)

func TestSequencerStartsAfterSeed(t *testing.T) {
	seq := NewSequencer(41)
	if got, want := seq.Next(), uint64(42); got != want {
		t.Fatalf("first Next() = %d, want %d", got, want)
	}
	if got, want := seq.Next(), uint64(43); got != want {
		t.Fatalf("second Next() = %d, want %d", got, want)
	}
}

func TestSequencerIsMonotonicUnderConcurrency(t *testing.T) {
	seq := NewSequencer(0)

	const workers = 8
	const perWorker = 64

	got := make(chan uint64, workers*perWorker)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perWorker; j++ {
				got <- seq.Next()
			}
		}()
	}
	wg.Wait()
	close(got)

	seen := make(map[uint64]struct{}, workers*perWorker)
	for n := range got {
		if _, ok := seen[n]; ok {
			t.Fatalf("duplicate sequence number %d", n)
		}
		seen[n] = struct{}{}
	}
	if got, want := len(seen), workers*perWorker; got != want {
		t.Fatalf("unique sequence count = %d, want %d", got, want)
	}
}

func TestNewPopulatesFieldsFromPair(t *testing.T) {
	enter := &types.OpenEvent{TraceId: types.SYS_ENTER_OPENAT, Time: 1234, Pid: 42, Tid: 84}
	exit := &types.RetEvent{TraceId: types.SYS_EXIT_OPENAT, Time: 1300, Ret: -2, Pid: 42, Tid: 84}
	pair := event.NewPair(enter)
	pair.ExitEv = exit
	pair.File = file.NewFd(7, "/tmp/test.txt", 0)
	pair.Comm = "cat"
	pair.Duration = 66
	pair.DurationToPrev = 19
	pair.Bytes = 512

	got := New(9, pair)
	if got.Seq != 9 || got.TimeNs != 1234 {
		t.Fatalf("Seq/TimeNs = %d/%d, want 9/1234", got.Seq, got.TimeNs)
	}
	if got.Syscall != "openat" || got.Comm != "cat" {
		t.Fatalf("Syscall/Comm = %q/%q, want openat/cat", got.Syscall, got.Comm)
	}
	if got.PID != 42 || got.TID != 84 {
		t.Fatalf("PID/TID = %d/%d, want 42/84", got.PID, got.TID)
	}
	if got.FileName != "/tmp/test.txt" || got.FD != 7 {
		t.Fatalf("FileName/FD = %q/%d, want /tmp/test.txt/7", got.FileName, got.FD)
	}
	if got.DurationNs != 66 || got.GapNs != 19 || got.Bytes != 512 {
		t.Fatalf("DurationNs/GapNs/Bytes = %d/%d/%d, want 66/19/512", got.DurationNs, got.GapNs, got.Bytes)
	}
	if got.RetVal != -2 || !got.IsError {
		t.Fatalf("RetVal/IsError = %d/%v, want -2/true", got.RetVal, got.IsError)
	}
}

func TestNewWarningPopulatesSyntheticWarningFields(t *testing.T) {
	got := NewWarning(7, "Dropped malformed event")
	if got.Seq != 7 || got.TimeNs == 0 {
		t.Fatalf("Seq/TimeNs = %d/%d, want 7/non-zero", got.Seq, got.TimeNs)
	}
	if got.Syscall != "warning" || got.Comm != "ior" {
		t.Fatalf("Syscall/Comm = %q/%q, want warning/ior", got.Syscall, got.Comm)
	}
	if got.FileName != "Dropped malformed event" || got.FD != UnknownFD {
		t.Fatalf("FileName/FD = %q/%d, want warning text/%d", got.FileName, got.FD, UnknownFD)
	}
	if got.RetVal != -1 || !got.IsError {
		t.Fatalf("RetVal/IsError = %d/%v, want -1/true", got.RetVal, got.IsError)
	}
}

// TestRowValueAccessors verifies that all typed accessor methods return the
// underlying field values set on a Row.
func TestRowValueAccessors(t *testing.T) {
	r := Row{
		Syscall:    "read",
		Comm:       "cat",
		FileName:   "/etc/hosts",
		PID:        10,
		TID:        11,
		FD:         3,
		DurationNs: 500,
		GapNs:      200,
		Bytes:      1024,
		RetVal:     -1,
		IsError:    true,
	}

	if r.SyscallValue() != "read" {
		t.Fatalf("SyscallValue = %q, want read", r.SyscallValue())
	}
	if r.CommValue() != "cat" {
		t.Fatalf("CommValue = %q, want cat", r.CommValue())
	}
	if r.FileValue() != "/etc/hosts" {
		t.Fatalf("FileValue = %q, want /etc/hosts", r.FileValue())
	}
	if r.PIDValue() != 10 {
		t.Fatalf("PIDValue = %d, want 10", r.PIDValue())
	}
	if r.TIDValue() != 11 {
		t.Fatalf("TIDValue = %d, want 11", r.TIDValue())
	}
	if r.FDValue() != 3 {
		t.Fatalf("FDValue = %d, want 3", r.FDValue())
	}
	if r.LatencyValue() != 500 {
		t.Fatalf("LatencyValue = %d, want 500", r.LatencyValue())
	}
	if r.GapValue() != 200 {
		t.Fatalf("GapValue = %d, want 200", r.GapValue())
	}
	if r.BytesValue() != 1024 {
		t.Fatalf("BytesValue = %d, want 1024", r.BytesValue())
	}
	if r.ReturnValue() != -1 {
		t.Fatalf("ReturnValue = %d, want -1", r.ReturnValue())
	}
	if !r.ErrorValue() {
		t.Fatal("ErrorValue = false, want true")
	}
}

// TestSequencerNilSafeNext verifies that calling Next on a nil Sequencer returns
// 0 without panicking.
func TestSequencerNilSafeNext(t *testing.T) {
	var s *Sequencer
	if got := s.Next(); got != 0 {
		t.Fatalf("nil Sequencer.Next() = %d, want 0", got)
	}
}
