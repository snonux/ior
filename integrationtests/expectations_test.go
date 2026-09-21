package integrationtests

import (
	"path/filepath"
	"syscall"
	"testing"

	"ior/internal/file"
	"ior/internal/flamegraph"
	iorparquet "ior/internal/parquet"
	"ior/internal/types"

	parquetgo "github.com/parquet-go/parquet-go"
)

func TestExpectedEventFlagsRejectWrongExpectation(t *testing.T) {
	record := flamegraph.IterRecord{
		Path:    "/tmp/testfile.txt",
		TraceID: types.SYS_ENTER_OPENAT,
		Comm:    "ioworkload",
		Flags:   file.Flags(syscall.O_RDWR | syscall.O_CREAT),
	}

	accessReadWrite := syscall.O_RDWR
	if !matchesExpectation(record, ExpectedEvent{
		Tracepoint: "enter_openat",
		Flags: &ExpectedFlags{
			AccessMode: &accessReadWrite,
			Set:        syscall.O_CREAT,
			Clear:      syscall.O_CLOEXEC,
		},
	}) {
		t.Fatal("correct flags expectation did not match")
	}

	accessWriteOnly := syscall.O_WRONLY
	wrong := []ExpectedFlags{
		{AccessMode: &accessWriteOnly},
		{Set: syscall.O_APPEND},
		{Clear: syscall.O_CREAT},
	}
	for _, flags := range wrong {
		if matchesExpectation(record, ExpectedEvent{Tracepoint: "enter_openat", Flags: &flags}) {
			t.Errorf("deliberately wrong flags expectation matched: %+v", flags)
		}
	}
}

func TestExpectedRowChecksEverySemanticField(t *testing.T) {
	row := iorparquet.Record{
		Comm:              "ioworkload",
		PID:               42,
		Syscall:           "epoll_ctl",
		FD:                8,
		Ret:               0,
		Bytes:             32,
		AddressSpaceBytes: 4096,
		RequestedSleepNS:  2_000_000,
		File:              "/tmp/trace",
		IsError:           false,
		EpollOp:           "ADD",
		EpollTargetFD:     9,
		EpollEvents:       1,
	}
	zero32 := int32(0)
	zero64 := int64(0)
	want := ExpectedRow{
		FileContains:         "trace",
		Syscall:              "epoll_ctl",
		Comm:                 "ioworkload",
		FD:                   ptrTo(int32(8)),
		FDAtLeast:            &zero32,
		RetVal:               &zero64,
		RetValAtLeast:        &zero64,
		IsError:              ptrTo(false),
		Bytes:                ptrTo(uint64(32)),
		EpollOp:              ptrTo("ADD"),
		EpollTargetFD:        ptrTo(int32(9)),
		EpollTargetFDAtLeast: &zero32,
		EpollEvents:          ptrTo(uint32(1)),
		AddressSpaceBytes:    ptrTo(uint64(4096)),
		RequestedSleepNs:     ptrTo(int64(2_000_000)),
	}
	if !matchesRowExpectation(row, want) {
		t.Fatal("complete row expectation did not match")
	}

	wrong := []ExpectedRow{
		{FD: ptrTo(int32(7))},
		{FDAtLeast: ptrTo(int32(9))},
		{RetVal: ptrTo(int64(-1))},
		{RetValAtLeast: ptrTo(int64(1))},
		{IsError: ptrTo(true)},
		{Bytes: ptrTo(uint64(31))},
		{EpollOp: ptrTo("DEL")},
		{EpollTargetFD: ptrTo(int32(10))},
		{EpollTargetFDAtLeast: ptrTo(int32(10))},
		{EpollEvents: ptrTo(uint32(2))},
		{AddressSpaceBytes: ptrTo(uint64(8192))},
		{RequestedSleepNs: ptrTo(int64(3_000_000))},
	}
	for _, exp := range wrong {
		if matchesRowExpectation(row, exp) {
			t.Errorf("wrong row expectation matched: %+v", exp)
		}
	}
}

func TestLoadParquetRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rows.parquet")
	want := []iorparquet.Record{{Seq: 1, Syscall: "openat", Ret: -int64(syscall.ENOENT), IsError: true}}
	if err := parquetgo.WriteFile(path, want); err != nil {
		t.Fatalf("write parquet fixture: %v", err)
	}

	got, err := LoadParquetRows(path)
	if err != nil {
		t.Fatalf("LoadParquetRows() error = %v", err)
	}
	if len(got) != 1 || got[0] != want[0] {
		t.Fatalf("LoadParquetRows() = %+v, want %+v", got, want)
	}
}

func TestAssertEventsAbsentNoMatch(t *testing.T) {
	result := TestResult{
		Records: []flamegraph.IterRecord{
			{Path: "/tmp/testfile.txt", TraceID: types.SYS_ENTER_OPENAT, Comm: "ioworkload"},
		},
	}

	mt := &testing.T{}
	AssertEventsAbsent(mt, result, []ExpectedEvent{
		{PathContains: "missing.txt"},
	})
	if mt.Failed() {
		t.Error("AssertEventsAbsent should not fail when event is absent")
	}
}

func TestAssertEventsAbsentWithMatch(t *testing.T) {
	result := TestResult{
		Records: []flamegraph.IterRecord{
			{Path: "/tmp/testfile.txt", TraceID: types.SYS_ENTER_OPENAT, Comm: "ioworkload"},
		},
	}

	mt := &testing.T{}
	AssertEventsAbsent(mt, result, []ExpectedEvent{
		{PathContains: "testfile.txt"},
	})
	if !mt.Failed() {
		t.Error("AssertEventsAbsent should fail when event is present")
	}
}

func TestAssertEventsAbsentEmptyResult(t *testing.T) {
	result := TestResult{}

	mt := &testing.T{}
	AssertEventsAbsent(mt, result, []ExpectedEvent{
		{PathContains: "anything.txt"},
	})
	if mt.Failed() {
		t.Error("AssertEventsAbsent should not fail on empty result")
	}
}

func TestAssertEventsAbsentMultiField(t *testing.T) {
	result := TestResult{
		Records: []flamegraph.IterRecord{
			{Path: "/tmp/testfile.txt", TraceID: types.SYS_ENTER_OPENAT, Comm: "ioworkload"},
			{Path: "/tmp/testfile.txt", TraceID: types.SYS_ENTER_WRITE, Comm: "ioworkload"},
		},
	}

	// Multi-field match: path + tracepoint + comm — all match first record.
	mt := &testing.T{}
	AssertEventsAbsent(mt, result, []ExpectedEvent{
		{PathContains: "testfile.txt", Tracepoint: "enter_openat", Comm: "ioworkload"},
	})
	if !mt.Failed() {
		t.Error("AssertEventsAbsent should fail when multi-field event matches")
	}

	// Multi-field partial mismatch: path matches but tracepoint doesn't.
	mt2 := &testing.T{}
	AssertEventsAbsent(mt2, result, []ExpectedEvent{
		{PathContains: "testfile.txt", Tracepoint: "enter_read"},
	})
	if mt2.Failed() {
		t.Error("AssertEventsAbsent should pass when multi-field expectation partially mismatches")
	}
}

func TestAssertEventsAbsentMultipleExpectations(t *testing.T) {
	result := TestResult{
		Records: []flamegraph.IterRecord{
			{Path: "/tmp/found.txt", TraceID: types.SYS_ENTER_OPENAT, Comm: "ioworkload"},
		},
	}

	// First expectation absent, second present — should fail.
	mt := &testing.T{}
	AssertEventsAbsent(mt, result, []ExpectedEvent{
		{PathContains: "missing.txt"},
		{PathContains: "found.txt"},
	})
	if !mt.Failed() {
		t.Error("AssertEventsAbsent should fail when any expectation matches")
	}
}

func TestAssertEventsAbsentRejectsZeroValue(t *testing.T) {
	result := TestResult{
		Records: []flamegraph.IterRecord{
			{Path: "/tmp/testfile.txt", TraceID: types.SYS_ENTER_OPENAT, Comm: "ioworkload"},
		},
	}

	// Zero-value ExpectedEvent should be rejected with an error.
	mt := &testing.T{}
	AssertEventsAbsent(mt, result, []ExpectedEvent{{}})
	if !mt.Failed() {
		t.Error("AssertEventsAbsent should reject zero-value ExpectedEvent")
	}
}

func TestExpectedRowToleratesUnresolvedCommButRejectsAForeignOne(t *testing.T) {
	exp := ExpectedRow{Syscall: "mmap", Comm: "ioworkload"}
	tests := []struct {
		name string
		comm string
		want bool
	}{
		{name: "resolved and equal", comm: "ioworkload", want: true},
		{name: "not resolved yet", comm: "", want: true},
		{name: "foreign", comm: "bash", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			row := iorparquet.Record{Syscall: "mmap", Comm: tt.comm}
			if got := matchesRowExpectation(row, exp); got != tt.want {
				t.Fatalf("matchesRowExpectation(comm=%q) = %v, want %v", tt.comm, got, tt.want)
			}
		})
	}
}
