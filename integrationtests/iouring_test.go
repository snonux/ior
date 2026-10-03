package integrationtests

import (
	"strings"
	"syscall"
	"testing"

	iorparquet "ior/internal/parquet"
)

var iouringTraceArgs = []string{"-trace-syscalls", "io_uring_setup,io_uring_enter,io_uring_register,close"}

func TestIouringSetup(t *testing.T) {
	requireIoUring(t)
	runScenarioResultWithIorArgs(t, "iouring-setup", []ExpectedEvent{
		{
			Tracepoint: "enter_io_uring_setup",
			Comm:       "ioworkload",
			MinCount:   1,
		},
	}, iouringTraceArgs)
}

func TestIouringEnter(t *testing.T) {
	requireIoUring(t)
	runScenarioResultWithIorArgs(t, "iouring-enter", []ExpectedEvent{
		{
			Tracepoint: "enter_io_uring_enter",
			Comm:       "ioworkload",
			MinCount:   1,
		},
	}, iouringTraceArgs)
}

func TestIouringRegister(t *testing.T) {
	requireIoUring(t)
	runScenarioResultWithIorArgs(t, "iouring-register", []ExpectedEvent{
		{
			Tracepoint: "enter_io_uring_register",
			Comm:       "ioworkload",
			MinCount:   1,
		},
	}, iouringTraceArgs)
}

func TestIouringEnterEbadf(t *testing.T) {
	runParquetErrorScenario(t, "iouring-enter-ebadf", syscall.EBADF, ExpectedRow{
		Syscall: "io_uring_enter",
		FD:      ptrTo(int32(99999)),
	}, iouringTraceArgs)
}

func TestIouringRegisterEbadf(t *testing.T) {
	runParquetErrorScenario(t, "iouring-register-ebadf", syscall.EBADF, ExpectedRow{
		Syscall: "io_uring_register",
		FD:      ptrTo(int32(99999)),
	}, iouringTraceArgs)
}

// iouringRingName is what ior calls an io_uring descriptor.
const iouringRingName = "anon_inode:[io_uring]"

// iouringRingTraceArgs adds the calls that rebind a descriptor number to
// iouringTraceArgs, so that ior's fd table knows the decoy files the
// registered-ring scenarios put on the numbers a wrong lookup would hit.
var iouringRingTraceArgs = []string{"-trace-syscalls",
	"io_uring_setup,io_uring_enter,io_uring_register,close,open,openat,dup,dup3"}

// ringSetupRow returns the io_uring_setup row of the scenario's one ring:
// its tid is the thread that registers the ring, its fd the ring descriptor.
func ringSetupRow(t *testing.T, rows []iorparquet.Record) iorparquet.Record {
	t.Helper()
	for _, row := range rows {
		if row.Syscall == "io_uring_setup" {
			if row.File != iouringRingName || row.FD < 0 {
				t.Fatalf("io_uring_setup row does not name the ring descriptor: %+v", row)
			}
			return row
		}
	}
	logRowSummary(t, rows)
	t.Fatal("no io_uring_setup row")
	return iorparquet.Record{}
}

// TestIouringRegisteredRing pins tasks cq2 and js2: io_uring_enter with
// IORING_ENTER_REGISTERED_RING and io_uring_register with
// IORING_REGISTER_USE_REGISTERED_RING pass a registered-ring index in the fd
// argument. The workload parks a decoy file on fd 0, where that index (0 for a
// fresh thread) used to resolve; the rows must name the ring the thread
// registered under the index instead, with the ring's descriptor.
func TestIouringRegisteredRing(t *testing.T) {
	requireIoUring(t)
	rows, _ := runParquetScenarioRows(t, "iouring-registered-ring", defaultDuration, iouringRingTraceArgs, nil)
	setup := ringSetupRow(t, rows)

	var enterRows, registerRows int
	for _, row := range rows {
		if row.Syscall != "io_uring_enter" && row.Syscall != "io_uring_register" {
			continue
		}
		if row.File != iouringRingName || row.FD != setup.FD {
			t.Errorf("%s row is not named after the ring on fd %d: %+v", row.Syscall, setup.FD, row)
		}
		if row.Syscall == "io_uring_enter" {
			enterRows++
		} else {
			registerRows++
		}
	}
	// The scenario issues five of each through the registered ring, and
	// registers it with one more io_uring_register through the descriptor.
	if enterRows != 5 || registerRows != 6 {
		t.Errorf("io_uring rows: enter=%d register=%d, want 5 and 6", enterRows, registerRows)
		logRowSummary(t, rows)
	}
}

// Calls per phase of the iouring-ring-lifecycle scenario
// (cmd/ioworkload/scenario_iouring_ringfds.go).
const (
	ringLifecycleOpenCalls   = 3
	ringLifecycleClosedCalls = 4
	ringLifecycleGoneCalls   = 2
)

// TestIouringRegisteredRingLifecycle follows one registered ring through
// what decides the name of the rows that pass its index (task js2): the
// descriptor it was registered from is closed and its number reused by a
// decoy file, another thread passes the same index, and the index is
// unregistered.
func TestIouringRegisteredRingLifecycle(t *testing.T) {
	requireIoUring(t)
	rows, _ := runParquetScenarioRows(t, "iouring-ring-lifecycle", defaultDuration, iouringRingTraceArgs, nil)
	setup := ringSetupRow(t, rows)
	var own, foreign []iorparquet.Record
	for _, row := range rows {
		if strings.Contains(row.File, "ioworkload-iouring-reuse-") && strings.HasPrefix(row.Syscall, "io_uring") {
			t.Errorf("%s row attributed to the file that reused the ring's descriptor number: %+v", row.Syscall, row)
		}
		switch {
		case row.Syscall != "io_uring_enter":
		case row.TID == setup.TID:
			own = append(own, row)
		default:
			foreign = append(foreign, row)
		}
	}
	checkRingLifecycleEnters(t, own, setup.FD)
	checkRingLifecycleForeignEnter(t, foreign)
	checkRingLifecycleRegisters(t, rows, setup)
	if t.Failed() {
		logRowSummary(t, rows)
	}
}

// checkRingLifecycleEnters checks the registering thread's io_uring_enter
// rows, in order: named after the ring with its descriptor while that is
// open, named after the ring without a descriptor once the number belongs to
// the decoy, and labelled with the index once the slot is released.
func checkRingLifecycleEnters(t *testing.T, own []iorparquet.Record, ringFd int32) {
	t.Helper()
	want := ringLifecycleOpenCalls + ringLifecycleClosedCalls + ringLifecycleGoneCalls
	if len(own) != want {
		t.Fatalf("the registering thread has %d io_uring_enter rows, want %d", len(own), want)
	}
	for i, row := range own {
		wantFile, wantFd, wantErr := iouringRingName, ringFd, false
		switch {
		case i >= ringLifecycleOpenCalls+ringLifecycleClosedCalls:
			wantFile, wantFd, wantErr = "io_uring:reg[", -1, true
		case i >= ringLifecycleOpenCalls:
			wantFd = -1
		}
		if !strings.HasPrefix(row.File, wantFile) || row.FD != wantFd || row.IsError != wantErr {
			t.Errorf("io_uring_enter row %d: file %q fd %d error %v, want file %q.. fd %d error %v",
				i, row.File, row.FD, row.IsError, wantFile, wantFd, wantErr)
		}
	}
}

// checkRingLifecycleForeignEnter checks the one io_uring_enter of the thread
// that registered nothing: the index is its own table's, so the row is
// labelled with it and not named after the other thread's ring.
func checkRingLifecycleForeignEnter(t *testing.T, foreign []iorparquet.Record) {
	t.Helper()
	if len(foreign) != 1 {
		t.Fatalf("other threads have %d io_uring_enter rows, want 1", len(foreign))
	}
	row := foreign[0]
	if !strings.HasPrefix(row.File, "io_uring:reg[") || row.FD != -1 || !row.IsError {
		t.Errorf("io_uring_enter of a thread without the registration: %+v, want the index label, fd -1, an error", row)
	}
}

// checkRingLifecycleRegisters checks the two io_uring_register rows: the
// registration through the descriptor, and the release that addresses the
// ring by the very index it releases - still that ring's row, though its
// descriptor number is the decoy's by then.
func checkRingLifecycleRegisters(t *testing.T, rows []iorparquet.Record, setup iorparquet.Record) {
	t.Helper()
	var registers []iorparquet.Record
	for _, row := range rows {
		if row.Syscall == "io_uring_register" {
			registers = append(registers, row)
		}
	}
	if len(registers) != 2 {
		t.Fatalf("%d io_uring_register rows, want 2", len(registers))
	}
	if reg := registers[0]; reg.File != iouringRingName || reg.FD != setup.FD || reg.Ret != 1 {
		t.Errorf("registration row: %+v, want the ring on fd %d and ret 1", reg, setup.FD)
	}
	if rel := registers[1]; rel.File != iouringRingName || rel.FD != -1 || rel.Ret != 1 {
		t.Errorf("release row: %+v, want the ring without a descriptor and ret 1", rel)
	}
}
