package integrationtests

import (
	"syscall"
	"testing"
)

const (
	mmapParquetDuration           = 6
	mmapWorkloadStartupEnv        = "IOR_WORKLOAD_STARTUP_DELAY_MS=1000"
	mmapScenarioAddressSpaceBytes = 8192
	mmapMinAddressSpaceBytesTotal = mmapScenarioAddressSpaceBytes * 2
)

var mmapTraceArgs = []string{"-trace-syscalls", "openat,write,close,mmap,msync,mremap,munmap"}

// mmapMemoryLockTraceArgs traces the memory-locking cluster. mlock/mlock2/
// munlock are KindMem and mlockall/munlockall are KindNull; in all cases only
// the sys_enter_ tracepoint presence is asserted (return is UNCLASSIFIED).
var mmapMemoryLockTraceArgs = []string{"-trace-syscalls", "mlock,mlock2,munlock,mlockall,munlockall"}

func TestMmapBasic(t *testing.T) {
	runScenarioResultWithIorArgs(t, "mmap-basic", []ExpectedEvent{
		{
			PathContains: "mmapfile.txt",
			Tracepoint:   "enter_mmap",
			Comm:         "ioworkload",
			MinCount:     1,
			Flags:        &ExpectedFlags{AccessMode: ptrTo(syscall.O_RDWR)},
		},
	}, mmapTraceArgs)
}

func TestMmapMsyncSync(t *testing.T) {
	rows, _ := runParquetScenarioRows(t, "mmap-msync-sync", defaultDuration, mmapTraceArgs, nil)
	AssertRowsPresent(t, rows, []ExpectedRow{
		{
			FileContains: "msyncfile.txt",
			Syscall:      "mmap",
			Comm:         "ioworkload",
			IsError:      ptrTo(false),
		},
		{
			Syscall: "msync",
			Comm:    "ioworkload",
			RetVal:  ptrTo(int64(0)),
			IsError: ptrTo(false),
		},
	})
}

func TestMmapMsyncInvalidFlags(t *testing.T) {
	rows, _ := runParquetScenarioRows(t, "mmap-msync-invalid-flags", defaultDuration, mmapTraceArgs, nil)
	AssertRowsPresent(t, rows, []ExpectedRow{
		{
			FileContains: "msyncinvalidfile.txt",
			Syscall:      "mmap",
			Comm:         "ioworkload",
			IsError:      ptrTo(false),
		},
		{
			Syscall: "msync",
			Comm:    "ioworkload",
			RetVal:  ptrTo(-int64(syscall.EINVAL)),
			IsError: ptrTo(true),
		},
	})
}

// TestMmapMemoryLock asserts the memory-locking cluster fires its enter
// tracepoints end-to-end. mlock/mlock2/munlock (KindMem) and mlockall/
// munlockall (KindNull) all return UNCLASSIFIED, so enter-presence is the
// correct check. mlock/mlock2/mlockall may hit EPERM/ENOMEM under a low
// RLIMIT_MEMLOCK, but the sys_enter_ tracepoint fires regardless.
func TestMmapMemoryLock(t *testing.T) {
	runScenarioResultWithIorArgs(t, "mmap-memory-lock", []ExpectedEvent{
		{
			Tracepoint: "enter_mlock",
			Comm:       "ioworkload",
			MinCount:   1,
		},
		{
			Tracepoint: "enter_munlock",
			Comm:       "ioworkload",
			MinCount:   1,
		},
		{
			Tracepoint: "enter_mlock2",
			Comm:       "ioworkload",
			MinCount:   1,
		},
		{
			Tracepoint: "enter_mlockall",
			Comm:       "ioworkload",
			MinCount:   1,
		},
		{
			Tracepoint: "enter_munlockall",
			Comm:       "ioworkload",
			MinCount:   1,
		},
	}, mmapMemoryLockTraceArgs)
}

func TestMmapMremapMunmapAddressSpaceBytesInParquet(t *testing.T) {
	rows, _ := runParquetScenarioRows(t, "mmap-mremap-munmap", mmapParquetDuration,
		mmapTraceArgs, []string{mmapWorkloadStartupEnv})
	zeroBytes := uint64(0)
	AssertRowsPresent(t, rows, []ExpectedRow{
		{
			Syscall:           "mremap",
			Comm:              "ioworkload",
			IsError:           ptrTo(false),
			Bytes:             &zeroBytes,
			AddressSpaceBytes: ptrTo(uint64(mmapScenarioAddressSpaceBytes)),
		},
		{
			Syscall:           "munmap",
			Comm:              "ioworkload",
			RetVal:            ptrTo(int64(0)),
			IsError:           ptrTo(false),
			Bytes:             &zeroBytes,
			AddressSpaceBytes: ptrTo(uint64(mmapScenarioAddressSpaceBytes)),
		},
	})

	var addressSpaceTotal uint64
	for _, row := range rows {
		switch row.Syscall {
		case "mremap":
			addressSpaceTotal += row.AddressSpaceBytes
		case "munmap":
			addressSpaceTotal += row.AddressSpaceBytes
		}
	}

	if addressSpaceTotal < mmapMinAddressSpaceBytesTotal {
		t.Fatalf("mremap+munmap AddressSpaceBytes total = %d, want >= %d", addressSpaceTotal, mmapMinAddressSpaceBytesTotal)
	}
}
