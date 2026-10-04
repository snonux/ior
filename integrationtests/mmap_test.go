package integrationtests

import (
	"os"
	"syscall"
	"testing"
)

const (
	mmapParquetDuration    = 6
	mmapWorkloadStartupEnv = "IOR_WORKLOAD_STARTUP_DELAY_MS=1000"
)

// The address-space metric counts whole pages, as the kernel maps and unmaps
// them (mmap(len=21) maps one page), so every expectation is the workload's
// requested length rounded up to the host page size. ior traces the host it
// runs on, so os.Getpagesize() is the traced page size too.
var (
	mmapPage                      = uint64(os.Getpagesize())
	mmapScenarioAddressSpaceBytes = mmapRoundUp(8192)
	mmapInitialAddressSpaceBytes  = mmapRoundUp(4096)
	mmapMinAddressSpaceBytesTotal = mmapInitialAddressSpaceBytes + mmapScenarioAddressSpaceBytes*2
	mmapBasicLength               = mmapRoundUp(uint64(len("mmap shared page data")))
	mmapMsyncLength               = mmapRoundUp(uint64(len("msync shared page data")))
)

func mmapRoundUp(n uint64) uint64 {
	return (n + mmapPage - 1) / mmapPage * mmapPage
}

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

func TestMmapBasicAddressSpaceBytesInParquet(t *testing.T) {
	rows, _ := runParquetScenarioRows(t, "mmap-basic", defaultDuration, mmapTraceArgs, nil)
	AssertRowsPresent(t, rows, []ExpectedRow{
		{
			FileContains:      "mmapfile.txt",
			Syscall:           "mmap",
			Comm:              "ioworkload",
			IsError:           ptrTo(false),
			AddressSpaceBytes: ptrTo(mmapBasicLength),
		},
	})
}

func TestMmapMsyncSync(t *testing.T) {
	rows, _ := runParquetScenarioRows(t, "mmap-msync-sync", defaultDuration, mmapTraceArgs, nil)
	AssertRowsPresent(t, rows, []ExpectedRow{
		{
			FileContains:      "msyncfile.txt",
			Syscall:           "mmap",
			Comm:              "ioworkload",
			IsError:           ptrTo(false),
			AddressSpaceBytes: ptrTo(mmapMsyncLength),
		},
		{
			// msync flushes an existing range: it does not change the
			// address space, so it contributes nothing to the metric.
			Syscall:           "msync",
			Comm:              "ioworkload",
			RetVal:            ptrTo(int64(0)),
			IsError:           ptrTo(false),
			AddressSpaceBytes: ptrTo(uint64(0)),
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
			Syscall:           "msync",
			Comm:              "ioworkload",
			RetVal:            ptrTo(-int64(syscall.EINVAL)),
			IsError:           ptrTo(true),
			AddressSpaceBytes: ptrTo(uint64(0)),
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
			FileContains:      "anon",
			Syscall:           "mmap",
			Comm:              "ioworkload",
			IsError:           ptrTo(false),
			Bytes:             &zeroBytes,
			AddressSpaceBytes: ptrTo(mmapInitialAddressSpaceBytes),
		},
		{
			Syscall:           "mremap",
			Comm:              "ioworkload",
			IsError:           ptrTo(false),
			Bytes:             &zeroBytes,
			AddressSpaceBytes: ptrTo(mmapScenarioAddressSpaceBytes),
		},
		{
			Syscall:           "munmap",
			Comm:              "ioworkload",
			RetVal:            ptrTo(int64(0)),
			IsError:           ptrTo(false),
			Bytes:             &zeroBytes,
			AddressSpaceBytes: ptrTo(mmapScenarioAddressSpaceBytes),
		},
	})

	var addressSpaceTotal uint64
	for _, row := range rows {
		switch row.Syscall {
		case "mmap":
			addressSpaceTotal += row.AddressSpaceBytes
		case "mremap":
			addressSpaceTotal += row.AddressSpaceBytes
		case "munmap":
			addressSpaceTotal += row.AddressSpaceBytes
		}
	}

	if addressSpaceTotal < mmapMinAddressSpaceBytesTotal {
		t.Fatalf("mmap+mremap+munmap AddressSpaceBytes total = %d, want >= %d", addressSpaceTotal, mmapMinAddressSpaceBytesTotal)
	}
}
