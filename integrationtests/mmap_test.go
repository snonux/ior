package integrationtests

import "testing"

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
		},
	}, mmapTraceArgs)
}

func TestMmapMsyncSync(t *testing.T) {
	runScenarioResultWithIorArgs(t, "mmap-msync-sync", []ExpectedEvent{
		{
			PathContains: "msyncfile.txt",
			Tracepoint:   "enter_mmap",
			Comm:         "ioworkload",
			MinCount:     1,
		},
		{
			Tracepoint: "enter_msync",
			Comm:       "ioworkload",
			MinCount:   1,
		},
	}, mmapTraceArgs)
}

func TestMmapMsyncInvalidFlags(t *testing.T) {
	runScenarioResultWithIorArgs(t, "mmap-msync-invalid-flags", []ExpectedEvent{
		{
			PathContains: "msyncinvalidfile.txt",
			Tracepoint:   "enter_mmap",
			Comm:         "ioworkload",
			MinCount:     1,
		},
		{
			Tracepoint: "enter_msync",
			Comm:       "ioworkload",
			MinCount:   1,
		},
	}, mmapTraceArgs)
}

func TestMmapMremapMunmap(t *testing.T) {
	result, _ := runScenarioResultWithIorArgs(t, "mmap-mremap-munmap", []ExpectedEvent{
		{
			Tracepoint: "enter_mremap",
			Comm:       "ioworkload",
			MinCount:   1,
		},
		{
			Tracepoint: "enter_munmap",
			Comm:       "ioworkload",
			MinCount:   1,
		},
	}, mmapTraceArgs)

	assertEventBytesEqual(t, result, ExpectedEvent{
		Tracepoint: "enter_mremap",
		Comm:       "ioworkload",
	}, 0)
	assertEventBytesEqual(t, result, ExpectedEvent{
		Tracepoint: "enter_munmap",
		Comm:       "ioworkload",
	}, 0)
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
	h := newTestHarness(t)
	h.WorkloadEnv = []string{mmapWorkloadStartupEnv}
	path, pid, err := h.RunParquetWithIorArgs("mmap-mremap-munmap", mmapParquetDuration, mmapTraceArgs)
	if err != nil {
		t.Fatalf("run mmap-mremap-munmap parquet scenario: %v", err)
	}

	rows := filterRecordsByPID(readParquetRecords(t, path), uint32(pid))
	if len(rows) == 0 {
		t.Fatalf("expected parquet rows for workload PID %d", pid)
	}

	var foundMremap, foundMunmap bool
	var addressSpaceTotal uint64
	for _, row := range rows {
		switch row.Syscall {
		case "mremap":
			if row.Bytes != 0 {
				t.Fatalf("mremap bytes = %d, want 0 (I/O bytes must stay separate)", row.Bytes)
			}
			if row.AddressSpaceBytes == mmapScenarioAddressSpaceBytes {
				foundMremap = true
			}
			addressSpaceTotal += row.AddressSpaceBytes
		case "munmap":
			if row.Bytes != 0 {
				t.Fatalf("munmap bytes = %d, want 0 (I/O bytes must stay separate)", row.Bytes)
			}
			if row.AddressSpaceBytes == mmapScenarioAddressSpaceBytes {
				foundMunmap = true
			}
			addressSpaceTotal += row.AddressSpaceBytes
		}
	}

	if !foundMremap {
		t.Fatalf("expected mremap row with AddressSpaceBytes=%d", mmapScenarioAddressSpaceBytes)
	}
	if !foundMunmap {
		t.Fatalf("expected munmap row with AddressSpaceBytes=%d", mmapScenarioAddressSpaceBytes)
	}
	if addressSpaceTotal < mmapMinAddressSpaceBytesTotal {
		t.Fatalf("mremap+munmap AddressSpaceBytes total = %d, want >= %d", addressSpaceTotal, mmapMinAddressSpaceBytesTotal)
	}
}
