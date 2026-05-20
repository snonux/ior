package integrationtests

import "testing"

const (
	mmapParquetDuration           = 6
	mmapWorkloadStartupEnv        = "IOR_WORKLOAD_STARTUP_DELAY_MS=1000"
	mmapScenarioAddressSpaceBytes = 8192
	mmapMinAddressSpaceBytesTotal = mmapScenarioAddressSpaceBytes * 2
)

func TestMmapBasic(t *testing.T) {
	runScenario(t, "mmap-basic", []ExpectedEvent{
		{
			PathContains: "mmapfile.txt",
			Tracepoint:   "enter_mmap",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestMmapMsyncSync(t *testing.T) {
	runScenario(t, "mmap-msync-sync", []ExpectedEvent{
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
	})
}

func TestMmapMsyncInvalidFlags(t *testing.T) {
	runScenario(t, "mmap-msync-invalid-flags", []ExpectedEvent{
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
	})
}

func TestMmapMremapMunmap(t *testing.T) {
	result, _ := runScenarioResult(t, "mmap-mremap-munmap", []ExpectedEvent{
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
	})

	assertEventBytesEqual(t, result, ExpectedEvent{
		Tracepoint: "enter_mremap",
		Comm:       "ioworkload",
	}, 0)
	assertEventBytesEqual(t, result, ExpectedEvent{
		Tracepoint: "enter_munmap",
		Comm:       "ioworkload",
	}, 0)
}

func TestMmapMremapMunmapAddressSpaceBytesInParquet(t *testing.T) {
	h := newTestHarness(t)
	h.WorkloadEnv = []string{mmapWorkloadStartupEnv}
	path, pid, err := h.RunParquet("mmap-mremap-munmap", mmapParquetDuration)
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
