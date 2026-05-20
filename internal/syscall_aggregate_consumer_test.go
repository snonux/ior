package internal

import (
	"bytes"
	"encoding/binary"
	"testing"

	"ior/internal/flags"
	"ior/internal/types"
)

func TestBuildSyscallSamplingRatesFamilyAndSyscallOverride(t *testing.T) {
	cfg := flags.NewFlags()
	cfg.SyscallFamilySamplingRates[types.FamilyTime] = 100
	cfg.SyscallSamplingRates["clock_gettime"] = 3

	rates := buildSyscallSamplingRates(cfg)
	if got := rates[types.SYS_ENTER_NANOSLEEP]; got != 100 {
		t.Fatalf("nanosleep rate = %d, want 100", got)
	}
	if got := rates[types.SYS_ENTER_CLOCK_GETTIME]; got != 3 {
		t.Fatalf("clock_gettime rate = %d, want 3", got)
	}
}

func TestDecodeRawSyscallAggregate(t *testing.T) {
	want := rawSyscallAggregate{
		Count:         7,
		Errors:        2,
		TotalDuration: 1234,
		MinDuration:   12,
		MaxDuration:   456,
		Histogram:     [8]uint64{1, 2, 3, 4, 5, 6, 7, 8},
	}
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, want); err != nil {
		t.Fatalf("binary write: %v", err)
	}

	got, err := decodeRawSyscallAggregate(buf.Bytes())
	if err != nil {
		t.Fatalf("decodeRawSyscallAggregate error: %v", err)
	}
	if got != want {
		t.Fatalf("decoded aggregate = %+v, want %+v", got, want)
	}
}

func TestDecodeRawSyscallAggregateRejectsBadSize(t *testing.T) {
	if _, err := decodeRawSyscallAggregate([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected error for short value")
	}
}
