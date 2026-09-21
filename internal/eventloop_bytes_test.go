package internal

import (
	"testing"

	"ior/internal/event"
	"ior/internal/types"
)

func TestBytesFromRet(t *testing.T) {
	tests := []struct {
		name     string
		pair     *event.Pair
		expected uint64
	}{
		{name: "nil pair", pair: nil, expected: 0},
		{name: "nil exit", pair: &event.Pair{}, expected: 0},
		{
			name: "negative",
			pair: &event.Pair{ExitEv: &types.RetEvent{
				Ret:     -1,
				RetType: types.READ_CLASSIFIED,
			}},
			expected: 0,
		},
		{
			name: "zero",
			pair: &event.Pair{ExitEv: &types.RetEvent{
				Ret:     0,
				RetType: types.READ_CLASSIFIED,
			}},
			expected: 0,
		},
		{
			name: "unclassified",
			pair: &event.Pair{ExitEv: &types.RetEvent{
				Ret:     512,
				RetType: types.UNCLASSIFIED,
			}},
			expected: 0,
		},
		{
			name: "read",
			pair: &event.Pair{ExitEv: &types.RetEvent{
				Ret:     128,
				RetType: types.READ_CLASSIFIED,
			}},
			expected: 128,
		},
		{
			name: "write",
			pair: &event.Pair{ExitEv: &types.RetEvent{
				Ret:     256,
				RetType: types.WRITE_CLASSIFIED,
			}},
			expected: 256,
		},
		{
			name: "transfer",
			pair: &event.Pair{ExitEv: &types.RetEvent{
				Ret:     1024,
				RetType: types.TRANSFER_CLASSIFIED,
			}},
			expected: 1024,
		},
		{
			name: "path xattr zero-size probe",
			pair: &event.Pair{
				EnterEv: &types.PathEvent{Size: 0, SizeValid: 1},
				ExitEv:  &types.RetEvent{Ret: 128, RetType: types.READ_CLASSIFIED},
			},
			expected: 0,
		},
		{
			name: "fd xattr zero-size probe",
			pair: &event.Pair{
				EnterEv: &types.FdEvent{Size: 0, SizeValid: 1},
				ExitEv:  &types.RetEvent{Ret: 128, RetType: types.READ_CLASSIFIED},
			},
			expected: 0,
		},
		{
			name: "legacy xattr payload with unknown size",
			pair: &event.Pair{
				EnterEv: &types.PathEvent{Size: 0, SizeValid: 0},
				ExitEv:  &types.RetEvent{Ret: 128, RetType: types.READ_CLASSIFIED},
			},
			expected: 128,
		},
		{
			name: "xattr data read",
			pair: &event.Pair{
				EnterEv: &types.PathEvent{Size: 256, SizeValid: 1},
				ExitEv:  &types.RetEvent{Ret: 128, RetType: types.READ_CLASSIFIED},
			},
			expected: 128,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := bytesFromRet(tt.pair); got != tt.expected {
				t.Errorf("bytesFromRet() = %d, want %d", got, tt.expected)
			}
		})
	}
}

func TestApplyRetBytesForNullEnterRetExitPair(t *testing.T) {
	pair := &event.Pair{
		EnterEv: &types.NullEvent{TraceId: types.SYS_ENTER_SPLICE},
		ExitEv: &types.RetEvent{
			TraceId: types.SYS_EXIT_SPLICE,
			Ret:     4096,
			RetType: types.TRANSFER_CLASSIFIED,
		},
	}

	applyRetBytes(pair)

	if pair.Bytes != 4096 {
		t.Fatalf("pair.Bytes = %d, want 4096", pair.Bytes)
	}
}

func TestAddressSpaceBytesFromMem(t *testing.T) {
	tests := []struct {
		name    string
		traceID types.TraceId
		length  uint64
		length2 uint64
		want    uint64
	}{
		{
			name:    "mmap",
			traceID: types.SYS_ENTER_MMAP,
			length:  4096,
			want:    4096,
		},
		{
			name:    "msync",
			traceID: types.SYS_ENTER_MSYNC,
			length:  8192,
			want:    8192,
		},
		{
			name:    "munmap",
			traceID: types.SYS_ENTER_MUNMAP,
			length:  4096,
			want:    4096,
		},
		{
			name:    "mremap uses larger extent",
			traceID: types.SYS_ENTER_MREMAP,
			length:  4096,
			length2: 8192,
			want:    8192,
		},
		{
			name:    "non-memory",
			traceID: types.SYS_ENTER_READ,
			length:  123,
			want:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := addressSpaceBytesFromMem(tt.traceID, tt.length, tt.length2); got != tt.want {
				t.Fatalf("addressSpaceBytesFromMem() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestApplyAddressSpaceBytesIgnoresFailedMmap(t *testing.T) {
	pair := &event.Pair{
		EnterEv: &types.MmapEvent{
			TraceId: types.SYS_ENTER_MMAP,
			Length:  16384,
		},
		ExitEv: &types.RetEvent{
			TraceId: types.SYS_EXIT_MMAP,
			Ret:     -1,
		},
	}

	applyAddressSpaceBytes(pair)
	if pair.AddressSpaceBytes != 0 {
		t.Fatalf("failed mmap AddressSpaceBytes = %d, want 0", pair.AddressSpaceBytes)
	}
}

func TestApplyAddressSpaceBytes(t *testing.T) {
	pair := &event.Pair{
		EnterEv: &types.MemEvent{
			TraceId: types.SYS_ENTER_MUNMAP,
			Length:  16384,
		},
		ExitEv: &types.RetEvent{
			TraceId: types.SYS_EXIT_MUNMAP,
			Ret:     0,
		},
	}

	applyAddressSpaceBytes(pair)
	if pair.AddressSpaceBytes != 16384 {
		t.Fatalf("pair.AddressSpaceBytes = %d, want 16384", pair.AddressSpaceBytes)
	}
	if pair.Bytes != 0 {
		t.Fatalf("pair.Bytes = %d, want 0 (IO bytes must stay separate)", pair.Bytes)
	}
}

func TestApplyRequestedSleepNs(t *testing.T) {
	pair := &event.Pair{
		EnterEv: &types.SleepEvent{
			TraceId:     types.SYS_ENTER_NANOSLEEP,
			RequestedNs: 7_500_000,
			EventType:   types.ENTER_SLEEP_EVENT,
			Time:        10,
			Pid:         1,
			Tid:         2,
		},
		ExitEv: &types.RetEvent{
			TraceId: types.SYS_EXIT_NANOSLEEP,
			Ret:     0,
		},
	}

	applyRequestedSleepNs(pair)
	if pair.RequestedSleepNs != 7_500_000 {
		t.Fatalf("pair.RequestedSleepNs = %d, want 7500000", pair.RequestedSleepNs)
	}
}
