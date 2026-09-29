package internal

import (
	"encoding/binary"
	"math"
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

func TestApplyAddressSpaceBytesUsesTheErrnoReturnWindow(t *testing.T) {
	tests := []struct {
		ret  int64
		want uint64
	}{
		{ret: -4096, want: 16384},
		{ret: -4095, want: 0},
	}

	for _, tt := range tests {
		pair := &event.Pair{
			EnterEv: &types.MmapEvent{
				TraceId: types.SYS_ENTER_MMAP,
				Length:  16384,
			},
			ExitEv: &types.RetEvent{
				TraceId: types.SYS_EXIT_MMAP,
				Ret:     tt.ret,
			},
		}

		applyAddressSpaceBytes(pair)
		if pair.AddressSpaceBytes != tt.want {
			t.Errorf("ret %d AddressSpaceBytes = %d, want %d", tt.ret, pair.AddressSpaceBytes, tt.want)
		}
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

// TestApplyRequestedSleepNs decodes real sleep_event wire bytes and checks
// that requested_ns reaches the pair unchanged, including the BPF-side -1
// "unknown" sentinel and the S64_MAX saturation of oversized requests (e.g.
// `sleep infinity`), neither of which userspace may reinterpret.
func TestApplyRequestedSleepNs(t *testing.T) {
	for _, requested := range []int64{7_500_000, 0, -1, math.MaxInt64} {
		raw := make([]byte, 32)
		binary.LittleEndian.PutUint32(raw[0:4], uint32(types.ENTER_SLEEP_EVENT))
		binary.LittleEndian.PutUint32(raw[4:8], uint32(types.SYS_ENTER_NANOSLEEP))
		binary.LittleEndian.PutUint64(raw[8:16], 10)
		binary.LittleEndian.PutUint32(raw[16:20], 1)
		binary.LittleEndian.PutUint32(raw[20:24], 2)
		binary.LittleEndian.PutUint64(raw[24:32], uint64(requested))
		enterEv := types.NewSleepEventFast(raw)
		if enterEv == nil {
			t.Fatalf("NewSleepEventFast rejected a %d-byte payload", len(raw))
		}
		pair := &event.Pair{
			EnterEv: enterEv,
			ExitEv:  &types.RetEvent{TraceId: types.SYS_EXIT_NANOSLEEP, Ret: 0},
		}

		applyRequestedSleepNs(pair)
		if pair.RequestedSleepNs != requested {
			t.Errorf("pair.RequestedSleepNs = %d, want %d", pair.RequestedSleepNs, requested)
		}
	}
}
