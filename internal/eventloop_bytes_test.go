package internal

import (
	"testing"

	"ior/internal/event"
	"ior/internal/types"
)

func TestBytesFromRet(t *testing.T) {
	tests := []struct {
		name     string
		retEvent *types.RetEvent
		expected uint64
	}{
		{name: "nil", retEvent: nil, expected: 0},
		{
			name: "negative",
			retEvent: &types.RetEvent{
				Ret:     -1,
				RetType: types.READ_CLASSIFIED,
			},
			expected: 0,
		},
		{
			name: "zero",
			retEvent: &types.RetEvent{
				Ret:     0,
				RetType: types.READ_CLASSIFIED,
			},
			expected: 0,
		},
		{
			name: "unclassified",
			retEvent: &types.RetEvent{
				Ret:     512,
				RetType: types.UNCLASSIFIED,
			},
			expected: 0,
		},
		{
			name: "read",
			retEvent: &types.RetEvent{
				Ret:     128,
				RetType: types.READ_CLASSIFIED,
			},
			expected: 128,
		},
		{
			name: "write",
			retEvent: &types.RetEvent{
				Ret:     256,
				RetType: types.WRITE_CLASSIFIED,
			},
			expected: 256,
		},
		{
			name: "transfer",
			retEvent: &types.RetEvent{
				Ret:     1024,
				RetType: types.TRANSFER_CLASSIFIED,
			},
			expected: 1024,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := bytesFromRet(tt.retEvent); got != tt.expected {
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
		name string
		ev   *types.MemEvent
		want uint64
	}{
		{
			name: "munmap",
			ev:   &types.MemEvent{TraceId: types.SYS_ENTER_MUNMAP, Length: 4096},
			want: 4096,
		},
		{
			name: "mremap uses larger extent",
			ev:   &types.MemEvent{TraceId: types.SYS_ENTER_MREMAP, Length: 4096, Length2: 8192},
			want: 8192,
		},
		{
			name: "non-memory",
			ev:   &types.MemEvent{TraceId: types.SYS_ENTER_READ, Length: 123},
			want: 0,
		},
		{
			name: "nil",
			ev:   nil,
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := addressSpaceBytesFromMem(tt.ev); got != tt.want {
				t.Fatalf("addressSpaceBytesFromMem() = %d, want %d", got, tt.want)
			}
		})
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
