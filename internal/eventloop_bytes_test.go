package internal

import (
	"encoding/binary"
	"math"
	"testing"

	"golang.org/x/sys/unix"

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

// recvPair builds a recvfrom/recvmsg pair the way the fd_size_event decoder
// hands it to the byte accounting: the enter carries the recv flags and the
// buffer capacity, the exit the raw return value.
func recvPair(traceID types.TraceId, flags uint32, size uint64, sizeValid uint32, ret int64) *event.Pair {
	return &event.Pair{
		EnterEv: &types.FdEvent{TraceId: traceID, Flags: flags, Size: size, SizeValid: sizeValid},
		ExitEv:  &types.RetEvent{Ret: ret, RetType: types.READ_CLASSIFIED},
	}
}

// TestBytesFromRetReceiveFlags pins the accounting of the receives whose
// return value is not the bytes consumed by the caller. The netlink rows are
// the reported defect: iproute2 peeks every datagram with
// recvmsg(fd, {iov_len=0}, MSG_PEEK|MSG_TRUNC) and then reads it again, which
// used to count every reply twice.
func TestBytesFromRetReceiveFlags(t *testing.T) {
	const (
		peek  = unix.MSG_PEEK
		trunc = unix.MSG_TRUNC
	)
	tests := []struct {
		name string
		pair *event.Pair
		want uint64
	}{
		{"recvfrom plain", recvPair(types.SYS_ENTER_RECVFROM, 0, 4096, 1, 100), 100},
		{"recvfrom peek copies without consuming", recvPair(types.SYS_ENTER_RECVFROM, peek, 4096, 1, 100), 0},
		{"recvfrom peek with unknown capacity", recvPair(types.SYS_ENTER_RECVFROM, peek, 0, 0, 100), 0},
		{"recvfrom trunc counts what fit", recvPair(types.SYS_ENTER_RECVFROM, trunc, 10, 1, 1000), 10},
		{"recvfrom trunc that fit is exact", recvPair(types.SYS_ENTER_RECVFROM, trunc, 4096, 1, 1000), 1000},
		{"recvfrom trunc exactly full", recvPair(types.SYS_ENTER_RECVFROM, trunc, 1000, 1, 1000), 1000},
		{"recvfrom peek|trunc null buffer probe", recvPair(types.SYS_ENTER_RECVFROM, peek|trunc, 0, 1, 1000), 0},
		{"recvfrom trunc into a zero-length buffer", recvPair(types.SYS_ENTER_RECVFROM, trunc, 0, 1, 1000), 0},
		{"recvfrom trunc with unknown capacity keeps ret", recvPair(types.SYS_ENTER_RECVFROM, trunc, 0, 0, 1000), 1000},
		{"recvfrom other flags are ignored", recvPair(types.SYS_ENTER_RECVFROM, unix.MSG_DONTWAIT|unix.MSG_WAITALL, 4096, 1, 100), 100},
		{"recvmsg plain", recvPair(types.SYS_ENTER_RECVMSG, 0, 0, 0, 3680), 3680},
		{"recvmsg netlink peek|trunc probe", recvPair(types.SYS_ENTER_RECVMSG, peek|trunc, 0, 1, 3680), 0},
		{"recvmsg peek", recvPair(types.SYS_ENTER_RECVMSG, peek, 0, 0, 3680), 0},
		{"recvmsg trunc counts the iovec capacity", recvPair(types.SYS_ENTER_RECVMSG, trunc, 40, 1, 400), 40},
		{"recvmsg trunc that fit is exact", recvPair(types.SYS_ENTER_RECVMSG, trunc, 4096, 1, 400), 400},
		{"recvmsg trunc with unknown iovec keeps ret", recvPair(types.SYS_ENTER_RECVMSG, trunc, 0, 0, 400), 400},
		{"recvmsg failed", recvPair(types.SYS_ENTER_RECVMSG, 0, 0, 0, -int64(unix.EAGAIN)), 0},
		{"recvfrom peek failed", recvPair(types.SYS_ENTER_RECVFROM, peek, 4096, 1, -int64(unix.EAGAIN)), 0},
		{
			// Flags are only meaningful for the receive syscalls: the same
			// bit patterns on another fd event must not touch its count.
			name: "read is never adjusted",
			pair: &event.Pair{
				EnterEv: &types.FdEvent{TraceId: types.SYS_ENTER_READ, Flags: peek | trunc, Size: 1, SizeValid: 1},
				ExitEv:  &types.RetEvent{Ret: 100, RetType: types.READ_CLASSIFIED},
			},
			want: 100,
		},
		{
			// A payload from an older BPF object is a plain fd_event: no
			// flags, no size. It keeps its historical count.
			name: "legacy fd_event recvfrom keeps ret",
			pair: &event.Pair{
				EnterEv: &types.FdEvent{TraceId: types.SYS_ENTER_RECVFROM},
				ExitEv:  &types.RetEvent{Ret: 100, RetType: types.READ_CLASSIFIED},
			},
			want: 100,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := bytesFromRet(tt.pair); got != tt.want {
				t.Errorf("bytesFromRet() = %d, want %d", got, tt.want)
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
