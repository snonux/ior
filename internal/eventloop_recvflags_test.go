package internal

import (
	"testing"

	"golang.org/x/sys/unix"

	"ior/internal/event"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

// recv appends a recvfrom/recvmsg pair as the current BPF object emits it: an
// fd_size_event whose flags word (right after fd) carries the receive flags
// and whose size is the buffer capacity, followed by the raw-return exit.
func (s *payloadScenario) recv(enterID, exitID types.TraceId, flags uint32, size uint64, sizeValid int64, ret int64) {
	raw := psHeader(48, psEnterFdSize, enterID, s.enterTime())
	psPut32(raw, 24, 77) // an fd ior never saw opened: irrelevant to byte counting
	psPut32(raw, 28, int64(flags))
	psPut64(raw, 32, size)
	psPut32(raw, 40, sizeValid)
	psPut32(raw, 44, psFdSizeSchema)
	s.add(raw)
	s.ret(exitID, ret, psReadClassified)
}

// TestRecvFlagsByteCountsThroughTheRawEventPath drives fd_size_event receive
// records through the real decode and pairing path and checks the byte count
// of every emitted row. The last two rows use the fd_event an older BPF object
// emits for the same syscalls, which carries no flags and keeps its
// historical count.
func TestRecvFlagsByteCountsThroughTheRawEventPath(t *testing.T) {
	const peekTrunc = unix.MSG_PEEK | unix.MSG_TRUNC
	s := &payloadScenario{wire: payloadWireSplit, now: defaulTime}
	from := func(flags uint32, size uint64, ret int64) {
		s.recv(types.SYS_ENTER_RECVFROM, types.SYS_EXIT_RECVFROM, flags, size, 1, ret)
	}
	msg := func(flags uint32, size uint64, sizeValid, ret int64) {
		s.recv(types.SYS_ENTER_RECVMSG, types.SYS_EXIT_RECVMSG, flags, size, sizeValid, ret)
	}
	from(0, 4096, 100)                                                                // plain: 100
	from(unix.MSG_PEEK, 4096, 100)                                                    // peek: 0
	from(unix.MSG_TRUNC, 10, 1000)                                                    // real length 1000, 10 fit: 10
	msg(peekTrunc, 0, 1, 3680)                                                        // netlink size probe: 0
	msg(0, 0, 0, 3680)                                                                // netlink read: 3680
	msg(unix.MSG_TRUNC, 40, 1, 400)                                                   // two iovecs of 25+15: 40
	msg(unix.MSG_TRUNC, 0, 0, 400)                                                    // iovec unknown: keeps ret, 400
	s.fd(types.SYS_ENTER_RECVFROM, types.SYS_EXIT_RECVFROM, 77, 55, psReadClassified) // fd_event wire
	s.fd(types.SYS_ENTER_RECVMSG, types.SYS_EXIT_RECVMSG, 77, 66, psReadClassified)   // fd_event wire
	want := []uint64{100, 0, 10, 0, 3680, 40, 400, 55, 66}

	el := newFilteredEventLoop(t, globalfilter.Filter{})
	out := make(chan *event.Pair, 1)
	var got []uint64
	for _, raw := range s.raws {
		el.processRawEvent(raw, out)
		select {
		case ep := <-out:
			got = append(got, ep.Bytes)
			ep.Recycle()
		default:
		}
	}
	if len(got) != len(want) {
		t.Fatalf("emitted %d rows, want %d (bytes %v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("row %d bytes = %d, want %d (all: %v)", i, got[i], want[i], got)
		}
	}
}
