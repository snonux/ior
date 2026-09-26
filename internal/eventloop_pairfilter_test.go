package internal

import (
	"syscall"
	"testing"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

// processRawSync feeds raw events through the event loop synchronously and
// returns the emitted pairs.
func processRawSync(t *testing.T, el *eventLoop, raws ...[]byte) []*event.Pair {
	t.Helper()
	var out []*event.Pair
	el.printCb = func(ep *event.Pair) { out = append(out, ep) }
	el.initRawHandlers()
	ch := make(chan *event.Pair, 16)
	for _, raw := range raws {
		el.processRawEvent(raw, ch)
		for len(ch) > 0 {
			el.emit(<-ch)
		}
	}
	return out
}

func TestPairFilterSeesBytes(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	el.SetFilter(globalfilter.Filter{Bytes: &globalfilter.NumericFilter{Op: globalfilter.OpGt, Value: 0}})
	_, enter := makeEnterFdEvent(t, 100, 1, 1, 3, types.SYS_ENTER_READ)
	exitEv := types.RetEvent{EventType: types.EXIT_RET_EVENT, TraceId: types.SYS_EXIT_READ, Time: 200, Pid: 1, Tid: 1, Ret: 4096, RetType: types.READ_CLASSIFIED}
	exit, _ := exitEv.Bytes()
	if out := processRawSync(t, el, enter, exit); len(out) != 1 {
		t.Fatalf("expected 4096-byte read to pass bytes>0 filter, got %d pairs", len(out))
	}
}

func TestPairFilterSeesLatency(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	el.SetFilter(globalfilter.Filter{LatencyNs: &globalfilter.NumericFilter{Op: globalfilter.OpGte, Value: 50}})
	_, enter := makeEnterFdEvent(t, 100, 1, 1, 3, types.SYS_ENTER_READ)
	_, exit := makeExitRetEvent(t, 1000, 1, 1, types.SYS_EXIT_READ, 1)
	if out := processRawSync(t, el, enter, exit); len(out) != 1 {
		t.Fatalf("expected 900ns read to pass latency>=50 filter, got %d pairs", len(out))
	}
}

func TestFcntlSetflKeepsAccessMode(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	el.fdState().set(3, 1, file.NewFd(3, "/tmp/x", syscall.O_WRONLY))
	_, enter := makeEnterFcntlEvent(t, 100, 1, 1, 3, syscall.F_SETFL, syscall.O_NONBLOCK)
	_, exit := makeExitRetEvent(t, 200, 1, 1, types.SYS_EXIT_FCNTL, 0)
	processRawSync(t, el, enter, exit)
	f, _ := el.fdState().get(3, 1)
	if !f.Flags().Is(syscall.O_WRONLY) || !f.Flags().Is(syscall.O_NONBLOCK) {
		t.Fatalf("expected O_WRONLY|O_NONBLOCK after F_SETFL, got %v", f.Flags())
	}
}

func TestFdTableIsPerProcess(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	el.fdState().set(3, 1, file.NewFd(3, "/pidA/file", 0))
	_, enter := makeEnterFdEvent(t, 100, 999999, 999999, 3, types.SYS_ENTER_READ)
	_, exit := makeExitRetEvent(t, 200, 999999, 999999, types.SYS_EXIT_READ, 1)
	out := processRawSync(t, el, enter, exit)
	if len(out) == 1 && out[0].File.Name() == "/pidA/file" {
		t.Fatalf("fd 3 of pid 999999 was attributed to another process' file")
	}
	if _, ok := el.fdState().get(3, 1); !ok {
		t.Fatalf("expected pid 1's fd 3 to stay tracked")
	}
}

func TestFilteredDup2StillUpdatesFdTable(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	el.fdState().set(3, 1, file.NewFd(3, "/a", 0))
	el.fdState().set(4, 1, file.NewFd(4, "/b", 0))
	el.SetFilter(globalfilter.Filter{Syscall: &globalfilter.StringFilter{Pattern: "read"}})
	_, enter := makeEnterFdEvent(t, 100, 1, 1, 4, types.SYS_ENTER_DUP2)
	_, exit := makeExitRetEvent(t, 200, 1, 1, types.SYS_EXIT_DUP2, 3)
	if out := processRawSync(t, el, enter, exit); len(out) != 0 {
		t.Fatalf("expected dup2 to be filtered out, got %d pairs", len(out))
	}
	if f, _ := el.fdState().get(3, 1); f == nil || f.Name() != "/b" {
		t.Fatalf("expected fd 3 to point at /b after dup2(4, 3), got %v", f)
	}
}
