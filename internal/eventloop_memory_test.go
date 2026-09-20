package internal

import (
	"syscall"
	"testing"

	"ior/internal/event"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

func TestHandleMemExitAppliesPairFilter(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{
		filter: globalfilter.Filter{
			Syscall: &globalfilter.StringFilter{Pattern: "openat"},
		},
	})

	enter := &types.MemEvent{
		EventType: types.ENTER_MEM_EVENT,
		TraceId:   types.SYS_ENTER_MUNMAP,
		Time:      100,
		Pid:       91,
		Tid:       92,
		Length:    4096,
	}
	exit := &types.RetEvent{
		EventType: types.EXIT_RET_EVENT,
		TraceId:   types.SYS_EXIT_MUNMAP,
		Time:      200,
		Pid:       91,
		Tid:       92,
		Ret:       0,
	}
	ep := &event.Pair{EnterEv: enter, ExitEv: exit}

	if ok := el.handleMemExit(ep, enter); ok {
		t.Fatal("handleMemExit should reject pair due to filter mismatch")
	}
}

func TestInitRawHandlersRegistersMemoryEvents(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	if _, ok := el.rawHandlers[types.ENTER_MEM_EVENT]; !ok {
		t.Fatal("ENTER_MEM_EVENT handler is not registered")
	}
	if _, ok := el.rawHandlers[types.ENTER_MMAP_EVENT]; !ok {
		t.Fatal("ENTER_MMAP_EVENT handler is not registered")
	}
}

func TestHandleMmapExitLabelsAnonymousMapping(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	enter := &types.MmapEvent{
		EventType: types.ENTER_MMAP_EVENT,
		TraceId:   types.SYS_ENTER_MMAP,
		Pid:       91,
		Tid:       92,
		Length:    4096,
		Flags:     syscall.MAP_PRIVATE | syscall.MAP_ANON,
		Fd:        -1,
	}
	ep := &event.Pair{
		EnterEv: enter,
		ExitEv:  &types.RetEvent{TraceId: types.SYS_EXIT_MMAP, Ret: 0x70000000},
	}

	if ok := el.handleMmapExit(ep, enter); !ok {
		t.Fatal("handleMmapExit rejected anonymous mapping")
	}
	if ep.File == nil {
		t.Fatal("anonymous mmap has no file representation")
	}
	if got := ep.File.Name(); got != "anon" {
		t.Fatalf("anonymous mmap name = %q, want anon", got)
	}
	if got := ep.File.String(); got != "anon" {
		t.Fatalf("anonymous mmap rendering = %q, want anon", got)
	}
}
