package internal

import (
	"testing"

	"ior/internal/event"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

func TestHandleSleepExitCarriesCommAndAppliesFilter(t *testing.T) {
	t.Run("accepted", func(t *testing.T) {
		el := mustNewEventLoop(t, eventLoopConfig{})
		enter := &types.SleepEvent{
			EventType:   types.ENTER_SLEEP_EVENT,
			TraceId:     types.SYS_ENTER_NANOSLEEP,
			Time:        100,
			Pid:         10,
			Tid:         11,
			RequestedNs: 2_000_000,
		}
		exit := &types.RetEvent{
			EventType: types.EXIT_RET_EVENT,
			TraceId:   types.SYS_EXIT_NANOSLEEP,
			Time:      120,
			Ret:       0,
			Pid:       10,
			Tid:       11,
		}
		ep := &event.Pair{EnterEv: enter, ExitEv: exit}

		if ok := el.handleSleepExit(ep, enter); !ok {
			t.Fatal("handleSleepExit returned false")
		}
		if ep.Comm != "" {
			t.Fatalf("expected empty comm for unresolved tid, got %q", ep.Comm)
		}
	})

	t.Run("filtered", func(t *testing.T) {
		el := mustNewEventLoop(t, eventLoopConfig{
			filter: globalfilter.Filter{
				Syscall: &globalfilter.StringFilter{Pattern: "openat"},
			},
		})
		enter := &types.SleepEvent{
			EventType:   types.ENTER_SLEEP_EVENT,
			TraceId:     types.SYS_ENTER_CLOCK_NANOSLEEP,
			Time:        100,
			Pid:         10,
			Tid:         11,
			RequestedNs: 3_000_000,
		}
		exit := &types.RetEvent{
			EventType: types.EXIT_RET_EVENT,
			TraceId:   types.SYS_EXIT_CLOCK_NANOSLEEP,
			Time:      120,
			Ret:       0,
			Pid:       10,
			Tid:       11,
		}
		ep := &event.Pair{EnterEv: enter, ExitEv: exit}

		if ok := el.handleSleepExit(ep, enter); ok {
			t.Fatal("handleSleepExit should reject pair due to filter mismatch")
		}
	})
}

func TestInitRawHandlersRegistersSleepEvents(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	if _, ok := el.rawHandlers[types.ENTER_SLEEP_EVENT]; !ok {
		t.Fatal("ENTER_SLEEP_EVENT handler is not registered")
	}
}

