package internal

import (
	"testing"

	"ior/internal/globalfilter"
)

// TestHandlersNameToHandleAtPassesTheHeldRow: a restarting signal handler
// that takes a file handle sends three records under the held tid - the
// enter, the FILE_HANDLE_EVENT control record and the exit. All three belong
// to the handler's own call and must pass the row that waits for its
// re-execution (stepHandlerRecord): none of them is a row (name_to_handle_at
// never is), the row stays held in the handler phase, the handle gets its
// name, and the interrupted read still folds once the handler has returned.
//
// The control record is the one at risk: every other control record of the
// tid ends the wait, and a release there would emit the interrupted read
// unfolded and make its re-execution a second row.
func TestHandlersNameToHandleAtPassesTheHeldRow(t *testing.T) {
	const taken = "/data/taken-in-handler.txt"
	f := newReexecFixture(t, globalfilter.Filter{})
	f.interruptRead(restartBase, restartTid, restartSys)
	f.feedNone(f.handlerRecord(restartBase+510, restartTid, true), "HANDLER record")

	records := makeNameToHandleAtRecords(t, restartBase+600, restartPid, restartTid, taken, testHandleA)
	for i, what := range []string{"enter", "handle record", "exit"} {
		f.feedNone(records[i], "the handler's name_to_handle_at "+what)
		if held, ok := f.el.restarts.lookup(restartTid); !ok || held.phase != restartInHandler {
			t.Fatalf("after the %s: held = %+v (ok=%v), want the row held in the handler phase", what, held, ok)
		}
	}
	if name, ok := f.el.handleState().lookup(testHandleA.key(), restartPid); !ok || name != taken {
		t.Fatalf("handle taken in the handler is named (%q, %v), want %q", name, ok, taken)
	}

	if ret := f.sigreturn(restartBase+750, restartTid); ret.name != "rt_sigreturn" {
		t.Fatalf("handler return row = %+v, want rt_sigreturn", ret)
	}
	f.feedNone(f.resumeRecord(restartBase+800, restartTid), "RESUME record")
	f.feedNone(f.readEnter(restartBase+800, restartTid), "re-executed read enter")
	row := f.feedOne(f.readExit(restartBase+4000, restartTid, 1), "re-executed read exit")
	if row.name != "read" || row.ret != 1 || row.enterTime != restartBase || row.duration != 4000 {
		t.Fatalf("row = %+v, want the read folded from %d to its re-execution's exit", row, restartBase)
	}
	f.requireNothingHeld()
}
