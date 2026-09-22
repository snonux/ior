package internal

import (
	"context"
	"testing"

	"ior/internal/event"
)

// TestRunIgnoresEmptyRawPayload checks that an empty raw record is skipped
// without producing a pair or counting as a tracepoint.
func TestRunIgnoresEmptyRawPayload(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	emitted := 0
	el.SetPrintCallback(func(ep *event.Pair) {
		emitted++
		ep.Recycle()
	})
	rawCh := make(chan []byte, 2)
	rawCh <- nil
	rawCh <- []byte{}
	close(rawCh)

	el.run(context.Background(), rawCh)

	if emitted != 0 {
		t.Fatalf("emitted %d pairs for empty raw payloads, want 0", emitted)
	}
	if el.numTracepoints != 0 {
		t.Fatalf("numTracepoints = %d for empty raw payloads, want 0", el.numTracepoints)
	}
}
