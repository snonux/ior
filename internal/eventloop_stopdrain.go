package internal

import (
	"fmt"
	"time"

	"ior/internal/event"
)

// defaultStopDrainBudget bounds how long the event loop keeps decoding the
// records that were still buffered in rawCh when the trace was stopped. The
// backlog is at most appconfig.DefaultChannelBufferSize records, which decode
// in milliseconds; the budget only matters when the consumer behind the print
// callback is slow (a stalled stdout pipe, a saturated TUI), so that a stop
// can never hang on it. Records left when it runs out are counted, not
// silently lost (numDiscardedAtStop).
const defaultStopDrainBudget = time.Second

// drainBacklogAtStop decodes the records that were already buffered in rawCh
// when ctx was cancelled, then records what it could not get to.
//
// Why: the BPF ring buffer's poller (libbpfgo) fills rawCh ahead of the
// decoder, and RingBuffer.Stop discards whatever is left in it. Returning at
// ctx.Done() alone therefore threw away up to a full channel of records that
// the kernel had already delivered - and they were in neither "tracepoints"
// (decoded) nor "ring buffer drops" (kernel-side loss), so "drops: 0"
// overstated completeness and the tail of a -plain / -parquet / -flamegraph
// trace went missing whenever the consumer lagged (task tq2).
//
// Only the backlog present at the stop is drained (a snapshot of len(rawCh)),
// not whatever the still-attached probes add meanwhile: the trace window ends
// at the stop, and a loop that chased a saturated producer would never finish.
// The drain also ends early when the time budget runs out or the -plain
// output already failed (its rows have nowhere to go); the undecoded
// remainder is added to numDiscardedAtStop and reported by stats().
//
// It runs on the event-loop goroutine, so the drain emits in stream order on
// the same goroutine as the running loop and, like it, leaves no pair pending
// when run returns.
func (e *eventLoop) drainBacklogAtStop(rawCh <-chan []byte, pairs chan *event.Pair, flush *flushTimer) {
	backlog := len(rawCh)
	if backlog == 0 {
		return
	}
	budget := e.stopDrainBudget
	if budget <= 0 {
		budget = defaultStopDrainBudget
	}
	deadline := time.Now().Add(budget)

	taken := 0
	for taken < backlog && e.outputErr == nil && time.Now().Before(deadline) {
		select {
		case raw, ok := <-rawCh:
			if !ok {
				// Closed and emptied early: nothing more can be lost.
				return
			}
			taken++
			e.consumeRaw(raw, pairs, flush)
		default:
			// Emptied by someone else: nothing more can be lost.
			return
		}
	}
	if left := backlog - taken; left > 0 {
		e.numDiscardedAtStop += uint(left)
		e.notifyWarningOrLog(discardedAtStopWarning(left, e.outputErr != nil))
	}
}

// discardedAtStopWarning words the warning for records the stop drain could
// not decode. It goes through notifyWarningOrLog because it reports lost data.
func discardedAtStopWarning(left int, outputFailed bool) string {
	reason := "the stop-time drain ran out of time"
	if outputFailed {
		reason = "the output had already failed"
	}
	return fmt.Sprintf("%d buffered ring-buffer records were discarded at stop: %s", left, reason)
}

// discardedAtStopStatLine renders the end-of-run "discarded at stop" line. It
// is empty on a run that decoded its whole backlog, like outputLossStatLine.
// These records reached userspace but were never decoded, so they appear in
// neither "tracepoints" nor "ring buffer drops"; without this line a
// "drops: 0" run would read as complete.
func (e *eventLoop) discardedAtStopStatLine() string {
	if e.numDiscardedAtStop == 0 {
		return ""
	}
	return fmt.Sprintf(
		"\trecords discarded at stop: %d (delivered but not decoded; not counted in tracepoints or ring buffer drops)\n",
		e.numDiscardedAtStop,
	)
}
