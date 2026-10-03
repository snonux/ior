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

// The stop first waits for the ring-buffer poller to come to rest (see
// backlogAtStop). stopSettleBudget bounds that wait; it is part of the drain
// budget, not added to it. The poller needs microseconds per record, so it
// either empties the ring or fills rawCh (4096 records) within about a
// millisecond; the budget only matters on a starved host. stopSettleStep is
// the pause between two looks at the ring: a poller moves its consumer
// position within nanoseconds of handing a record on, so one step after the
// send that filled rawCh the position is behind that record.
const (
	stopSettleBudget = 50 * time.Millisecond
	stopSettleStep   = time.Millisecond
)

// drainBacklogAtStop decodes the records that were already buffered in rawCh
// when ctx was cancelled, then records what it could not get to and what the
// kernel ring buffer still held.
//
// Why: the BPF ring buffer's poller (libbpfgo) fills rawCh ahead of the
// decoder, and RingBuffer.Stop discards whatever is left in it. Returning at
// ctx.Done() alone therefore threw away up to a full channel of records that
// the kernel had already delivered - and they were in neither "tracepoints"
// (decoded) nor "ring buffer drops" (kernel-side loss), so "drops: 0"
// overstated completeness and the tail of a -plain / -parquet / -flamegraph
// trace went missing whenever the consumer lagged (task tq2).
//
// Only the backlog present at the stop is drained (the snapshot backlogAtStop
// takes), not whatever the still-attached probes add meanwhile: the trace
// window ends at the stop, and a loop that chased a saturated producer would
// never finish. The drain also ends early when the time budget runs out or
// the -plain output already failed (its rows have nowhere to go); the
// undecoded remainder is added to numDiscardedAtStop and reported by stats().
//
// The kernel ring is counted in the same snapshot, before the drain, not
// after it (task f23): every record the drain takes makes room in rawCh, the
// poller moves a record from the ring into it, and RingBuffer.Stop throws
// that one away later. Counted after the drain, a lagging run was short of
// exactly one channel's worth of records in every end-of-run figure.
//
// It runs on the event-loop goroutine, so the drain emits in stream order on
// the same goroutine as the running loop and, like it, leaves no pair pending
// when run returns.
func (e *eventLoop) drainBacklogAtStop(rawCh <-chan []byte, pairs chan *event.Pair, flush *flushTimer) {
	budget := e.stopDrainBudget
	if budget <= 0 {
		budget = defaultStopDrainBudget
	}
	deadline := time.Now().Add(budget)

	backlog, ringLeft := e.backlogAtStop(rawCh, deadline)
	taken := e.decodeBacklog(rawCh, backlog, deadline, pairs, flush)
	if left := backlog - taken; left > 0 {
		e.numDiscardedAtStop += uint(left)
		e.notifyWarningOrLog(discardedAtStopWarning(left, e.outputErr != nil))
	}
	e.countKernelRingLeftAtStop(ringLeft)
}

// decodeBacklog consumes up to backlog records from rawCh, until the deadline
// or a failed output, and reports how many of the backlog are accounted for:
// the records it took, or the whole backlog when rawCh turned out closed or
// empty early (someone else took the rest, so none of it is left to discard).
func (e *eventLoop) decodeBacklog(rawCh <-chan []byte, backlog int, deadline time.Time, pairs chan *event.Pair, flush *flushTimer) int {
	taken := 0
	for taken < backlog && e.outputErr == nil && time.Now().Before(deadline) {
		select {
		case raw, ok := <-rawCh:
			if !ok {
				return backlog // closed and emptied early
			}
			taken++
			e.consumeRaw(raw, pairs, flush)
		default:
			return backlog // emptied by someone else
		}
	}
	return taken
}

// backlogAtStop takes the stop's snapshot: how many records rawCh holds for
// the drain, and what the kernel ring buffer holds behind them. The two must
// be read while the poller rests, or a record on its way from the ring into
// rawCh is counted in both or in neither. The poller (libbpfgo's
// ringbufferCallback under libbpf's ring_buffer__poll) handles one record at
// a time: it sends the copy to rawCh, and only when the send returned does
// libbpf advance the ring's consumer position. Nothing receives from rawCh
// while this runs, so the poller comes to rest in one of two ways:
//
//   - the ring is empty (or its first record is still being written, which
//     no consumer gets past either). Unread reads the consumer position
//     before the producer position, so "empty" means every record produced
//     until then was consumed, and its send into rawCh came before that:
//     len(rawCh), read afterwards, holds them all. Nothing is left in the
//     ring. Records produced later are behind the stop.
//   - rawCh is full and the poller is blocked sending the record at the
//     consumer position, which is therefore in the ring's count and not in
//     rawCh. A poller that is not blocked yet, having just sent the record
//     that filled rawCh, advances the consumer position next, and until then
//     that record is in rawCh and in the ring's count. So the ring is read
//     only when rawCh was already full one stopSettleStep earlier: the send
//     that filled it is then at least a step old. That is not a proof (a
//     poller thread descheduled for the whole step between the send and the
//     advance would count one record twice), only as good as waiting gets:
//     libbpfgo offers no way to stop its poller without also discarding
//     rawCh.
//
// Without a reader (tests, a failed attach) or when the ring cannot be read,
// the snapshot is len(rawCh) alone, as before task us2. When the poller does
// not come to rest within stopSettleBudget (or the drain's deadline), the
// last look is used as it is.
func (e *eventLoop) backlogAtStop(rawCh <-chan []byte, deadline time.Time) (int, ringbufUnread) {
	if e.ringUnread == nil {
		return len(rawCh), ringbufUnread{}
	}
	settleBy := time.Now().Add(stopSettleBudget)
	if deadline.Before(settleBy) {
		settleBy = deadline
	}
	wasFull := false
	for {
		unread, err := e.ringUnread.Unread()
		if err != nil {
			e.notifyWarningOrLog(fmt.Sprintf("could not read the kernel ring buffer backlog at stop: %v", err))
			return len(rawCh), ringbufUnread{}
		}
		if unread.bytes == 0 {
			return len(rawCh), ringbufUnread{}
		}
		full := len(rawCh) == cap(rawCh)
		if full && wasFull {
			return len(rawCh), unread
		}
		if !time.Now().Before(settleBy) {
			return len(rawCh), unread
		}
		wasFull = full
		time.Sleep(stopSettleStep)
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

// countKernelRingLeftAtStop records what the consumer left in the kernel ring
// buffer (task us2), as backlogAtStop saw it at the stop. The libbpfgo poller
// feeds rawCh ahead of the decoder and blocks when it is full, so a consumer
// that lagged until the stop leaves records in the kernel's ring. The poller
// still moves some of them into rawCh while the drain makes room there, and
// RingBuffer.Stop abandons those like the rest: none of them is decoded
// (only the poller consumes the ring, and the trace window ended), which is
// why the count is the one from before the drain (task f23). They are counted
// so "drops: 0" does not read as a complete trace.
func (e *eventLoop) countKernelRingLeftAtStop(unread ringbufUnread) {
	if unread.records == 0 {
		return
	}
	e.numLeftInKernelRing += uint(unread.records)
	e.notifyWarningOrLog(fmt.Sprintf("%d records were still in the kernel ring buffer at stop and were not read: the consumer lagged", unread.records))
}

// leftInKernelRingStatLine renders the end-of-run "left in the kernel ring
// buffer" line, empty when the consumer kept up. These records were never
// delivered to userspace, so they appear in none of "tracepoints", "ring buffer
// drops" and "discarded at stop".
func (e *eventLoop) leftInKernelRingStatLine() string {
	if e.numLeftInKernelRing == 0 {
		return ""
	}
	return fmt.Sprintf(
		"\trecords left in the kernel ring buffer at stop: %d (never delivered; not counted in tracepoints, ring buffer drops or discarded at stop)\n",
		e.numLeftInKernelRing,
	)
}
