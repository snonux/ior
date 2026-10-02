package internal

import (
	"errors"
	"fmt"
	"sync"
)

// errSkippedRunsNotReported is what a kernel without the recursion_misses
// field makes of every read of it.
var errSkippedRunsNotReported = errors.New("the kernel does not report skipped bpf program runs")

// skippedRunCounter counts the records ior lost because the kernel did not
// run the tracepoint program that would have written them. Such a run
// reserves nothing, so the ring-buffer drop counter (ringbuf_drop_map, bumped
// by the program itself) never sees it; the kernel counts it in the
// program's recursion_misses instead, and this type adds those up over every
// program ior loaded (task 723).
//
// When the kernel skips a program. The facts were read in the 6.19.8 source
// and, for the running 7.2.5, in its headers and its machine code, and both
// ways were reproduced on 7.2.5 with a tracer of two programs:
//
//   - a classic tracepoint program is skipped while the per-CPU counter
//     bpf_prog_active is raised (trace_call_bpf, kernel/trace/bpf_trace.c).
//     Besides a running kprobe or tracepoint program, which no task-context
//     tracepoint can interrupt, every bpf(2) map lookup, update and delete
//     raises it (bpf_disable_instrumentation, include/linux/bpf.h:
//     migrate_disable and the increment, with preemption left enabled). A
//     task preempted in the middle of such a map operation - any BPF user on
//     the host, or ior reading its own drop counter - leaves it raised, and
//     every program of that kind on that CPU is skipped until the task runs
//     again. Up to 6.19 that covers the syscall tracepoints too; 7.2 runs
//     those through trace_call_bpf_faultable, which no longer asks the
//     counter, so there it is left to ior's sched and signal probes.
//   - a raw tracepoint program (task_rename) and, on 7.2, every syscall
//     tracepoint program is skipped while the SAME program is in flight on
//     that CPU (the per-CPU prog->active). The syscall programs of 7.2 run
//     preemptibly, so a task preempted inside ior's handler of a syscall
//     costs every other task on that CPU its records of that syscall's
//     enter (or exit) until it runs again. No other BPF user is needed for
//     that, only a preemption inside the kernel: a real-time task waking up,
//     or any wake-up under preempt=full.
//
// Each skip is counted per program and CPU, at the moment of the skip, and
// read with one bpf(2) per program that is not a map operation and so cannot
// cause a skip itself (progRecursionMisses). Classic tracepoint programs
// count only since Linux 6.7; before that the skip was silent, and this
// counter is not built (newSkippedRunCounter's caller asks
// kernelCountsSkippedRuns).
//
// The cost. A sweep is one system call per program, some 740 of them: about
// a third of a millisecond. The drop monitor pays that once per period. The
// restart fold and the exec adoption ask per interrupted call, on the event
// loop, and get the last sweep when it is new enough for the question
// (TotalAsOf): a miss is counted when it happens, so a sweep that began
// after the record that asks was stamped has every miss among the records
// before it. A loop that lags behind the kernel therefore sweeps once per
// backlog, not once per question.
type skippedRunCounter struct {
	// fds are the loaded programs, attached or not: a detached program
	// cannot be skipped and its count stands still.
	fds  []int
	read func(fd int) (misses uint64, reported bool, err error)
	// clock is the boot clock the drop watch stamps its observations with
	// (eventLoop.readDropStampClock), comparable with a record's time.
	clock func() uint64

	// mu serialises the sweeps of the monitor's goroutine and the loop's and
	// guards the result of the last one.
	mu      sync.Mutex
	swept   bool
	total   uint64
	sweptAt uint64 // clock reading taken before the sweep's first read
}

// newSkippedRunCounter returns a counter over the programs behind fds, after
// one sweep that proves the kernel reports the field for each of them.
func newSkippedRunCounter(fds []int, read func(int) (uint64, bool, error), clock func() uint64) (*skippedRunCounter, error) {
	if len(fds) == 0 {
		return nil, errors.New("no loaded bpf programs")
	}
	counter := &skippedRunCounter{fds: fds, read: read, clock: clock}
	if _, err := counter.Total(); err != nil {
		return nil, err
	}
	return counter, nil
}

// Total sweeps every program now and returns the sum of their skipped runs.
func (c *skippedRunCounter) Total() (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sweepLocked()
}

// TotalAsOf returns a sum that includes every run skipped at or before the
// boot-clock time asOf: the last sweep's when that sweep began after asOf,
// and a new sweep's otherwise. asOf is the time of a record the loop is
// processing, so "after asOf" is in the past for a loop that lags.
func (c *skippedRunCounter) TotalAsOf(asOf uint64) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.swept && c.sweptAt > asOf {
		return c.total, nil
	}
	return c.sweepLocked()
}

// sweepLocked reads every program and keeps the sum together with a clock
// reading taken before the first read. A sweep that fails keeps nothing: the
// next question sweeps again instead of trusting an older sum.
func (c *skippedRunCounter) sweepLocked() (uint64, error) {
	c.swept = false
	startedAt := c.clock()
	var total uint64
	for _, fd := range c.fds {
		misses, reported, err := c.read(fd)
		if err != nil {
			return 0, fmt.Errorf("skipped program runs: %w", err)
		}
		if !reported {
			return 0, errSkippedRunsNotReported
		}
		total += misses
	}
	c.total, c.sweptAt, c.swept = total, startedAt, true
	return total, nil
}

// recordLoss is one reading of both kernel-side loss counters.
type recordLoss struct {
	ring    uint64 // records the full ring buffer refused (ringbuf_drop_map)
	skipped uint64 // program runs the kernel skipped (skippedRunCounter)
}

func (l recordLoss) total() uint64 { return l.ring + l.skipped }

// recordLossSource is the drop source of a run that counts both ways a
// record is lost in the kernel. Its Total is their sum, so that everything
// that takes a moved drop counter for "records are missing" - the drop
// monitor's warning and its end-of-run figure, the restart folds, the exec
// adoption, the trust in rename records - takes a skipped run the same way.
// Both parts only grow, so the sum stands still exactly when both do.
type recordLossSource struct {
	ring    ringbufDropSource
	skipped *skippedRunCounter
}

// Total makes recordLossSource a ringbufDropSource.
func (s *recordLossSource) Total() (uint64, error) {
	loss, err := s.Loss()
	return loss.total(), err
}

// Loss reads both counters now (recordLossReader).
func (s *recordLossSource) Loss() (recordLoss, error) {
	return s.read(s.skipped.Total)
}

// TotalAsOf reads the ring-buffer drops now and the skipped runs as of asOf
// (datedDropSource, skippedRunCounter.TotalAsOf).
func (s *recordLossSource) TotalAsOf(asOf uint64) (uint64, error) {
	loss, err := s.read(func() (uint64, error) { return s.skipped.TotalAsOf(asOf) })
	return loss.total(), err
}

func (s *recordLossSource) read(skippedRuns func() (uint64, error)) (recordLoss, error) {
	ring, err := s.ring.Total()
	if err != nil {
		return recordLoss{}, err
	}
	skipped, err := skippedRuns()
	if err != nil {
		return recordLoss{}, err
	}
	return recordLoss{ring: ring, skipped: skipped}, nil
}
