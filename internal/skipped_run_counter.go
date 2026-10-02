package internal

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"sync"
)

// errSkippedRunsNotReported is what a kernel without the recursion_misses
// field makes of every read of it.
var errSkippedRunsNotReported = errors.New("the kernel does not report skipped bpf program runs")

// skippedRunCounter counts the runs of ior's attached tracepoint programs
// that the kernel skipped: it did not call the program at all. Such a run
// reserves nothing, so the ring-buffer drop counter (ringbuf_drop_map, bumped
// by the program itself) never sees it; the kernel counts it in the program's
// recursion_misses instead, and this type adds those up (task 723).
//
// What the count is evidence of. A skipped run is a tracepoint hit of SOME
// task on the host that ior's program did not see. The ring-buffer counter is
// bumped after the program's filter passed, so it counts records ior wanted;
// this one is bumped before any program code ran, so it also counts the hits
// of tasks outside a -pid/-tid/-comm filter, which would have written no
// record anyway (and of ior's own threads). A grown count therefore says
// that a record MAY be missing, never that one is: it is weaker evidence than
// a ring-buffer drop, and the two are kept apart all the way (recordLossSource,
// restartDropWatch, the statistics). Reproduced on 7.2.5: `-pid` of a task
// that loops over getppid, with an unrelated SCHED_FIFO task making the same
// call on that CPU, counted tens of thousands of skipped runs while every
// row of the traced task was there.
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
// cause a skip itself (progMissesReader). Classic tracepoint programs count
// only since Linux 6.7; before that the skip was silent, and this counter is
// not built (newSkippedRunCounter's caller asks kernelCountsSkippedRuns).
//
// Which programs are read. Only an attached program can be skipped, so a
// sweep reads the programs that have a live link at that moment (fds:
// libbpfAttachedProgramFDs - the syscall pairs the probe manager has
// attached, which the TUI changes at runtime, and the hand-attached probes)
// and, once more, those that had one at the previous sweep and lost it
// since: a detached program keeps its count, and that last read picks up the
// runs skipped between the previous sweep and the detach. The object's other
// programs, some 500 in a default run, are never read. The sum is kept per
// program (last) and only ever grows, whatever is attached.
//
// The cost. A read is one system call in which the kernel adds the program's
// per-CPU counters up over every POSSIBLE CPU (bpf_prog_get_stats), so it
// scales with the CPU count of the host, and a sweep with that times the
// attached programs. Measured inside ior on an 8-CPU host with 7.2.5, under
// load: 0.24 to 0.38 ms for the 242 programs of a default run (118 syscall
// pairs and the six hand-attached probes), and 8 to 20 microseconds for the
// 8 programs of a run that traces one syscall. That is 1 to 2.5 microseconds
// per program; read in a tight loop the same program takes 0.3 to 0.9
// (TestSkippedRunsAreReadFromReallyAttachedPrograms logs it), so most of a
// sweep is cache misses on counters the other CPUs keep writing. The drop
// monitor pays that once per period. The restart fold and
// the exec adoption ask per interrupted call, on the event loop, and get the
// last sweep when it is new enough for the question (TotalAsOf): a miss is
// counted when it happens, so a sweep that began after the record that asks
// was stamped has every miss among the records before it. A loop that lags
// behind the kernel therefore sweeps once per backlog, not once per
// question; a loop that has caught up sweeps per question.
type skippedRunCounter struct {
	// fds returns the programs attached now, in a slice of the caller's own.
	// It must not block for long: the event loop calls it per sweep.
	fds  func() []int
	read func(fd int) (misses uint64, reported bool, err error)
	// clock is the boot clock the drop watch stamps its observations with
	// (eventLoop.readDropStampClock), comparable with a record's time.
	clock func() uint64

	// mu serialises the sweeps of the monitor's goroutine and the loop's and
	// guards everything below.
	mu sync.Mutex
	// last is the latest count read of every program ever swept, and total
	// their sum. A program's count stands still while it is detached, so its
	// entry stays true without a read.
	last  map[int]uint64
	total uint64
	// attached are the programs the latest sweep found attached; the next
	// one reads those of them that are gone once more.
	attached []int
	// reusable says that the latest sweep succeeded and has a time
	// (sweptAt, a clock reading taken before its first read), so that it
	// can answer for the past (TotalAsOf).
	reusable bool
	sweptAt  uint64
}

// newSkippedRunCounter returns a counter over the programs fds names, after
// one sweep that proves the kernel reports the field for each of them. With
// nothing attached yet (a TUI run with every probe off whose hand probes
// failed) there is nothing to prove it with, and nothing that could be
// skipped; a kernel that does not report shows at the first sweep that reads
// a program, as a failed read.
func newSkippedRunCounter(fds func() []int, read func(int) (uint64, bool, error), clock func() uint64) (*skippedRunCounter, error) {
	counter := &skippedRunCounter{fds: fds, read: read, clock: clock, last: map[int]uint64{}}
	if _, err := counter.Total(); err != nil {
		return nil, err
	}
	return counter, nil
}

// Total sweeps the attached programs now and returns the sum of the skipped
// runs.
func (c *skippedRunCounter) Total() (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sweepLocked()
}

// TotalAsOf returns a sum that includes every run skipped at or before the
// boot-clock time asOf: the last sweep's when that sweep began after asOf,
// and a new sweep's otherwise. asOf is the time of a record the loop is
// processing, so "after asOf" is in the past for a loop that lags.
//
// The comparison is between a record's time and a clock reading of ior's
// own (bootclock.go). With an unknown POSITIVE boottime offset of ior's time
// namespace the readings run ahead of the record times by the offset, and a
// sweep that began up to that long BEFORE the record passes for one begun
// after it: the answer is then only as fresh as the last sweep, which the
// drop monitor renews every period.
func (c *skippedRunCounter) TotalAsOf(asOf uint64) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.reusable && c.sweptAt > asOf {
		return c.total, nil
	}
	return c.sweepLocked()
}

// sweepLocked reads every attached program, and every program detached since
// the previous sweep, and returns the sum.
//
// A sweep that fails answers nothing and is not reusable: the next question
// sweeps again instead of trusting an older sum. What it read before the
// failure stays added, since those runs were skipped. A sweep without a time
// is not reusable either: an unreadable clock reads as the maximum value
// (bootClockNs), which is "after" every record, and a sweep stamped with it
// would answer every later question for the rest of the run.
func (c *skippedRunCounter) sweepLocked() (uint64, error) {
	c.reusable = false
	startedAt := c.clock()
	attached := c.fds()
	for _, fd := range c.sweepSet(attached) {
		misses, reported, err := c.read(fd)
		if err != nil {
			return 0, fmt.Errorf("skipped program runs: %w", err)
		}
		if !reported {
			return 0, errSkippedRunsNotReported
		}
		// The kernel's count only grows; one that reads lower is ignored
		// rather than taken out of a sum that must never fall.
		if misses > c.last[fd] {
			c.total += misses - c.last[fd]
			c.last[fd] = misses
		}
	}
	c.attached = attached
	c.sweptAt, c.reusable = startedAt, startedAt != math.MaxUint64
	return c.total, nil
}

// sweepSet returns the programs a sweep reads: the attached ones, and those
// the previous sweep found attached that are not any more, whose count up to
// their detach was not read yet.
func (c *skippedRunCounter) sweepSet(attached []int) []int {
	set := slices.Clone(attached)
	for _, fd := range c.attached {
		if !slices.Contains(attached, fd) {
			set = append(set, fd)
		}
	}
	return set
}

// recordLossSource is the drop source of a run that counts both ways a
// record is lost in the kernel, apart: Total is the ring-buffer drops alone
// (ringbufDropSource: records ior wanted and lost), and the skipped program
// runs have their own two questions (skippedRunSource: records that MAY be
// missing, see skippedRunCounter). They are never added up - what each is
// evidence of differs, and so does what the loop does about it
// (restartDropWatch) - and one failing to read says nothing about the other.
type recordLossSource struct {
	ring    ringbufDropSource
	skipped *skippedRunCounter
}

// Total makes recordLossSource a ringbufDropSource: the ring-buffer drops.
func (s *recordLossSource) Total() (uint64, error) {
	return s.ring.Total()
}

// SkippedRuns sweeps the attached programs now (skippedRunSource).
func (s *recordLossSource) SkippedRuns() (uint64, error) {
	return s.skipped.Total()
}

// SkippedRunsAsOf returns the skipped runs as of the boot-clock time asOf
// (skippedRunSource, skippedRunCounter.TotalAsOf).
func (s *recordLossSource) SkippedRunsAsOf(asOf uint64) (uint64, error) {
	return s.skipped.TotalAsOf(asOf)
}
