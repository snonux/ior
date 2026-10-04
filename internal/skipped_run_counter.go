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
// runs skipped between the previous sweep and the detach. A fold's question
// (SkippedSince) reads its own programs whether they are attached now or
// were before (fdsOn: libbpfAttachedProgramFDsOn), since a fold may be
// decided between a detach and the probe change's stamp. The object's other
// programs, some 500 in a default run, are never read. The count is kept per
// program (programs) and the sum only ever grows, whatever is attached.
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
// monitor pays that once per period, and the exec adoption, which asks
// rarely, with TotalAsOf: it gets the last sweep when that is new enough for
// the question (a miss is counted when it happens, so a sweep that began
// after the record that asks was stamped has every miss among the records
// before it), and sweeps otherwise.
//
// A restart fold asks per interrupted call, on the event loop, and a full
// sweep per question made a caught-up loop sweep 242 programs per fold: on
// a pipe read interrupted some 6,000 times a second, 15 million bpf(2) calls
// in 10 s and four times the CPU of a run that did not count; with the
// fold's own programs only, 0.65 million and about 1.25 times. Those are
// the syscall's pair and the six hand probes' programs - 8, or 9 when
// rt_sigreturn is traced, whose generated program shares
// sys_enter_rt_sigreturn with the restart program - and for a -516 row
// restart_syscall's pair as well, two more. So a fold
// asks about the programs its proof depends on only (SkippedSince,
// restartFoldTracepoints: the syscall's pair, restart_syscall's for -516,
// the hand probes), per program: each program's latest read, of a full sweep
// or of an earlier question, answers when it began after the record that
// asks, and the others are read then.
type skippedRunCounter struct {
	// fds returns the programs attached now, in a slice of the caller's own;
	// fdsOn those attached to one of the tracepoints it is given, now or
	// earlier while the module is open (attachedProgramSet).
	// Neither may block for long: the event loop calls them per question.
	fds   func() []int
	fdsOn func(tracepoints []string) []int
	read  func(fd int) (misses uint64, reported bool, err error)
	// clock is the boot clock the drop watch stamps its observations with
	// (eventLoop.readDropStampClock), comparable with a record's time.
	clock func() uint64

	// mu serialises the reads of the monitor's goroutine and the loop's and
	// guards everything below.
	mu sync.Mutex
	// programs is what is known of every program ever read, and total the
	// sum of their counts. A program's count stands still while it is
	// detached, so its entry stays true without a read.
	programs map[int]*programSkips
	total    uint64
	// attached are the programs the latest full sweep found attached; the
	// next one reads those of them that are gone once more.
	attached []int
	// reusable says that the latest full sweep succeeded and has a time
	// (sweptAt, a clock reading taken before its first read), so that it
	// can answer for the past (TotalAsOf).
	reusable bool
	sweptAt  uint64
	// reads is the buffer of one batch of reads (readLocked), kept to spare
	// the event loop an allocation per question.
	reads []programRead
}

// programSkips is what the counter knows of one program: the count of its
// latest read, the stamp of the earliest read that returned that count (a
// clock reading taken after that read), and when its latest read began (a
// clock reading taken before it; dated says it is one). The zero value is
// true of a program never read: a program is loaded with a count of 0, so
// "0, first seen at time 0" holds until a read says otherwise.
//
// This is restartDropWatch's stampedTotal per program, under the same
// invariant: the program's count was `count` in a read that finished at or
// before firstSeenAt. A fold asks it per program (SkippedSince).
type programSkips struct {
	count       uint64
	firstSeenAt uint64
	readFrom    uint64
	dated       bool
}

// covers reports whether the latest read of the program holds every run of
// it skipped at or before the boot-clock time asOf: it began after asOf. A
// skip is counted when it happens, so a read begun later sees it.
func (p *programSkips) covers(asOf uint64) bool {
	return p != nil && p.dated && p.readFrom > asOf
}

// programRead is one successful read of a program's count.
type programRead struct {
	fd     int
	misses uint64
}

// newSkippedRunCounter returns a counter over the programs fds names (and
// fdsOn, per tracepoint), after one sweep that proves the kernel reports the
// field for each of them. With nothing attached yet (a TUI run with every
// probe off whose hand probes failed) there is nothing to prove it with, and
// nothing that could be skipped; a kernel that does not report shows at the
// first sweep that reads a program, as a failed read.
func newSkippedRunCounter(fds func() []int, fdsOn func([]string) []int, read func(int) (uint64, bool, error), clock func() uint64) (*skippedRunCounter, error) {
	counter := &skippedRunCounter{fds: fds, fdsOn: fdsOn, read: read, clock: clock, programs: map[int]*programSkips{}}
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
// boot-clock time asOf: the last full sweep's when that sweep began after
// asOf, and a new sweep's otherwise. asOf is the time of a record the loop is
// processing, so "after asOf" is in the past for a loop that lags. (The sum
// may also hold reads of single programs made since that sweep; they only
// add what is newer.)
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

// SkippedSince reports whether a run of one of the programs attached to
// tracepoints (names without the category) was skipped at or after the
// boot-clock time since: the question of a restart fold, about the
// programs its proof depends on (restartFoldTracepoints), between its
// interrupted exit (since) and the record that asks (upTo). It also
// returns the counter's total after the question, whatever the answer:
// the reads it made may have raised it, and the caller tells the drop
// watch (restartDropWatch.lostSince), so that a skip first seen here is
// dated now and not at the next full sweep.
//
// A program whose latest read - of a full sweep or of an earlier question -
// began after upTo is answered from it (programSkips.covers); the others are
// read now, together. So a lagging loop reads nothing, and a caught-up one
// reads the fold's few programs, not every attached one. Each program's
// answer goes by its own stamp: its count first seen at or after since may
// be a skip among the fold's records, and refuses it. Like the watch, that
// also refuses a fold for a skip first seen late that happened before since.
//
// A program detached before the question is asked all the same: fdsOn
// names every program that was attached to the tracepoints while the
// module is open (attachedProgramSet). The probe change that detached it
// refuses the fold on its own (restartAcrossProbeChange), but only once it
// is stamped, after both links of the pair are gone and the manager
// reported; a fold decided in between depends on the program's skips like
// any other. Its count stands still, so a read of it is the last one that
// matters. An error answers true: a count that cannot be read proves
// nothing.
func (c *skippedRunCounter) SkippedSince(tracepoints []string, since, upTo uint64) (skipped bool, total uint64, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	fds := c.fdsOn(tracepoints)
	if stale := c.staleAsOf(fds, upTo); len(stale) > 0 {
		if _, err := c.readLocked(stale); err != nil {
			return true, c.total, err
		}
	}
	for _, fd := range fds {
		// Every program of fds has an entry now; one without would be a
		// count never read, which proves nothing.
		if program := c.programs[fd]; program == nil || program.firstSeenAt >= since {
			return true, c.total, nil
		}
	}
	return false, c.total, nil
}

// staleAsOf returns the programs of fds whose latest read does not cover
// the time asOf, in a slice of its own (nil when there are none: a lagging
// loop allocates nothing).
func (c *skippedRunCounter) staleAsOf(fds []int, asOf uint64) []int {
	var stale []int
	for _, fd := range fds {
		if !c.programs[fd].covers(asOf) {
			stale = append(stale, fd)
		}
	}
	return stale
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
	attached := c.fds()
	startedAt, err := c.readLocked(c.sweepSet(attached))
	if err != nil {
		return 0, err
	}
	c.attached = attached
	c.sweptAt, c.reusable = startedAt, startedAt != math.MaxUint64
	return c.total, nil
}

// readLocked reads the programs of fds as one batch between two clock
// readings and returns the first: each count read is stamped with the
// second, its read with the first (record). A failed read ends the batch;
// the reads before it are recorded all the same.
func (c *skippedRunCounter) readLocked(fds []int) (startedAt uint64, err error) {
	startedAt = c.clock()
	c.reads = c.reads[:0]
	for _, fd := range fds {
		misses, reported, readErr := c.read(fd)
		if readErr != nil {
			err = fmt.Errorf("skipped program runs: %w", readErr)
			break
		}
		if !reported {
			err = errSkippedRunsNotReported
			break
		}
		c.reads = append(c.reads, programRead{fd: fd, misses: misses})
	}
	seenAt := c.clock()
	for _, read := range c.reads {
		c.record(read, startedAt, seenAt)
	}
	return startedAt, err
}

// record takes one read into the program's entry and the total.
func (c *skippedRunCounter) record(read programRead, startedAt, seenAt uint64) {
	program := c.programs[read.fd]
	if program == nil {
		program = &programSkips{}
		c.programs[read.fd] = program
	}
	// The kernel's count only grows; one that reads lower is ignored
	// rather than taken out of a sum that must never fall.
	if read.misses > program.count {
		c.total += read.misses - program.count
		program.count = read.misses
		program.firstSeenAt = seenAt
	}
	program.readFrom, program.dated = startedAt, startedAt != math.MaxUint64
}

// sweepSet returns the programs a sweep reads: the attached ones, and those
// the previous sweep found attached that are not any more, whose count up to
// their detach was not read yet.
func (c *skippedRunCounter) sweepSet(attached []int) []int {
	set := slices.Clone(attached)
	now := make(map[int]struct{}, len(attached))
	for _, fd := range attached {
		now[fd] = struct{}{}
	}
	for _, fd := range c.attached {
		if _, still := now[fd]; !still {
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

// SkippedRunsSince reports whether a program attached to one of tracepoints
// had a run skipped at or after since, as of upTo, and the sum of the
// skipped runs after the question (skippedRunSource,
// skippedRunCounter.SkippedSince).
func (s *recordLossSource) SkippedRunsSince(tracepoints []string, since, upTo uint64) (bool, uint64, error) {
	return s.skipped.SkippedSince(tracepoints, since, upTo)
}
