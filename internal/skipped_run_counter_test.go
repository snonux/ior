package internal

import (
	"encoding/binary"
	"errors"
	"math"
	"os"
	"reflect"
	"strings"
	"testing"

	bpf "github.com/aquasecurity/libbpfgo"
	"golang.org/x/sys/unix"
)

// Tests for the count of the program runs the kernel skipped (task 723):
// reading one program's recursion_misses, adding them up over the attached
// programs, and the count's way - beside the ring-buffer drops, never added
// to them - into the drop monitor's results, its warning and the end-of-run
// statistics. What the restart folds and the exec adoption make of it is
// tested in eventloop_restart_skipped_test.go, the list of attached programs
// in ior_bpflink_test.go, and the read of a really loaded program in
// ior_bpflink_root_test.go.

// progInfoWithMisses is a bpf_prog_info buffer as the kernel fills it, with
// recursion_misses set and a neighbour on each side that must not be taken
// for it (run_cnt before, verified_insns after).
func progInfoWithMisses(misses uint64) []byte {
	info := make([]byte, bpfProgInfoMissesEnd+8)
	binary.NativeEndian.PutUint64(info[bpfProgInfoMissesOffset-8:], 0x1111111111111111)
	binary.NativeEndian.PutUint64(info[bpfProgInfoMissesOffset:], misses)
	binary.NativeEndian.PutUint64(info[bpfProgInfoMissesEnd:], 0x2222222222222222)
	return info
}

func TestDecodeProgRecursionMissesReadsTheFieldAtItsOffset(t *testing.T) {
	const want = 0x0102030405060708
	info := progInfoWithMisses(want)
	for _, infoLen := range []uint32{bpfProgInfoMissesEnd, bpfProgInfoMissesEnd + 8, 232} {
		if got, reported := decodeProgRecursionMisses(info, infoLen); !reported || got != want {
			t.Errorf("info_len %d: got %#x reported=%v, want %#x reported", infoLen, got, reported, uint64(want))
		}
	}
	if bpfProgInfoMissesOffset != 208 {
		t.Fatalf("recursion_misses offset = %d, want 208 (offsetof in include/uapi/linux/bpf.h)", bpfProgInfoMissesOffset)
	}
}

// A kernel whose bpf_prog_info ends before the field, or in the middle of
// it, says nothing about skipped runs: the bytes are the caller's zeroes (or,
// here, whatever the buffer held), not a count.
func TestDecodeProgRecursionMissesRejectsAShortInfo(t *testing.T) {
	info := progInfoWithMisses(7)
	for _, infoLen := range []uint32{0, 200, bpfProgInfoMissesOffset, bpfProgInfoMissesEnd - 1} {
		if got, reported := decodeProgRecursionMisses(info, infoLen); reported || got != 0 {
			t.Errorf("info_len %d: got %d reported=%v, want 0 and not reported", infoLen, got, reported)
		}
	}
	if got, reported := decodeProgRecursionMisses(info[:bpfProgInfoMissesEnd-1], bpfProgInfoMissesEnd); reported || got != 0 {
		t.Errorf("short buffer: got %d reported=%v, want 0 and not reported", got, reported)
	}
}

// The system call itself, as far as it goes without a loaded program: a
// descriptor that is not a BPF program is an error, never a zero count. A
// closed one is EBADFD - not EBADF - from the kernel's
// bpf_obj_get_info_by_fd.
func TestProgMissesReaderFailsOnADescriptorThatIsNoProgram(t *testing.T) {
	reader := newProgMissesReader()
	if misses, reported, err := reader.misses(-1); !errors.Is(err, unix.EBADFD) {
		t.Errorf("fd -1: got %d reported=%v err=%v, want EBADFD", misses, reported, err)
	}
	file, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	defer func() { _ = file.Close() }()
	if misses, reported, err := reader.misses(int(file.Fd())); err == nil {
		t.Errorf("an open file: got %d reported=%v without an error", misses, reported)
	}
}

func TestKernelCountsSkippedRunsFromLinux67(t *testing.T) {
	cases := map[string]bool{
		"7.2.5-200.fc44.x86_64":        true,
		"6.19.8-200.fc43.x86_64":       true,
		"6.7.0":                        true,
		"6.7-rc1":                      true,
		"10.0.1":                       true,
		"6.6.99":                       false,
		"5.14.0-503.11.1.el9_5.x86_64": false,
		"4.18.0-553.el8_10.x86_64":     false,
		"":                             false,
		"6":                            false,
		"six.seven":                    false,
		"6.x":                          false,
	}
	for release, want := range cases {
		if got := kernelCountsSkippedRuns(release); got != want {
			t.Errorf("kernelCountsSkippedRuns(%q) = %v, want %v", release, got, want)
		}
	}
}

// steppingClock is a boot clock that moves by one with every reading.
type steppingClock struct{ now uint64 }

func (c *steppingClock) read() uint64 {
	c.now++
	return c.now
}

func TestSkippedRunCounterSumsTheAttachedPrograms(t *testing.T) {
	programs := newScriptedPrograms(3, 4, 5)
	// A loaded program without a link: never read, and its count - which
	// cannot move - never added.
	programs.misses[6] = 1000
	clock := &steppingClock{}
	counter, err := newSkippedRunCounter(programs.fds, programs.fdsOn, programs.read, clock.read)
	if err != nil {
		t.Fatalf("newSkippedRunCounter: %v", err)
	}
	if programs.reads != 3 {
		t.Fatalf("the first sweep made %d reads, want one per attached program", programs.reads)
	}
	programs.skip(3, 2)
	programs.skip(5, 40)
	if total, err := counter.Total(); err != nil || total != 42 || programs.reads != 6 {
		t.Fatalf("Total = %d, %v after %d reads, want 42 after 6", total, err, programs.reads)
	}
}

// TestSkippedRunCounterReadsADetachedProgramOnceMore: the runs skipped
// between the last sweep and a probe's detach are still in the program's
// count, so the sweep after the detach reads it one last time. After that it
// costs nothing, its count stays in the sum - which never falls - and when
// the probe is attached again only what was skipped since is added.
func TestSkippedRunCounterReadsADetachedProgramOnceMore(t *testing.T) {
	programs := newScriptedPrograms(3, 4)
	counter, err := newSkippedRunCounter(programs.fds, programs.fdsOn, programs.read, (&steppingClock{}).read)
	if err != nil {
		t.Fatalf("newSkippedRunCounter: %v", err)
	}
	programs.skip(4, 5)
	programs.detach(4)
	swept := programs.reads
	if total, err := counter.Total(); err != nil || total != 5 || programs.reads != swept+2 {
		t.Fatalf("first sweep after the detach: Total = %d, %v after %d reads, want 5 after 2",
			total, err, programs.reads-swept)
	}
	swept = programs.reads
	if total, err := counter.Total(); err != nil || total != 5 || programs.reads != swept+1 {
		t.Fatalf("second sweep after the detach: Total = %d, %v after %d reads, want the 5 kept after 1",
			total, err, programs.reads-swept)
	}
	programs.attached = append(programs.attached, 4)
	programs.skip(4, 2)
	if total, err := counter.Total(); err != nil || total != 7 {
		t.Fatalf("after the probe was attached again: Total = %d, %v, want 7 (5 and the 2 skipped since)", total, err)
	}
}

// A kernel that does not report the field, or a read that fails, builds no
// counter: its zero would be read as "none skipped". Nothing attached is not
// that: nothing can be skipped, and 0 is the count.
func TestSkippedRunCounterNeedsAKernelThatReports(t *testing.T) {
	none := newScriptedPrograms()
	counter, err := newSkippedRunCounter(none.fds, none.fdsOn, none.read, (&steppingClock{}).read)
	if err != nil {
		t.Fatalf("a counter over no attached program: %v", err)
	}
	if total, err := counter.Total(); err != nil || total != 0 || none.reads != 0 {
		t.Errorf("Total = %d, %v after %d reads, want 0 and no read", total, err, none.reads)
	}
	programs := newScriptedPrograms(3)
	programs.unreported = true
	if _, err := newSkippedRunCounter(programs.fds, programs.fdsOn, programs.read, (&steppingClock{}).read); !errors.Is(err, errSkippedRunsNotReported) {
		t.Errorf("err = %v, want errSkippedRunsNotReported", err)
	}
	boom := errors.New("boom")
	programs = newScriptedPrograms(3)
	programs.err = boom
	if _, err := newSkippedRunCounter(programs.fds, programs.fdsOn, programs.read, (&steppingClock{}).read); !errors.Is(err, boom) {
		t.Errorf("err = %v, want the read's error", err)
	}
}

// TestSkippedRunCounterAnswersThePastFromItsLastSweep: a sweep is dated by a
// clock reading taken BEFORE its first read, and answers every question about
// a time before that reading. A question about that very instant or a later
// one sweeps again: a run skipped at the instant may have been skipped after
// the program was read.
func TestSkippedRunCounterAnswersThePastFromItsLastSweep(t *testing.T) {
	programs := newScriptedPrograms(3, 4)
	clock := &steppingClock{now: 99}
	counter, err := newSkippedRunCounter(programs.fds, programs.fdsOn, programs.read, clock.read)
	if err != nil {
		t.Fatalf("newSkippedRunCounter: %v", err)
	}
	const sweptAt = 100 // the one clock reading of the first sweep
	programs.skip(4, 5)
	swept := programs.reads
	if total, err := counter.TotalAsOf(sweptAt - 1); err != nil || total != 0 || programs.reads != swept {
		t.Fatalf("TotalAsOf(before the sweep) = %d, %v after %d reads, want the swept 0 and no read",
			total, err, programs.reads-swept)
	}
	if total, err := counter.TotalAsOf(sweptAt); err != nil || total != 5 || programs.reads != swept+2 {
		t.Fatalf("TotalAsOf(the sweep's own stamp) = %d, %v after %d reads, want a new sweep's 5",
			total, err, programs.reads-swept)
	}
	// Before the reads, which dates the sweep, and after them, which stamps
	// a count read in it (restartDropWatch's rule, per program).
	if clock.now != sweptAt+3 {
		t.Fatalf("the clock was read %d times for two sweeps, want twice each", clock.now-99)
	}
}

// A sweep stamped after its reads would answer for a time at which some
// program had already been read: the stamp must be the earlier reading.
func TestSkippedRunCounterStampsASweepBeforeItsReads(t *testing.T) {
	programs := newScriptedPrograms(3)
	clock := &steppingClock{}
	var readAt uint64
	read := func(fd int) (uint64, bool, error) {
		readAt = clock.read()
		return programs.read(fd)
	}
	counter, err := newSkippedRunCounter(programs.fds, programs.fdsOn, read, clock.read)
	if err != nil {
		t.Fatalf("newSkippedRunCounter: %v", err)
	}
	swept := programs.reads
	if _, err := counter.TotalAsOf(readAt); err != nil || programs.reads == swept {
		t.Fatalf("a question about the time of the sweep's read was answered from that sweep (err %v)", err)
	}
}

// TestSkippedRunCounterNeverReusesASweepWithoutATime: a boot clock that
// cannot be read returns the maximum value (bootClockNs), which is later
// than every record. A sweep stamped with it would be "begun after" every
// question from then on, and answer them all with a count that never moves
// again. Such a sweep answers its own question and no other.
func TestSkippedRunCounterNeverReusesASweepWithoutATime(t *testing.T) {
	programs := newScriptedPrograms(3)
	now := uint64(math.MaxUint64)
	counter, err := newSkippedRunCounter(programs.fds, programs.fdsOn, programs.read, func() uint64 { return now })
	if err != nil {
		t.Fatalf("newSkippedRunCounter: %v", err)
	}
	for _, skippedSoFar := range []uint64{1, 2} {
		programs.skip(3, 1)
		swept := programs.reads
		if total, err := counter.TotalAsOf(5000); err != nil || total != skippedSoFar || programs.reads != swept+1 {
			t.Fatalf("TotalAsOf with an unreadable clock = %d, %v after %d reads, want a new sweep's %d",
				total, err, programs.reads-swept, skippedSoFar)
		}
	}
	// Once the clock reads again, a sweep is dated and reused as usual.
	now = 9000
	if _, err := counter.Total(); err != nil {
		t.Fatalf("Total: %v", err)
	}
	swept := programs.reads
	if _, err := counter.TotalAsOf(5000); err != nil || programs.reads != swept {
		t.Fatalf("a dated sweep was not reused (err %v, %d reads)", err, programs.reads-swept)
	}
}

// A sweep that failed leaves no sum to answer from: the next question reads
// again, also one about the past.
func TestSkippedRunCounterForgetsItsSweepWhenOneFails(t *testing.T) {
	programs := newScriptedPrograms(3)
	clock := &steppingClock{now: 99}
	counter, err := newSkippedRunCounter(programs.fds, programs.fdsOn, programs.read, clock.read)
	if err != nil {
		t.Fatalf("newSkippedRunCounter: %v", err)
	}
	programs.err = errors.New("boom")
	if _, err := counter.Total(); err == nil {
		t.Fatal("Total succeeded although the read failed")
	}
	if _, err := counter.TotalAsOf(0); err == nil {
		t.Fatal("TotalAsOf answered from a sweep older than a failed one")
	}
	programs.err = nil
	programs.skip(3, 9)
	if total, err := counter.TotalAsOf(0); err != nil || total != 9 {
		t.Fatalf("TotalAsOf after the read recovered = %d, %v, want 9", total, err)
	}
}

// foldPrograms returns scripted programs 3, 4 and 5 attached to the
// tracepoints "a", "b" and "c", and a counter over them that has swept once,
// on a clock that moves by one per reading from 100.
func foldPrograms(t *testing.T) (*scriptedPrograms, *skippedRunCounter, *steppingClock) {
	t.Helper()
	programs := newScriptedPrograms()
	for fd, tracepoint := range map[int]string{3: "a", 4: "b", 5: "c"} {
		programs.attachOn(fd, tracepoint)
	}
	clock := &steppingClock{now: 99}
	counter, err := newSkippedRunCounter(programs.fds, programs.fdsOn, programs.read, clock.read)
	if err != nil {
		t.Fatalf("newSkippedRunCounter: %v", err)
	}
	return programs, counter, clock
}

// TestSkippedSinceAsksOnlyTheProgramsOfItsTracepoints: a fold's question
// reads the programs on its tracepoints and no other, and a skip of another
// program is no answer to it.
func TestSkippedSinceAsksOnlyTheProgramsOfItsTracepoints(t *testing.T) {
	programs, counter, clock := foldPrograms(t)
	programs.skip(5, 1)
	swept := programs.reads
	skipped, _, err := counter.SkippedSince([]string{"a", "b"}, 1, clock.now)
	if err != nil || skipped || programs.reads != swept+2 {
		t.Fatalf("SkippedSince(a, b) = %v, %v after %d reads, want no skip after 2", skipped, err, programs.reads-swept)
	}
	programs.skip(4, 1)
	if skipped, _, err := counter.SkippedSince([]string{"a", "b"}, 1, clock.now); err != nil || !skipped {
		t.Fatalf("SkippedSince(a, b) after b's skip = %v, %v, want a skip", skipped, err)
	}
}

// TestSkippedSinceGoesByEachProgramsOwnStamp: a program's count first seen
// before since lies before the fold's records; one first seen at or after
// it may be among them. A count read without a change keeps its stamp.
func TestSkippedSinceGoesByEachProgramsOwnStamp(t *testing.T) {
	programs, counter, clock := foldPrograms(t)
	programs.skip(3, 1)
	if _, err := counter.Total(); err != nil { // reads the clock at 102 and 103
		t.Fatalf("Total: %v", err)
	}
	const seenAt = 103
	for since, want := range map[uint64]bool{seenAt: true, seenAt + 1: false} {
		if skipped, _, err := counter.SkippedSince([]string{"a"}, since, clock.now); err != nil || skipped != want {
			t.Fatalf("SkippedSince(a, since %d) = %v, %v, want %v", since, skipped, err, want)
		}
	}
}

// TestASmallReadAnswersOnlyForItsOwnPrograms is the reuse rule of the
// fold's question: a program's latest read answers for the records before
// it began, whether a full sweep or another fold's question made it, and a
// question's reads answer for no program they did not read.
func TestASmallReadAnswersOnlyForItsOwnPrograms(t *testing.T) {
	programs, counter, clock := foldPrograms(t)
	asOf := clock.now // after the first sweep began
	ask := func(tracepoints ...string) int {
		t.Helper()
		before := programs.reads
		if _, _, err := counter.SkippedSince(tracepoints, 0, asOf); err != nil {
			t.Fatalf("SkippedSince(%v): %v", tracepoints, err)
		}
		return programs.reads - before
	}
	if reads := ask("a"); reads != 1 {
		t.Fatalf("a, newer than the sweep: %d reads, want 1", reads)
	}
	if reads := ask("a"); reads != 0 {
		t.Fatalf("a again: %d reads, want none: its read began after asOf", reads)
	}
	if reads := ask("a", "b"); reads != 1 {
		t.Fatalf("a and b: %d reads, want b's alone: a's read is not b's", reads)
	}
	if _, err := counter.Total(); err != nil {
		t.Fatalf("Total: %v", err)
	}
	asOf = clock.now - 2 // before the full sweep began
	if reads := ask("a", "b", "c"); reads != 0 {
		t.Fatalf("a, b and c behind a full sweep: %d reads, want none", reads)
	}
}

// A read answers for the records before it began, not for one stamped at
// that very instant: a run skipped then may have been skipped after the
// program was read.
func TestAProgramsReadDoesNotAnswerForItsOwnInstant(t *testing.T) {
	programs, counter, _ := foldPrograms(t)
	const sweptAt = 100 // the first clock reading of the first sweep
	for upTo, wantReads := range map[uint64]int{sweptAt - 1: 0, sweptAt: 1} {
		before := programs.reads
		if _, _, err := counter.SkippedSince([]string{"a"}, 1, upTo); err != nil || programs.reads-before != wantReads {
			t.Fatalf("SkippedSince as of %d: %v after %d reads, want %d", upTo, err, programs.reads-before, wantReads)
		}
	}
}

// A count that cannot be read proves nothing: the fold's question answers
// "skipped" with the error. A read without a time - the boot clock could
// not be read - answers its own question and no later one.
func TestSkippedSinceRefusesWhatItCannotRead(t *testing.T) {
	programs, counter, clock := foldPrograms(t)
	programs.err = errors.New("boom")
	if skipped, _, err := counter.SkippedSince([]string{"a"}, 0, clock.now); err == nil || !skipped {
		t.Fatalf("SkippedSince with an unreadable program = %v, %v, want a skip and the error", skipped, err)
	}
	programs.err = nil
	now := uint64(math.MaxUint64)
	undated, err := newSkippedRunCounter(programs.fds, programs.fdsOn, programs.read, func() uint64 { return now })
	if err != nil {
		t.Fatalf("newSkippedRunCounter: %v", err)
	}
	for range 2 {
		before := programs.reads
		if _, _, err := undated.SkippedSince([]string{"a"}, 0, 5000); err != nil || programs.reads != before+1 {
			t.Fatalf("SkippedSince with an unreadable clock: %v after %d reads, want a read each time", err, programs.reads-before)
		}
	}
}

// lossSourceOver builds the drop source of a kernel that counts skipped runs
// over a scripted ring counter and scripted programs.
func lossSourceOver(t *testing.T, ring ringbufDropSource, programs *scriptedPrograms, clock func() uint64) *recordLossSource {
	t.Helper()
	skipped, err := newSkippedRunCounter(programs.fds, programs.fdsOn, programs.read, clock)
	if err != nil {
		t.Fatalf("newSkippedRunCounter: %v", err)
	}
	return &recordLossSource{ring: ring, skipped: skipped}
}

// The two counters are not added up: a ring-buffer drop is a record ior
// wanted, a skipped run one that may be missing.
func TestRecordLossSourceKeepsSkippedRunsApartFromRingDrops(t *testing.T) {
	ring := uint64(3)
	programs := newScriptedPrograms(3, 4)
	source := lossSourceOver(t, ringbufDropSourceFunc(func() (uint64, error) { return ring, nil }),
		programs, (&steppingClock{now: 99}).read)
	programs.skip(4, 10)
	if total, err := source.Total(); err != nil || total != 3 {
		t.Fatalf("Total = %d, %v, want the 3 ring-buffer drops alone", total, err)
	}
	if skipped, err := source.SkippedRuns(); err != nil || skipped != 10 {
		t.Fatalf("SkippedRuns = %d, %v, want 10", skipped, err)
	}
	// The past is answered from the sweep SkippedRuns just made.
	programs.skip(3, 100)
	swept := programs.reads
	if skipped, err := source.SkippedRunsAsOf(0); err != nil || skipped != 10 || programs.reads != swept {
		t.Fatalf("SkippedRunsAsOf(0) = %d, %v after %d program reads, want 10 and none", skipped, err, programs.reads-swept)
	}
}

// One counter that cannot be read says nothing about the other.
func TestRecordLossSourceFailsEachCounterApart(t *testing.T) {
	boom := errors.New("boom")
	var ringErr error
	programs := newScriptedPrograms(3)
	source := lossSourceOver(t, ringbufDropSourceFunc(func() (uint64, error) { return 1, ringErr }),
		programs, (&steppingClock{}).read)
	ringErr = boom
	if _, err := source.Total(); !errors.Is(err, boom) {
		t.Errorf("Total with an unreadable ring counter: err = %v", err)
	}
	if skipped, err := source.SkippedRuns(); err != nil || skipped != 0 {
		t.Errorf("SkippedRuns with an unreadable ring counter = %d, %v, want 0 and no error", skipped, err)
	}
	ringErr, programs.err = nil, boom
	if total, err := source.Total(); err != nil || total != 1 {
		t.Errorf("Total with unreadable programs = %d, %v, want 1 and no error", total, err)
	}
	if _, err := source.SkippedRuns(); !errors.Is(err, boom) {
		t.Errorf("SkippedRuns with unreadable programs: err = %v", err)
	}
	if _, err := source.SkippedRunsAsOf(^uint64(0)); !errors.Is(err, boom) {
		t.Errorf("SkippedRunsAsOf with unreadable programs: err = %v", err)
	}
}

func TestDropMonitorReportsSkippedRunsBesideTheDrops(t *testing.T) {
	ring := uint64(0)
	programs := newScriptedPrograms(3)
	monitor := newRingbufDropMonitor(lossSourceOver(t,
		ringbufDropSourceFunc(func() (uint64, error) { return ring, nil }), programs, (&steppingClock{}).read))
	if got, want := monitor.Tick(), (ringbufDropResult{skippedCounted: true}); got != want {
		t.Fatalf("first tick = %+v, want %+v", got, want)
	}
	ring = 4
	programs.skip(3, 6)
	want := ringbufDropResult{total: 4, delta: 4, skippedCounted: true, skipped: 6, skippedDelta: 6}
	if got := monitor.Tick(); got != want {
		t.Fatalf("tick = %+v, want %+v", got, want)
	}
	programs.skip(3, 1)
	want = ringbufDropResult{total: 4, skippedCounted: true, skipped: 7, skippedDelta: 1}
	if got := monitor.Tick(); got != want || !got.lost() {
		t.Fatalf("tick = %+v (lost %v), want %+v and a loss", got, got.lost(), want)
	}
	if got := monitor.Tick(); got.lost() {
		t.Fatalf("a tick that found nothing new reports a loss: %+v", got)
	}
	// A plain source has no skipped runs to report.
	plain := newRingbufDropMonitor(&ringbufDropSourceStub{totals: []uint64{5}})
	if got, want := plain.Tick(), (ringbufDropResult{total: 5, delta: 5}); got != want {
		t.Fatalf("plain tick = %+v, want %+v", got, want)
	}
}

// TestDropMonitorReadsEachCounterApart: a failed read of one counter is that
// counter's warning. The other was read, and its figures stand - a failed
// sweep of the programs must not make the ring-buffer drops unknown, nor the
// reverse.
func TestDropMonitorReadsEachCounterApart(t *testing.T) {
	var ringErr error
	programs := newScriptedPrograms(3)
	monitor := newRingbufDropMonitor(lossSourceOver(t,
		ringbufDropSourceFunc(func() (uint64, error) { return 2, ringErr }), programs, (&steppingClock{}).read))
	programs.err = errors.New("boom")
	got := monitor.Tick()
	if got.warning != "" || got.total != 2 || got.delta != 2 || got.skippedCounted ||
		!strings.Contains(got.skippedWarning, "skipped probe run counter read failed: ") {
		t.Fatalf("tick with unreadable programs = %+v, want the ring-buffer figures and a skipped-run warning", got)
	}
	programs.err, ringErr = nil, errors.New("boom")
	programs.skip(3, 5)
	got = monitor.Tick()
	if !strings.Contains(got.warning, "ring buffer drop counter read failed: ") || got.skippedWarning != "" ||
		!got.skippedCounted || got.skipped != 5 || got.skippedDelta != 5 {
		t.Fatalf("tick with an unreadable ring counter = %+v, want its warning and the skipped-run figures", got)
	}
}

// TestDropWarningNamesEachKindOfLoss: the two parts say different things. A
// drop is events lost; a skipped run is counted for every task on the host,
// so its part says that events MAY be missing and that the count is not the
// traced tasks' alone - never that "their events are missing", which a run
// with a -pid filter and a busy real-time task elsewhere proved false.
func TestDropWarningNamesEachKindOfLoss(t *testing.T) {
	const skipText = "Kernel skipped 3 probe runs (5 total this run): events may be missing; " +
		"the count includes tasks outside the trace filter - a task was preempted inside a BPF program or map operation"
	ringOnly := formatRingbufDropWarning(ringbufDropResult{total: 7, delta: 4, skippedCounted: true, skipped: 2})
	if want := "Ring buffer full: 4 events dropped kernel-side (7 total this run) - consider a larger -mapSize"; ringOnly != want {
		t.Errorf("ring only = %q, want %q", ringOnly, want)
	}
	skippedOnly := formatRingbufDropWarning(ringbufDropResult{total: 4, skippedCounted: true, skipped: 5, skippedDelta: 3})
	if skippedOnly != skipText {
		t.Errorf("skipped only = %q, want %q", skippedOnly, skipText)
	}
	both := formatRingbufDropWarning(ringbufDropResult{total: 4, delta: 2, skippedCounted: true, skipped: 5, skippedDelta: 3})
	if want := "Ring buffer full: 2 events dropped kernel-side (4 total this run) - consider a larger -mapSize; " + skipText; both != want {
		t.Errorf("both = %q, want %q", both, want)
	}
	if none := formatRingbufDropWarning(ringbufDropResult{total: 4, skippedCounted: true, skipped: 5}); none != "" {
		t.Errorf("nothing new = %q, want no warning", none)
	}
	if strings.Contains(skipText, "their events are missing") {
		t.Error("the warning claims the traced tasks' events are missing")
	}
}

// statsOf closes a loop that never ran and returns its statistics block.
func statsOf(el *eventLoop) string {
	el.done = make(chan struct{})
	close(el.done)
	return el.stats()
}

func TestStatsReportSkippedRunsApartFromRingDrops(t *testing.T) {
	programs := newScriptedPrograms(3)
	el := &eventLoop{}
	el.dropSrc = lossSourceOver(t, &ringbufDropSourceStub{totals: []uint64{4}}, programs, el.readDropStampClock)
	monitor := newRingbufDropMonitor(el.dropSrc)
	el.handleRingbufDropResult(monitor.Tick())
	if stats := statsOf(el); !strings.Contains(stats, "\tprobe runs skipped by the kernel: 0\n") {
		t.Errorf("no skipped run must read as a bare 0:\n%s", stats)
	}
	programs.skip(3, 6)
	el.handleRingbufDropResult(monitor.Tick())
	stats := statsOf(el)
	skippedLine := "\tprobe runs skipped by the kernel: 6 " +
		"(events may be missing; the count includes tasks outside the trace filter)\n"
	for _, want := range []string{"\tring buffer drops: 4 (", skippedLine} {
		if !strings.Contains(stats, want) {
			t.Errorf("stats lack %q:\n%s", want, stats)
		}
	}
	if ring := strings.Index(stats, "\tring buffer drops: "); ring > strings.Index(stats, "\tprobe runs skipped") {
		t.Errorf("the skipped-run line must follow the ring-buffer line:\n%s", stats)
	}
}

// A figure nobody read is not printed as 0: a source that does not count
// skipped runs says so, and a failed reading makes the line unknown.
func TestStatsNeverReportUncountedSkippedRunsAsZero(t *testing.T) {
	plain := &eventLoop{dropSrc: &ringbufDropSourceStub{}}
	plain.handleRingbufDropResult(newRingbufDropMonitor(plain.dropSrc).Tick())
	if stats := statsOf(plain); !strings.Contains(stats, "\tprobe runs skipped by the kernel: not counted\n") {
		t.Errorf("a source without skipped runs must say \"not counted\":\n%s", stats)
	}
	if stats := statsOf(&eventLoop{}); !strings.Contains(stats, "\tprobe runs skipped by the kernel: not counted\n") {
		t.Errorf("a run without a drop source must say \"not counted\":\n%s", stats)
	}

	programs := newScriptedPrograms(3)
	el := &eventLoop{}
	el.dropSrc = lossSourceOver(t, &ringbufDropSourceStub{}, programs, el.readDropStampClock)
	monitor := newRingbufDropMonitor(el.dropSrc)
	programs.err = errors.New("boom")
	el.handleRingbufDropResult(monitor.Tick())
	if stats := statsOf(el); !strings.Contains(stats, "\tprobe runs skipped by the kernel: unknown (counter unreadable)\n") {
		t.Errorf("an unreadable counter must say \"unknown\":\n%s", stats)
	}
	programs.err = nil
	programs.skip(3, 2)
	el.handleRingbufDropResult(monitor.Tick())
	programs.err = errors.New("boom")
	el.handleRingbufDropResult(monitor.Tick())
	want := "\tprobe runs skipped by the kernel: unknown (counter unreadable; 2 counted before the failure)\n"
	if stats := statsOf(el); !strings.Contains(stats, want) {
		t.Errorf("stats lack %q:\n%s", want, stats)
	}
}

// warningsOf wires a warning sink to el and returns what it collects.
func warningsOf(el *eventLoop) *[]string {
	var warnings []string
	el.warningCb = func(text string) { warnings = append(warnings, text) }
	return &warnings
}

// TestAFailedSkippedRunSweepLeavesTheRingBufferFiguresAlone: the programs
// could not be read while the ring-buffer counter could. The ring-buffer
// line states its figure, the warning names the counter that failed and no
// other, and the comm trust that leans on both counters is off until the
// sweep works again. The reverse failure leaves the skipped-run line alone.
func TestAFailedSkippedRunSweepLeavesTheRingBufferFiguresAlone(t *testing.T) {
	programs := newScriptedPrograms(3)
	el := &eventLoop{renameRecordsTrusted: true}
	warnings := warningsOf(el)
	var ringErr error
	el.dropSrc = lossSourceOver(t, ringbufDropSourceFunc(func() (uint64, error) { return 0, ringErr }),
		programs, el.readDropStampClock)
	monitor := newRingbufDropMonitor(el.dropSrc)
	programs.err = errors.New("boom")
	el.handleRingbufDropResult(monitor.Tick())
	stats := statsOf(el)
	if !strings.Contains(stats, "\tring buffer drops: 0 (") || el.ringbufDropReadFailed.Load() {
		t.Errorf("a failed sweep of the programs made the ring-buffer drops unknown:\n%s", stats)
	}
	if len(*warnings) != 1 || !strings.HasPrefix((*warnings)[0], "skipped probe run counter read failed: ") {
		t.Errorf("warnings = %q, want the skipped-run counter's alone", *warnings)
	}
	if !el.provisionalSeedNeedsRecheck(^uint64(0)) {
		t.Error("rename records are trusted although a skipped rename could not show up")
	}
	programs.err, ringErr = nil, errors.New("boom")
	el.handleRingbufDropResult(monitor.Tick())
	stats = statsOf(el)
	if !strings.Contains(stats, "\tring buffer drops: unknown (drop counter unreadable)\n") ||
		!strings.Contains(stats, "\tprobe runs skipped by the kernel: 0\n") {
		t.Errorf("a failed read of the ring counter must leave the skipped-run line alone:\n%s", stats)
	}
}

// TestSkippedRunsRequestTheCommSweep: a skipped run may have been a rename or
// exec record's, so a poll that finds new ones asks for the comm sweep and
// stamps it, as a poll that finds drops does; a seed recorded up to that
// stamp keeps its /proc read. A sweep that was not needed costs /proc reads
// only, which is why the weaker evidence is enough here.
func TestSkippedRunsRequestTheCommSweep(t *testing.T) {
	el := &eventLoop{renameRecordsTrusted: true, dropStampClock: func() uint64 { return 700 }}
	warningsOf(el)
	el.handleRingbufDropResult(ringbufDropResult{skippedCounted: true})
	if el.commRefreshPending.Load() || el.provisionalSeedNeedsRecheck(1) {
		t.Fatal("a poll without a skipped run asked for the comm sweep")
	}
	el.handleRingbufDropResult(ringbufDropResult{skippedCounted: true, skipped: 2, skippedDelta: 2})
	if !el.commRefreshPending.Load() || el.lastDropSeenBootNs.Load() != 700 {
		t.Fatalf("after 2 skipped runs: sweep pending = %v, stamp = %d, want a sweep stamped 700",
			el.commRefreshPending.Load(), el.lastDropSeenBootNs.Load())
	}
	if !el.provisionalSeedNeedsRecheck(700) || el.provisionalSeedNeedsRecheck(701) {
		t.Fatal("a seed recorded up to the stamp must keep its /proc read, and a later one must not")
	}
}

// skippedRunSetup replaces the four questions withSkippedRuns asks the
// system for one test.
func skippedRunSetup(t *testing.T, release string, programs *scriptedPrograms) {
	t.Helper()
	oldRelease, oldFDs, oldFDsOn, oldMisses := skippedRunKernelRelease, skippedRunProgramFDs, skippedRunProgramFDsOn, skippedRunProgramMisses
	t.Cleanup(func() {
		skippedRunKernelRelease, skippedRunProgramFDs, skippedRunProgramFDsOn, skippedRunProgramMisses = oldRelease, oldFDs, oldFDsOn, oldMisses
	})
	skippedRunKernelRelease = func() string { return release }
	skippedRunProgramFDs = func(*bpf.Module) []int { return programs.fds() }
	skippedRunProgramFDsOn = func(_ *bpf.Module, tracepoints []string) []int { return programs.fdsOn(tracepoints) }
	skippedRunProgramMisses = func() func(int) (uint64, bool, error) { return programs.read }
}

func TestWithSkippedRunsCountsThemWhereTheKernelDoes(t *testing.T) {
	ring := &ringbufDropSourceStub{totals: []uint64{2}}
	programs := newScriptedPrograms(3)
	skippedRunSetup(t, "6.7.0", programs)
	warned := 0
	source := withSkippedRuns(ring, nil, (&steppingClock{}).read, func(...any) { warned++ })
	programs.skip(3, 5)
	skipped, err := source.(skippedRunSource).SkippedRuns()
	if total, ringErr := source.Total(); ringErr != nil || err != nil || total != 2 || skipped != 5 || warned != 0 {
		t.Fatalf("Total = %d (%v), SkippedRuns = %d (%v) with %d warnings, want 2 drops, 5 skipped runs and none",
			total, ringErr, skipped, err, warned)
	}
	// The counter follows what is attached: a probe switched on later is
	// read by the next sweep.
	programs.attachOn(9, "sys_enter_read")
	programs.skip(9, 1)
	if skipped, err := source.(skippedRunSource).SkippedRuns(); err != nil || skipped != 6 {
		t.Fatalf("SkippedRuns after a probe was attached = %d, %v, want 6", skipped, err)
	}
	// A fold asks the module's programs on its tracepoints.
	programs.skip(9, 1)
	if skipped, _, err := source.(skippedRunSource).SkippedRunsSince([]string{"sys_enter_read"}, 0, ^uint64(0)); err != nil || !skipped {
		t.Fatalf("SkippedRunsSince(read's) = %v, %v, want the skip of program 9", skipped, err)
	}
}

// Before 6.7 a classic tracepoint program's skipped run is not counted, and a
// zero from such a kernel must not pass for "none": the ring counter is used
// alone, the programs are not even read, and nobody is warned about a run
// that is as good as that kernel allows.
func TestWithSkippedRunsLeavesAnOlderKernelsRingCounterAlone(t *testing.T) {
	ring := &ringbufDropSourceStub{totals: []uint64{2}}
	programs := newScriptedPrograms(3)
	skippedRunSetup(t, "6.6.99", programs)
	warned := 0
	source := withSkippedRuns(ring, nil, (&steppingClock{}).read, func(...any) { warned++ })
	if source != ringbufDropSource(ring) || programs.reads != 0 || warned != 0 {
		t.Fatalf("source = %T after %d program reads and %d warnings, want the ring counter itself, 0 and 0",
			source, programs.reads, warned)
	}
}

// A kernel that should count them and cannot be read is a degraded run: the
// ring counter alone, and a warning that says what goes unreported.
func TestWithSkippedRunsWarnsWhenTheCountCannotBeRead(t *testing.T) {
	ring := &ringbufDropSourceStub{totals: []uint64{2}}
	for name, breakIt := range map[string]func(*scriptedPrograms){
		"read fails":         func(p *scriptedPrograms) { p.err = errors.New("boom") },
		"field not reported": func(p *scriptedPrograms) { p.unreported = true },
	} {
		t.Run(name, func(t *testing.T) {
			programs := newScriptedPrograms(3)
			breakIt(programs)
			skippedRunSetup(t, "7.2.5", programs)
			var warned []any
			source := withSkippedRuns(ring, nil, (&steppingClock{}).read, func(args ...any) { warned = args })
			if source != ringbufDropSource(ring) || len(warned) != 2 {
				t.Fatalf("source = %T, warning %v, want the ring counter itself and one warning with its cause", source, warned)
			}
			if text, _ := warned[0].(string); !strings.Contains(text, "skipped by the kernel will not be counted") {
				t.Fatalf("warning = %q", text)
			}
		})
	}
}

// The seams withSkippedRuns asks are the real ones unless a test replaced
// them: the attached programs of the module, and a reader of its own.
func TestWithSkippedRunsAsksTheSeamForTheAttachedPrograms(t *testing.T) {
	if got, want := reflect.ValueOf(skippedRunProgramFDs).Pointer(), reflect.ValueOf(libbpfAttachedProgramFDs).Pointer(); got != want {
		t.Fatal("skippedRunProgramFDs is not libbpfAttachedProgramFDs")
	}
	if fds := libbpfAttachedProgramFDs(nil); fds != nil {
		t.Fatalf("libbpfAttachedProgramFDs(nil) = %v, want none", fds)
	}
	if got, want := reflect.ValueOf(skippedRunProgramFDsOn).Pointer(), reflect.ValueOf(libbpfAttachedProgramFDsOn).Pointer(); got != want {
		t.Fatal("skippedRunProgramFDsOn is not libbpfAttachedProgramFDsOn")
	}
	if _, _, err := skippedRunProgramMisses()(-1); !errors.Is(err, unix.EBADFD) {
		t.Fatalf("skippedRunProgramMisses does not read through bpf(2): err = %v", err)
	}
}
