package internal

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	bpf "github.com/aquasecurity/libbpfgo"
)

// Tests for the count of the program runs the kernel skipped (task 723):
// reading one program's recursion_misses, summing them over the loaded
// programs, and the sum's way into the drop monitor's results, its warning
// and the end-of-run statistics. What the restart folds and the exec
// adoption make of it is tested in eventloop_restart_skipped_test.go.

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
// descriptor that is not a BPF object is an error, never a zero count.
func TestProgRecursionMissesFailsOnADescriptorThatIsNoProgram(t *testing.T) {
	for _, fd := range []int{-1, 0} {
		if misses, reported, err := progRecursionMisses(fd); err == nil {
			t.Errorf("fd %d: got %d reported=%v without an error", fd, misses, reported)
		}
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

func TestSkippedRunCounterSumsEveryProgram(t *testing.T) {
	programs := newScriptedPrograms(3, 4, 5)
	clock := &steppingClock{}
	counter, err := newSkippedRunCounter(programs.fds(), programs.read, clock.read)
	if err != nil {
		t.Fatalf("newSkippedRunCounter: %v", err)
	}
	if programs.reads != 3 {
		t.Fatalf("the first sweep made %d reads, want one per program", programs.reads)
	}
	programs.skip(3, 2)
	programs.skip(5, 40)
	if total, err := counter.Total(); err != nil || total != 42 {
		t.Fatalf("Total = %d, %v, want 42", total, err)
	}
}

func TestSkippedRunCounterNeedsAKernelThatReports(t *testing.T) {
	if _, err := newSkippedRunCounter(nil, newScriptedPrograms().read, (&steppingClock{}).read); err == nil {
		t.Error("a counter over no programs was built: its zero would be read as \"none skipped\"")
	}
	programs := newScriptedPrograms(3)
	programs.unreported = true
	if _, err := newSkippedRunCounter(programs.fds(), programs.read, (&steppingClock{}).read); !errors.Is(err, errSkippedRunsNotReported) {
		t.Errorf("err = %v, want errSkippedRunsNotReported", err)
	}
	boom := errors.New("boom")
	programs = newScriptedPrograms(3)
	programs.err = boom
	if _, err := newSkippedRunCounter(programs.fds(), programs.read, (&steppingClock{}).read); !errors.Is(err, boom) {
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
	counter, err := newSkippedRunCounter(programs.fds(), programs.read, clock.read)
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
	if clock.now != sweptAt+1 {
		t.Fatalf("the clock was read %d times for two sweeps, want once each", clock.now-99)
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
	counter, err := newSkippedRunCounter(programs.fds(), read, clock.read)
	if err != nil {
		t.Fatalf("newSkippedRunCounter: %v", err)
	}
	swept := programs.reads
	if _, err := counter.TotalAsOf(readAt); err != nil || programs.reads == swept {
		t.Fatalf("a question about the time of the sweep's read was answered from that sweep (err %v)", err)
	}
}

// A sweep that failed leaves no sum to answer from: the next question reads
// again, also one about the past.
func TestSkippedRunCounterForgetsItsSweepWhenOneFails(t *testing.T) {
	programs := newScriptedPrograms(3)
	clock := &steppingClock{now: 99}
	counter, err := newSkippedRunCounter(programs.fds(), programs.read, clock.read)
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

// lossSourceOver builds the drop source of a kernel that counts skipped runs
// over a scripted ring counter and scripted programs.
func lossSourceOver(t *testing.T, ring ringbufDropSource, programs *scriptedPrograms, clock func() uint64) *recordLossSource {
	t.Helper()
	skipped, err := newSkippedRunCounter(programs.fds(), programs.read, clock)
	if err != nil {
		t.Fatalf("newSkippedRunCounter: %v", err)
	}
	return &recordLossSource{ring: ring, skipped: skipped}
}

func TestRecordLossSourceAddsSkippedRunsToRingDrops(t *testing.T) {
	ring := uint64(3)
	programs := newScriptedPrograms(3, 4)
	source := lossSourceOver(t, ringbufDropSourceFunc(func() (uint64, error) { return ring, nil }),
		programs, (&steppingClock{now: 99}).read)
	programs.skip(4, 10)
	if total, err := source.Total(); err != nil || total != 13 {
		t.Fatalf("Total = %d, %v, want 13", total, err)
	}
	if loss, err := source.Loss(); err != nil || loss != (recordLoss{ring: 3, skipped: 10}) {
		t.Fatalf("Loss = %+v, %v, want ring 3 and skipped 10", loss, err)
	}
	// The past is asked of the skipped runs only: the ring counter is read
	// anew, the programs are not.
	ring = 4
	programs.skip(3, 100)
	swept := programs.reads
	if total, err := source.TotalAsOf(0); err != nil || total != 14 || programs.reads != swept {
		t.Fatalf("TotalAsOf(0) = %d, %v after %d program reads, want 14 and none", total, err, programs.reads-swept)
	}
}

func TestRecordLossSourceFailsWhenEitherCounterDoes(t *testing.T) {
	boom := errors.New("boom")
	var ringErr error
	programs := newScriptedPrograms(3)
	source := lossSourceOver(t, ringbufDropSourceFunc(func() (uint64, error) { return 1, ringErr }),
		programs, (&steppingClock{}).read)
	ringErr = boom
	if _, err := source.Total(); !errors.Is(err, boom) {
		t.Errorf("Total with an unreadable ring counter: err = %v", err)
	}
	ringErr, programs.err = nil, boom
	if total, err := source.Total(); !errors.Is(err, boom) || total != 0 {
		t.Errorf("Total with unreadable programs = %d, %v, want 0 and the error", total, err)
	}
	if _, err := source.TotalAsOf(^uint64(0)); !errors.Is(err, boom) {
		t.Errorf("TotalAsOf with unreadable programs: err = %v", err)
	}
}

func TestDropMonitorSplitsItsDeltaIntoDropsAndSkippedRuns(t *testing.T) {
	ring := uint64(0)
	programs := newScriptedPrograms(3)
	monitor := newRingbufDropMonitor(lossSourceOver(t,
		ringbufDropSourceFunc(func() (uint64, error) { return ring, nil }), programs, (&steppingClock{}).read))
	if got := monitor.Tick(); got != (ringbufDropResult{}) {
		t.Fatalf("first tick = %+v, want all zero", got)
	}
	ring = 4
	programs.skip(3, 6)
	if got, want := monitor.Tick(), (ringbufDropResult{total: 10, delta: 10, skipped: 6, skippedDelta: 6}); got != want {
		t.Fatalf("tick = %+v, want %+v", got, want)
	}
	programs.skip(3, 1)
	if got, want := monitor.Tick(), (ringbufDropResult{total: 11, delta: 1, skipped: 7, skippedDelta: 1}); got != want {
		t.Fatalf("tick = %+v, want %+v", got, want)
	}
	// A plain source has no skipped share.
	plain := newRingbufDropMonitor(&ringbufDropSourceStub{totals: []uint64{5}})
	if got, want := plain.Tick(), (ringbufDropResult{total: 5, delta: 5}); got != want {
		t.Fatalf("plain tick = %+v, want %+v", got, want)
	}
}

func TestDropWarningNamesEachKindOfLoss(t *testing.T) {
	const ringText, skipText = "Ring buffer full: ", "Kernel skipped "
	ringOnly := formatRingbufDropWarning(ringbufDropResult{total: 9, delta: 4, skipped: 2})
	if want := "Ring buffer full: 4 events dropped kernel-side (7 total this run) - consider a larger -mapSize"; ringOnly != want {
		t.Errorf("ring only = %q, want %q", ringOnly, want)
	}
	skippedOnly := formatRingbufDropWarning(ringbufDropResult{total: 9, delta: 3, skipped: 5, skippedDelta: 3})
	if strings.Contains(skippedOnly, ringText) || strings.Contains(skippedOnly, "mapSize") ||
		!strings.HasPrefix(skippedOnly, "Kernel skipped 3 probe runs (5 total this run)") {
		t.Errorf("skipped only = %q", skippedOnly)
	}
	both := formatRingbufDropWarning(ringbufDropResult{total: 9, delta: 5, skipped: 5, skippedDelta: 3})
	if !strings.HasPrefix(both, "Ring buffer full: 2 events dropped kernel-side (4 total this run)") ||
		!strings.Contains(both, "; "+skipText+"3 probe runs (5 total this run)") {
		t.Errorf("both = %q", both)
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
	programs.skip(3, 6)
	el.handleRingbufDropResult(newRingbufDropMonitor(el.dropSrc).Tick())
	stats := statsOf(el)
	for _, want := range []string{"\tring buffer drops: 4 (", "\tprobe runs skipped by the kernel: 6\n"} {
		if !strings.Contains(stats, want) {
			t.Errorf("stats lack %q:\n%s", want, stats)
		}
	}
	if ring := strings.Index(stats, "\tring buffer drops: "); ring > strings.Index(stats, "\tprobe runs skipped") {
		t.Errorf("the skipped-run line must follow the ring-buffer line:\n%s", stats)
	}
}

// A figure nobody read is not printed as 0: a source that does not count
// skipped runs says so, and a failed reading makes both lines unknown.
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

// skippedRunSetup replaces the three questions withSkippedRuns asks the
// system for one test.
func skippedRunSetup(t *testing.T, release string, programs *scriptedPrograms) {
	t.Helper()
	oldRelease, oldFDs, oldMisses := skippedRunKernelRelease, skippedRunProgramFDs, skippedRunProgramMisses
	t.Cleanup(func() {
		skippedRunKernelRelease, skippedRunProgramFDs, skippedRunProgramMisses = oldRelease, oldFDs, oldMisses
	})
	skippedRunKernelRelease = func() string { return release }
	skippedRunProgramFDs = func(*bpf.Module) []int { return programs.fds() }
	skippedRunProgramMisses = programs.read
}

func TestWithSkippedRunsCountsThemWhereTheKernelDoes(t *testing.T) {
	ring := &ringbufDropSourceStub{totals: []uint64{2}}
	programs := newScriptedPrograms(3)
	skippedRunSetup(t, "6.7.0", programs)
	warned := 0
	source := withSkippedRuns(ring, nil, (&steppingClock{}).read, func(...any) { warned++ })
	programs.skip(3, 5)
	if total, err := source.Total(); err != nil || total != 7 || warned != 0 {
		t.Fatalf("Total = %d, %v with %d warnings, want 7 (2 drops and 5 skipped runs) and none", total, err, warned)
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
		"no programs":        func(p *scriptedPrograms) { p.misses = map[int]uint64{} },
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

func TestLibbpfProgramFDsOfNoModule(t *testing.T) {
	if fds := libbpfProgramFDs(nil); fds != nil {
		t.Fatalf("libbpfProgramFDs(nil) = %v, want none", fds)
	}
}
