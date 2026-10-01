package internal

import (
	"syscall"
	"testing"

	"ior/internal/event"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

// The raw output modes (-plain, -flamegraph, headless -parquet) have no second
// filtering stage: whatever an exit handler returns true for is printed. The
// TUI has two further stages - shouldIngestTracePair on ingest and the Stream
// tab's own applyFilter - and all three now call the same predicate
// (MatchPair / Matches), whose file dimension is either-name-aware for the
// rename kinds (Candidate.OldFileValue), so all three agree by construction.
//
// Two kinds used to escape the pair filter entirely. handleOpenExit returned
// true unconditionally, relying on the raw enter filter MatchOpenEvent - but
// that only covers the comm and path dimensions. handleNameExit applied only
// the comm dimension, because its raw enter filter matches oldname-OR-newname while
// oldnameNewnameFile.Name() reports only the newname, so a plain MatchPair
// would have dropped every row a -path <oldname> filter legitimately selected.
// Either way -latency/-bytes/-ret/-fd/-family/-syscall and non-equality
// -pid/-tid reached those rows nowhere at all.
//
// The exit-side latency and bytes assertions below are only meaningful because
// the derived values are now computed before the exit handlers run
// (applyDerivedPairValues): the filter used to see Duration == 0 and
// Bytes == 0 for every kind, which turned -latency/-gap/-bytes into a
// compare-against-zero.

// openPairLatency is the synthetic enter->exit distance of the open and rename
// pairs fed below, in nanoseconds.
const openPairLatency = 100

// feedOpenPair drives one openat enter/exit pair through the raw event path and
// returns the emitted pair, or nil when the filter dropped it.
func feedOpenPair(t *testing.T, el *eventLoop, filename, comm string, ret int64) *event.Pair {
	t.Helper()

	enterEv := types.OpenEvent{
		EventType:     types.ENTER_OPEN_EVENT,
		TraceId:       types.SYS_ENTER_OPENAT,
		Time:          defaulTime,
		Pid:           execCommPid,
		Tid:           execCommTid,
		Flags:         syscall.O_RDONLY,
		SchemaVersion: types.OPEN_EVENT_SCHEMA_VERSION,
	}
	copy(enterEv.Filename[:], filename)
	copy(enterEv.Comm[:], comm)
	enterRaw, err := enterEv.Bytes()
	if err != nil {
		t.Fatalf("encode open enter event: %v", err)
	}
	exitEv := types.RetEvent{
		EventType: types.EXIT_OPEN_EVENT,
		TraceId:   types.SYS_EXIT_OPENAT,
		Time:      defaulTime + openPairLatency,
		Ret:       ret,
		Pid:       execCommPid,
		Tid:       execCommTid,
	}
	exitRaw, err := exitEv.Bytes()
	if err != nil {
		t.Fatalf("encode open exit event: %v", err)
	}

	out := make(chan *event.Pair, 1)
	el.processRawEvent(enterRaw, out)
	el.processRawEvent(exitRaw, out)
	select {
	case ep := <-out:
		return ep
	default:
		return nil
	}
}

// feedRenamePair drives one rename enter/exit pair through the raw event path
// and returns the emitted pair, or nil when the filter dropped it.
func feedRenamePair(t *testing.T, el *eventLoop, oldname, newname string, ret int64) *event.Pair {
	t.Helper()

	_, enterRaw := makeEnterNameEvent(t, defaulTime, execCommPid, execCommTid,
		oldname, newname, types.SYS_ENTER_RENAME)
	_, exitRaw := makeExitRetEvent(t, defaulTime+openPairLatency, execCommPid, execCommTid,
		types.SYS_EXIT_RENAME, ret)

	out := make(chan *event.Pair, 1)
	el.processRawEvent(enterRaw, out)
	el.processRawEvent(exitRaw, out)
	select {
	case ep := <-out:
		return ep
	default:
		return nil
	}
}

func newFilteredEventLoop(t *testing.T, filter globalfilter.Filter) *eventLoop {
	t.Helper()
	el := mustNewEventLoop(t, eventLoopConfig{
		filter:       filter,
		commResolver: newHermeticCommResolver(),
	})
	t.Cleanup(el.commResolver.shutdown)
	el.setCachedComm(execCommTid, "ioworkload")
	return el
}

func TestOpenKindsApplyEveryFilterDimension(t *testing.T) {
	const filename = "/tmp/open-filter.txt"
	const openedFd = 42

	t.Run("dropped by a -latency filter it does not satisfy", func(t *testing.T) {
		el := newFilteredEventLoop(t, globalfilter.Filter{
			LatencyNs: &globalfilter.NumericFilter{Op: globalfilter.OpGte, Value: openPairLatency + 1},
		})
		if ep := feedOpenPair(t, el, filename, "ioworkload", openedFd); ep != nil {
			defer ep.Recycle()
			t.Fatalf("open row with latency %d survived -latency >= %d: %v",
				ep.Duration, openPairLatency+1, ep)
		}
	})

	t.Run("survives a -latency filter it does satisfy", func(t *testing.T) {
		el := newFilteredEventLoop(t, globalfilter.Filter{
			LatencyNs: &globalfilter.NumericFilter{Op: globalfilter.OpGte, Value: openPairLatency},
		})
		ep := feedOpenPair(t, el, filename, "ioworkload", openedFd)
		if ep == nil {
			t.Fatal("open row matching -latency must still be emitted")
		}
		defer ep.Recycle()
		if ep.Duration != openPairLatency {
			t.Fatalf("open row duration = %d, want %d", ep.Duration, openPairLatency)
		}
		if ep.File == nil || ep.File.Name() != filename {
			t.Fatalf("open row file = %v, want %q", ep.File, filename)
		}
		if ep.Comm != "ioworkload" {
			t.Fatalf("open row comm = %q, want \"ioworkload\"", ep.Comm)
		}
	})

	t.Run("dropped by a -bytes filter it does not satisfy", func(t *testing.T) {
		// An openat exit is not a transfer, so the row carries zero bytes and
		// a "at least one byte" filter must exclude it.
		el := newFilteredEventLoop(t, globalfilter.Filter{
			Bytes: &globalfilter.NumericFilter{Op: globalfilter.OpGte, Value: 1},
		})
		if ep := feedOpenPair(t, el, filename, "ioworkload", openedFd); ep != nil {
			defer ep.Recycle()
			t.Fatalf("open row with %d bytes survived -bytes >= 1: %v", ep.Bytes, ep)
		}
	})

	t.Run("survives a -bytes filter it does satisfy", func(t *testing.T) {
		el := newFilteredEventLoop(t, globalfilter.Filter{
			Bytes: &globalfilter.NumericFilter{Op: globalfilter.OpLte, Value: 0},
		})
		ep := feedOpenPair(t, el, filename, "ioworkload", openedFd)
		if ep == nil {
			t.Fatal("open row matching -bytes <= 0 must still be emitted")
		}
		defer ep.Recycle()
		if ep.Bytes != 0 {
			t.Fatalf("open row bytes = %d, want 0", ep.Bytes)
		}
	})

	t.Run("dropped by a -ret filter it does not satisfy", func(t *testing.T) {
		el := newFilteredEventLoop(t, globalfilter.Filter{
			RetVal: &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: openedFd + 1},
		})
		if ep := feedOpenPair(t, el, filename, "ioworkload", openedFd); ep != nil {
			defer ep.Recycle()
			t.Fatalf("open row returning %d survived -ret == %d: %v", openedFd, openedFd+1, ep)
		}
	})

	t.Run("survives a -ret filter it does satisfy", func(t *testing.T) {
		el := newFilteredEventLoop(t, globalfilter.Filter{
			RetVal: &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: openedFd},
		})
		ep := feedOpenPair(t, el, filename, "ioworkload", openedFd)
		if ep == nil {
			t.Fatal("open row matching -ret must still be emitted")
		}
		ep.Recycle()
	})

	t.Run("dropped by errors-only when it succeeded", func(t *testing.T) {
		el := newFilteredEventLoop(t, globalfilter.Filter{ErrorsOnly: true})
		if ep := feedOpenPair(t, el, filename, "ioworkload", openedFd); ep != nil {
			defer ep.Recycle()
			t.Fatalf("successful open row survived -errors-only: %v", ep)
		}
	})

	t.Run("dropped by a non-equality -pid filter", func(t *testing.T) {
		// Equality pid/tid filters are pushed kernel-side, so a comparison
		// operator is the one that has to be honoured in userspace. The bound
		// is relative to the fixture pid, which lies above every real pid
		// (absentPidBase), so a fixed small bound would not exclude it.
		el := newFilteredEventLoop(t, globalfilter.Filter{
			PID: &globalfilter.NumericFilter{Op: globalfilter.OpGt, Value: execCommPid},
		})
		if ep := feedOpenPair(t, el, filename, "ioworkload", openedFd); ep != nil {
			defer ep.Recycle()
			t.Fatalf("open row of pid %d survived -pid > %d: %v", execCommPid, execCommPid, ep)
		}
	})

	t.Run("dropped by a -syscall filter naming another syscall", func(t *testing.T) {
		el := newFilteredEventLoop(t, globalfilter.Filter{
			Syscall: &globalfilter.StringFilter{Pattern: "^sys_enter_read$"},
		})
		if ep := feedOpenPair(t, el, filename, "ioworkload", openedFd); ep != nil {
			defer ep.Recycle()
			t.Fatalf("openat row survived a -syscall read filter: %v", ep)
		}
	})

	t.Run("failed open is dropped by a -fd filter it does not satisfy", func(t *testing.T) {
		// A failed open keeps its pathname but has no descriptor, so it
		// reports fd -1 and must not pass a "real descriptor" filter.
		el := newFilteredEventLoop(t, globalfilter.Filter{
			FD: &globalfilter.NumericFilter{Op: globalfilter.OpGte, Value: 0},
		})
		if ep := feedOpenPair(t, el, filename, "ioworkload", -int64(syscall.ENOENT)); ep != nil {
			defer ep.Recycle()
			t.Fatalf("failed open row survived -fd >= 0: %v", ep)
		}
	})
}

func TestNameKindsApplyEveryFilterDimension(t *testing.T) {
	const oldname = "/tmp/rename-old.txt"
	const newname = "/tmp/rename-new.txt"

	t.Run("dropped by a -latency filter it does not satisfy", func(t *testing.T) {
		el := newFilteredEventLoop(t, globalfilter.Filter{
			LatencyNs: &globalfilter.NumericFilter{Op: globalfilter.OpGte, Value: openPairLatency + 1},
		})
		if ep := feedRenamePair(t, el, oldname, newname, 0); ep != nil {
			defer ep.Recycle()
			t.Fatalf("rename row with latency %d survived -latency >= %d: %v",
				ep.Duration, openPairLatency+1, ep)
		}
	})

	t.Run("survives a -latency filter it does satisfy", func(t *testing.T) {
		el := newFilteredEventLoop(t, globalfilter.Filter{
			LatencyNs: &globalfilter.NumericFilter{Op: globalfilter.OpGte, Value: openPairLatency},
		})
		ep := feedRenamePair(t, el, oldname, newname, 0)
		if ep == nil {
			t.Fatal("rename row matching -latency must still be emitted")
		}
		defer ep.Recycle()
		if ep.Duration != openPairLatency {
			t.Fatalf("rename row duration = %d, want %d", ep.Duration, openPairLatency)
		}
		if ep.File == nil || ep.File.Name() != newname {
			t.Fatalf("rename row file = %v, want %q", ep.File, newname)
		}
		if ep.Oldname != oldname {
			t.Fatalf("rename row oldname = %q, want %q", ep.Oldname, oldname)
		}
	})

	t.Run("dropped by a -bytes filter it does not satisfy", func(t *testing.T) {
		el := newFilteredEventLoop(t, globalfilter.Filter{
			Bytes: &globalfilter.NumericFilter{Op: globalfilter.OpGte, Value: 1},
		})
		if ep := feedRenamePair(t, el, oldname, newname, 0); ep != nil {
			defer ep.Recycle()
			t.Fatalf("rename row with %d bytes survived -bytes >= 1: %v", ep.Bytes, ep)
		}
	})

	t.Run("dropped by a -ret filter it does not satisfy", func(t *testing.T) {
		el := newFilteredEventLoop(t, globalfilter.Filter{
			RetVal: &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: 0},
		})
		if ep := feedRenamePair(t, el, oldname, newname, -int64(syscall.ENOENT)); ep != nil {
			defer ep.Recycle()
			t.Fatalf("failed rename row survived -ret == 0: %v", ep)
		}
	})

	t.Run("survives a -ret filter it does satisfy", func(t *testing.T) {
		el := newFilteredEventLoop(t, globalfilter.Filter{
			RetVal: &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: 0},
		})
		ep := feedRenamePair(t, el, oldname, newname, 0)
		if ep == nil {
			t.Fatal("rename row matching -ret == 0 must still be emitted")
		}
		ep.Recycle()
	})

	t.Run("dropped by a non-equality -tid filter", func(t *testing.T) {
		el := newFilteredEventLoop(t, globalfilter.Filter{
			TID: &globalfilter.NumericFilter{Op: globalfilter.OpNeq, Value: execCommTid},
		})
		if ep := feedRenamePair(t, el, oldname, newname, 0); ep != nil {
			defer ep.Recycle()
			t.Fatalf("rename row of tid %d survived -tid != %d: %v", execCommTid, execCommTid, ep)
		}
	})

	// The three cases below are the reason the file dimension of MatchPair is
	// either-name-aware for the rename kinds (Candidate.OldFileValue): it has
	// to keep matching oldname-OR-newname, and only that dimension widens.
	t.Run("row matched on its OLD name survives the full pair filter", func(t *testing.T) {
		el := newFilteredEventLoop(t, globalfilter.Filter{
			File:      &globalfilter.StringFilter{Pattern: oldname},
			LatencyNs: &globalfilter.NumericFilter{Op: globalfilter.OpGte, Value: openPairLatency},
		})
		ep := feedRenamePair(t, el, oldname, newname, 0)
		if ep == nil {
			t.Fatalf("a rename matched on its oldname %q must still be emitted", oldname)
		}
		defer ep.Recycle()
		if ep.File == nil || ep.File.Name() != newname {
			t.Fatalf("rename row file = %v, want %q", ep.File, newname)
		}
		if ep.Oldname != oldname {
			t.Fatalf("rename row oldname = %q, want %q", ep.Oldname, oldname)
		}
	})

	t.Run("oldname match is not a bypass for the other dimensions", func(t *testing.T) {
		// Widening the file dimension must not turn into "an oldname hit
		// exempts the row from everything else".
		el := newFilteredEventLoop(t, globalfilter.Filter{
			File:      &globalfilter.StringFilter{Pattern: oldname},
			LatencyNs: &globalfilter.NumericFilter{Op: globalfilter.OpGte, Value: openPairLatency + 1},
		})
		if ep := feedRenamePair(t, el, oldname, newname, 0); ep != nil {
			defer ep.Recycle()
			t.Fatalf("rename matched on its oldname escaped -latency >= %d: %v",
				openPairLatency+1, ep)
		}
	})

	t.Run("row matched on its new name survives", func(t *testing.T) {
		el := newFilteredEventLoop(t, globalfilter.Filter{
			File: &globalfilter.StringFilter{Pattern: newname},
		})
		ep := feedRenamePair(t, el, oldname, newname, 0)
		if ep == nil {
			t.Fatalf("a rename matched on its newname %q must still be emitted", newname)
		}
		ep.Recycle()
	})
}

// TestDerivedPairValuesAreVisibleToTheFilter pins the ordering the two fixes
// above depend on. The pair filter runs inside the exit handlers, so latency,
// gap and byte counts must already be on the Pair by then; while they were
// computed afterwards, every -latency/-gap/-bytes comparison silently ran
// against zero and dropped rows that satisfied it - for every kind, not just
// the two this change routes through the filter.
func TestDerivedPairValuesAreVisibleToTheFilter(t *testing.T) {
	el := newFilteredEventLoop(t, globalfilter.Filter{
		LatencyNs: &globalfilter.NumericFilter{Op: globalfilter.OpGte, Value: openPairLatency},
	})

	out := make(chan *event.Pair, 1)
	_, enterRaw := makeEnterPathEvent(t, defaulTime, execCommPid, execCommTid,
		"/etc/ld.so.preload", types.SYS_ENTER_ACCESS)
	_, exitRaw := makeExitRetEvent(t, defaulTime+openPairLatency, execCommPid, execCommTid,
		types.SYS_EXIT_ACCESS, -2)
	el.processRawEvent(enterRaw, out)
	el.processRawEvent(exitRaw, out)

	select {
	case ep := <-out:
		defer ep.Recycle()
		if ep.Duration != openPairLatency {
			t.Fatalf("access row duration = %d, want %d", ep.Duration, openPairLatency)
		}
	default:
		t.Fatalf("an access row with latency %d was dropped by -latency >= %d",
			openPairLatency, openPairLatency)
	}
}

// TestFilteredPairDoesNotAdvanceTheGapBaseline pins the deliberate split
// between applyDerivedPairValues (before the exit handlers, so the filter sees
// real durations) and finalizeTracepointPair (after, so only an EMITTED pair
// advances the per-tid previous-exit timestamp).
//
// Without that split a row dropped by the filter would still move the
// baseline, and every later durationToPrevNs would be measured from a pair the
// user never saw. Moving setPrevTime into applyDerivedPairValues makes this
// test fail while the rest of the suite stays green.
func TestFilteredPairDoesNotAdvanceTheGapBaseline(t *testing.T) {
	const droppedFd = 7
	const keptFd = 42

	// -fd 42 drops the first open (fd 7) and keeps the second (fd 42).
	el := newFilteredEventLoop(t, globalfilter.Filter{
		FD: &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: keptFd},
	})

	if ep := feedOpenPair(t, el, "/tmp/dropped.txt", "ioworkload", droppedFd); ep != nil {
		defer ep.Recycle()
		t.Fatalf("open row with fd %d survived -fd == %d", droppedFd, keptFd)
	}

	// The second pair starts one full openPairLatency after the first one's
	// exit, so if the dropped pair had advanced the baseline the gap would be
	// measured from it instead of from the last emitted exit.
	enterEv := types.OpenEvent{
		EventType:     types.ENTER_OPEN_EVENT,
		TraceId:       types.SYS_ENTER_OPENAT,
		Time:          defaulTime + 2*openPairLatency,
		Pid:           execCommPid,
		Tid:           execCommTid,
		Flags:         syscall.O_RDONLY,
		SchemaVersion: types.OPEN_EVENT_SCHEMA_VERSION,
	}
	copy(enterEv.Filename[:], "/tmp/kept.txt")
	copy(enterEv.Comm[:], "ioworkload")
	enterRaw, err := enterEv.Bytes()
	if err != nil {
		t.Fatalf("encode open enter event: %v", err)
	}
	exitEv := types.RetEvent{
		EventType: types.EXIT_OPEN_EVENT,
		TraceId:   types.SYS_EXIT_OPENAT,
		Time:      defaulTime + 3*openPairLatency,
		Ret:       keptFd,
		Pid:       execCommPid,
		Tid:       execCommTid,
	}
	exitRaw, err := exitEv.Bytes()
	if err != nil {
		t.Fatalf("encode open exit event: %v", err)
	}

	out := make(chan *event.Pair, 1)
	el.processRawEvent(enterRaw, out)
	el.processRawEvent(exitRaw, out)

	select {
	case ep := <-out:
		defer ep.Recycle()
		// prevTime was never set (the only prior pair was filtered out), so
		// CalculateDurations reports a zero gap rather than one measured from
		// the dropped pair's exit at defaulTime+openPairLatency.
		if ep.DurationToPrev != 0 {
			t.Fatalf("gap = %d, want 0: a filtered-out pair must not advance the gap baseline",
				ep.DurationToPrev)
		}
	default:
		t.Fatalf("open row with fd %d must survive -fd == %d", keptFd, keptFd)
	}
}

// TestGapIsMeasuredFromTheLastEmittedPair is the stronger form of
// TestFilteredPairDoesNotAdvanceTheGapBaseline: emit A, drop B, emit C, and
// require C's gap to be measured from A's exit.
//
// The zero-gap assertion above is satisfied by any implementation that leaves
// no baseline at all — including a wrong one that CLEARS prevTime when a pair
// is dropped. Only a three-pair sequence distinguishes "measured from the last
// emitted pair" from "zero for some other reason".
func TestGapIsMeasuredFromTheLastEmittedPair(t *testing.T) {
	const droppedFd = 7
	const keptFd = 42

	el := newFilteredEventLoop(t, globalfilter.Filter{
		FD: &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: keptFd},
	})

	feedOpenAt := func(t *testing.T, enterTime uint64, fd int64) *event.Pair {
		t.Helper()
		enterEv := types.OpenEvent{
			EventType:     types.ENTER_OPEN_EVENT,
			TraceId:       types.SYS_ENTER_OPENAT,
			Time:          enterTime,
			Pid:           execCommPid,
			Tid:           execCommTid,
			Flags:         syscall.O_RDONLY,
			SchemaVersion: types.OPEN_EVENT_SCHEMA_VERSION,
		}
		copy(enterEv.Filename[:], "/tmp/gap.txt")
		copy(enterEv.Comm[:], "ioworkload")
		enterRaw, err := enterEv.Bytes()
		if err != nil {
			t.Fatalf("encode open enter event: %v", err)
		}
		exitEv := types.RetEvent{
			EventType: types.EXIT_OPEN_EVENT,
			TraceId:   types.SYS_EXIT_OPENAT,
			Time:      enterTime + openPairLatency,
			Ret:       fd,
			Pid:       execCommPid,
			Tid:       execCommTid,
		}
		exitRaw, err := exitEv.Bytes()
		if err != nil {
			t.Fatalf("encode open exit event: %v", err)
		}
		out := make(chan *event.Pair, 1)
		el.processRawEvent(enterRaw, out)
		el.processRawEvent(exitRaw, out)
		select {
		case ep := <-out:
			return ep
		default:
			return nil
		}
	}

	// A: emitted, exits at defaulTime+openPairLatency.
	epA := feedOpenAt(t, defaulTime, keptFd)
	if epA == nil {
		t.Fatal("pair A must be emitted")
	}
	epA.Recycle()

	// B: dropped by -fd, exits at defaulTime+3*openPairLatency.
	if ep := feedOpenAt(t, defaulTime+2*openPairLatency, droppedFd); ep != nil {
		defer ep.Recycle()
		t.Fatal("pair B must be dropped by the fd filter")
	}

	// C: emitted, enters at defaulTime+4*openPairLatency. Its gap must be
	// measured from A's exit, not from B's.
	epC := feedOpenAt(t, defaulTime+4*openPairLatency, keptFd)
	if epC == nil {
		t.Fatal("pair C must be emitted")
	}
	defer epC.Recycle()

	const wantFromA = 3 * openPairLatency // C.enter - A.exit
	const wrongFromB = openPairLatency    // C.enter - B.exit
	if epC.DurationToPrev == wrongFromB {
		t.Fatalf("gap = %d: measured from the DROPPED pair B, want %d (from the last emitted pair A)",
			epC.DurationToPrev, wantFromA)
	}
	if epC.DurationToPrev != wantFromA {
		t.Fatalf("gap = %d, want %d (C.enter - A.exit)", epC.DurationToPrev, wantFromA)
	}
}

// TestDroppedOpenStillRegistersTheFd pins that handleOpenExit updates the
// global fd table and the comm cache BEFORE applying the filter. That
// ordering only became load-bearing when handleOpenExit started dropping rows;
// if it regressed, every later read/write/close on a descriptor whose open was
// filtered away would lose its filename.
func TestDroppedOpenStillRegistersTheFd(t *testing.T) {
	const filename = "/tmp/registered.txt"
	const openedFd = 42
	const payloadComm = "renamed-proc"

	// A latency filter no open pair can satisfy: the row is dropped, but the
	// descriptor it opened must still be resolvable afterwards.
	el := newFilteredEventLoop(t, globalfilter.Filter{
		LatencyNs: &globalfilter.NumericFilter{Op: globalfilter.OpGte, Value: openPairLatency + 1},
	})

	if ep := feedOpenPair(t, el, filename, payloadComm, openedFd); ep != nil {
		defer ep.Recycle()
		t.Fatalf("open row survived a -latency filter it cannot satisfy: %v", ep)
	}

	resolved, ok := el.fdState().get(openedFd, execCommPid)
	if !ok || resolved == nil {
		t.Fatalf("fd %d was not registered because its open row was filtered out", openedFd)
	}
	if resolved.Name() != filename {
		t.Fatalf("fd %d resolved to %q, want %q", openedFd, resolved.Name(), filename)
	}

	// The comm cache is the other half of the same invariant: the payload comm
	// is authoritative and must retire the seeded value even when the row it
	// arrived on is dropped. newFilteredEventLoop seeds "ioworkload", so a
	// different payload comm proves the refresh happened before the filter.
	if got := el.comm(execCommTid); got != payloadComm {
		t.Fatalf("comm cache = %q, want %q: the payload comm must be applied before the filter",
			got, payloadComm)
	}
}
