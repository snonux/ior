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
// TUI does re-apply MatchPair in shouldIngestTracePair, which is why the gaps
// closed here were never visible on the dashboard.
//
// Two kinds used to escape the pair filter entirely. handleOpenExit returned
// true unconditionally, relying on the raw enter filter MatchOpenEvent - but
// that only covers the comm and path dimensions. handleNameExit applied only
// MatchComm, because its raw enter filter matches oldname-OR-newname while
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
		EventType: types.ENTER_OPEN_EVENT,
		TraceId:   types.SYS_ENTER_OPENAT,
		Time:      defaulTime,
		Pid:       execCommPid,
		Tid:       execCommTid,
		Flags:     syscall.O_RDONLY,
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
		// operator is the one that has to be honoured in userspace.
		el := newFilteredEventLoop(t, globalfilter.Filter{
			PID: &globalfilter.NumericFilter{Op: globalfilter.OpGt, Value: 99999},
		})
		if ep := feedOpenPair(t, el, filename, "ioworkload", openedFd); ep != nil {
			defer ep.Recycle()
			t.Fatalf("open row of pid %d survived -pid > 99999: %v", execCommPid, ep)
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

	// The three cases below are the reason the name kinds get
	// MatchPairEitherName rather than a plain MatchPair: the file dimension
	// has to keep matching oldname-OR-newname, and only the file dimension.
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
		EventType: types.ENTER_OPEN_EVENT,
		TraceId:   types.SYS_ENTER_OPENAT,
		Time:      defaulTime + 2*openPairLatency,
		Pid:       execCommPid,
		Tid:       execCommTid,
		Flags:     syscall.O_RDONLY,
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

// TestDroppedOpenStillRegistersTheFd pins that handleOpenExit updates the
// global fd table and the comm cache BEFORE applying the filter. That
// ordering only became load-bearing when handleOpenExit started dropping rows;
// if it regressed, every later read/write/close on a descriptor whose open was
// filtered away would lose its filename.
func TestDroppedOpenStillRegistersTheFd(t *testing.T) {
	const filename = "/tmp/registered.txt"
	const openedFd = 42

	// A latency filter no open pair can satisfy: the row is dropped, but the
	// descriptor it opened must still be resolvable afterwards.
	el := newFilteredEventLoop(t, globalfilter.Filter{
		LatencyNs: &globalfilter.NumericFilter{Op: globalfilter.OpGte, Value: openPairLatency + 1},
	})

	if ep := feedOpenPair(t, el, filename, "ioworkload", openedFd); ep != nil {
		defer ep.Recycle()
		t.Fatalf("open row survived a -latency filter it cannot satisfy: %v", ep)
	}

	resolved, ok := el.fdState().get(openedFd)
	if !ok || resolved == nil {
		t.Fatalf("fd %d was not registered because its open row was filtered out", openedFd)
	}
	if resolved.Name() != filename {
		t.Fatalf("fd %d resolved to %q, want %q", openedFd, resolved.Name(), filename)
	}
}
