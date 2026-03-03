package benchutil

import (
	"syscall"
	"testing"

	"ior/internal/types"
)

func TestEventGeneratorEventMethodsRoundTrip(t *testing.T) {
	gen := NewEventGenerator()

	const (
		time uint64 = 1000
		pid  uint32 = 42
		tid  uint32 = 84
	)

	t.Run("EnterOpenEvent", func(t *testing.T) {
		want, raw := gen.EnterOpenEvent(time, pid, tid)
		got := types.NewOpenEvent(raw)
		defer got.Recycle()
		if !want.Equals(got) {
			t.Fatalf("EnterOpenEvent mismatch: want=%v got=%v", want, got)
		}
	})

	t.Run("ExitOpenEvent", func(t *testing.T) {
		want, raw := gen.ExitOpenEvent(time, pid, tid)
		got := types.NewRetEvent(raw)
		defer got.Recycle()
		if !want.Equals(got) {
			t.Fatalf("ExitOpenEvent mismatch: want=%v got=%v", want, got)
		}
	})

	t.Run("EnterFdEvent", func(t *testing.T) {
		want, raw := gen.EnterFdEvent(time, pid, tid, 11, types.SYS_ENTER_READ)
		got := types.NewFdEvent(raw)
		defer got.Recycle()
		if !want.Equals(got) {
			t.Fatalf("EnterFdEvent mismatch: want=%v got=%v", want, got)
		}
	})

	t.Run("ExitFdEvent", func(t *testing.T) {
		want, raw := gen.ExitFdEvent(time, pid, tid, 11, types.SYS_EXIT_CLOSE)
		got := types.NewFdEvent(raw)
		defer got.Recycle()
		if !want.Equals(got) {
			t.Fatalf("ExitFdEvent mismatch: want=%v got=%v", want, got)
		}
	})

	t.Run("EnterNullEvent", func(t *testing.T) {
		want, raw := gen.EnterNullEvent(time, pid, tid, types.SYS_ENTER_SYNC)
		got := types.NewNullEvent(raw)
		defer got.Recycle()
		if !want.Equals(got) {
			t.Fatalf("EnterNullEvent mismatch: want=%v got=%v", want, got)
		}
	})

	t.Run("ExitNullEvent", func(t *testing.T) {
		want, raw := gen.ExitNullEvent(time, pid, tid, types.SYS_EXIT_SYNC)
		got := types.NewNullEvent(raw)
		defer got.Recycle()
		if !want.Equals(got) {
			t.Fatalf("ExitNullEvent mismatch: want=%v got=%v", want, got)
		}
	})

	t.Run("ExitRetEvent", func(t *testing.T) {
		want, raw := gen.ExitRetEvent(time, pid, tid, types.SYS_EXIT_READ, 256)
		got := types.NewRetEvent(raw)
		defer got.Recycle()
		if !want.Equals(got) {
			t.Fatalf("ExitRetEvent mismatch: want=%v got=%v", want, got)
		}
		if got.RetType != types.READ_CLASSIFIED {
			t.Fatalf("ExitRetEvent RetType = %d, want %d", got.RetType, types.READ_CLASSIFIED)
		}
	})

	t.Run("EnterPathEvent", func(t *testing.T) {
		want, raw := gen.EnterPathEvent(time, pid, tid, "/tmp/path", types.SYS_ENTER_MKDIR)
		got := types.NewPathEvent(raw)
		defer got.Recycle()
		if !want.Equals(got) {
			t.Fatalf("EnterPathEvent mismatch: want=%v got=%v", want, got)
		}
	})

	t.Run("EnterNameEvent", func(t *testing.T) {
		want, raw := gen.EnterNameEvent(time, pid, tid, "/tmp/old", "/tmp/new", types.SYS_ENTER_RENAME)
		got := types.NewNameEvent(raw)
		defer got.Recycle()
		if !want.Equals(got) {
			t.Fatalf("EnterNameEvent mismatch: want=%v got=%v", want, got)
		}
	})

	t.Run("EnterFcntlEvent", func(t *testing.T) {
		want, raw := gen.EnterFcntlEvent(time, pid, tid, 33, syscall.F_SETFL, syscall.O_NONBLOCK)
		got := types.NewFcntlEvent(raw)
		defer got.Recycle()
		if !want.Equals(got) {
			t.Fatalf("EnterFcntlEvent mismatch: want=%v got=%v", want, got)
		}
	})

	t.Run("EnterDup3Event", func(t *testing.T) {
		want, raw := gen.EnterDup3Event(time, pid, tid, 44, syscall.O_CLOEXEC)
		got := types.NewDup3Event(raw)
		defer got.Recycle()
		if !want.Equals(got) {
			t.Fatalf("EnterDup3Event mismatch: want=%v got=%v", want, got)
		}
	})

	t.Run("EnterOpenByHandleAtEvent", func(t *testing.T) {
		want, raw := gen.EnterOpenByHandleAtEvent(time, pid, tid, syscall.O_RDONLY)
		got := types.NewOpenByHandleAtEvent(raw)
		defer got.Recycle()
		if !want.Equals(got) {
			t.Fatalf("EnterOpenByHandleAtEvent mismatch: want=%v got=%v", want, got)
		}
	})
}

func TestEventGeneratorPairMethods(t *testing.T) {
	gen := NewEventGenerator()

	const (
		start uint64 = 5000
		pid   uint32 = 77
		tid   uint32 = 88
	)

	t.Run("OpenPair", func(t *testing.T) {
		enterRaw, exitRaw := gen.OpenPair(start, pid, tid)
		enter := types.NewOpenEvent(enterRaw)
		defer enter.Recycle()
		exit := types.NewRetEvent(exitRaw)
		defer exit.Recycle()

		assertPairTimingAndIdentity(t, start, pid, tid, enter.Time, enter.Pid, enter.Tid, exit.Time, exit.Pid, exit.Tid, gen.pairDelta())
		if enter.TraceId != types.SYS_ENTER_OPENAT || exit.TraceId != types.SYS_EXIT_OPENAT {
			t.Fatalf("OpenPair trace IDs mismatch: enter=%v exit=%v", enter.TraceId, exit.TraceId)
		}
	})

	t.Run("FdPair", func(t *testing.T) {
		enterRaw, exitRaw := gen.FdPair(start, pid, tid, 9, types.SYS_ENTER_READ, types.SYS_EXIT_READ, 128)
		enter := types.NewFdEvent(enterRaw)
		defer enter.Recycle()
		exit := types.NewRetEvent(exitRaw)
		defer exit.Recycle()

		assertPairTimingAndIdentity(t, start, pid, tid, enter.Time, enter.Pid, enter.Tid, exit.Time, exit.Pid, exit.Tid, gen.pairDelta())
		if enter.TraceId != types.SYS_ENTER_READ || exit.TraceId != types.SYS_EXIT_READ {
			t.Fatalf("FdPair trace IDs mismatch: enter=%v exit=%v", enter.TraceId, exit.TraceId)
		}
		if exit.Ret != 128 {
			t.Fatalf("FdPair ret = %d, want %d", exit.Ret, 128)
		}
	})

	t.Run("NullPair", func(t *testing.T) {
		enterRaw, exitRaw := gen.NullPair(start, pid, tid, types.SYS_ENTER_SYNC, types.SYS_EXIT_SYNC)
		enter := types.NewNullEvent(enterRaw)
		defer enter.Recycle()
		exit := types.NewNullEvent(exitRaw)
		defer exit.Recycle()

		assertPairTimingAndIdentity(t, start, pid, tid, enter.Time, enter.Pid, enter.Tid, exit.Time, exit.Pid, exit.Tid, gen.pairDelta())
		if enter.TraceId != types.SYS_ENTER_SYNC || exit.TraceId != types.SYS_EXIT_SYNC {
			t.Fatalf("NullPair trace IDs mismatch: enter=%v exit=%v", enter.TraceId, exit.TraceId)
		}
	})

	t.Run("PathPair", func(t *testing.T) {
		enterRaw, exitRaw := gen.PathPair(start, pid, tid, "/tmp/p", types.SYS_ENTER_MKDIR, types.SYS_EXIT_MKDIR, 0)
		enter := types.NewPathEvent(enterRaw)
		defer enter.Recycle()
		exit := types.NewRetEvent(exitRaw)
		defer exit.Recycle()

		assertPairTimingAndIdentity(t, start, pid, tid, enter.Time, enter.Pid, enter.Tid, exit.Time, exit.Pid, exit.Tid, gen.pairDelta())
		if enter.TraceId != types.SYS_ENTER_MKDIR || exit.TraceId != types.SYS_EXIT_MKDIR {
			t.Fatalf("PathPair trace IDs mismatch: enter=%v exit=%v", enter.TraceId, exit.TraceId)
		}
	})

	t.Run("NamePair", func(t *testing.T) {
		enterRaw, exitRaw := gen.NamePair(start, pid, tid, "old", "new", types.SYS_ENTER_RENAME, types.SYS_EXIT_RENAME, 0)
		enter := types.NewNameEvent(enterRaw)
		defer enter.Recycle()
		exit := types.NewRetEvent(exitRaw)
		defer exit.Recycle()

		assertPairTimingAndIdentity(t, start, pid, tid, enter.Time, enter.Pid, enter.Tid, exit.Time, exit.Pid, exit.Tid, gen.pairDelta())
		if enter.TraceId != types.SYS_ENTER_RENAME || exit.TraceId != types.SYS_EXIT_RENAME {
			t.Fatalf("NamePair trace IDs mismatch: enter=%v exit=%v", enter.TraceId, exit.TraceId)
		}
	})

	t.Run("FcntlPair", func(t *testing.T) {
		enterRaw, exitRaw := gen.FcntlPair(start, pid, tid, 5, syscall.F_SETFL, syscall.O_NONBLOCK, types.SYS_EXIT_FCNTL, 0)
		enter := types.NewFcntlEvent(enterRaw)
		defer enter.Recycle()
		exit := types.NewRetEvent(exitRaw)
		defer exit.Recycle()

		assertPairTimingAndIdentity(t, start, pid, tid, enter.Time, enter.Pid, enter.Tid, exit.Time, exit.Pid, exit.Tid, gen.pairDelta())
		if enter.TraceId != types.SYS_ENTER_FCNTL || exit.TraceId != types.SYS_EXIT_FCNTL {
			t.Fatalf("FcntlPair trace IDs mismatch: enter=%v exit=%v", enter.TraceId, exit.TraceId)
		}
	})

	t.Run("Dup3Pair", func(t *testing.T) {
		enterRaw, exitRaw := gen.Dup3Pair(start, pid, tid, 8, syscall.O_CLOEXEC, types.SYS_EXIT_DUP3, 9)
		enter := types.NewDup3Event(enterRaw)
		defer enter.Recycle()
		exit := types.NewRetEvent(exitRaw)
		defer exit.Recycle()

		assertPairTimingAndIdentity(t, start, pid, tid, enter.Time, enter.Pid, enter.Tid, exit.Time, exit.Pid, exit.Tid, gen.pairDelta())
		if enter.TraceId != types.SYS_ENTER_DUP3 || exit.TraceId != types.SYS_EXIT_DUP3 {
			t.Fatalf("Dup3Pair trace IDs mismatch: enter=%v exit=%v", enter.TraceId, exit.TraceId)
		}
	})
}

func TestEventGeneratorPairDeltaDefaultAndCustom(t *testing.T) {
	const (
		start uint64 = 10
		pid   uint32 = 1
		tid   uint32 = 2
	)

	t.Run("default", func(t *testing.T) {
		gen := EventGenerator{}
		enterRaw, exitRaw := gen.OpenPair(start, pid, tid)
		enter := types.NewOpenEvent(enterRaw)
		defer enter.Recycle()
		exit := types.NewRetEvent(exitRaw)
		defer exit.Recycle()
		if got, want := exit.Time-enter.Time, uint64(defaultPairDelta); got != want {
			t.Fatalf("default pair delta = %d, want %d", got, want)
		}
	})

	t.Run("custom", func(t *testing.T) {
		const customDelta uint64 = 7
		gen := EventGenerator{PairDelta: customDelta}
		enterRaw, exitRaw := gen.OpenPair(start, pid, tid)
		enter := types.NewOpenEvent(enterRaw)
		defer enter.Recycle()
		exit := types.NewRetEvent(exitRaw)
		defer exit.Recycle()
		if got := exit.Time - enter.Time; got != customDelta {
			t.Fatalf("custom pair delta = %d, want %d", got, customDelta)
		}
	})
}

func assertPairTimingAndIdentity(t *testing.T, start uint64, pid, tid uint32, enterTime uint64, enterPid, enterTid uint32, exitTime uint64, exitPid, exitTid uint32, delta uint64) {
	t.Helper()
	if enterTime != start {
		t.Fatalf("enter time = %d, want %d", enterTime, start)
	}
	if enterPid != pid || enterTid != tid {
		t.Fatalf("enter identity mismatch: pid/tid = %d/%d, want %d/%d", enterPid, enterTid, pid, tid)
	}
	if exitTime != start+delta {
		t.Fatalf("exit time = %d, want %d", exitTime, start+delta)
	}
	if exitPid != pid || exitTid != tid {
		t.Fatalf("exit identity mismatch: pid/tid = %d/%d, want %d/%d", exitPid, exitTid, pid, tid)
	}
}
