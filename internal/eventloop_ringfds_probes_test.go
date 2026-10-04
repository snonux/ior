package internal

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"ior/internal/event"
	"ior/internal/probemanager"
	"ior/internal/types"
)

func TestRegisteredRingProbeGaps(t *testing.T) {
	for _, wake := range []bool{false, true} {
		t.Run(map[bool]string{false: "raw-before-wake", true: "wake-before-raw"}[wake], func(t *testing.T) {
			f := newRingFeed(t)
			f.register(0, realRingFd)
			at := f.time + 500
			f.el.dropStampClock = func() uint64 { return at }
			change := func(phase probemanager.ChangePhase, attached bool) {
				f.el.probesChanged(probemanager.Change{Syscall: "io_uring_register", Phase: phase, Attached: attached})
				if wake {
					f.el.probeChangeNoticed(make(chan *event.Pair, 3))
				}
			}
			change(probemanager.Changed, false)
			wantIndexLabel(t, f.enter(0), 0)
			// Even a control record newer than detach cannot restore a table
			// while capture is off (e.g. a delayed, partial probe teardown).
			f.register(0, realRingFd)
			wantIndexLabel(t, f.enter(0), 0)
			change(probemanager.ChangeBegins, false)
			f.register(0, realRingFd)
			wantIndexLabel(t, f.enter(0), 0)
			at = f.time + 500
			change(probemanager.ChangeEnds, true)
			for _, stamp := range []uint64{at - 1, at} {
				f.raw(eventBytes(t, f.record(stamp, ringOpRegister, ringUpdate{0, uint64(realRingFd)})))
				wantIndexLabel(t, f.enter(0), 0)
			}
			f.register(0, secondRingFd)
			wantRing(t, f.enter(0), 0, secondRingFd, secondRingFd)
			// A begin alone must invalidate existing knowledge, and a failed
			// attachment must keep capture closed after its count comes down.
			change(probemanager.ChangeBegins, false)
			wantIndexLabel(t, f.enter(0), 0)
			change(probemanager.ChangeEnds, false)
			f.register(0, realRingFd)
			wantIndexLabel(t, f.enter(0), 0)
			change(probemanager.ChangeBegins, false)
			at = f.time + 500
			change(probemanager.ChangeEnds, true)
			f.register(0, secondRingFd)
			wantRing(t, f.enter(0), 0, secondRingFd, secondRingFd)
		})
	}
}

func TestRegisteredRingUnrelatedProbeChangesKeepMappings(t *testing.T) {
	f := newRingFeed(t)
	f.register(0, realRingFd)
	f.el.dropStampClock = func() uint64 { return f.time + 500 }
	for _, syscall := range []string{"read", "io_uring_enter", "restart_syscall"} {
		for _, phase := range []probemanager.ChangePhase{probemanager.Changed, probemanager.ChangeBegins, probemanager.ChangeEnds} {
			f.el.probesChanged(probemanager.Change{Syscall: syscall, Phase: phase, Attached: phase == probemanager.ChangeEnds})
			f.el.probeChangeNoticed(make(chan *event.Pair, 3))
			wantRing(t, f.enter(0), 0, realRingFd, realRingFd)
		}
	}
}

// The real select loop runs concurrently with the registered manager hook.
// Synchronizing on each emitted row keeps the assertions independent of which
// ready channel select chooses, without reading loop-owned tables from here.
func TestRunningLoopRegisteredRingProbeGaps(t *testing.T) {
	f := newRingFeed(t)
	f.register(0, realRingFd)
	var now atomic.Uint64
	now.Store(f.time + 500)
	f.el.dropStampClock = now.Load
	var hook func(probemanager.Change)
	f.el.watchProbeChanges(func(h func(probemanager.Change)) { hook = h }, func(string) bool { return true })
	rows := make(chan *event.Pair, 1)
	f.el.SetPrintCallback(func(ep *event.Pair) { rows <- ep })
	raw := make(chan []byte)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.el.run(ctx, raw)
	}()
	t.Cleanup(func() { cancel(); <-done })
	send := func(b []byte) {
		t.Helper()
		select {
		case raw <- b:
		case <-time.After(5 * time.Second):
			t.Fatal("loop did not consume record")
		}
	}
	enter := func(known bool) {
		t.Helper()
		f.time += 1000
		_, in := makeEnterIoUringEvent(t, f.time, f.pid, f.tid, types.SYS_ENTER_IO_URING_ENTER, 0, enterRegisteredRing)
		_, out := makeExitRetEvent(t, f.time+100, f.pid, f.tid, types.SYS_EXIT_IO_URING_ENTER, 0)
		send(in)
		send(out)
		select {
		case ep := <-rows:
			if known {
				wantRing(t, ep, 0, secondRingFd, secondRingFd)
			} else {
				wantIndexLabel(t, ep, 0)
			}
			ep.Recycle()
		case <-time.After(5 * time.Second):
			t.Fatal("loop did not emit enter row")
		}
	}
	register := func(stamp uint64) {
		send(eventBytes(t, f.record(stamp, ringOpRegister, ringUpdate{0, uint64(secondRingFd)})))
	}
	// Installing the hook fences any unreported earlier gap: the mapping
	// established before installation must already be unknown, and a queued
	// control record at the installation fence cannot restore it.
	enter(false)
	register(now.Load())
	enter(false)
	// Establish a mapping newer than hook installation.
	register(now.Load() + 1)
	enter(true)
	for i := 0; i < 20; i++ {
		now.Store(f.time + 500)
		hook(probemanager.Change{Syscall: "io_uring_register", Phase: probemanager.Changed})
		enter(false)
		hook(probemanager.Change{Syscall: "io_uring_register", Phase: probemanager.ChangeBegins})
		register(now.Load() + 1)
		enter(false)
		now.Store(f.time + 500)
		hook(probemanager.Change{Syscall: "io_uring_register", Phase: probemanager.ChangeEnds, Attached: true})
		register(now.Load() - 1)
		enter(false)
		register(f.time + 1)
		enter(true)
		hook(probemanager.Change{Syscall: "read", Phase: probemanager.Changed})
		enter(true)
	}
}
