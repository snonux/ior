package internal

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"ior/internal/event"
	"ior/internal/globalfilter"
)

// targetExitLoop builds an event loop armed the way runTraceLoop arms a
// headless -pid run, with stopTrace and the status sink recorded.
func targetExitLoop(t *testing.T, pid int, armed bool) (el *eventLoop, stops *int, status *[]string) {
	t.Helper()
	el = mustNewEventLoop(t, eventLoopConfig{
		pidFilter:    pid,
		filter:       globalfilter.Filter{},
		commResolver: newHermeticCommResolver(),
	})
	t.Cleanup(el.commResolver.shutdown)
	stops, status = new(int), new([]string)
	el.stopTrace = func() { *stops++ }
	el.statusCb = func(args ...any) {
		*status = append(*status, strings.TrimSpace(fmt.Sprintln(args...)))
	}
	el.stopOnTargetExit = armed
	return el, stops, status
}

// TestPidTargetGroupDeadExitStopsTheTrace is the vr2 fix: the whole-process
// death of the -pid target ends a headless trace, with one status line naming
// the pid.
func TestPidTargetGroupDeadExitStopsTheTrace(t *testing.T) {
	el, stops, status := targetExitLoop(t, int(crossPidA), true)
	out := make(chan *event.Pair, 1)

	el.processRawEvent(makeProcessExitEvent(t, defaulTime, crossPidA, crossTidA), out)

	if *stops != 1 {
		t.Fatalf("stopTrace called %d times after the target's group-dead exit, want 1", *stops)
	}
	if len(*status) != 1 || !strings.Contains((*status)[0], "exited, stopping the trace") {
		t.Fatalf("status lines = %q, want one 'exited, stopping the trace' line", *status)
	}
}

// TestTargetExitStopsTheTraceOnce covers the repeated group-dead records old
// kernels produce and a recycled pid dying later: the trace is cancelled and
// announced once.
func TestTargetExitStopsTheTraceOnce(t *testing.T) {
	el, stops, status := targetExitLoop(t, int(crossPidA), true)
	out := make(chan *event.Pair, 1)

	el.processRawEvent(makeProcessExitEvent(t, defaulTime, crossPidA, crossTidA), out)
	el.processRawEvent(makeProcessExitEvent(t, defaulTime+1_000, crossPidA, crossTidA+1), out)
	el.processRawEvent(makeProcessExitEvent(t, defaulTime+2*groupDeadDedupWindowNs, crossPidA, crossTidA), out)

	if *stops != 1 || len(*status) != 1 {
		t.Fatalf("stopTrace calls = %d, status lines = %d, want 1 and 1", *stops, len(*status))
	}
}

// TestTargetExitIgnoresEveryOtherExit is the negative test: only the
// whole-process death of the -pid target may end the trace. A thread exit of
// the target (siblings live), the legacy record with unknown group_dead, the
// death of another pid, and any death without -pid all keep it running.
func TestTargetExitIgnoresEveryOtherExit(t *testing.T) {
	tests := []struct {
		name  string
		pid   int
		armed bool
		raw   func(t *testing.T) []byte
	}{
		{"thread exit of the target", int(crossPidA), true, func(t *testing.T) []byte {
			return makeThreadExitEvent(t, defaulTime, crossPidA, crossTidA)
		}},
		{"legacy exit record of the target", int(crossPidA), true, func(t *testing.T) []byte {
			return makeThreadExitEvent(t, defaulTime, crossPidA, crossTidA)[:24]
		}},
		{"group-dead exit of another pid", int(crossPidA), true, func(t *testing.T) []byte {
			return makeProcessExitEvent(t, defaulTime, crossPidB, crossTidB)
		}},
		{"no -pid filter", -1, true, func(t *testing.T) []byte {
			return makeProcessExitEvent(t, defaulTime, crossPidA, crossTidA)
		}},
		{"not armed (TUI)", int(crossPidA), false, func(t *testing.T) []byte {
			return makeProcessExitEvent(t, defaulTime, crossPidA, crossTidA)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			el, stops, status := targetExitLoop(t, tt.pid, tt.armed)
			el.processRawEvent(tt.raw(t), make(chan *event.Pair, 1))
			if *stops != 0 || len(*status) != 0 {
				t.Fatalf("stopTrace calls = %d, status = %q, want none", *stops, *status)
			}
		})
	}
}

// runPidTraceLoop runs runTraceLoop over a -plain loop scoped to defaultPid
// and feeds it one syscall pair followed by the group-dead exit of that pid.
// It reports whether the loop ended by itself (nothing cancels the context)
// within wait, and the rows that reached stdout. The loop is cancelled before
// returning either way.
func runPidTraceLoop(t *testing.T, verbose bool, wait time.Duration) (ended bool, stdout string) {
	t.Helper()
	infra, rawCh, pipeR, _ := plainTraceInfra(t)
	infra.el.cfg.pidFilter = int(defaultPid)
	infra.el.SetStatusCallback(func(...any) {})

	finished := make(chan struct{})
	go func() {
		defer close(finished)
		runTraceLoop(infra, verbose, nil, func(...any) {})
	}()
	sendOpenPair(t, rawCh, defaulTime)
	rawCh <- makeProcessExitEvent(t, defaulTime+1_000, defaultPid, defaultTid)

	select {
	case <-finished:
		ended = true
	case <-time.After(wait):
		infra.cancel()
		<-finished
	}
	return ended, readPipeFor(t, pipeR, 200*time.Millisecond)
}

// TestHeadlessPidRunEndsWithItsTarget drives the real runTraceLoop wiring: a
// headless -pid run whose target dies ends by itself, and the rows the target
// produced before dying are still written.
func TestHeadlessPidRunEndsWithItsTarget(t *testing.T) {
	ended, stdout := runPidTraceLoop(t, true, 10*time.Second)
	if !ended {
		t.Fatal("the headless trace kept running after its -pid target exited")
	}
	if !strings.Contains(stdout, "openat") {
		t.Fatalf("the target's row before its exit was lost, stdout = %q", stdout)
	}
}

// TestInteractivePidRunSurvivesItsTarget is the negative wiring test: with
// verbose=false (the TUI) the target's death must not end the session.
func TestInteractivePidRunSurvivesItsTarget(t *testing.T) {
	if ended, _ := runPidTraceLoop(t, false, 500*time.Millisecond); ended {
		t.Fatal("a non-headless trace ended when its -pid target exited")
	}
}
