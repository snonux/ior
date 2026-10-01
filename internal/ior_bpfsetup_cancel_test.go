package internal

import (
	"context"
	"errors"
	"sync"
	"testing"

	"ior/internal/probemanager"
	"ior/internal/runtime"
)

// recordingAttacher hands out one fresh link per AttachTracepoint call and
// remembers every link, so a test can check that everything attached was also
// destroyed. onAttach, when set, runs after each successful attach with the
// running attach count (sched probes included).
type recordingAttacher struct {
	mu       sync.Mutex
	links    []*fakeProbeLink
	onAttach func(count int)
}

type recordingProgram struct{ attacher *recordingAttacher }

func (a *recordingAttacher) GetProgram(string) (probemanager.Program, error) {
	return recordingProgram{attacher: a}, nil
}

func (p recordingProgram) AttachTracepoint(string, string) (probemanager.Link, error) {
	return p.attachLink()
}

// AttachRawTracepoint hands out a link like AttachTracepoint does: the rename
// probe is the one hand-written probe attached as a raw tracepoint, and it
// counts as a sched probe link (schedProbeLinks).
func (p recordingProgram) AttachRawTracepoint(string) (probemanager.Link, error) {
	return p.attachLink()
}

func (p recordingProgram) attachLink() (probemanager.Link, error) {
	a := p.attacher
	a.mu.Lock()
	link := &fakeProbeLink{}
	a.links = append(a.links, link)
	count := len(a.links)
	a.mu.Unlock()
	if a.onAttach != nil {
		a.onAttach(count)
	}
	return link, nil
}

// attached returns the number of links handed out and how many of them are
// still attached (never destroyed).
func (a *recordingAttacher) attached() (total, live int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, link := range a.links {
		if link.destroyCount() == 0 {
			live++
		}
	}
	return len(a.links), live
}

// schedProbeLinks is the number of links attachTraceProbes creates before the
// syscall walk: the sched_process_exec, sched_process_exit, task_newtask and
// task_rename probes.
const schedProbeLinks = 4

// TestAttachTraceProbesStopsAndDetachesWhenCancelledDuringAttach is the
// regression test for a restart during "Attaching tracepoints...": the old
// session used to finish the whole walk and then publish its probe manager
// over the new session's. Cancelling mid-walk must stop attaching further
// tracepoints, detach what was attached (syscall pairs and sched probes) and
// report the cancellation.
func TestAttachTraceProbesStopsAndDetachesWhenCancelledDuringAttach(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Cancel once the sched probes and the first syscall pair are attached.
	attacher := &recordingAttacher{onAttach: func(count int) {
		if count == schedProbeLinks+2 {
			cancel()
		}
	}}
	names := syscallPairNames("openat", "read", "write", "close", "fstat")

	mgr, release, err := attachTraceProbes(ctx, attacher, nil, names, bpfSetupLog{status: failOnLog(t)})

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("attachTraceProbes() error = %v, want context.Canceled", err)
	}
	if mgr != nil || release != nil {
		t.Fatal("a cancelled attach must not hand out a probe manager or release closure")
	}
	total, live := attacher.attached()
	if want := schedProbeLinks + 2; total != want {
		t.Fatalf("attached %d links, want %d: attaching must stop once the session is cancelled", total, want)
	}
	if live != 0 {
		t.Fatalf("%d links still attached after a cancelled setup, want all detached", live)
	}
}

// TestAttachTraceProbesCancelledBeforeWalkAttachesNoSyscallProbe covers the
// boundary where the session is cancelled before the syscall walk starts:
// no syscall tracepoint may be attached and the sched probes are released.
func TestAttachTraceProbesCancelledBeforeWalkAttachesNoSyscallProbe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	attacher := &recordingAttacher{}

	_, _, err := attachTraceProbes(ctx, attacher, nil, syscallPairNames("openat", "read"), bpfSetupLog{status: failOnLog(t)})

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("attachTraceProbes() error = %v, want context.Canceled", err)
	}
	if total, live := attacher.attached(); total != schedProbeLinks || live != 0 {
		t.Fatalf("attached %d links (%d live), want only the %d sched probes, all released", total, live, schedProbeLinks)
	}
}

// TestAttachTraceProbesAttachesEverythingWhenNotCancelled is the negative
// case: without cancellation the wrapper must not change what is attached,
// and must still honour the tracepoint selection.
func TestAttachTraceProbesAttachesEverythingWhenNotCancelled(t *testing.T) {
	attacher := &recordingAttacher{}
	onlyOpenatAndRead := func(name string) bool {
		return name == "sys_enter_openat" || name == "sys_exit_openat" ||
			name == "sys_enter_read" || name == "sys_exit_read"
	}

	mgr, release, err := attachTraceProbes(context.Background(), attacher, onlyOpenatAndRead,
		syscallPairNames("openat", "read", "write"), bpfSetupLog{status: failOnLog(t)})
	if err != nil {
		t.Fatalf("attachTraceProbes() error = %v", err)
	}
	if active, total := mgr.ActiveCount(); active != 2 || total != 3 {
		t.Fatalf("ActiveCount() = %d/%d, want 2/3", active, total)
	}
	if total, live := attacher.attached(); total != schedProbeLinks+4 || live != total {
		t.Fatalf("attached %d links (%d live), want %d all live", total, live, schedProbeLinks+4)
	}

	release()
	if err := mgr.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if _, live := attacher.attached(); live != 0 {
		t.Fatalf("%d links still attached after release and Close", live)
	}
}

// probePublisherRecorder records every SetProbeManager call.
type probePublisherRecorder struct {
	published []runtime.ProbeManager
}

func (r *probePublisherRecorder) SetProbeManager(manager runtime.ProbeManager) {
	r.published = append(r.published, manager)
}

// TestPublishProbeManagerPublishesAndClearsOnRelease pins the publish/clear
// pair trace setup performs through the session's publisher, and the
// headless (nil publisher) case, which must still release the sched probes.
func TestPublishProbeManagerPublishesAndClearsOnRelease(t *testing.T) {
	mgr := probemanager.NewManager(&recordingAttacher{})

	t.Run("tui", func(t *testing.T) {
		publisher := &probePublisherRecorder{}
		var schedReleases int
		release := publishProbeManager(publisher, mgr, func() { schedReleases++ })
		if len(publisher.published) != 1 || publisher.published[0] != runtime.ProbeManager(mgr) {
			t.Fatalf("published = %v, want the manager once", publisher.published)
		}
		release()
		if len(publisher.published) != 2 || publisher.published[1] != nil {
			t.Fatalf("published = %v, want the manager cleared on release", publisher.published)
		}
		if schedReleases != 1 {
			t.Fatalf("sched probe releases = %d, want 1", schedReleases)
		}
	})

	t.Run("headless", func(t *testing.T) {
		var schedReleases int
		release := publishProbeManager(nil, mgr, func() { schedReleases++ })
		release()
		if schedReleases != 1 {
			t.Fatalf("sched probe releases = %d, want 1", schedReleases)
		}
	})
}
