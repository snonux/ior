package internal

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"ior/internal/probemanager"
)

// The exec probe is attached outside the probemanager's enter/exit pair model,
// but through the same Attacher/Program/Link seam, so its non-fatal failure
// paths and its detach path are reachable without a live BPF module.

type fakeProbeLink struct {
	destroys int
	err      error
}

func (l *fakeProbeLink) Destroy() error {
	l.destroys++
	return l.err
}

type fakeProbeProgram struct {
	link     probemanager.Link
	err      error
	category string
	name     string
}

func (p *fakeProbeProgram) AttachTracepoint(category, name string) (probemanager.Link, error) {
	p.category, p.name = category, name
	if p.err != nil {
		return nil, p.err
	}
	return p.link, nil
}

type fakeProbeAttacher struct {
	prog      probemanager.Program
	err       error
	requested string
}

func (a *fakeProbeAttacher) GetProgram(name string) (probemanager.Program, error) {
	a.requested = name
	if a.err != nil {
		return nil, a.err
	}
	return a.prog, nil
}

// captureStderr runs fn with os.Stderr redirected and returns what it wrote.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	_, stderr, restore := captureStdoutStderr(t)
	fn()
	restore()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, stderr)
	return buf.String()
}

// TestAttachProcessExecProbeAttachesTheSchedTracepoint pins the exact program
// and tracepoint the comm fix depends on, and the idempotence of the returned
// release closure: setupBPFModule hands that closure out both directly and
// wrapped inside releaseBindings, and destroying a libbpf link twice is not
// safe.
func TestAttachProcessExecProbeAttachesTheSchedTracepoint(t *testing.T) {
	link := &fakeProbeLink{}
	prog := &fakeProbeProgram{link: link}
	attacher := &fakeProbeAttacher{prog: prog}

	release := attachProcessExecProbe(attacher)

	if attacher.requested != processExecProgName {
		t.Fatalf("requested program %q, want %q", attacher.requested, processExecProgName)
	}
	if prog.category != "sched" || prog.name != "sched_process_exec" {
		t.Fatalf("attached %s:%s, want sched:sched_process_exec", prog.category, prog.name)
	}

	release()
	release()
	if link.destroys != 1 {
		t.Fatalf("link destroyed %d times, want exactly 1", link.destroys)
	}
}

// TestAttachProcessExecProbeFailuresAreNonFatal covers both skip paths. A
// missing program or a kernel without the tracepoint must degrade to
// procfs-only comm labelling, not abort the trace, and must leave a usable
// (no-op) release closure behind.
func TestAttachProcessExecProbeFailuresAreNonFatal(t *testing.T) {
	for _, tc := range []struct {
		name     string
		attacher *fakeProbeAttacher
		wantLog  string
	}{
		{
			name:     "program missing from the object",
			attacher: &fakeProbeAttacher{err: errors.New("no such program")},
			wantLog:  "get program " + processExecProgName,
		},
		{
			name: "tracepoint missing on this kernel",
			attacher: &fakeProbeAttacher{
				prog: &fakeProbeProgram{err: errors.New("no such tracepoint")},
			},
			wantLog: "no such tracepoint",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var release func()
			logged := captureStderr(t, func() {
				release = attachProcessExecProbe(tc.attacher)
			})

			if release == nil {
				t.Fatal("expected a non-nil release closure even on failure")
			}
			// Must be safe to call, repeatedly, with nothing attached.
			release()
			release()

			if !strings.Contains(logged, "skipping sched_process_exec probe") {
				t.Fatalf("stderr = %q, want it to report the skipped probe", logged)
			}
			if !strings.Contains(logged, tc.wantLog) {
				t.Fatalf("stderr = %q, want it to contain %q", logged, tc.wantLog)
			}
		})
	}
}

// TestAttachProcessExecProbeReportsDetachErrors keeps the teardown path honest:
// a failing Destroy is reported rather than swallowed, and still counts as done.
func TestAttachProcessExecProbeReportsDetachErrors(t *testing.T) {
	link := &fakeProbeLink{err: errors.New("detach boom")}
	attacher := &fakeProbeAttacher{prog: &fakeProbeProgram{link: link}}

	release := attachProcessExecProbe(attacher)
	logged := captureStderr(t, func() {
		release()
		release()
	})

	if link.destroys != 1 {
		t.Fatalf("link destroyed %d times, want exactly 1", link.destroys)
	}
	if !strings.Contains(logged, "detach boom") {
		t.Fatalf("stderr = %q, want it to report the detach error", logged)
	}
}

// TestAttachProcessExecProbeWithoutAttacher guards the nil guard: setup code
// must never panic on a missing module.
func TestAttachProcessExecProbeWithoutAttacher(t *testing.T) {
	release := attachProcessExecProbe(nil)
	if release == nil {
		t.Fatal("expected a non-nil release closure")
	}
	release()
}
