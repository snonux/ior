package internal

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"

	"ior/internal/probemanager"
)

// The exec probe is attached outside the probemanager's enter/exit pair model,
// but through the same Attacher/Program/Link seam, so its non-fatal failure
// paths and its detach path are reachable without a live BPF module.

// fakeProbeLink counts Destroy calls. Destroy is goroutine-safe because the
// probemanager destroys a syscall's enter and exit links concurrently (see
// probemanager.destroyLinkPair) and detaches entries in parallel on Close, and
// these tests hand the same link to both sides of a pair; an unguarded counter
// is a data race under -race. Read the count through destroyCount. err is set
// before the link is shared and never written afterwards.
type fakeProbeLink struct {
	mu       sync.Mutex
	destroys int
	err      error
}

func (l *fakeProbeLink) Destroy() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.destroys++
	return l.err
}

// destroyCount returns how many times Destroy was called, synchronised with
// concurrent Destroy calls.
func (l *fakeProbeLink) destroyCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.destroys
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

// rawProbeProgram is a fakeProbeProgram that can also attach as a raw
// tracepoint, recording the tracepoint name it was asked for. The embedded
// program still records a classic attach, so a test can assert the rename
// probe never goes through that path.
type rawProbeProgram struct {
	fakeProbeProgram
	rawName string
}

func (p *rawProbeProgram) AttachRawTracepoint(name string) (probemanager.Link, error) {
	p.rawName = name
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
	_, stderr := captureConsole(t, fn)
	return stderr
}

// captureConsole runs fn with os.Stdout and os.Stderr redirected and returns
// what it wrote to each. Output must stay below the pipe buffer size, since
// the pipes are drained only after fn returns.
func captureConsole(t *testing.T, fn func()) (stdout, stderr string) {
	t.Helper()
	outR, errR, restore := captureStdoutStderr(t)
	fn()
	restore()
	var outBuf, errBuf bytes.Buffer
	_, _ = io.Copy(&outBuf, outR)
	_, _ = io.Copy(&errBuf, errR)
	return outBuf.String(), errBuf.String()
}

// setupLogRecorders records each bpfSetupLog sink separately, so a test can
// tell which sink a message used.
type setupLogRecorders struct {
	status, warn, teardown lineRecorder
}

func (r *setupLogRecorders) log() bpfSetupLog {
	return bpfSetupLog{status: r.status.log, warn: r.warn.log, teardown: r.teardown.log}
}

// requireOnlySink fails unless every recorded line went to want.
func (r *setupLogRecorders) requireOnlySink(t *testing.T, want *lineRecorder) {
	t.Helper()
	for name, sink := range map[string]*lineRecorder{"status": &r.status, "warn": &r.warn, "teardown": &r.teardown} {
		if sink != want && len(sink.lines()) != 0 {
			t.Fatalf("message reached the %s sink: %q", name, sink.lines())
		}
	}
}

// requireNoConsoleOutput fails when setup code wrote to the terminal
// directly instead of through its injected loggers.
func requireNoConsoleOutput(t *testing.T, stdout, stderr string) {
	t.Helper()
	if stdout != "" || stderr != "" {
		t.Fatalf("wrote to the console directly: stdout=%q stderr=%q", stdout, stderr)
	}
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

	release := attachProcessExecProbe(attacher, bpfSetupLog{status: failOnLog(t), warn: failOnLog(t), teardown: failOnLog(t)})

	if attacher.requested != processExecProgName {
		t.Fatalf("requested program %q, want %q", attacher.requested, processExecProgName)
	}
	if prog.category != "sched" || prog.name != "sched_process_exec" {
		t.Fatalf("attached %s:%s, want sched:sched_process_exec", prog.category, prog.name)
	}

	release()
	release()
	if link.destroyCount() != 1 {
		t.Fatalf("link destroyed %d times, want exactly 1", link.destroyCount())
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
			var rec setupLogRecorders
			var release func()
			stdout, stderr := captureConsole(t, func() {
				release = attachProcessExecProbe(tc.attacher, rec.log())
			})
			requireNoConsoleOutput(t, stdout, stderr)
			// A skipped sched probe is a degradation the user must see in
			// every mode, so it goes to the replayed warn sink - not to
			// status, which TUI mode silences.
			rec.requireOnlySink(t, &rec.warn)
			logged := rec.warn.joined()

			if release == nil {
				t.Fatal("expected a non-nil release closure even on failure")
			}
			// Must be safe to call, repeatedly, with nothing attached.
			release()
			release()

			if !strings.Contains(logged, "skipping sched_process_exec probe") {
				t.Fatalf("warn log = %q, want it to report the skipped probe", logged)
			}
			if !strings.Contains(logged, tc.wantLog) {
				t.Fatalf("warn log = %q, want it to contain %q", logged, tc.wantLog)
			}
		})
	}
}

// TestAttachProcessExecProbeReportsDetachErrors keeps the teardown path honest:
// a failing Destroy is reported rather than swallowed, and still counts as done.
func TestAttachProcessExecProbeReportsDetachErrors(t *testing.T) {
	link := &fakeProbeLink{err: errors.New("detach boom")}
	attacher := &fakeProbeAttacher{prog: &fakeProbeProgram{link: link}}

	var rec setupLogRecorders
	release := attachProcessExecProbe(attacher, rec.log())
	stdout, stderr := captureConsole(t, func() {
		release()
		release()
	})
	requireNoConsoleOutput(t, stdout, stderr)

	if link.destroyCount() != 1 {
		t.Fatalf("link destroyed %d times, want exactly 1", link.destroyCount())
	}
	// Teardown errors stay visible in every mode, so they must use the
	// always-on teardown sink, never the status sink that TUI mode silences.
	rec.requireOnlySink(t, &rec.teardown)
	if logged := rec.teardown.joined(); !strings.Contains(logged, "detach boom") {
		t.Fatalf("teardown log = %q, want it to report the detach error", logged)
	}
}

// TestAttachProcessExecProbeWithoutAttacher guards the nil guard: setup code
// must never panic on a missing module.
func TestAttachProcessExecProbeWithoutAttacher(t *testing.T) {
	release := attachProcessExecProbe(nil, bpfSetupLog{status: failOnLog(t), warn: failOnLog(t), teardown: failOnLog(t)})
	if release == nil {
		t.Fatal("expected a non-nil release closure")
	}
	release()
}

// TestAttachProcessExitProbeAttachesTheSchedTracepoint pins the exit probe's
// program and tracepoint the same way the exec probe tests above pin theirs:
// the fdTracker eviction depends on sched:sched_process_exit records, and the
// release closure must stay idempotent for the same double-handout reason.
func TestAttachProcessExitProbeAttachesTheSchedTracepoint(t *testing.T) {
	link := &fakeProbeLink{}
	prog := &fakeProbeProgram{link: link}
	attacher := &fakeProbeAttacher{prog: prog}

	release := attachProcessExitProbe(attacher, bpfSetupLog{status: failOnLog(t), warn: failOnLog(t), teardown: failOnLog(t)})

	if attacher.requested != processExitProgName {
		t.Fatalf("requested program %q, want %q", attacher.requested, processExitProgName)
	}
	if prog.category != "sched" || prog.name != "sched_process_exit" {
		t.Fatalf("attached %s:%s, want sched:sched_process_exit", prog.category, prog.name)
	}

	release()
	release()
	if link.destroyCount() != 1 {
		t.Fatalf("link destroyed %d times, want exactly 1", link.destroyCount())
	}
}

// TestAttachProcessExitProbeFailuresAreNonFatal mirrors the exec probe's
// policy: a missing program or tracepoint degrades to LRU-only fd-table
// eviction, never an aborted trace, and leaves a usable no-op release.
func TestAttachProcessExitProbeFailuresAreNonFatal(t *testing.T) {
	for _, tc := range []struct {
		name     string
		attacher *fakeProbeAttacher
		wantLog  string
	}{
		{
			name:     "program missing from the object",
			attacher: &fakeProbeAttacher{err: errors.New("no such program")},
			wantLog:  "get program " + processExitProgName,
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
			var rec setupLogRecorders
			var release func()
			stdout, stderr := captureConsole(t, func() {
				release = attachProcessExitProbe(tc.attacher, rec.log())
			})
			requireNoConsoleOutput(t, stdout, stderr)
			// A skipped sched probe is a degradation the user must see in
			// every mode, so it goes to the replayed warn sink - not to
			// status, which TUI mode silences.
			rec.requireOnlySink(t, &rec.warn)
			logged := rec.warn.joined()

			if release == nil {
				t.Fatal("expected a non-nil release closure even on failure")
			}
			release()
			release()

			if !strings.Contains(logged, "skipping sched_process_exit probe") {
				t.Fatalf("warn log = %q, want it to report the skipped probe", logged)
			}
			if !strings.Contains(logged, tc.wantLog) {
				t.Fatalf("warn log = %q, want it to contain %q", logged, tc.wantLog)
			}
		})
	}
}

// TestAttachTaskNewtaskProbeAttachesTheTaskTracepoint pins the newtask probe's
// program and its *task* (not sched) subsystem: attaching it under the wrong
// category would fail on every kernel and silently return to the racy procfs
// comm lookup it replaces. The release closure stays idempotent.
func TestAttachTaskNewtaskProbeAttachesTheTaskTracepoint(t *testing.T) {
	link := &fakeProbeLink{}
	prog := &fakeProbeProgram{link: link}
	attacher := &fakeProbeAttacher{prog: prog}

	release := attachTaskNewtaskProbe(attacher, bpfSetupLog{status: failOnLog(t), warn: failOnLog(t), teardown: failOnLog(t)})

	if attacher.requested != taskNewtaskProgName {
		t.Fatalf("requested program %q, want %q", attacher.requested, taskNewtaskProgName)
	}
	if prog.category != "task" || prog.name != "task_newtask" {
		t.Fatalf("attached %s:%s, want task:task_newtask", prog.category, prog.name)
	}

	release()
	release()
	if link.destroyCount() != 1 {
		t.Fatalf("link destroyed %d times, want exactly 1", link.destroyCount())
	}
}

// TestAttachTaskNewtaskProbeFailuresAreNonFatal: a missing program or
// tracepoint degrades to the asynchronous procfs comm lookup, is reported on
// the warn sink (visible in every mode) and leaves a usable no-op release.
func TestAttachTaskNewtaskProbeFailuresAreNonFatal(t *testing.T) {
	for _, tc := range []struct {
		name     string
		attacher *fakeProbeAttacher
		wantLog  string
	}{
		{
			name:     "program missing from the object",
			attacher: &fakeProbeAttacher{err: errors.New("no such program")},
			wantLog:  "get program " + taskNewtaskProgName,
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
			var rec setupLogRecorders
			release := attachTaskNewtaskProbe(tc.attacher, rec.log())
			rec.requireOnlySink(t, &rec.warn)
			logged := rec.warn.joined()
			if release == nil {
				t.Fatal("expected a non-nil release closure even on failure")
			}
			release()
			release()
			if !strings.Contains(logged, "skipping task_newtask probe") || !strings.Contains(logged, tc.wantLog) {
				t.Fatalf("warn log = %q, want the skipped probe and %q", logged, tc.wantLog)
			}
		})
	}
}

// TestAttachTaskRenameProbeAttachesTheRawTracepoint pins the rename probe's
// program and that it goes through the raw-tracepoint attach (the classic one
// is never used: the program's section is raw_tracepoint, and a classic attach
// of it fails on every kernel, silently returning to the stale-name behaviour).
// The release closure stays idempotent, and the attach is announced on the
// attached sink exactly once (trace setup trusts rename records from it, task
// xr2).
func TestAttachTaskRenameProbeAttachesTheRawTracepoint(t *testing.T) {
	link := &fakeProbeLink{}
	prog := &rawProbeProgram{fakeProbeProgram: fakeProbeProgram{link: link}}
	attacher := &fakeProbeAttacher{prog: prog}
	var announced []string

	release := attachTaskRenameProbe(attacher, bpfSetupLog{status: failOnLog(t), warn: failOnLog(t), teardown: failOnLog(t),
		attached: func(name string) { announced = append(announced, name) }})

	if len(announced) != 1 || announced[0] != taskRenameProbeName {
		t.Fatalf("attached announcements = %q, want exactly [%q]", announced, taskRenameProbeName)
	}
	if attacher.requested != taskRenameProgName {
		t.Fatalf("requested program %q, want %q", attacher.requested, taskRenameProgName)
	}
	if prog.rawName != "task_rename" {
		t.Fatalf("raw-attached %q, want task_rename", prog.rawName)
	}
	if prog.category != "" || prog.name != "" {
		t.Fatalf("classic attach used for %s:%s, want raw only", prog.category, prog.name)
	}

	release()
	release()
	if link.destroyCount() != 1 {
		t.Fatalf("link destroyed %d times, want exactly 1", link.destroyCount())
	}
}

// TestAttachTaskRenameProbeFailuresAreNonFatal: a missing program, a failing
// raw attach and a program that cannot attach as a raw tracepoint at all each
// degrade to serving the old cached name, are reported on the warn sink,
// leave a usable no-op release and are never announced as attached (which
// would make trace setup skip the corrective comm reads, task xr2).
func TestAttachTaskRenameProbeFailuresAreNonFatal(t *testing.T) {
	for _, tc := range []struct {
		name     string
		attacher *fakeProbeAttacher
		wantLog  string
	}{
		{
			name:     "program missing from the object",
			attacher: &fakeProbeAttacher{err: errors.New("no such program")},
			wantLog:  "get program " + taskRenameProgName,
		},
		{
			name: "raw tracepoint missing on this kernel",
			attacher: &fakeProbeAttacher{
				prog: &rawProbeProgram{fakeProbeProgram: fakeProbeProgram{err: errors.New("no such tracepoint")}},
			},
			wantLog: "no such tracepoint",
		},
		{
			name:     "program without raw attach support",
			attacher: &fakeProbeAttacher{prog: &fakeProbeProgram{link: &fakeProbeLink{}}},
			wantLog:  "cannot attach as a raw tracepoint",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var rec setupLogRecorders
			log := rec.log()
			log.attached = func(name string) { t.Errorf("failed attach announced as attached: %q", name) }
			release := attachTaskRenameProbe(tc.attacher, log)
			rec.requireOnlySink(t, &rec.warn)
			logged := rec.warn.joined()
			if release == nil {
				t.Fatal("expected a non-nil release closure even on failure")
			}
			release()
			release()
			if !strings.Contains(logged, "skipping task_rename probe") || !strings.Contains(logged, tc.wantLog) {
				t.Fatalf("warn log = %q, want the skipped probe and %q", logged, tc.wantLog)
			}
		})
	}
}

// TestAttachRestartFoldProbesAttachTheirTracepoints pins the two probes of
// the restart fold (task 103): each asks for its own program, attaches it as
// a classic tracepoint to the right event - the rt_sigreturn one to the
// syscall's enter tracepoint, under a probe name of its own - announces the
// attach exactly once under that name (trace setup turns the fold on from the
// signal_deliver announcement) and has an idempotent release.
func TestAttachRestartFoldProbesAttachTheirTracepoints(t *testing.T) {
	for _, tc := range []struct {
		name                              string
		attach                            func(probemanager.Attacher, bpfSetupLog) func()
		progName, probeName, category, tp string
	}{
		{"signal_deliver", attachSignalDeliverProbe, signalDeliverProgName, signalDeliverProbeName,
			"signal", "signal_deliver"},
		{"rt_sigreturn", attachRestartSigreturnProbe, restartSigreturnProgName, restartSigreturnProbeName,
			"syscalls", "sys_enter_rt_sigreturn"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			link := &fakeProbeLink{}
			prog := &fakeProbeProgram{link: link}
			attacher := &fakeProbeAttacher{prog: prog}
			var announced []string

			release := tc.attach(attacher, bpfSetupLog{status: failOnLog(t), warn: failOnLog(t), teardown: failOnLog(t),
				attached: func(name string) { announced = append(announced, name) }})

			if len(announced) != 1 || announced[0] != tc.probeName {
				t.Fatalf("attached announcements = %q, want exactly [%q]", announced, tc.probeName)
			}
			if attacher.requested != tc.progName {
				t.Fatalf("requested program %q, want %q", attacher.requested, tc.progName)
			}
			if prog.category != tc.category || prog.name != tc.tp {
				t.Fatalf("attached to %s:%s, want %s:%s", prog.category, prog.name, tc.category, tc.tp)
			}
			release()
			release()
			if link.destroyCount() != 1 {
				t.Fatalf("link destroyed %d times, want exactly 1", link.destroyCount())
			}
		})
	}
}

// TestAttachRestartFoldProbeFailuresAreNonFatal: a missing program (an older
// IOR_BPF_OBJECT) or a failing attach (a kernel without the tracepoint)
// leaves kernel-restarted calls unfolded, is reported on the warn sink,
// leaves a usable no-op release and is never announced as attached - an
// announcement of the signal probe would turn the fold on without its proof.
func TestAttachRestartFoldProbeFailuresAreNonFatal(t *testing.T) {
	attachers := map[string]func() (*fakeProbeAttacher, string){
		"program missing from the object": func() (*fakeProbeAttacher, string) {
			return &fakeProbeAttacher{err: errors.New("no such program")}, "get program "
		},
		"tracepoint missing on this kernel": func() (*fakeProbeAttacher, string) {
			return &fakeProbeAttacher{prog: &fakeProbeProgram{err: errors.New("no such tracepoint")}}, "no such tracepoint"
		},
	}
	probes := map[string]func(probemanager.Attacher, bpfSetupLog) func(){
		signalDeliverProbeName:    attachSignalDeliverProbe,
		restartSigreturnProbeName: attachRestartSigreturnProbe,
	}
	for probeName, attach := range probes {
		for name, build := range attachers {
			t.Run(probeName+"/"+name, func(t *testing.T) {
				attacher, wantLog := build()
				var rec setupLogRecorders
				log := rec.log()
				log.attached = func(name string) { t.Errorf("failed attach announced as attached: %q", name) }
				release := attach(attacher, log)
				rec.requireOnlySink(t, &rec.warn)
				logged := rec.warn.joined()
				if release == nil {
					t.Fatal("expected a non-nil release closure even on failure")
				}
				release()
				release()
				if !strings.Contains(logged, "skipping "+probeName+" probe") || !strings.Contains(logged, wantLog) {
					t.Fatalf("warn log = %q, want the skipped probe and %q", logged, wantLog)
				}
			})
		}
	}
}
