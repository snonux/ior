package internal

import (
	"context"
	"errors"
	"fmt"
	"sync"

	appconfig "ior/internal/config"
	"ior/internal/flags"
	"ior/internal/probemanager"
	"ior/internal/tracepoints"

	bpf "github.com/aquasecurity/libbpfgo"
)

// libbpfTracepointProgram wraps a libbpf BPF program as a probemanager.Program.
type libbpfTracepointProgram struct {
	prog *bpf.BPFProg
}

func (p libbpfTracepointProgram) AttachTracepoint(category, name string) (probemanager.Link, error) {
	return p.prog.AttachTracepoint(category, name)
}

// AttachRawTracepoint makes libbpfTracepointProgram a
// probemanager.RawTracepointProgram.
func (p libbpfTracepointProgram) AttachRawTracepoint(name string) (probemanager.Link, error) {
	return p.prog.AttachRawTracepoint(name)
}

// libbpfTracepointModule wraps a libbpf BPF module as a probemanager.Module.
type libbpfTracepointModule struct {
	module *bpf.Module
}

func (m libbpfTracepointModule) GetProgram(progName string) (probemanager.Program, error) {
	prog, err := m.module.GetProgram(progName)
	if err != nil {
		return nil, err
	}
	return libbpfTracepointProgram{prog: prog}, nil
}

func setupBPFModuleError(stage string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("setup BPF module: %s: %w", stage, err)
}

// bpfSetupLog routes the console output of BPF setup. Nothing in setup writes
// to the terminal directly: in TUI mode Bubble Tea owns it, and each trace
// restart re-runs this attach path while the dashboard is on screen.
//
// A nil sink falls back to stderr (see withDefaults), so a partially filled
// value can neither panic nor silently drop a message.
type bpfSetupLog struct {
	// status receives per-syscall attach diagnostics. It is the
	// mode-dependent logln: stderr in headless modes and a no-op in TUI mode,
	// where a skipped syscall probe keeps its lastErr in the probe manager and
	// States() surfaces it in the probe view instead. One line per missing
	// tracepoint is also too many to replay as TUI warning rows on every
	// trace start (dozens on an older kernel).
	status func(args ...any)
	// warn receives non-fatal degradations the user must see in every mode
	// (a sched probe that could not attach). Trace setup wires the
	// setupWarnings collector, which replays them as event-loop warnings.
	warn func(args ...any)
	// teardown receives detach failures of the sched probes. Like every other
	// teardown error it must stay visible in all modes (audit domain-10 F2),
	// so trace setup wires the always-on stderr logger here.
	teardown func(args ...any)
}

// withDefaults returns l with every nil sink replaced by the stderr logger.
func (l bpfSetupLog) withDefaults() bpfSetupLog {
	if l.status == nil {
		l.status = logStatus
	}
	if l.warn == nil {
		l.warn = logStatus
	}
	if l.teardown == nil {
		l.teardown = logStatus
	}
	return l
}

// setupBPFModule loads and attaches the BPF module, attaching tracepoints
// and handing the probe manager to probes, the TUI publisher of the session.
// A nil probes (headless modes) registers the manager nowhere.
//
// ctx is the trace session's parent context. Loading and attaching take
// seconds, and a TUI restart cancels the old session without waiting for it,
// so setup checks ctx between its stages and stops attaching the moment it is
// cancelled (see attachTraceProbes). A cancelled setup releases everything it
// built and returns an error wrapping ctx.Err(), so the caller can tell a
// requested stop (errors.Is(err, context.Canceled)) from a real failure. Most
// importantly it never publishes the probe manager: a session the user has
// already abandoned must not hand the TUI a manager that is about to close.
//
// Two checks keep a session from being silently empty: the -pid/-tid scope
// must name a process/thread that exists (reportTraceTarget) and at least one
// syscall probe must attach (attachRequiredTraceProbes). Both are errors when
// probes is nil (a headless run nobody can correct afterwards) and warnings in
// the TUI, where the user can still pick a target or enable probes.
func setupBPFModule(ctx context.Context, cfg flags.Config, probes probeManagerPublisher, log bpfSetupLog) (*bpf.Module, *probemanager.Manager, func(), error) {
	noRelease := func() {}
	log = log.withDefaults()
	if err := ctx.Err(); err != nil {
		return nil, nil, noRelease, setupBPFModuleError("start", err)
	}

	// An impossible -pid/-tid scope is reported before the slow load/attach so
	// a headless run fails at once instead of tracing nothing for -duration.
	if err := reportTraceTarget(cfg, probes == nil, log.warn); err != nil {
		return nil, nil, noRelease, err
	}

	bpfModule, stage, err := loadSessionBPFModule(cfg, log.warn)
	if err != nil {
		if bpfModule != nil {
			bpfModule.Close()
		}
		return nil, nil, noRelease, setupBPFModuleError(stage, err)
	}
	// Loading is the other slow stage; do not start attaching for a session
	// that was cancelled while it ran.
	if err := ctx.Err(); err != nil {
		bpfModule.Close()
		return nil, nil, noRelease, setupBPFModuleError("load", err)
	}

	mgr, release, err := attachSessionProbes(ctx, libbpfTracepointModule{module: bpfModule}, cfg, probes, log)
	if err != nil {
		bpfModule.Close()
		return nil, nil, noRelease, setupBPFModuleError("attach probes", err)
	}
	return bpfModule, mgr, release, nil
}

// loadSessionBPFModule is the BPF load stage of setupBPFModule. It is a
// variable only so tests can exercise the stages around the load (the target
// check before it, the attach stage after it) without root and a kernel.
var loadSessionBPFModule = loadConfiguredBPFModule

// attachSessionProbes is the attach stage of setupBPFModule: it attaches the
// session's probes through attacher and publishes the manager. The session is
// headless exactly when probes is nil (see probeManagerPublisher), which is
// what decides whether zero attached syscall probes is an error or a warning
// (attachRequiredTraceProbes).
func attachSessionProbes(ctx context.Context, attacher probemanager.Attacher, cfg flags.Config, probes probeManagerPublisher, log bpfSetupLog) (*probemanager.Manager, func(), error) {
	headless := probes == nil
	mgr, releaseSchedProbes, err := attachRequiredTraceProbes(ctx, attacher, cfg.TracepointSelector.ShouldAttach, tracepoints.List, headless, log)
	if err != nil {
		return nil, nil, err
	}
	return mgr, publishProbeManager(probes, mgr, releaseSchedProbes), nil
}

// loadConfiguredBPFModule opens the embedded BPF object, sizes its maps, sets
// its globals, loads it into the kernel and applies the sampling rates. warn
// receives non-fatal setup degradations (see setTidFilterTgid). On
// failure it returns the failed stage and, when the module was already opened,
// the module itself so the caller can close it (nil otherwise).
func loadConfiguredBPFModule(cfg flags.Config, warn func(args ...any)) (*bpf.Module, string, error) {
	bpfModule, stage, err := loadBPFModule()
	if err != nil {
		return nil, stage, err
	}
	if err := resizeBPFMaps(cfg, bpfModule); err != nil {
		return bpfModule, "resize maps", err
	}
	if err := setBPFGlobals(cfg, bpfModule, warn); err != nil {
		return bpfModule, "set globals", err
	}
	if err := bpfModule.BPFLoadObject(); err != nil {
		return bpfModule, "load object", err
	}
	if err := applySyscallSamplingRates(cfg, bpfModule); err != nil {
		return bpfModule, "configure sampling rates", err
	}
	return bpfModule, "", nil
}

// attachTraceProbes attaches the sched probes and then the syscall tracepoint
// pairs through attacher, and returns the probe manager together with the
// idempotent release closure of the sched probes.
//
// The sched probes go first. AttachAll walks hundreds of tracepoints and takes
// a noticeable amount of time, during which syscall records already flow from
// the ones attached first. Any task that execs in that window would otherwise
// produce syscall rows with no preceding comm record, which is exactly the
// stale/empty label the exec probe exists to prevent; the same goes for a task
// created in that window and the newtask probe, and a thread that renamed itself
// in that window and the rename probe. The exit probe has no ordering requirement
// but costs nothing to attach here.
//
// Cancellation: shouldAttach is wrapped so that once ctx is done every
// remaining tracepoint is skipped instead of attached, which ends the long
// AttachAll walk early. If ctx is done after the walk - whether it stopped
// early or not - everything attached so far is detached again (probe manager
// first, then the sched probes) and an error wrapping ctx.Err() is returned;
// a detach failure is folded into that error. It takes the Attacher seam, not
// a *bpf.Module, so all of this is testable without a live BPF module.
func attachTraceProbes(ctx context.Context, attacher probemanager.Attacher, shouldAttach func(string) bool, tpNames []string, log bpfSetupLog) (*probemanager.Manager, func(), error) {
	log = log.withDefaults()
	releaseExecProbe := attachProcessExecProbe(attacher, log)
	releaseExitProbe := attachProcessExitProbe(attacher, log)
	releaseNewtaskProbe := attachTaskNewtaskProbe(attacher, log)
	releaseRenameProbe := attachTaskRenameProbe(attacher, log)
	releaseSchedProbes := releaseConcurrently(releaseExecProbe, releaseExitProbe, releaseNewtaskProbe, releaseRenameProbe)

	attachUnlessCancelled := func(name string) bool {
		if ctx.Err() != nil {
			return false
		}
		return shouldAttach == nil || shouldAttach(name)
	}
	mgr, err := attachSyscallProbes(attacher, attachUnlessCancelled, tpNames, log.status)
	if err == nil && ctx.Err() != nil {
		err = ctx.Err()
		if closeErr := mgr.Close(); closeErr != nil {
			err = fmt.Errorf("%w (close probe manager: %v)", err, closeErr)
		}
	}
	if err != nil {
		releaseSchedProbes()
		return nil, nil, err
	}
	return mgr, releaseSchedProbes, nil
}

// attachRequiredTraceProbes is attachTraceProbes plus the guard against a
// session that attached no syscall probe at all (see requireAttachedProbes).
func attachRequiredTraceProbes(ctx context.Context, attacher probemanager.Attacher, shouldAttach func(string) bool, tpNames []string, headless bool, log bpfSetupLog) (*probemanager.Manager, func(), error) {
	log = log.withDefaults()
	mgr, releaseSchedProbes, err := attachTraceProbes(ctx, attacher, shouldAttach, tpNames, log)
	if err != nil {
		return nil, nil, err
	}
	return requireAttachedProbes(mgr, releaseSchedProbes, headless, log)
}

// requireAttachedProbes guards against a session that attached no syscall
// probe at all. Such a session - a -tps or -trace-* selection matching
// nothing, or every attach failing on the running kernel - used to run its
// whole -duration, print "Detaching 0 active BPF probe pairs" and exit 0 with
// an empty trace.
//
// What to do about it depends on whether anybody can still attach probes
// later. A headless run (headless == true) cannot, so zero probes is an error:
// the probe manager is closed and the sched probes are released again, and the
// caller aborts setup. In the TUI the probes modal can attach probes at
// runtime, and a user who switched every probe off before a restart
// legitimately ends up here, so it is only a warning row.
//
// Closing the manager on the error path detaches nothing today (a pair that
// fails to attach cleans up its own enter link, so a manager without an active
// probe holds no links) but marks it closed, so nothing can attach through a
// manager the caller no longer owns. It is kept so the error path stays
// correct should the manager ever retain links of inactive probes.
func requireAttachedProbes(mgr *probemanager.Manager, releaseSchedProbes func(), headless bool, log bpfSetupLog) (*probemanager.Manager, func(), error) {
	noProbes := noProbesError(mgr.States(), headless)
	if noProbes == nil {
		return mgr, releaseSchedProbes, nil
	}
	if !headless {
		log.warn("ior: " + noProbes.Error())
		return mgr, releaseSchedProbes, nil
	}
	if closeErr := mgr.Close(); closeErr != nil {
		noProbes = fmt.Errorf("%w (close probe manager: %v)", noProbes, closeErr)
	}
	releaseSchedProbes()
	return nil, nil, noProbes
}

// noProbesError returns the reason no syscall probe is active in states, or
// nil when at least one is. It separates the two causes because they call for
// different fixes: probes that were selected but failed to attach carry an
// Error (the kernel lacks the tracepoints), while a selection that matched
// nothing leaves every probe merely registered and inactive. For the second
// cause the text depends on the mode: headless, the startup flags are the only
// selection there is and the message names them; in the TUI the user may have
// emptied the selection in the probes modal, so the flags would be a false
// lead and the message points at the modal instead.
func noProbesError(states []probemanager.ProbeState, headless bool) error {
	failed := 0
	for _, state := range states {
		if state.Active {
			return nil
		}
		if state.Error != "" {
			failed++
		}
	}
	if failed > 0 {
		return fmt.Errorf("no syscall probe attached: all %d selected tracepoint pairs failed to attach (see the skipped-tracepoint messages)", failed)
	}
	if !headless {
		return errors.New("no syscall probe attached: no probes are enabled - enable some in the probes modal (o/O)")
	}
	return fmt.Errorf("no syscall probe attached: the -trace-*/-tps/-tpsExclude selection matches none of the %d traceable syscalls", len(states))
}

// releaseConcurrently returns a closure that runs every release in parallel and
// returns once all have finished. Each hand-attached tracepoint release closes
// a perf-event fd that waits for an RCU grace period (~30ms); grace periods
// only merge when the waits overlap, so running the sched/task probe releases
// one after another would pay for each of them.
func releaseConcurrently(releases ...func()) func() {
	return func() {
		var wg sync.WaitGroup
		for _, release := range releases {
			wg.Add(1)
			go func() {
				defer wg.Done()
				release()
			}()
		}
		wg.Wait()
	}
}

// publishProbeManager hands mgr to probes (the TUI probes modal) and returns
// the session's release closure: it clears the published manager again and
// detaches the sched probes. A nil probes (headless) publishes nothing and the
// release only detaches the sched probes.
//
// The clear is safe against overlapping sessions because in TUI mode probes is
// the session-scoped view of the TUI bindings (see the tui package's
// traceSessionBindings): once a newer session has begun, both this session's
// publish and its clear are dropped there, so a slow setup or teardown of an
// older session can neither replace nor erase the newer session's manager.
func publishProbeManager(probes probeManagerPublisher, mgr *probemanager.Manager, releaseSchedProbes func()) func() {
	if probes == nil {
		return releaseSchedProbes
	}
	probes.SetProbeManager(mgr)
	return func() {
		probes.SetProbeManager(nil)
		releaseSchedProbes()
	}
}

// attachSyscallProbes registers every syscall tracepoint pair with a new probe
// manager and attaches the ones shouldAttach selects.
//
// Per-syscall attach failures are non-fatal: on older kernels the tracepoint
// may be absent (e.g. binary built against a newer kernel). They are reported
// through logln (stderr when nil) and skipped; the affected probe stays in the
// manager with its lastErr set, so States() and the TUI surface the failure.
//
// The error branch is defensive: with a non-nil attach-error callback,
// AttachAll only fails on a nil manager, which NewManager never returns. It is
// kept so a future fatal AttachAll error still releases what was attached, and
// a failing Close is folded into the returned error rather than printed: the
// caller (in TUI mode the trace starter) is the one place that can surface it
// without writing over the dashboard.
func attachSyscallProbes(attacher probemanager.Attacher, shouldAttach func(string) bool, tpNames []string, logln func(args ...any)) (*probemanager.Manager, error) {
	if logln == nil {
		logln = logStatus
	}
	mgr := probemanager.NewManager(attacher)
	warn := func(syscall string, err error) {
		logln(fmt.Sprintf("ior: skipping tracepoint for %s: %v", syscall, err))
	}
	if err := mgr.AttachAll(shouldAttach, tpNames, warn); err != nil {
		if closeErr := mgr.Close(); closeErr != nil {
			return nil, fmt.Errorf("%w (close probe manager: %v)", err, closeErr)
		}
		return nil, err
	}
	return mgr, nil
}

// processExecProgName is the BPF program in internal/c/exec.c that reports the
// post-exec task comm.
const processExecProgName = "handle_sched_process_exec"

// processExitProgName is the BPF program in internal/c/exec.c that reports an
// exiting task's tgid, so the fdTracker can evict its per-(pid, fd) entries.
const processExitProgName = "handle_sched_process_exit"

// taskNewtaskProgName is the BPF program in internal/c/exec.c that reports a
// newly created task's inherited comm, so a new tid is named before its first
// syscall instead of after an asynchronous procfs lookup.
const taskNewtaskProgName = "handle_task_newtask"

// attachProcessExecProbe attaches sched:sched_process_exec, whose records keep
// the pid->comm cache correct across execve (see internal/c/exec.c and
// eventLoop.handleProcessExecEvent). It is not a syscall tracepoint, so it is
// outside the probemanager's enter/exit pair model and is attached directly
// here, for the whole run, independently of -trace-* selection.
func attachProcessExecProbe(attacher probemanager.Attacher, log bpfSetupLog) func() {
	return attachHandTracepoint(attacher, processExecProgName, "sched", "sched_process_exec", log)
}

// attachProcessExitProbe attaches sched:sched_process_exit, whose control
// records evict a dead process's fdTracker entries (see internal/c/exec.c and
// eventLoop.handleProcessExitEvent). Same attach policy as the exec probe:
// direct attach, whole run, independent of -trace-* selection.
func attachProcessExitProbe(attacher probemanager.Attacher, log bpfSetupLog) func() {
	return attachHandTracepoint(attacher, processExitProgName, "sched", "sched_process_exit", log)
}

// attachTaskNewtaskProbe attaches task:task_newtask, whose records name every
// new process and thread before its first syscall (see internal/c/exec.c and
// eventLoop.handleTaskNewtaskEvent). Same attach policy as the exec and exit
// probes: direct attach, whole run, independent of -trace-* selection. Without
// it comms of new tids fall back to the racy procfs lookup.
func attachTaskNewtaskProbe(attacher probemanager.Attacher, log bpfSetupLog) func() {
	return attachHandTracepoint(attacher, taskNewtaskProgName, "task", "task_newtask", log)
}

// taskRenameProgName is the BPF program in internal/c/exec.c that reports a
// task's new comm, so a thread that renames itself (prctl PR_SET_NAME,
// pthread_setname_np) is relabelled instead of keeping its old cached name.
const taskRenameProgName = "handle_task_rename"

// attachTaskRenameProbe attaches the task_rename raw tracepoint, whose records
// update a renamed task's cached comm (see internal/c/exec.c and
// eventLoop.handleTaskRenameEvent). Same attach policy as the exec, exit and
// newtask probes: direct attach, whole run, independent of -trace-* selection.
// Without it a renamed thread keeps its old name until another record corrects
// it. It attaches as a raw tracepoint (not a classic one) for the verifier
// reasons given in exec.c, which is why it has its own attach path.
func attachTaskRenameProbe(attacher probemanager.Attacher, log bpfSetupLog) func() {
	return attachHandProbe(attacher, taskRenameProgName, "task_rename", log,
		func(prog probemanager.Program) (probemanager.Link, error) {
			raw, ok := prog.(probemanager.RawTracepointProgram)
			if !ok {
				return nil, errors.New("program cannot attach as a raw tracepoint")
			}
			return raw.AttachRawTracepoint("task_rename")
		})
}

// attachHandTracepoint attaches one hand-written (non-syscall) tracepoint
// program from internal/c/exec.c, subsystem/tracepointName being the tracepoint
// it hooks (sched/sched_process_exec, task/task_newtask, ...). The policy is
// documented on attachHandProbe.
func attachHandTracepoint(attacher probemanager.Attacher, progName, subsystem, tracepointName string, log bpfSetupLog) func() {
	return attachHandProbe(attacher, progName, tracepointName, log,
		func(prog probemanager.Program) (probemanager.Link, error) {
			return prog.AttachTracepoint(subsystem, tracepointName)
		})
}

// attachHandProbe attaches one hand-written (non-syscall) BPF program from
// internal/c/exec.c through attach, which picks the attach flavor (classic
// tracepoint or raw tracepoint) for the tracepoint named probeName.
//
// Failure is deliberately non-fatal and mirrors the per-syscall attach policy:
// without the exec, newtask or rename probe comms fall back to the asynchronous
// procfs resolver (or keep an outdated name), and without the exit probe the fd
// table falls back to LRU eviction - all exactly the pre-fix behaviour:
// degraded, not a broken trace.
//
// It takes the same probemanager.Attacher seam the syscall probes use rather
// than a *bpf.Module, so both non-fatal failure paths and the detach path are
// reachable from tests without a live BPF module. The returned release closure
// is idempotent: attachTraceProbes calls it on a cancelled setup and
// publishProbeManager wraps it into the session's release closure, and a
// double Destroy on a libbpf link is not safe.
//
// A skipped probe is reported through log.warn, which trace setup replays as
// an event-loop warning (a TUI warning row, stderr headless); a detach failure
// goes to log.teardown, which stays visible in every mode.
func attachHandProbe(attacher probemanager.Attacher, progName, probeName string, log bpfSetupLog,
	attach func(probemanager.Program) (probemanager.Link, error)) func() {
	noop := func() {}
	if attacher == nil {
		return noop
	}
	log = log.withDefaults()
	prog, err := attacher.GetProgram(progName)
	if err != nil {
		log.warn(fmt.Sprintf("skipping %s probe: get program %s: %v", probeName, progName, err))
		return noop
	}
	link, err := attach(prog)
	if err != nil {
		log.warn(fmt.Sprintf("skipping %s probe: %v", probeName, err))
		return noop
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			if err := link.Destroy(); err != nil {
				log.teardown(fmt.Sprintf("ior: %s probe detach error: %v", probeName, err))
			}
		})
	}
}

// setupEventChannel initialises the BPF ring-buffer and returns both the event
// channel and the ring-buffer handle. The caller must call rb.Stop() when the
// trace ends (before bpfModule.Close()) to promptly halt the background polling
// goroutine and release the C ring_buffer struct. bpfModule.Close() also closes
// all ring buffers it owns, but only calling Stop() first ensures the goroutine
// exits without waiting for the module teardown path.
func setupEventChannel(bpfModule *bpf.Module) (chan []byte, *bpf.RingBuffer, error) {
	ch := make(chan []byte, appconfig.DefaultChannelBufferSize)
	rb, err := bpfModule.InitRingBuf("event_map", ch)
	if err != nil {
		return nil, nil, err
	}
	rb.Poll(300)
	return ch, rb, nil
}

// --- compile-time interface satisfaction assertions ---
//
// These blank-identifier assignments cause a build error if the libbpf wrapper
// types drift out of sync with the probemanager interfaces they satisfy.

var (
	// libbpfTracepointProgram wraps a *bpf.BPFProg as a probemanager.Program.
	_ probemanager.Program = (*libbpfTracepointProgram)(nil)

	// libbpfTracepointModule wraps a *bpf.Module as a probemanager.Attacher.
	_ probemanager.Attacher = (*libbpfTracepointModule)(nil)
)
