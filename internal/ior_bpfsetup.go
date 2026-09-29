package internal

import (
	"context"
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
func setupBPFModule(ctx context.Context, cfg flags.Config, probes probeManagerPublisher, log bpfSetupLog) (*bpf.Module, *probemanager.Manager, func(), error) {
	noRelease := func() {}
	log = log.withDefaults()
	if err := ctx.Err(); err != nil {
		return nil, nil, noRelease, setupBPFModuleError("start", err)
	}

	bpfModule, stage, err := loadConfiguredBPFModule(cfg)
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

	attacher := libbpfTracepointModule{module: bpfModule}
	mgr, releaseSchedProbes, err := attachTraceProbes(ctx, attacher, cfg.TracepointSelector.ShouldAttach, tracepoints.List, log)
	if err != nil {
		bpfModule.Close()
		return nil, nil, noRelease, setupBPFModuleError("attach probes", err)
	}
	return bpfModule, mgr, publishProbeManager(probes, mgr, releaseSchedProbes), nil
}

// loadConfiguredBPFModule opens the embedded BPF object, sizes its maps, sets
// its globals, loads it into the kernel and applies the sampling rates. On
// failure it returns the failed stage and, when the module was already opened,
// the module itself so the caller can close it (nil otherwise).
func loadConfiguredBPFModule(cfg flags.Config) (*bpf.Module, string, error) {
	bpfModule, stage, err := loadBPFModule()
	if err != nil {
		return nil, stage, err
	}
	if err := resizeBPFMaps(cfg, bpfModule); err != nil {
		return bpfModule, "resize maps", err
	}
	if err := setBPFGlobals(cfg, bpfModule); err != nil {
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
// stale/empty label the exec probe exists to prevent. The exit probe has no
// ordering requirement but costs nothing to attach here.
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
	releaseSchedProbes := func() {
		releaseExecProbe()
		releaseExitProbe()
	}

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

// attachProcessExecProbe attaches sched:sched_process_exec, whose records keep
// the pid->comm cache correct across execve (see internal/c/exec.c and
// eventLoop.handleProcessExecEvent). It is not a syscall tracepoint, so it is
// outside the probemanager's enter/exit pair model and is attached directly
// here, for the whole run, independently of -trace-* selection.
func attachProcessExecProbe(attacher probemanager.Attacher, log bpfSetupLog) func() {
	return attachSchedProbe(attacher, processExecProgName, "sched_process_exec", log)
}

// attachProcessExitProbe attaches sched:sched_process_exit, whose control
// records evict a dead process's fdTracker entries (see internal/c/exec.c and
// eventLoop.handleProcessExitEvent). Same attach policy as the exec probe:
// direct attach, whole run, independent of -trace-* selection.
func attachProcessExitProbe(attacher probemanager.Attacher, log bpfSetupLog) func() {
	return attachSchedProbe(attacher, processExitProgName, "sched_process_exit", log)
}

// attachSchedProbe attaches one hand-written sched tracepoint program from
// internal/c/exec.c.
//
// Failure is deliberately non-fatal and mirrors the per-syscall attach policy:
// without the exec probe comms fall back to the asynchronous procfs resolver,
// and without the exit probe the fd table falls back to LRU eviction - both
// are exactly the pre-fix behaviour: degraded, not a broken trace.
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
func attachSchedProbe(attacher probemanager.Attacher, progName, tracepointName string, log bpfSetupLog) func() {
	noop := func() {}
	if attacher == nil {
		return noop
	}
	log = log.withDefaults()
	prog, err := attacher.GetProgram(progName)
	if err != nil {
		log.warn(fmt.Sprintf("skipping %s probe: get program %s: %v", tracepointName, progName, err))
		return noop
	}
	link, err := prog.AttachTracepoint("sched", tracepointName)
	if err != nil {
		log.warn(fmt.Sprintf("skipping %s probe: %v", tracepointName, err))
		return noop
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			if err := link.Destroy(); err != nil {
				log.teardown(fmt.Sprintf("ior: %s probe detach error: %v", tracepointName, err))
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
