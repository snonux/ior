package internal

import (
	"context"
	"fmt"
	"os"

	appconfig "ior/internal/config"
	"ior/internal/flags"
	"ior/internal/probemanager"
	"ior/internal/runtime"
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

// setupBPFModule loads and attaches the BPF module, attaching tracepoints
// and registering the probe manager with any TUI runtime bindings.
func setupBPFModule(parentCtx context.Context, cfg flags.Config) (*bpf.Module, *probemanager.Manager, func(), error) {
	releaseBindings := func() {}

	bpfModule, stage, err := loadBPFModule()
	if err != nil {
		return nil, nil, releaseBindings, setupBPFModuleError(stage, err)
	}
	if err := resizeBPFMaps(cfg, bpfModule); err != nil {
		bpfModule.Close()
		return nil, nil, releaseBindings, setupBPFModuleError("resize maps", err)
	}
	if err := setBPFGlobals(cfg, bpfModule); err != nil {
		bpfModule.Close()
		return nil, nil, releaseBindings, setupBPFModuleError("set globals", err)
	}
	if err := bpfModule.BPFLoadObject(); err != nil {
		bpfModule.Close()
		return nil, nil, releaseBindings, setupBPFModuleError("load object", err)
	}
	if err := applySyscallSamplingRates(cfg, bpfModule); err != nil {
		bpfModule.Close()
		return nil, nil, releaseBindings, setupBPFModuleError("configure sampling rates", err)
	}

	// Attach the exec probe before the syscall tracepoints. AttachAll walks
	// hundreds of tracepoints and takes a noticeable amount of time, during
	// which syscall records already flow from the ones attached first. Any task
	// that execs in that window would otherwise produce syscall rows with no
	// preceding comm record, which is exactly the stale/empty label this probe
	// exists to prevent.
	releaseExecProbe := attachProcessExecProbe(bpfModule)

	mgr := probemanager.NewManager(libbpfTracepointModule{module: bpfModule})
	// Per-syscall attach failures are non-fatal: on older kernels the
	// tracepoint may be absent (e.g. binary built against a newer kernel).
	// We log and skip; the affected probe stays in the manager with its
	// lastErr set, so States() and the TUI surface the failure.
	warn := func(syscall string, err error) {
		fmt.Fprintf(os.Stderr, "ior: skipping tracepoint for %s: %v\n", syscall, err)
	}
	if err := mgr.AttachAll(cfg.TracepointSelector.ShouldAttach, tracepoints.List, warn); err != nil {
		releaseExecProbe()
		mgr.Close()
		bpfModule.Close()
		return nil, nil, releaseBindings, setupBPFModuleError("attach probes", err)
	}
	// setupBPFModule only injects the probe manager; it does not read TUI state,
	// so RuntimePublisher is the correct narrower interface to use here.
	if bindings, ok := runtime.RuntimePublisherFromContext(parentCtx); ok {
		bindings.SetProbeManager(mgr)
		releaseBindings = func() {
			bindings.SetProbeManager(nil)
			releaseExecProbe()
		}
		return bpfModule, mgr, releaseBindings, nil
	}
	return bpfModule, mgr, releaseExecProbe, nil
}

// processExecProgName is the BPF program in internal/c/exec.c that reports the
// post-exec task comm.
const processExecProgName = "handle_sched_process_exec"

// attachProcessExecProbe attaches sched:sched_process_exec, whose records keep
// the pid->comm cache correct across execve (see internal/c/exec.c and
// eventLoop.handleProcessExecEvent). It is not a syscall tracepoint, so it is
// outside the probemanager's enter/exit pair model and is attached directly
// here, for the whole run, independently of -trace-* selection.
//
// Failure is deliberately non-fatal and mirrors the per-syscall attach policy:
// without this probe comms fall back to the asynchronous procfs resolver, which
// is exactly the pre-fix behaviour - degraded labelling, not a broken trace.
func attachProcessExecProbe(bpfModule *bpf.Module) func() {
	noop := func() {}
	prog, err := bpfModule.GetProgram(processExecProgName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ior: skipping sched_process_exec probe: get program %s: %v\n", processExecProgName, err)
		return noop
	}
	link, err := prog.AttachTracepoint("sched", "sched_process_exec")
	if err != nil {
		fmt.Fprintf(os.Stderr, "ior: skipping sched_process_exec probe: %v\n", err)
		return noop
	}
	return func() {
		if err := link.Destroy(); err != nil {
			fmt.Fprintf(os.Stderr, "ior: sched_process_exec probe detach error: %v\n", err)
		}
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
