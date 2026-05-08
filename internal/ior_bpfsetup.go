package internal

import (
	"context"
	"fmt"
	"os"

	appconfig "ior/internal/config"
	"ior/internal/flags"
	"ior/internal/probemanager"
	"ior/internal/tracepoints"
	"ior/internal/tui"

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

	mgr := probemanager.NewManager(libbpfTracepointModule{module: bpfModule})
	// Per-syscall attach failures are non-fatal: on older kernels the
	// tracepoint may be absent (e.g. binary built against a newer kernel).
	// We log and skip; the affected probe stays in the manager with its
	// lastErr set, so States() and the TUI surface the failure.
	warn := func(syscall string, err error) {
		fmt.Fprintf(os.Stderr, "ior: skipping tracepoint for %s: %v\n", syscall, err)
	}
	if err := mgr.AttachAll(cfg.ShouldIAttachTracepoint, tracepoints.List, warn); err != nil {
		mgr.Close()
		bpfModule.Close()
		return nil, nil, releaseBindings, setupBPFModuleError("attach probes", err)
	}
	// setupBPFModule only injects the probe manager; it does not read TUI state,
	// so RuntimePublisher is the correct narrower interface to use here.
	if bindings, ok := tui.RuntimePublisherFromContext(parentCtx); ok {
		bindings.SetProbeManager(mgr)
		releaseBindings = func() { bindings.SetProbeManager(nil) }
	}
	return bpfModule, mgr, releaseBindings, nil
}

// setupEventChannel initialises the BPF ring-buffer and returns the event channel.
func setupEventChannel(bpfModule *bpf.Module) (chan []byte, error) {
	ch := make(chan []byte, appconfig.DefaultChannelBufferSize)
	rb, err := bpfModule.InitRingBuf("event_map", ch)
	if err != nil {
		return nil, err
	}
	rb.Poll(300)
	return ch, nil
}
