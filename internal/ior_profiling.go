package internal

import (
	"context"
	"os"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"sync"
	"time"

	"ior/internal/flags"
)

// profilingControl manages optional CPU, memory, and execution-trace profiling
// for a single tracing run.
type profilingControl struct {
	done          chan struct{}
	enabled       bool
	cpuProfile    *os.File
	memProfile    *os.File
	stopExecTrace func()
	stopOnce      sync.Once
}

// setupProfiling starts profiling if cfg.PprofEnable is set and returns a
// control handle. The caller must wait on control.done after the trace ends.
// started is non-nil in TUI mode; nil in plain/flamegraph mode.
func setupProfiling(ctx context.Context, cfg flags.Config, started chan<- struct{}) (*profilingControl, error) {
	control := &profilingControl{
		done:          make(chan struct{}),
		stopExecTrace: func() {},
	}
	if !cfg.PprofEnable {
		close(control.done)
		return control, nil
	}

	control.enabled = true
	isTUIMode := started != nil
	cpuProfilePath, memProfilePath, execTracePath, execTraceDuration := profilingFilesForMode(isTUIMode)

	cpuProfile, err := os.Create(cpuProfilePath)
	if err != nil {
		return nil, err
	}
	memProfile, err := os.Create(memProfilePath)
	if err != nil {
		_ = cpuProfile.Close()
		return nil, err
	}
	control.cpuProfile = cpuProfile
	control.memProfile = memProfile

	if execTracePath != "" {
		execTraceProfile, err := os.Create(execTracePath)
		if err != nil {
			_ = cpuProfile.Close()
			_ = memProfile.Close()
			return nil, err
		}
		if err := trace.Start(execTraceProfile); err != nil {
			_ = cpuProfile.Close()
			_ = memProfile.Close()
			_ = execTraceProfile.Close()
			return nil, err
		}
		var stopOnce sync.Once
		control.stopExecTrace = func() {
			stopOnce.Do(func() {
				trace.Stop()
				_ = execTraceProfile.Close()
			})
		}
		go func() {
			timer := time.NewTimer(execTraceDuration)
			defer timer.Stop()
			select {
			case <-ctx.Done():
			case <-timer.C:
			}
			control.stopExecTrace()
		}()
	}

	if err := pprof.StartCPUProfile(cpuProfile); err != nil {
		control.stopExecTrace()
		_ = cpuProfile.Close()
		_ = memProfile.Close()
		return nil, err
	}
	return control, nil
}

func (p *profilingControl) stop(logln func(...any)) {
	p.stopOnce.Do(func() {
		if !p.enabled {
			return
		}
		logln("Stopping profiling and writing profile files")
		pprof.StopCPUProfile()
		runtime.GC()
		// Log any failure writing the heap profile (e.g. full disk, permission
		// denied) so it is not silently swallowed.
		if err := pprof.WriteHeapProfile(p.memProfile); err != nil {
			logln("ERROR: failed to write heap profile:", err)
		}
		p.stopExecTrace()
		_ = p.cpuProfile.Close()
		_ = p.memProfile.Close()
		close(p.done)
	})
}

// profilingFilesForMode returns the file paths and exec-trace duration to use
// depending on whether the binary is running in TUI mode or plain/flamegraph mode.
func profilingFilesForMode(tuiMode bool) (cpuProfilePath, memProfilePath, execTracePath string, execTraceDuration time.Duration) {
	if tuiMode {
		return "ior-tui-cpu.prof", "ior-tui-mem.prof", "ior-tui-trace.out", 10 * time.Second
	}
	return "ior.cpuprofile", "ior.memprofile", "", 0
}
