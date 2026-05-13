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
	cpuProfilePath, memProfilePath, execTracePath, execTraceDuration := profilingFilesForMode(started != nil)

	cpuProfile, memProfile, err := openProfilingFiles(cpuProfilePath, memProfilePath)
	if err != nil {
		return nil, err
	}
	control.cpuProfile = cpuProfile
	control.memProfile = memProfile

	if execTracePath != "" {
		if err := startExecTrace(ctx, execTracePath, execTraceDuration, control); err != nil {
			_ = cpuProfile.Close()
			_ = memProfile.Close()
			return nil, err
		}
	}

	if err := pprof.StartCPUProfile(cpuProfile); err != nil {
		control.stopExecTrace()
		_ = cpuProfile.Close()
		_ = memProfile.Close()
		return nil, err
	}
	return control, nil
}

// openProfilingFiles creates the CPU and memory profile output files. On
// error any successfully opened file is closed before returning.
func openProfilingFiles(cpuPath, memPath string) (*os.File, *os.File, error) {
	cpuProfile, err := os.Create(cpuPath)
	if err != nil {
		return nil, nil, err
	}
	memProfile, err := os.Create(memPath)
	if err != nil {
		_ = cpuProfile.Close()
		return nil, nil, err
	}
	return cpuProfile, memProfile, nil
}

// startExecTrace creates the execution-trace output file, starts the runtime
// tracer, and wires a goroutine that stops it on context cancellation or after
// execTraceDuration, whichever comes first.
func startExecTrace(ctx context.Context, tracePath string, execTraceDuration time.Duration, control *profilingControl) error {
	execTraceProfile, err := os.Create(tracePath)
	if err != nil {
		return err
	}
	if err := trace.Start(execTraceProfile); err != nil {
		_ = execTraceProfile.Close()
		return err
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
	return nil
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
