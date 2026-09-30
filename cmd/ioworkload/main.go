// ioworkload is a standalone binary that performs deterministic I/O operations
// for integration testing of ior. It prints its PID to stdout, sleeps to allow
// ior to attach BPF tracepoints, then executes the requested I/O scenario.
//
// The Go runtime (1.25+) derives GOMAXPROCS from the cgroup CPU limit and
// re-reads <cgroup>/cpu.max on a timer from a background goroutine, i.e. it
// issues pread64/openat calls of its own that ior faithfully traces. Scenarios
// that count syscalls exactly (thread-comm-*) would see them as extra rows
// whenever they run longer than the timer period, so both the initial probe and
// the updater are switched off. No scenario needs a cgroup-derived GOMAXPROCS.
//
//go:debug containermaxprocs=0
//go:debug updatemaxprocs=0
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"slices"
	"strconv"
	"time"
)

// Give ior enough time to attach tracepoints before scenarios emit syscalls.
// Under slower CI or locally saturated systems, 5s can still miss first-call
// events for single-shot scenarios. Use a slightly larger delay for stability.
const (
	defaultStartupDelay = 8 * time.Second
	startupDelayEnv     = "IOR_WORKLOAD_STARTUP_DELAY_MS"
	startupFileEnv      = "IOR_WORKLOAD_STARTUP_FILE"
	startupFileTimeout  = 30 * time.Second
	// holdFileEnv names a file whose appearance lets the workload exit: after
	// its scenario succeeded the process stays alive until the file exists
	// (bounded by holdFileTimeout). Tests use it to keep the traced -pid
	// target alive past its I/O, since a headless ior ends as soon as that
	// process exits (task vr2) and signal/shutdown tests need ior to outlive
	// the scenario. Unset: the workload exits right after the scenario.
	holdFileEnv = "IOR_WORKLOAD_HOLD_FILE"
	// holdFileTimeout is only a safety net so a forgotten hold never leaks the
	// process. It must stay clearly above the longest -duration a test expects
	// the target to outlive (signal_shutdown_test.go uses 60s): on a stalled
	// host a workload that gave up early would end the ior run under test.
	holdFileTimeout = 120 * time.Second
)

// Pin the main goroutine to the main thread so scenario syscalls run with
// TID == PID. ior seeds the comm of the traced PID at startup but resolves
// other TIDs asynchronously via /proc; a single-syscall scenario that lands on
// another Go thread and exits right away can be recorded with an empty comm.
func init() {
	runtime.LockOSThread()
}

func main() {
	scenario := flag.String("scenario", "", "I/O scenario to execute")
	flag.Parse()

	if *scenario == "" {
		fmt.Fprintln(os.Stderr, "usage: ioworkload --scenario=<name>")
		os.Exit(2)
	}

	run, ok := scenarios[*scenario]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown scenario: %s\navailable scenarios:\n", *scenario)
		var names []string
		for name := range scenarios {
			names = append(names, name)
		}
		slices.Sort(names)
		for _, name := range names {
			fmt.Fprintf(os.Stderr, "  %s\n", name)
		}
		os.Exit(2)
	}

	// A pre-start hook runs before the PID is announced, i.e. before the
	// harness starts ior, for scenarios whose ior arguments depend on state
	// the workload must create first (e.g. a worker thread's TID for -tid).
	if prestart, ok := scenarioPrestarts[*scenario]; ok {
		if err := prestart(); err != nil {
			fmt.Fprintf(os.Stderr, "scenario %s prestart failed: %v\n", *scenario, err)
			os.Exit(1)
		}
	}

	fmt.Println(os.Getpid())
	if err := waitForStartup(); err != nil {
		fmt.Fprintf(os.Stderr, "startup wait failed: %v\n", err)
		os.Exit(1)
	}

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "scenario %s failed: %v\n", *scenario, err)
		os.Exit(1)
	}

	if err := waitForHold(); err != nil {
		fmt.Fprintf(os.Stderr, "hold wait failed: %v\n", err)
		os.Exit(1)
	}
}

// waitForHold keeps the process alive until $IOR_WORKLOAD_HOLD_FILE exists;
// without the variable it returns at once.
func waitForHold() error {
	path := os.Getenv(holdFileEnv)
	if path == "" {
		return nil
	}
	return waitForFile(path, holdFileTimeout, 50*time.Millisecond)
}

func waitForStartup() error {
	path := os.Getenv(startupFileEnv)
	if path == "" {
		time.Sleep(configuredStartupDelay())
		return nil
	}
	return waitForFile(path, startupFileTimeout, 10*time.Millisecond)
}

// waitForFile polls every poll until path exists, failing after timeout.
func waitForFile(path string, timeout, poll time.Duration) error {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()

	ticker := time.NewTicker(poll)
	defer ticker.Stop()

	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		} else if !os.IsNotExist(err) {
			return err
		}

		select {
		case <-ticker.C:
		case <-deadline.C:
			return fmt.Errorf("timeout waiting for %s", path)
		}
	}
}

func configuredStartupDelay() time.Duration {
	raw := os.Getenv(startupDelayEnv)
	if raw == "" {
		return defaultStartupDelay
	}
	ms, err := strconv.Atoi(raw)
	if err != nil || ms < 0 {
		return defaultStartupDelay
	}
	return time.Duration(ms) * time.Millisecond
}
