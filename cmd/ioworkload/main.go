// ioworkload is a standalone binary that performs deterministic I/O operations
// for integration testing of ior. It prints its PID to stdout, sleeps to allow
// ior to attach BPF tracepoints, then executes the requested I/O scenario.
package main

import (
	"flag"
	"fmt"
	"os"
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
)

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

	fmt.Println(os.Getpid())
	if err := waitForStartup(); err != nil {
		fmt.Fprintf(os.Stderr, "startup wait failed: %v\n", err)
		os.Exit(1)
	}

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "scenario %s failed: %v\n", *scenario, err)
		os.Exit(1)
	}
}

func waitForStartup() error {
	path := os.Getenv(startupFileEnv)
	if path == "" {
		time.Sleep(configuredStartupDelay())
		return nil
	}
	return waitForStartupFile(path)
}

func waitForStartupFile(path string) error {
	deadline := time.NewTimer(startupFileTimeout)
	defer deadline.Stop()

	ticker := time.NewTicker(10 * time.Millisecond)
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
