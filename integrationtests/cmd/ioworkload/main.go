// ioworkload is a standalone binary that performs deterministic I/O operations
// for integration testing of ior. It prints its PID to stdout, sleeps to allow
// ior to attach BPF tracepoints, then executes the requested I/O scenario.
package main

import (
	"flag"
	"fmt"
	"os"
	"slices"
	"time"
)

const startupDelay = 2 * time.Second

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
	time.Sleep(startupDelay)

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "scenario %s failed: %v\n", *scenario, err)
		os.Exit(1)
	}
}
