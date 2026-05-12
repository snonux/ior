package main

import (
	"fmt"
	"os"
	"runtime"

	"ior/internal"
	"ior/internal/flags"
	"ior/internal/tui"
)

// main is the entry point for the application. It checks if the OS is Linux,
// parses command-line flags, and runs the internal logic of the application.
func main() {
	if runtime.GOOS != "linux" {
		fmt.Println("Unsupported OS")
		os.Exit(2)
	}

	// Parse command-line flags
	if err := flags.Parse(); err != nil {
		fmt.Printf("Failed to parse flags: %v\n", err)
		os.Exit(2)
	}

	// flags.Get() is called here at the CLI boundary so internal code never reads the singleton.
	cfg := flags.Get()

	// Handle -version: print the banner plus version and exit.
	if cfg.ShowVersion {
		flags.PrintVersion()
		return
	}

	// Wire the concrete TUI runner functions into the core internal package.
	// This is the only place that imports both internal and internal/tui, which
	// breaks the cycle: internal no longer imports internal/tui.
	internal.SetTUIRunners(
		tui.RunWithTraceStarterConfig,
		tui.RunTestFlamesWithTraceStarterConfig,
		tui.RunTestFlamesWithTraceStarterConfig, // same runner; starter differs (static vs live)
	)

	// Run the internal logic of the application.
	if err := internal.Run(cfg); err != nil {
		fmt.Printf("Failed to run: %v\n", err)
		os.Exit(2)
	}
}
