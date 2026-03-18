package main

import (
	"fmt"
	"os"
	"runtime"

	"ior/internal"
	"ior/internal/flags"
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

	// Run the internal logic of the application.
	// flags.Get() is called here at the CLI boundary so internal code never reads the singleton.
	if err := internal.Run(flags.Get()); err != nil {
		fmt.Printf("Failed to run: %v\n", err)
		os.Exit(2)
	}
}
