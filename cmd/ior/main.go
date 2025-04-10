package main

import (
	"fmt"
	"ior/internal"
	"ior/internal/flags"
	"os"
	"runtime"
)

// main is the entry point for the application. It checks if the OS is Linux,
// parses command-line flags, and runs the internal logic of the application.
func main() {
	if runtime.GOOS != "linux" {
		fmt.Println("Unsupported OS")
		os.Exit(2)
	}

	// Parse command-line flags
	flags.Parse()

	// Run the internal logic of the application
	if err := internal.Run(); err != nil {
		fmt.Printf("Failed to run: %v\n", err)
		os.Exit(2)
	}
}
