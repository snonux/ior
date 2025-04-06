package main

import (
	"ior/internal"
	"ior/internal/flags"
	"log"
	"runtime"
)

// main is the entry point for the application. It checks if the OS is Linux,
// parses command-line flags, and runs the internal logic of the application.
func main() {
	if runtime.GOOS != "linux" {
		log.Fatal("Unsupported OS")
	}

	// Parse command-line flags
	flags.Parse()

	// Run the internal logic of the application
	if err := internal.Run(); err != nil {
		log.Fatalf("Failed to run: %v", err)
	}
}
