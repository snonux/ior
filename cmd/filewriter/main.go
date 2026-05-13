package main

import (
	"fmt"
	"os"
	"time"
)

func main() {
	// Open the file in append mode, create it if it doesn't exist
	file, err := os.OpenFile("output.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "filewriter: failed to open output file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	// Define the byte to be written
	data := []byte("A") // Replace 'A' with any byte you wish to write

	// Loop to write the byte every 3 seconds
	for {
		_, err := file.Write(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "filewriter: failed to write data: %v\n", err)
			os.Exit(1)
		}

		// Flush writes to stable storage
		err = file.Sync()
		if err != nil {
			fmt.Fprintf(os.Stderr, "filewriter: failed to sync file: %v\n", err)
			os.Exit(1)
		}

		// Wait for 3 seconds
		time.Sleep(3 * time.Second)
	}
}
