package main

import (
	"os"
	"time"
)

func main() {
	// Open the file in append mode, create it if it doesn't exist
	file, err := os.OpenFile("output.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	// Define the byte to be written
	data := []byte("A") // Replace 'A' with any byte you wish to write

	// Loop to write the byte every 3 seconds
	for {
		_, err := file.Write(data)
		if err != nil {
			panic(err)
		}

		// Flush writes to stable storage
		err = file.Sync()
		if err != nil {
			panic(err)
		}

		// Wait for 3 seconds
		time.Sleep(3 * time.Second)
	}
}
