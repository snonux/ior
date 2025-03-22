package main

import (
	"ior/internal"
	"ior/internal/flags"
	"runtime"
)

func main() {
	if runtime.GOOS != "linux" {
		panic("Unsupported OS")
	}
	internal.Run(flags.New())
}
