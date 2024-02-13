package main

import (
	"ioriotng/internal"
	"ioriotng/internal/flags"
)

func main() {
	internal.Run(flags.New())
}
