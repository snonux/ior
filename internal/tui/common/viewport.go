package common

import (
	"os"

	xterm "github.com/charmbracelet/x/term"
)

const (
	defaultViewportWidth  = 80
	defaultViewportHeight = 24
)

var queryTerminalSize = func() (int, int, error) {
	return xterm.GetSize(os.Stdout.Fd())
}

// EffectiveViewport returns a usable terminal viewport size. Missing or invalid
// dimensions fall back to defaults.
func EffectiveViewport(width, height int) (int, int) {
	if width <= 0 || height <= 0 {
		terminalWidth, terminalHeight, err := queryTerminalSize()
		if err == nil {
			if width <= 0 && terminalWidth > 0 {
				width = terminalWidth
			}
			if height <= 0 && terminalHeight > 0 {
				height = terminalHeight
			}
		}
	}

	if width <= 0 {
		width = defaultViewportWidth
	}
	if height <= 0 {
		height = defaultViewportHeight
	}
	return width, height
}
