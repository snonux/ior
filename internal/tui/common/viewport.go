package common

import (
	"os"

	xterm "github.com/charmbracelet/x/term"
)

const (
	defaultViewportWidth  = 80
	defaultViewportHeight = 24
)

// EffectiveViewport returns a usable terminal viewport size. Missing or invalid
// dimensions are resolved from the active terminal when possible.
func EffectiveViewport(width, height int) (int, int) {
	if width > 0 && height > 0 {
		return width, height
	}

	termWidth, termHeight, err := xterm.GetSize(os.Stdout.Fd())
	if err == nil {
		if width <= 0 && termWidth > 0 {
			width = termWidth
		}
		if height <= 0 && termHeight > 0 {
			height = termHeight
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
