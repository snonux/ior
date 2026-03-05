package common

const (
	defaultViewportWidth  = 80
	defaultViewportHeight = 24
)

// EffectiveViewport returns a usable terminal viewport size. Missing or invalid
// dimensions fall back to defaults.
func EffectiveViewport(width, height int) (int, int) {
	if width <= 0 {
		width = defaultViewportWidth
	}
	if height <= 0 {
		height = defaultViewportHeight
	}
	return width, height
}
