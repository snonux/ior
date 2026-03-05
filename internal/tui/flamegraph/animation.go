package flamegraph

import (
	"math"

	"github.com/charmbracelet/harmonica"
)

const springEpsilon = 0.01

type frameSpring struct {
	path        string
	base        tuiFrame
	widthSpring harmonica.Spring
	colSpring   harmonica.Spring

	currentW    float64
	currentCol  float64
	velocityW   float64
	velocityCol float64

	targetW   float64
	targetCol float64
}

// AnimationState stores per-frame spring interpolation state.
type AnimationState struct {
	springs []frameSpring
	settled bool

	fps             int
	angularVelocity float64
	damping         float64
}

// NewAnimationState builds a spring animation state with the provided parameters.
func NewAnimationState(fps int, angularVelocity, damping float64) AnimationState {
	if fps <= 0 {
		fps = 30
	}
	return AnimationState{
		fps:             fps,
		angularVelocity: angularVelocity,
		damping:         damping,
		settled:         true,
	}
}

// SetTargets sets new frame targets, preserving spring motion for matching paths.
func (a *AnimationState) SetTargets(targets []tuiFrame) {
	existing := make(map[string]frameSpring, len(a.springs))
	for _, spring := range a.springs {
		existing[spring.path] = spring
	}

	next := make([]frameSpring, 0, len(targets))
	for _, target := range targets {
		spring, ok := existing[target.Path]
		if !ok {
			spring = frameSpring{
				path:       target.Path,
				currentW:   float64(target.Width),
				currentCol: float64(target.Col),
			}
		}
		spring.base = target
		spring.targetW = float64(target.Width)
		spring.targetCol = float64(target.Col)
		spring.widthSpring = harmonica.NewSpring(harmonica.FPS(a.fps), a.angularVelocity, a.damping)
		spring.colSpring = harmonica.NewSpring(harmonica.FPS(a.fps), a.angularVelocity, a.damping)
		next = append(next, spring)
	}
	a.springs = next
	a.settled = len(a.springs) == 0
	for _, spring := range a.springs {
		if !isSpringSettled(spring) {
			a.settled = false
			break
		}
	}
}

// Tick advances springs by delta seconds and returns true while animation is active.
func (a *AnimationState) Tick(delta float64) bool {
	if len(a.springs) == 0 {
		a.settled = true
		return false
	}
	if delta <= 0 {
		delta = harmonica.FPS(a.fps)
	}

	active := false
	for idx := range a.springs {
		spring := &a.springs[idx]
		spring.widthSpring = harmonica.NewSpring(delta, a.angularVelocity, a.damping)
		spring.colSpring = harmonica.NewSpring(delta, a.angularVelocity, a.damping)
		spring.currentW, spring.velocityW = spring.widthSpring.Update(spring.currentW, spring.velocityW, spring.targetW)
		spring.currentCol, spring.velocityCol = spring.colSpring.Update(spring.currentCol, spring.velocityCol, spring.targetCol)
		if !isSpringSettled(*spring) {
			active = true
		}
	}
	a.settled = !active
	return active
}

// CurrentFrames returns interpolated frames for the current animation step.
func (a AnimationState) CurrentFrames() []tuiFrame {
	frames := make([]tuiFrame, 0, len(a.springs))
	for _, spring := range a.springs {
		frame := spring.base
		frame.Col = maxInt(0, int(math.Round(spring.currentCol)))
		frame.Width = maxInt(1, int(math.Round(spring.currentW)))
		frames = append(frames, frame)
	}
	return frames
}

// Settled reports whether all active springs are at rest.
func (a AnimationState) Settled() bool {
	return a.settled
}

func isSpringSettled(s frameSpring) bool {
	return math.Abs(s.currentW-s.targetW) < springEpsilon &&
		math.Abs(s.currentCol-s.targetCol) < springEpsilon &&
		math.Abs(s.velocityW) < springEpsilon &&
		math.Abs(s.velocityCol) < springEpsilon
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
