package internal

import (
	"ior/internal/flags"
	"ior/internal/flamegraph"
	"ior/internal/statsengine"
	"ior/internal/streamrow"
)

// runtimeComponents holds the freshly allocated trace-session components
// produced by RuntimeBuilder.Build. All fields are non-nil after a successful
// build. The caller is responsible for wiring these into the runtime bindings
// and event-loop callbacks.
type runtimeComponents struct {
	engine    *statsengine.Engine
	streamBuf *streamrow.RingBuffer
	streamSeq *streamrow.Sequencer
	liveTrie  *flamegraph.LiveTrie
}

// RuntimeBuilder encapsulates the allocation of per-trace-session runtime
// components. Construct one with newRuntimeBuilder, then call Build to
// produce a fresh runtimeComponents struct ready for wiring.
type RuntimeBuilder struct {
	// cfg holds the configuration used to size and configure the components.
	cfg flags.Config
}

// newRuntimeBuilder creates a RuntimeBuilder configured from cfg.
// The builder captures cfg at construction time; later cfg changes do not affect
// a builder already created.
func newRuntimeBuilder(cfg flags.Config) RuntimeBuilder {
	return RuntimeBuilder{cfg: cfg}
}

// Build allocates a fresh set of runtime components for one trace session.
// It creates a new stats engine, stream ring buffer, sequencer, and live trie
// each time it is called; callers must not share the returned components across
// concurrent trace sessions.
func (b RuntimeBuilder) Build() runtimeComponents {
	return runtimeComponents{
		engine:    statsengine.NewEngine(statsengine.DefaultTopN),
		streamBuf: streamrow.NewRingBuffer(),
		streamSeq: streamrow.NewSequencer(0),
		liveTrie:  flamegraph.NewLiveTrie(b.cfg.CollapsedFields, b.cfg.CountField, b.cfg.CountField),
	}
}
