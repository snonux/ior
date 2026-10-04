package runtime

import (
	"ior/internal/parquet"
	"ior/internal/sampling"
)

// RecordingSampling is what a trace session tells the TUI about sampling, so
// that a Parquet recording started with the R key can be marked like a sampled
// raw-mode file (footer keys ior.sampling and ior.sampling.totals).
type RecordingSampling interface {
	// SampledSyscalls returns every syscall the session samples (effective
	// rate other than 1, including the aggregate-only rate 0) with its Rate
	// and Family; nil when nothing is sampled. The rates are fixed for the
	// whole ior process (they come from the -syscall-sampling-* flags and
	// their defaults), so every session reports the same list.
	SampledSyscalls() []sampling.Entry
	// FlushCounters drains the kernel aggregate counters and reads the
	// ring-buffer drop counter now, handing both to their sinks, the active
	// recording included (counts, and a loss as a lower bound). The TUI calls
	// it right before a recording starts (so counts and drops from before the
	// start go to no recording) and right before it stops or the session
	// retires (so the last partial poll interval is not lost). Safe from any
	// goroutine; a no-op once the session's poll loops have stopped.
	//
	// It reports false when the aggregate drain failed. A failed drain leaves
	// some deltas in the kernel map, so at a recording's start the next
	// successful drain may carry pre-start counts into the recording: the
	// TUI then marks the new recording's totals unavailable.
	FlushCounters() (complete bool)
}

// RecordingSamplingPublisher is the optional capability of a RuntimePublisher
// to take the session's RecordingSampling. Only the TUI's session view
// implements it; bindings without one (fakes, the test-flames modes) simply
// produce unmarked recordings, which is right for them since they sample
// nothing.
type RecordingSamplingPublisher interface {
	SetRecordingSampling(source RecordingSampling)
}

// RecordingSamplingCounter is the optional capability of a recorder to keep
// the sampling totals of its active recording: *parquet.Recorder implements
// it, and so does the TUI's session-gated recorder view, which drops what a
// retired session still reports. The trace core feeds it from the aggregate
// drain loop and the ring-buffer drop monitor.
type RecordingSamplingCounter interface {
	// CountKernelOnly adds n kernel-counted invocations of syscall (no row).
	CountKernelOnly(syscall string, n uint64)
	// MarkSamplingLowerBound records lost events (ring-buffer drops, probe
	// runs the kernel skipped, rows a retired session may still deliver).
	MarkSamplingLowerBound()
	// MarkSamplingUnavailable records why the kernel counts are incomplete.
	MarkSamplingUnavailable(reason string)
}

var _ RecordingSamplingCounter = (*parquet.Recorder)(nil)
