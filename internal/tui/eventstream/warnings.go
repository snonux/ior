package eventstream

// WarningCounter is optionally implemented by a Source that keeps an exact
// count of the synthetic warning rows it holds. It is optional so that test
// sources and other Source implementations need not grow a method; without it
// the stream reports no warnings.
//
// Every type the TUI publishes as its stream source must implement it, or the
// warning badge silently reads 0: the raw ring buffer (streamrow.RingBuffer,
// the source before the first trace, after a PID-change reset and in the
// -tuiTestFlames modes) and the trace session's gated sink (tui's
// sessionEventSink, the source of every real trace), which forwards to that
// same ring buffer. Each carries a compile-time assertion against this
// interface (below and in internal/tui/tracesession.go).
type WarningCounter interface {
	WarningCount() int
}

// WarningCount returns the number of synthetic warning rows (wrong -tid,
// zero probes attached, libbpf and runtime warnings) the live source holds.
// The dashboard turns it into a status-line badge on the other tabs (task
// ys2), since those rows appear nowhere but the Stream tab.
//
// It reads the live source rather than the model's last snapshot: the
// snapshot is frozen while the stream is paused and refreshed only while the
// Stream tab ticks, whereas the badge is shown precisely while the user is on
// another tab. Every warning row the source holds is also in the Stream
// tab's buffer, because warning rows bypass the stream filter (filterRows).
func (m *Model) WarningCount() int {
	if counter, ok := m.source.(WarningCounter); ok {
		return counter.WarningCount()
	}
	return 0
}

// The TUI's ring buffer must keep counting: since WarningCounter is an
// optional interface, a renamed or dropped RingBuffer.WarningCount would
// otherwise compile and silently hide the badge. The session sink's
// assertion lives next to that type (internal/tui/tracesession.go).
var _ WarningCounter = (*RingBuffer)(nil)
