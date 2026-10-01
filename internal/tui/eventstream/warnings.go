package eventstream

// warningCounter is optionally implemented by a Source that keeps an exact
// count of the synthetic warning rows it holds (streamrow.RingBuffer does).
// It is optional so that test sources and other Source implementations need
// not grow a method; without it the stream reports no warnings.
type warningCounter interface {
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
// another tab. Every warning row the source holds is also on the Stream tab,
// because warning rows bypass the stream filter (filterRows).
func (m *Model) WarningCount() int {
	if counter, ok := m.source.(warningCounter); ok {
		return counter.WarningCount()
	}
	return 0
}

// The TUI's ring buffer must keep counting: since warningCounter is an
// optional interface, a renamed or dropped RingBuffer.WarningCount would
// otherwise compile and silently hide the badge.
var _ warningCounter = (*RingBuffer)(nil)
