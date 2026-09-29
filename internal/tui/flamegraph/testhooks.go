package flamegraph

import (
	"time"

	tea "charm.land/bubbletea/v2"
)

// IsAnimationTick reports whether msg is a frame animation tick of this
// package. Packages that route flamegraph messages, such as the dashboard,
// use it in tests to tell animation ticks from their own messages without
// naming the unexported type.
func IsAnimationTick(msg tea.Msg) bool {
	_, ok := msg.(animTickMsg)
	return ok
}

// KeepTickLoopFresh is a test-only hook. It marks the live tick loop's
// pending tick as due an hour from now, so the loop counts as live however
// long a test runs and no restart can come from lost-tick recovery (see
// tickLostAfter). It has no effect when no loop is live.
func (m *Model) KeepTickLoopFresh() {
	m.anim.tickDue = time.Now().Add(time.Hour)
}

// ForceTickLost is a test-only hook. It marks the live tick loop's pending
// tick as overdue by more than tickLostAfter, as if the tick had been dropped
// long ago, so the next animation restart treats the loop as lost without the
// test sleeping. It has no effect when no loop is live.
func (m *Model) ForceTickLost() {
	m.anim.tickDue = time.Now().Add(-tickLostAfter - time.Millisecond)
}
