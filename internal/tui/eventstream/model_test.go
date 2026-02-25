package eventstream

import "testing"

func pushEvents(rb *RingBuffer, count int) {
	for i := 0; i < count; i++ {
		rb.Push(StreamEvent{
			Seq:        uint64(i),
			Syscall:    map[bool]string{true: "read", false: "write"}[i%2 == 0],
			Comm:       "proc",
			PID:        100,
			TID:        uint32(100 + i),
			DurationNs: uint64(1000 + i),
			GapNs:      uint64(10 + i),
			Bytes:      uint64(64 + i),
			FileName:   "/tmp/file",
			RetVal:     int64(i),
			IsError:    i%3 == 0,
		})
	}
}

func TestModelPauseFreezesDisplay(t *testing.T) {
	rb := NewRingBuffer()
	m := NewModel(rb)
	m.height = 20
	pushEvents(rb, 3)
	m.Refresh()
	if len(m.filtered) != 3 {
		t.Fatalf("filtered=%d, want 3", len(m.filtered))
	}

	if !m.HandleKey("space") {
		t.Fatalf("space should be handled")
	}
	pushEvents(rb, 2)
	m.Refresh()
	if len(m.filtered) != 3 {
		t.Fatalf("paused refresh should not change filtered len, got %d", len(m.filtered))
	}
}

func TestModelScrollClamp(t *testing.T) {
	rb := NewRingBuffer()
	m := NewModel(rb)
	m.height = 10
	pushEvents(rb, 30)
	m.Refresh()

	for i := 0; i < 100; i++ {
		m.HandleKey("j")
	}
	if m.scrollOffset > m.maxScrollOffset() {
		t.Fatalf("scrollOffset=%d exceeds max=%d", m.scrollOffset, m.maxScrollOffset())
	}

	for i := 0; i < 100; i++ {
		m.HandleKey("k")
	}
	if m.scrollOffset != 0 {
		t.Fatalf("scrollOffset=%d, want 0", m.scrollOffset)
	}
}

func TestModelFilterReducesVisibleRows(t *testing.T) {
	rb := NewRingBuffer()
	m := NewModel(rb)
	m.height = 20
	pushEvents(rb, 10)
	m.Refresh()

	m.setFilterForTest(Filter{Syscall: &StringFilter{Pattern: "read"}})
	m.applyFilter()

	if len(m.filtered) >= len(m.allEvents) {
		t.Fatalf("expected filtered rows to be less than all rows: filtered=%d all=%d", len(m.filtered), len(m.allEvents))
	}
}

func TestModelAutoScrollBehavior(t *testing.T) {
	rb := NewRingBuffer()
	m := NewModel(rb)
	m.height = 10
	pushEvents(rb, 12)
	m.Refresh()

	if m.scrollOffset != m.maxScrollOffset() {
		t.Fatalf("expected auto-scroll at bottom, got offset=%d max=%d", m.scrollOffset, m.maxScrollOffset())
	}

	m.HandleKey("k")
	prev := m.scrollOffset
	pushEvents(rb, 3)
	m.Refresh()
	if m.scrollOffset != prev {
		t.Fatalf("when autoScroll=false, offset should stay %d, got %d", prev, m.scrollOffset)
	}

	m.HandleKey("G")
	if m.scrollOffset != m.maxScrollOffset() {
		t.Fatalf("G should jump to tail")
	}
}

func TestModelHandleKeyRouting(t *testing.T) {
	rb := NewRingBuffer()
	m := NewModel(rb)

	if m.HandleKey("x") {
		t.Fatalf("unknown key should not be handled")
	}
	if !m.HandleKey("f") {
		t.Fatalf("f should be handled")
	}
	if !m.filterModal.Visible() {
		t.Fatalf("modal should be visible after f")
	}
	if !m.HandleKey("esc") {
		t.Fatalf("esc should route to modal")
	}
	if m.filterModal.Visible() {
		t.Fatalf("modal should close on esc")
	}
}
