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

func TestModelPageScrollWithPgUpPgDown(t *testing.T) {
	rb := NewRingBuffer()
	m := NewModel(rb)
	m.height = 12 // visibleRows=4, pageStep=3
	pushEvents(rb, 30)
	m.Refresh()
	m.HandleKey("g")

	if !m.HandleKey("pgdown") {
		t.Fatalf("pgdown should be handled")
	}
	if m.scrollOffset != 3 {
		t.Fatalf("expected page down to move by 3, got %d", m.scrollOffset)
	}

	if !m.HandleKey("pagedown") {
		t.Fatalf("pagedown should be handled")
	}
	if m.scrollOffset != 6 {
		t.Fatalf("expected pagedown alias to move by 3, got %d", m.scrollOffset)
	}

	if !m.HandleKey("pgup") {
		t.Fatalf("pgup should be handled")
	}
	if m.scrollOffset != 3 {
		t.Fatalf("expected page up to move up by 3, got %d", m.scrollOffset)
	}
	if !m.HandleKey("pageup") {
		t.Fatalf("pageup should be handled")
	}
	if m.scrollOffset != 0 {
		t.Fatalf("expected pageup alias to return to top, got %d", m.scrollOffset)
	}
}

func TestModelArrowAndJKScroll(t *testing.T) {
	rb := NewRingBuffer()
	m := NewModel(rb)
	m.height = 12
	pushEvents(rb, 30)
	m.Refresh()
	m.HandleKey("g")

	if !m.HandleKey("down") {
		t.Fatalf("down should be handled")
	}
	if m.scrollOffset != 1 {
		t.Fatalf("expected down to increment offset, got %d", m.scrollOffset)
	}
	if !m.HandleKey("j") {
		t.Fatalf("j should be handled")
	}
	if m.scrollOffset != 2 {
		t.Fatalf("expected j to increment offset, got %d", m.scrollOffset)
	}
	if !m.HandleKey("up") {
		t.Fatalf("up should be handled")
	}
	if m.scrollOffset != 1 {
		t.Fatalf("expected up to decrement offset, got %d", m.scrollOffset)
	}
	if !m.HandleKey("k") {
		t.Fatalf("k should be handled")
	}
	if m.scrollOffset != 0 {
		t.Fatalf("expected k to decrement offset, got %d", m.scrollOffset)
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

func TestFilterModalTemporarilyPausesAndRestoresState(t *testing.T) {
	rb := NewRingBuffer()
	m := NewModel(rb)
	m.height = 20
	pushEvents(rb, 4)
	m.Refresh()

	if m.paused {
		t.Fatalf("expected model to start unpaused")
	}
	if !m.HandleKey("f") {
		t.Fatalf("f should be handled")
	}
	if !m.paused {
		t.Fatalf("expected model paused while filter modal is open")
	}
	if !m.filterModal.Visible() {
		t.Fatalf("expected filter modal visible after f")
	}
	if !m.HandleKey("esc") {
		t.Fatalf("esc should be routed to filter modal")
	}
	if m.filterModal.Visible() {
		t.Fatalf("expected filter modal closed after esc")
	}
	if m.paused {
		t.Fatalf("expected pause state restored to unpaused after modal close")
	}

	// If the user was already paused before opening the filter modal,
	// that pause state should remain after closing.
	if !m.HandleKey("space") {
		t.Fatalf("space should toggle pause")
	}
	if !m.paused {
		t.Fatalf("expected paused=true after space")
	}
	if !m.HandleKey("f") {
		t.Fatalf("f should be handled while paused")
	}
	if !m.HandleKey("esc") {
		t.Fatalf("esc should close modal")
	}
	if !m.paused {
		t.Fatalf("expected paused state preserved after modal close")
	}
}

func TestUnpauseRestoresLiveTailAndRefresh(t *testing.T) {
	rb := NewRingBuffer()
	m := NewModel(rb)
	m.height = 10
	pushEvents(rb, 20)
	m.Refresh()

	// Move off tail, then pause.
	m.HandleKey("g")
	if m.autoScroll {
		t.Fatalf("expected autoScroll disabled at top")
	}
	m.HandleKey("space")
	if !m.paused {
		t.Fatalf("expected paused")
	}

	// New events arrive while paused.
	pushEvents(rb, 5)
	m.Refresh()

	// Resume: should auto-tail and refresh immediately.
	m.HandleKey("space")
	if m.paused {
		t.Fatalf("expected unpaused")
	}
	if !m.autoScroll {
		t.Fatalf("expected autoScroll restored on resume")
	}
	if m.scrollOffset != m.maxScrollOffset() {
		t.Fatalf("expected tail offset after resume, got offset=%d max=%d", m.scrollOffset, m.maxScrollOffset())
	}
}

func TestPausedScrollWithJKAndPageKeys(t *testing.T) {
	rb := NewRingBuffer()
	m := NewModel(rb)
	m.height = 20
	pushEvents(rb, 100)
	m.Refresh()
	if !m.HandleKey("space") {
		t.Fatalf("space should toggle pause")
	}
	before := rowNumber(m.scrollOffset, len(m.filtered))
	if !m.HandleKey("k") {
		t.Fatalf("k should be handled while paused")
	}
	afterK := rowNumber(m.scrollOffset, len(m.filtered))
	if afterK >= before {
		t.Fatalf("expected k to scroll up while paused: before=%d after=%d", before, afterK)
	}
	if !m.HandleKey("pgup") {
		t.Fatalf("pgup should be handled while paused")
	}
	afterPgUp := rowNumber(m.scrollOffset, len(m.filtered))
	if afterPgUp >= afterK {
		t.Fatalf("expected pgup to scroll up while paused: afterK=%d afterPgUp=%d", afterK, afterPgUp)
	}
	if !m.HandleKey("pgdown") {
		t.Fatalf("pgdown should be handled while paused")
	}
	afterPgDown := rowNumber(m.scrollOffset, len(m.filtered))
	if afterPgDown <= afterPgUp {
		t.Fatalf("expected pgdown to scroll down while paused: afterPgUp=%d afterPgDown=%d", afterPgUp, afterPgDown)
	}
}
