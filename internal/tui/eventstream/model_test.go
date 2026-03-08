package eventstream

import (
	"encoding/csv"
	"os"
	"strings"
	"testing"
)

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
			FD:         UnknownFD,
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
	if m.HandleKey("f") {
		t.Fatalf("stream-local filter shortcut should no longer be handled here")
	}
}

func TestSetFilterReappliesCurrentBufferedRows(t *testing.T) {
	rb := NewRingBuffer()
	m := NewModel(rb)
	m.height = 20
	pushEvents(rb, 6)
	m.Refresh()

	m.SetFilter(Filter{Syscall: &StringFilter{Pattern: "read"}})
	if len(m.filtered) != 3 {
		t.Fatalf("expected 3 matching rows after filter, got %d", len(m.filtered))
	}

	m.SetFilter(Filter{})
	if len(m.filtered) != 6 {
		t.Fatalf("expected clearing filter to restore all rows, got %d", len(m.filtered))
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

func TestPausedSelectionInitializesNearMiddleAndCenters(t *testing.T) {
	rb := NewRingBuffer()
	m := NewModel(rb)
	m.height = 20 // visibleRows = 12
	pushEvents(rb, 100)
	m.Refresh()

	if !m.HandleKey("space") {
		t.Fatalf("space should toggle pause")
	}
	if !m.paused {
		t.Fatalf("expected paused state")
	}
	if m.selectedIdx < 0 {
		t.Fatalf("expected selected index while paused")
	}

	mid := m.visibleRows() / 2
	wantOffset := clamp(m.selectedIdx-mid, 0, m.maxScrollOffset())
	if m.scrollOffset != wantOffset {
		t.Fatalf("expected centered offset %d, got %d", wantOffset, m.scrollOffset)
	}
}

func TestPausedSelectionMovesAndRecentersWithJKAndArrows(t *testing.T) {
	rb := NewRingBuffer()
	m := NewModel(rb)
	m.height = 20 // visibleRows = 12
	pushEvents(rb, 100)
	m.Refresh()

	if !m.HandleKey("g") {
		t.Fatalf("g should be handled")
	}
	if !m.HandleKey("space") {
		t.Fatalf("space should toggle pause")
	}
	startSel := m.selectedIdx

	if !m.HandleKey("j") {
		t.Fatalf("j should be handled while paused")
	}
	if m.selectedIdx != startSel+1 {
		t.Fatalf("expected selected index +1 after j, got %d->%d", startSel, m.selectedIdx)
	}
	mid := m.visibleRows() / 2
	if m.scrollOffset != clamp(m.selectedIdx-mid, 0, m.maxScrollOffset()) {
		t.Fatalf("expected centered viewport after j")
	}

	if !m.HandleKey("up") {
		t.Fatalf("up should be handled while paused")
	}
	if m.selectedIdx != startSel {
		t.Fatalf("expected selected index back to start after up, got %d", m.selectedIdx)
	}
	if m.scrollOffset != clamp(m.selectedIdx-mid, 0, m.maxScrollOffset()) {
		t.Fatalf("expected centered viewport after up")
	}
}

func TestPausedSelectionMovesAcrossColumnsWithLeftRightAndHL(t *testing.T) {
	rb := NewRingBuffer()
	m := NewModel(rb)
	m.height = 20
	pushEvents(rb, 100)
	m.Refresh()

	if !m.HandleKey("space") {
		t.Fatalf("space should toggle pause")
	}
	startCol := m.selectedCol
	startRow := m.selectedIdx

	if !m.HandleKey("right") {
		t.Fatalf("right should be handled while paused")
	}
	if m.selectedCol != startCol+1 {
		t.Fatalf("expected selected col +1 after right, got %d->%d", startCol, m.selectedCol)
	}
	if m.selectedIdx != startRow {
		t.Fatalf("expected selected row unchanged after right, got %d->%d", startRow, m.selectedIdx)
	}

	if !m.HandleKey("l") {
		t.Fatalf("l should be handled while paused")
	}
	if m.selectedCol != startCol+2 {
		t.Fatalf("expected selected col +2 after l, got %d", m.selectedCol)
	}

	if !m.HandleKey("left") {
		t.Fatalf("left should be handled while paused")
	}
	if !m.HandleKey("h") {
		t.Fatalf("h should be handled while paused")
	}
	if m.selectedCol != startCol {
		t.Fatalf("expected selected col back to start, got %d", m.selectedCol)
	}
}

func TestPausedEnterDoesNotMutateGlobalFilter(t *testing.T) {
	rb := NewRingBuffer()
	rb.Push(StreamEvent{Seq: 1, PID: 1, TID: 1, Comm: "a", DurationNs: 100, GapNs: 5})
	rb.Push(StreamEvent{Seq: 2, PID: 1, TID: 2, Comm: "b", DurationNs: 200, GapNs: 6})
	m := NewModel(rb)
	m.height = 20
	m.Refresh()
	if !m.HandleKey("space") {
		t.Fatalf("space should pause")
	}

	m.selectedIdx = 0
	m.selectedCol = streamColLatency
	if m.HandleKey("enter") {
		t.Fatalf("expected enter not to mutate filters in paused stream mode")
	}
	if m.filter.IsActive() {
		t.Fatalf("expected enter to leave global filter unchanged")
	}
	if m.HandleKey("esc") {
		t.Fatalf("expected esc not to act as local filter undo anymore")
	}
}

func TestSetFilterKeepsPausedSelectionCentered(t *testing.T) {
	rb := NewRingBuffer()
	for i := 0; i < 300; i++ {
		comm := "other"
		if i >= 90 && i <= 210 {
			comm = "match"
		}
		rb.Push(StreamEvent{
			Seq:      uint64(i + 1),
			PID:      1000,
			TID:      uint32(2000 + i),
			Comm:     comm,
			Syscall:  "read",
			FileName: "/tmp/f",
		})
	}

	m := NewModel(rb)
	m.height = 20
	m.Refresh()
	_ = m.HandleKey("space")
	m.moveSelectionTo(150)
	before := m.selectedIdx - m.scrollOffset
	if before < 4 || before > 8 {
		t.Fatalf("expected initial selected row near middle, got relative idx %d", before)
	}

	m.SetFilter(Filter{Comm: &StringFilter{Pattern: "match"}})
	after := m.selectedIdx - m.scrollOffset
	if after < 4 || after > 8 {
		t.Fatalf("expected selected row to stay near middle after global refilter, got relative idx %d", after)
	}
}

func TestPausedQuickExportWritesFilteredRows(t *testing.T) {
	rb := NewRingBuffer()
	rb.Push(StreamEvent{Seq: 1, Comm: "firefox", PID: 10, TID: 100, Syscall: "read", FileName: "/a"})
	rb.Push(StreamEvent{Seq: 2, Comm: "bash", PID: 11, TID: 200, Syscall: "write", FileName: "/b"})
	rb.Push(StreamEvent{Seq: 3, Comm: "firefox", PID: 12, TID: 300, Syscall: "open", FileName: "/c"})

	m := NewModel(rb)
	m.height = 20
	m.setExportDirForTest(t.TempDir())
	m.Refresh()
	if !m.HandleKey("space") {
		t.Fatalf("space should pause")
	}

	m.SetFilter(Filter{Comm: &StringFilter{Pattern: "firefox"}})
	if len(m.filtered) != 2 {
		t.Fatalf("expected 2 filtered rows before export, got %d", len(m.filtered))
	}

	if !m.HandleKey("x") {
		t.Fatalf("x should quick-export while paused")
	}
	if m.lastExportPath == "" {
		t.Fatalf("expected last export path to be set")
	}
	records := readCSVRecords(t, m.lastExportPath)
	if len(records) != 3 {
		t.Fatalf("expected header + 2 rows in export, got %d records", len(records))
	}
	if records[1][4] != "firefox" || records[2][4] != "firefox" {
		t.Fatalf("expected only firefox rows exported, got %q and %q", records[1][4], records[2][4])
	}
}

func TestPausedExportAsModalSavesWithProvidedFilename(t *testing.T) {
	rb := NewRingBuffer()
	rb.Push(StreamEvent{Seq: 1, Comm: "proc", PID: 1, TID: 1, Syscall: "read"})
	m := NewModel(rb)
	m.height = 20
	m.setExportDirForTest(t.TempDir())
	m.Refresh()
	_ = m.HandleKey("space")

	if !m.HandleKey("X") {
		t.Fatalf("X should open export modal while paused")
	}
	if !m.exportModal.Visible() {
		t.Fatalf("expected export modal visible")
	}
	// Replace default value fully and submit.
	m.exportModal = m.exportModal.Open("custom-name")
	if !m.HandleKey("enter") {
		t.Fatalf("enter should submit export modal")
	}
	if m.exportModal.Visible() {
		t.Fatalf("expected export modal closed after submit")
	}
	if !strings.HasSuffix(m.lastExportPath, "custom-name.csv") {
		t.Fatalf("expected custom-name.csv export path, got %q", m.lastExportPath)
	}
	if _, err := os.Stat(m.lastExportPath); err != nil {
		t.Fatalf("expected exported file to exist: %v", err)
	}
}

func TestPausedOpenLastExportQueuesRequest(t *testing.T) {
	rb := NewRingBuffer()
	rb.Push(StreamEvent{Seq: 1, Comm: "proc", PID: 1, TID: 1, Syscall: "read"})
	m := NewModel(rb)
	m.height = 20
	m.setExportDirForTest(t.TempDir())
	m.Refresh()
	_ = m.HandleKey("space")
	_ = m.HandleKey("x")

	if !m.HandleKey("E") {
		t.Fatalf("E should queue opening last export while paused")
	}
	path, ok := m.ConsumeOpenEditorRequest()
	if !ok {
		t.Fatalf("expected queued open-editor request")
	}
	if path != m.lastExportPath {
		t.Fatalf("expected opened path %q, got %q", m.lastExportPath, path)
	}
	if _, ok := m.ConsumeOpenEditorRequest(); ok {
		t.Fatalf("expected request to be consumed once")
	}
}

func TestRegexSearchForwardBackwardAndRepeat(t *testing.T) {
	rb := NewRingBuffer()
	rb.Push(StreamEvent{Seq: 1, Comm: "alpha", PID: 10, TID: 100, Syscall: "read", FileName: "/tmp/a"})
	rb.Push(StreamEvent{Seq: 2, Comm: "beta", PID: 11, TID: 110, Syscall: "write", FileName: "/tmp/b"})
	rb.Push(StreamEvent{Seq: 3, Comm: "gamma", PID: 12, TID: 120, Syscall: "open", FileName: "/tmp/c"})
	rb.Push(StreamEvent{Seq: 4, Comm: "beta", PID: 13, TID: 130, Syscall: "close", FileName: "/tmp/d"})

	m := NewModel(rb)
	m.height = 20
	m.Refresh()
	_ = m.HandleKey("space")
	m.moveSelectionTo(0)

	if !m.HandleKey("/") {
		t.Fatalf("/ should open search modal")
	}
	if !m.searchModal.Visible() {
		t.Fatalf("expected search modal visible")
	}
	if !m.HandleKey("b") || !m.HandleKey("e") || !m.HandleKey("t") || !m.HandleKey("a") {
		t.Fatalf("expected term typing keys handled")
	}
	if !m.HandleKey("enter") {
		t.Fatalf("enter should submit search")
	}
	if m.selectedIdx != 1 {
		t.Fatalf("expected first forward beta hit at idx 1, got %d", m.selectedIdx)
	}
	if m.searchDirection != SearchForward {
		t.Fatalf("expected search direction forward")
	}

	if !m.HandleKey("n") {
		t.Fatalf("n should jump to next hit")
	}
	if m.selectedIdx != 3 {
		t.Fatalf("expected next forward beta hit at idx 3, got %d", m.selectedIdx)
	}

	if !m.HandleKey("N") {
		t.Fatalf("N should jump opposite direction")
	}
	if m.selectedIdx != 1 {
		t.Fatalf("expected opposite-direction beta hit at idx 1, got %d", m.selectedIdx)
	}

	if !m.HandleKey("?") {
		t.Fatalf("? should open backward search modal")
	}
	if !m.HandleKey("enter") {
		t.Fatalf("enter should submit backward search")
	}
	if m.selectedIdx != 3 {
		t.Fatalf("expected backward beta hit at idx 3, got %d", m.selectedIdx)
	}
	if m.searchDirection != SearchBackward {
		t.Fatalf("expected search direction backward")
	}
}

func readCSVRecords(t *testing.T, path string) [][]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open csv: %v", err)
	}
	defer f.Close()
	r := csv.NewReader(f)
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("read csv: %v", err)
	}
	return records
}
