package eventstream

import (
	"encoding/csv"
	"os"
	"strings"
	"testing"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/globalfilter"
	"ior/internal/globalfilter/presenter"
	"ior/internal/tui/messages"
	"ior/internal/types"

	tea "charm.land/bubbletea/v2"
)

func (m *Model) setFilterForTest(f Filter) {
	m.filter = f
}

func (m *Model) setExportDirForTest(dir string) {
	m.exportDir = dir
}

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

// TestPausedFooterRendersIndependentOfFooterVisible verifies the footer
// gating: the paused selection/column footer renders whenever the stream is
// paused, even with SetFooterVisible(false) (the dashboard help-bar state),
// while the live footer stays hidden until the help bar enables it.
func TestPausedFooterRendersIndependentOfFooterVisible(t *testing.T) {
	rb := NewRingBuffer()
	m := NewModel(rb)
	pushEvents(rb, 10)
	m.Refresh()

	// Footer hidden (help bar off) and live: no Row/Sel footer line.
	m.SetFooterVisible(false)
	if got := m.View(120, 24); strings.Contains(got, "Row ") {
		t.Fatalf("live + footer-hidden should not render the Row footer:\n%s", got)
	}

	// Pause and anchor a selection; the footer must render despite footer-hidden.
	if !pressLocal(t, &m, "space") {
		t.Fatalf("space should pause")
	}
	if !m.paused {
		t.Fatalf("expected paused state")
	}
	got := m.View(120, 24)
	if !strings.Contains(got, "Sel ") || !strings.Contains(got, "Col ") {
		t.Fatalf("paused stream must render Sel/Col footer regardless of SetFooterVisible(false):\n%s", got)
	}
	if !strings.Contains(got, "Enter push-filter") {
		t.Fatalf("paused footer should include the push-filter hint:\n%s", got)
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

	if !pressLocal(t, &m, "space") {
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
		pressLocal(t, &m, "j")
	}
	if m.scrollOffset > m.maxScrollOffset() {
		t.Fatalf("scrollOffset=%d exceeds max=%d", m.scrollOffset, m.maxScrollOffset())
	}

	for i := 0; i < 100; i++ {
		pressLocal(t, &m, "k")
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
	pressLocal(t, &m, "g")

	if !pressLocal(t, &m, "pgdown") {
		t.Fatalf("pgdown should be handled")
	}
	if m.scrollOffset != 3 {
		t.Fatalf("expected page down to move by 3, got %d", m.scrollOffset)
	}

	if !pressLocal(t, &m, "pagedown") {
		t.Fatalf("pagedown should be handled")
	}
	if m.scrollOffset != 6 {
		t.Fatalf("expected pagedown alias to move by 3, got %d", m.scrollOffset)
	}

	if !pressLocal(t, &m, "pgup") {
		t.Fatalf("pgup should be handled")
	}
	if m.scrollOffset != 3 {
		t.Fatalf("expected page up to move up by 3, got %d", m.scrollOffset)
	}
	if !pressLocal(t, &m, "pageup") {
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
	pressLocal(t, &m, "g")

	if !pressLocal(t, &m, "down") {
		t.Fatalf("down should be handled")
	}
	if m.scrollOffset != 1 {
		t.Fatalf("expected down to increment offset, got %d", m.scrollOffset)
	}
	if !pressLocal(t, &m, "j") {
		t.Fatalf("j should be handled")
	}
	if m.scrollOffset != 2 {
		t.Fatalf("expected j to increment offset, got %d", m.scrollOffset)
	}
	if !pressLocal(t, &m, "up") {
		t.Fatalf("up should be handled")
	}
	if m.scrollOffset != 1 {
		t.Fatalf("expected up to decrement offset, got %d", m.scrollOffset)
	}
	if !pressLocal(t, &m, "k") {
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

	pressLocal(t, &m, "k")
	prev := m.scrollOffset
	pushEvents(rb, 3)
	m.Refresh()
	if m.scrollOffset != prev {
		t.Fatalf("when autoScroll=false, offset should stay %d, got %d", prev, m.scrollOffset)
	}

	pressLocal(t, &m, "G")
	if m.scrollOffset != m.maxScrollOffset() {
		t.Fatalf("G should jump to tail")
	}
}

func TestModelHandleKeyRouting(t *testing.T) {
	rb := NewRingBuffer()
	m := NewModel(rb)

	if pressLocal(t, &m, "x") {
		t.Fatalf("unknown key should not be handled")
	}
	if pressLocal(t, &m, "f") {
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
	pressLocal(t, &m, "g")
	if m.autoScroll {
		t.Fatalf("expected autoScroll disabled at top")
	}
	pressLocal(t, &m, "space")
	if !m.paused {
		t.Fatalf("expected paused")
	}

	// New events arrive while paused.
	pushEvents(rb, 5)
	m.Refresh()

	// Resume: should auto-tail and refresh immediately.
	pressLocal(t, &m, "space")
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
	if !pressLocal(t, &m, "space") {
		t.Fatalf("space should toggle pause")
	}
	before := rowNumber(m.scrollOffset, len(m.filtered))
	if !pressLocal(t, &m, "k") {
		t.Fatalf("k should be handled while paused")
	}
	afterK := rowNumber(m.scrollOffset, len(m.filtered))
	if afterK >= before {
		t.Fatalf("expected k to scroll up while paused: before=%d after=%d", before, afterK)
	}
	if !pressLocal(t, &m, "pgup") {
		t.Fatalf("pgup should be handled while paused")
	}
	afterPgUp := rowNumber(m.scrollOffset, len(m.filtered))
	if afterPgUp >= afterK {
		t.Fatalf("expected pgup to scroll up while paused: afterK=%d afterPgUp=%d", afterK, afterPgUp)
	}
	if !pressLocal(t, &m, "pgdown") {
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

	if !pressLocal(t, &m, "space") {
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

	if !pressLocal(t, &m, "g") {
		t.Fatalf("g should be handled")
	}
	if !pressLocal(t, &m, "space") {
		t.Fatalf("space should toggle pause")
	}
	startSel := m.selectedIdx

	if !pressLocal(t, &m, "j") {
		t.Fatalf("j should be handled while paused")
	}
	if m.selectedIdx != startSel+1 {
		t.Fatalf("expected selected index +1 after j, got %d->%d", startSel, m.selectedIdx)
	}
	mid := m.visibleRows() / 2
	if m.scrollOffset != clamp(m.selectedIdx-mid, 0, m.maxScrollOffset()) {
		t.Fatalf("expected centered viewport after j")
	}

	if !pressLocal(t, &m, "up") {
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

	if !pressLocal(t, &m, "space") {
		t.Fatalf("space should toggle pause")
	}
	startCol := m.selectedCol
	startRow := m.selectedIdx

	if !pressLocal(t, &m, "right") {
		t.Fatalf("right should be handled while paused")
	}
	if m.selectedCol != startCol+1 {
		t.Fatalf("expected selected col +1 after right, got %d->%d", startCol, m.selectedCol)
	}
	if m.selectedIdx != startRow {
		t.Fatalf("expected selected row unchanged after right, got %d->%d", startRow, m.selectedIdx)
	}

	if !pressLocal(t, &m, "l") {
		t.Fatalf("l should be handled while paused")
	}
	if m.selectedCol != startCol+2 {
		t.Fatalf("expected selected col +2 after l, got %d", m.selectedCol)
	}

	if !pressLocal(t, &m, "left") {
		t.Fatalf("left should be handled while paused")
	}
	if !pressLocal(t, &m, "h") {
		t.Fatalf("h should be handled while paused")
	}
	if m.selectedCol != startCol {
		t.Fatalf("expected selected col back to start, got %d", m.selectedCol)
	}
}

func TestPausedEnterEmitsGlobalFilterRequestFromSelectedCell(t *testing.T) {
	rb := NewRingBuffer()
	rb.Push(StreamEvent{Seq: 1, PID: 1, TID: 1, Comm: "a", DurationNs: 100, GapNs: 5})
	rb.Push(StreamEvent{Seq: 2, PID: 1, TID: 2, Comm: "b", DurationNs: 200, GapNs: 6})
	m := NewModel(rb)
	m.height = 20
	m.Refresh()
	m.SetFilter(Filter{PID: &NumericFilter{Op: OpEq, Value: 1}})
	if !pressLocal(t, &m, "space") {
		t.Fatalf("space should pause")
	}

	m.selectedIdx = 0
	m.selectedCol = streamColComm
	req := pressRequest[messages.GlobalFilterRequestedMsg](t, &m, "enter")
	if m.filter.Comm != nil {
		t.Fatalf("expected local stream filter state to remain unchanged until parent applies it")
	}
	if req.Action != "comm~^a$" {
		t.Fatalf("expected action label comm~^a$, got %q", req.Action)
	}
	if req.Filter.PID == nil || req.Filter.PID.Op != OpEq || req.Filter.PID.Value != 1 {
		t.Fatalf("expected existing pid filter preserved, got %+v", req.Filter.PID)
	}
	if req.Filter.Comm == nil || req.Filter.Comm.Pattern != "^a$" {
		t.Fatalf("expected selected comm folded into global filter, got %+v", req.Filter.Comm)
	}
	if pressLocal(t, &m, "esc") {
		t.Fatalf("expected esc without a filter stack to fall through")
	}
}

// TestGlobalFilterRequestIsDetachedFromLocalFilter verifies the emitted
// filter is a snapshot: changing the stream's own filter after the key press
// but before the command runs must not leak into the request.
func TestGlobalFilterRequestIsDetachedFromLocalFilter(t *testing.T) {
	rb := NewRingBuffer()
	rb.Push(StreamEvent{Seq: 1, PID: 7, TID: 1, Comm: "a"})
	m := NewModel(rb)
	m.height = 20
	m.Refresh()
	m.SetFilter(Filter{Comm: &StringFilter{Pattern: "a"}})
	pressLocal(t, &m, "space")
	m.selectedIdx = 0
	m.selectedCol = streamColPID

	handled, cmd := m.HandleKey("enter")
	if !handled || cmd == nil {
		t.Fatalf("expected enter to be handled with a command, got handled=%v cmd=%v", handled, cmd != nil)
	}
	m.filter.Comm.Pattern = "mutated"
	m.SetFilter(Filter{})

	req, ok := cmd().(messages.GlobalFilterRequestedMsg)
	if !ok {
		t.Fatalf("expected GlobalFilterRequestedMsg")
	}
	if req.Filter.Comm == nil || req.Filter.Comm.Pattern != "a" {
		t.Fatalf("expected request to keep the comm filter from key-press time, got %+v", req.Filter.Comm)
	}
	if req.Filter.PID == nil || req.Filter.PID.Value != 7 || req.Action != "pid=7" {
		t.Fatalf("expected pid=7 request, got action=%q pid=%+v", req.Action, req.Filter.PID)
	}
}

// pressEnterOnCell pauses a stream holding only ev, selects column col of
// its row and presses enter, returning whether the key was handled and the
// command it produced.
func pressEnterOnCell(t *testing.T, ev StreamEvent, col int) (bool, tea.Cmd) {
	t.Helper()
	rb := NewRingBuffer()
	rb.Push(ev)
	m := NewModel(rb)
	m.height = 20
	m.Refresh()
	pressLocal(t, &m, "space")
	m.selectedIdx = 0
	m.selectedCol = col
	return m.HandleKey("enter")
}

// TestPausedEnterActionLabelPerColumn pins every column's action label to the
// presenter's canonical token for the dimension the column sets, so the undo
// stack reads exactly like the filter summary (durations included: the label
// uses time.Duration wording such as "1.5µs", not the table cell's "1.5us").
func TestPausedEnterActionLabelPerColumn(t *testing.T) {
	ev := StreamEvent{
		Seq: 1, PID: 11, TID: 12, Comm: "cc", Syscall: "openat", FD: 3,
		RetVal: -2, Bytes: 64, FileName: "/etc/x", DurationNs: 1500, GapNs: 40,
	}
	tests := []struct {
		col  int
		dim  presenter.Dimension
		want string
	}{
		{streamColGap, presenter.DimGap, "gap>=40ns"},
		{streamColLatency, presenter.DimLatency, "latency>=1.5µs"},
		{streamColComm, presenter.DimComm, "comm~^cc$"},
		{streamColPID, presenter.DimPID, "pid=11"},
		{streamColTID, presenter.DimTID, "tid=12"},
		{streamColSyscall, presenter.DimSyscall, "syscall~^openat$"},
		{streamColFD, presenter.DimFD, "fd=3"},
		{streamColRet, presenter.DimRet, "ret=-2"},
		{streamColBytes, presenter.DimBytes, "bytes=64"},
		{streamColFile, presenter.DimFile, "file~^/etc/x$"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			handled, cmd := pressEnterOnCell(t, ev, tt.col)
			if !handled || cmd == nil {
				t.Fatalf("column %d: expected enter to emit a request", tt.col)
			}
			req, ok := cmd().(messages.GlobalFilterRequestedMsg)
			if !ok {
				t.Fatalf("column %d: expected GlobalFilterRequestedMsg", tt.col)
			}
			if req.Action != tt.want {
				t.Fatalf("column %d: expected action %q, got %q", tt.col, tt.want, req.Action)
			}
			if canonical := presenter.DimensionSummary(req.Filter, tt.dim); req.Action != canonical {
				t.Fatalf("column %d: action %q differs from presenter token %q", tt.col, req.Action, canonical)
			}
			if !req.Filter.IsActive() {
				t.Fatalf("column %d: expected an active filter in the request", tt.col)
			}
		})
	}
}

// TestPausedEnterActionLabelEdgeValues covers values whose wording used to
// be hand-built: zero and negative numbers, sub-microsecond and multi-second
// durations, and string cells holding spaces or filter-syntax characters.
func TestPausedEnterActionLabelEdgeValues(t *testing.T) {
	tests := []struct {
		name string
		ev   StreamEvent
		col  int
		dim  presenter.Dimension
		want string
	}{
		{"zero gap", StreamEvent{Seq: 1, GapNs: 0}, streamColGap, presenter.DimGap, "gap>=0s"},
		{"seconds latency", StreamEvent{Seq: 1, DurationNs: 2_500_000_000}, streamColLatency, presenter.DimLatency, "latency>=2.5s"},
		{"odd latency", StreamEvent{Seq: 1, DurationNs: 1234}, streamColLatency, presenter.DimLatency, "latency>=1.234µs"},
		{"zero pid", StreamEvent{Seq: 1, PID: 0}, streamColPID, presenter.DimPID, "pid=0"},
		{"negative fd", StreamEvent{Seq: 1, FD: -1}, streamColFD, presenter.DimFD, "fd=-1"},
		{"zero bytes", StreamEvent{Seq: 1, Bytes: 0}, streamColBytes, presenter.DimBytes, "bytes=0"},
		{"comm with space and symbols", StreamEvent{Seq: 1, Comm: "kworker/0:1 ~x=y"}, streamColComm, presenter.DimComm, "comm~^kworker/0:1 ~x=y$"},
		{"comm with padding", StreamEvent{Seq: 1, Comm: "  sh  "}, streamColComm, presenter.DimComm, "comm~^  sh  $"},
		{"anchored file", StreamEvent{Seq: 1, FileName: "^/tmp/a b$"}, streamColFile, presenter.DimFile, "file~^^/tmp/a b$$"},
		{"unicode syscall", StreamEvent{Seq: 1, Syscall: "écrire"}, streamColSyscall, presenter.DimSyscall, "syscall~^écrire$"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handled, cmd := pressEnterOnCell(t, tt.ev, tt.col)
			if !handled || cmd == nil {
				t.Fatalf("expected enter to emit a request")
			}
			req, ok := cmd().(messages.GlobalFilterRequestedMsg)
			if !ok {
				t.Fatalf("expected GlobalFilterRequestedMsg")
			}
			if req.Action != tt.want {
				t.Fatalf("expected action %q, got %q", tt.want, req.Action)
			}
			if canonical := presenter.DimensionSummary(req.Filter, tt.dim); req.Action != canonical {
				t.Fatalf("action %q differs from presenter token %q", req.Action, canonical)
			}
		})
	}
}

// TestPausedEnterStringCellFilterIsExact checks what the pushed Comm, Syscall
// and File filters select, not just their labels: exactly the cell's value,
// case included (^value$ is case-sensitive), never a superstring of it, with
// edge blanks and a literal edge ^/$ kept literal. A bare substring pattern
// (the old behaviour) admitted readv for "read" and /tmp/ab for "/tmp/a",
// trimmed "/tmp/a " to "/tmp/a", and read "x$" as "ends with x".
func TestPausedEnterStringCellFilterIsExact(t *testing.T) {
	tests := []struct {
		name   string
		col    int
		with   func(string) StreamEvent
		value  string
		match  []string
		reject []string
	}{
		{"syscall", streamColSyscall, func(v string) StreamEvent { return StreamEvent{Seq: 1, Syscall: v} },
			"read", []string{"read"}, []string{"READ", "readv", "pread64", "rea", ""}},
		{"file", streamColFile, func(v string) StreamEvent { return StreamEvent{Seq: 1, FileName: v} },
			"/tmp/a", []string{"/tmp/a"}, []string{"/TMP/A", "/tmp/ab", "/var/tmp/a", "/tmp/a ", "/tmp"}},
		{"file with edge blank", streamColFile, func(v string) StreamEvent { return StreamEvent{Seq: 1, FileName: v} },
			"/tmp/a ", []string{"/tmp/a "}, []string{"/tmp/a", "/tmp/ab", "/tmp/a  "}},
		{"file with literal anchors", streamColFile, func(v string) StreamEvent { return StreamEvent{Seq: 1, FileName: v} },
			"^/tmp/x$", []string{"^/tmp/x$"}, []string{"/tmp/x", "^/tmp/x", "/tmp/x$", "^/tmp/x$y"}},
		{"comm", streamColComm, func(v string) StreamEvent { return StreamEvent{Seq: 1, Comm: v} },
			"sh", []string{"sh"}, []string{"SH", "bash", "sshd", "sh "}},
		{"comm with edge blanks", streamColComm, func(v string) StreamEvent { return StreamEvent{Seq: 1, Comm: v} },
			"  sh  ", []string{"  sh  "}, []string{"sh", " sh ", "  sh  x"}},
		{"comm with literal dollar", streamColComm, func(v string) StreamEvent { return StreamEvent{Seq: 1, Comm: v} },
			"x$", []string{"x$"}, []string{"x", "ax", "x$y"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handled, cmd := pressEnterOnCell(t, tt.with(tt.value), tt.col)
			if !handled || cmd == nil {
				t.Fatalf("expected enter to emit a request")
			}
			req, ok := cmd().(messages.GlobalFilterRequestedMsg)
			if !ok {
				t.Fatalf("expected GlobalFilterRequestedMsg")
			}
			for _, v := range tt.match {
				if ev := tt.with(v); !req.Filter.Matches(&ev) {
					t.Errorf("filter for %q (%s) should match %q", tt.value, req.Action, v)
				}
			}
			for _, v := range tt.reject {
				if ev := tt.with(v); req.Filter.Matches(&ev) {
					t.Errorf("filter for %q (%s) should not match %q", tt.value, req.Action, v)
				}
			}
		})
	}
}

// TestPausedEnterOnBlankStringCellIsNotHandled: a blank pattern constrains
// nothing (and has no presenter token), so enter on an empty comm, syscall or
// file cell must not push an empty undo layer.
func TestPausedEnterOnBlankStringCellIsNotHandled(t *testing.T) {
	for _, tt := range []struct {
		name string
		ev   StreamEvent
		col  int
	}{
		{"empty comm", StreamEvent{Seq: 1, PID: 5}, streamColComm},
		{"blank comm", StreamEvent{Seq: 1, PID: 5, Comm: "   "}, streamColComm},
		{"empty syscall", StreamEvent{Seq: 1, PID: 5}, streamColSyscall},
		{"empty file", StreamEvent{Seq: 1, PID: 5}, streamColFile},
		{"no-file placeholder", StreamEvent{Seq: 1, PID: 5, FileName: event.NoFileName, NoFile: true}, streamColFile},
	} {
		t.Run(tt.name, func(t *testing.T) {
			handled, cmd := pressEnterOnCell(t, tt.ev, tt.col)
			if handled || cmd != nil {
				t.Fatalf("expected blank cell enter to be ignored, got handled=%v cmd=%v", handled, cmd != nil)
			}
		})
	}
}

// TestPausedEnterOnFilelessPairRowPushesNoFilter is the task hp2 regression:
// a pair without a file renders its File cell as event.NoFileName, but the
// global filter reads that pair's file as "". Enter on the cell used to push
// ^N:file$, which kept the buffered placeholder rows yet rejected every new
// event, so the stream went silent. The placeholder must be treated like a
// blank cell. The MatchPair check pins the mismatch that made the old filter
// harmful; the last check shows a real file cell still yields a filter.
func TestPausedEnterOnFilelessPairRowPushesNoFilter(t *testing.T) {
	enter := &types.FdEvent{TraceId: types.SYS_ENTER_CLOSE, Time: 10, Pid: 5, Tid: 5, Fd: 3}
	pair := event.NewPair(enter)
	pair.ExitEv = &types.RetEvent{TraceId: types.SYS_EXIT_CLOSE, Time: 20, Pid: 5, Tid: 5}
	row := NewStreamEvent(1, pair)
	if row.FileName != event.NoFileName {
		t.Fatalf("fileless row FileName = %q, want %q", row.FileName, event.NoFileName)
	}

	handled, cmd := pressEnterOnCell(t, row, streamColFile)
	if handled || cmd != nil {
		t.Fatalf("enter on the no-file placeholder must push nothing, got handled=%v cmd=%v", handled, cmd != nil)
	}

	placeholderFilter := Filter{File: &StringFilter{Pattern: globalfilter.ExactPattern(event.NoFileName)}}
	if placeholderFilter.MatchPair(pair) {
		t.Fatalf("expected ^N:file$ to reject the live fileless pair (root cause changed?)")
	}

	withFile := row
	withFile.FileName = "/tmp/a"
	withFile.NoFile = false
	if handled, cmd := pressEnterOnCell(t, withFile, streamColFile); !handled || cmd == nil {
		t.Fatalf("enter on a real file cell must still push a filter")
	}
}

// TestRealFileNamedPlaceholderSurvivesFilterAndExport is the task zp2
// regression at the stream level: a row for a file really named "N:file"
// shows the same cell text as a fileless row, but filters on that name must
// keep it on the Stream refresh (as they keep the live pair) and in the CSV
// export, Enter on its cell must push the exact filter, and ^$ must not
// select it. The fileless row beside it is the control for the other side.
func TestRealFileNamedPlaceholderSurvivesFilterAndExport(t *testing.T) {
	closePair := func(f *file.FdFile) *event.Pair {
		enter := &types.FdEvent{TraceId: types.SYS_ENTER_CLOSE, Time: 10, Pid: 5, Tid: 5, Fd: 3}
		pair := event.NewPair(enter)
		pair.ExitEv = &types.RetEvent{TraceId: types.SYS_EXIT_CLOSE, Time: 20, Pid: 5, Tid: 5}
		if f != nil {
			pair.File = f
		}
		return pair
	}
	realPair := closePair(file.NewFd(3, event.NoFileName, 0))
	filelessPair := closePair(nil)
	realRow, filelessRow := NewStreamEvent(1, realPair), NewStreamEvent(2, filelessPair)

	rb := NewRingBuffer()
	rb.Push(realRow)
	rb.Push(filelessRow)
	m := NewModel(rb)
	m.height = 20
	m.Refresh()

	for pattern, wantReal := range map[string]bool{"N:file": true, "file": true, globalfilter.ExactPattern(event.NoFileName): true, "^$": false} {
		f := Filter{File: &StringFilter{Pattern: pattern}}
		m.SetFilter(f)
		var gotReal bool
		for _, ev := range m.filtered {
			gotReal = gotReal || ev.Seq == realRow.Seq
		}
		if gotReal != wantReal || f.MatchPair(realPair) != wantReal {
			t.Errorf("pattern %q: buffered keeps real row=%v, live pair=%v, want both %v", pattern, gotReal, f.MatchPair(realPair), wantReal)
		}
	}

	// The CSV export applies the same filter to the same buffered rows.
	path, err := exportSnapshotToCSV(rb, Filter{File: &StringFilter{Pattern: "^N:file$"}}, t.TempDir(), "zp2")
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read export: %v", err)
	}
	if lines := strings.Split(strings.TrimSpace(string(data)), "\n"); len(lines) != 2 {
		t.Fatalf("export must hold the header plus the one real-file row, got %q", data)
	}

	// Enter on the real file's cell constrains on its name; the fileless
	// row's cell (same text) pushes nothing.
	handled, cmd := pressEnterOnCell(t, realRow, streamColFile)
	if !handled || cmd == nil {
		t.Fatalf("enter on a real file named %q must push a filter, handled=%v", event.NoFileName, handled)
	}
	req, ok := cmd().(messages.GlobalFilterRequestedMsg)
	if !ok || req.Filter.File == nil || req.Filter.File.Pattern != globalfilter.ExactPattern(event.NoFileName) {
		t.Fatalf("expected ^N:file$ file filter, got %+v ok=%v", req.Filter.File, ok)
	}
	if !req.Filter.MatchPair(realPair) || req.Filter.MatchPair(filelessPair) {
		t.Fatalf("pushed filter must select the real file's pair and not the fileless one")
	}
	if handled, cmd := pressEnterOnCell(t, filelessRow, streamColFile); handled || cmd != nil {
		t.Fatalf("enter on the fileless row's identical-looking cell must push nothing")
	}
}

func TestEnterEmitsNoFilterRequestWithoutPausedSelection(t *testing.T) {
	rb := NewRingBuffer()
	rb.Push(StreamEvent{Seq: 1, PID: 1, TID: 1, Comm: "a"})
	m := NewModel(rb)
	m.height = 20
	m.Refresh()

	if pressLocal(t, &m, "enter") {
		t.Fatalf("enter on the live stream must fall through")
	}

	pressLocal(t, &m, "space")
	m.selectedCol = streamColumnCount // out of range: no column to filter on
	m.selectedIdx = 0
	if pressLocal(t, &m, "enter") {
		t.Fatalf("enter on an unknown column must fall through")
	}
}

func TestPausedEscEmitsGlobalFilterUndoWhenStackPresent(t *testing.T) {
	rb := NewRingBuffer()
	rb.Push(StreamEvent{Seq: 1, PID: 1, TID: 1, Comm: "a"})
	m := NewModel(rb)
	m.height = 20
	m.Refresh()
	m.SetFilterStack([]string{"comm~a"})
	if !pressLocal(t, &m, "space") {
		t.Fatalf("space should pause")
	}
	pressRequest[messages.GlobalFilterUndoRequestedMsg](t, &m, "esc")
	// Each press is its own request; nothing is buffered between them.
	pressRequest[messages.GlobalFilterUndoRequestedMsg](t, &m, "esc")
}

func TestUndoKeysFallThroughWithoutRequest(t *testing.T) {
	rb := NewRingBuffer()
	rb.Push(StreamEvent{Seq: 1, PID: 1, TID: 1, Comm: "a"})
	m := NewModel(rb)
	m.height = 20
	m.Refresh()

	// No filter stack: neither F nor esc has anything to undo.
	if pressLocal(t, &m, "F") {
		t.Fatalf("F without a filter stack must fall through")
	}
	pressLocal(t, &m, "space")
	if pressLocal(t, &m, "esc") {
		t.Fatalf("paused esc without a filter stack must fall through")
	}
	pressLocal(t, &m, "space") // back to live

	// Live stream with a stack: esc belongs to the parent, F still undoes.
	m.SetFilterStack([]string{"comm~a"})
	if pressLocal(t, &m, "esc") {
		t.Fatalf("live esc must fall through even with a filter stack")
	}
	pressRequest[messages.GlobalFilterUndoRequestedMsg](t, &m, "F")
}

func TestHandleTeaKeyEnterEmitsGlobalFilterRequest(t *testing.T) {
	rb := NewRingBuffer()
	rb.Push(StreamEvent{Seq: 1, PID: 1, TID: 1, Comm: "a"})
	m := NewModel(rb)
	m.height = 20
	m.Refresh()
	if handled, cmd := m.HandleTeaKey(tea.KeyPressMsg{Code: tea.KeySpace, Text: " "}); !handled || cmd != nil {
		t.Fatalf("space should pause without a command, got handled=%v cmd=%v", handled, cmd != nil)
	}
	m.selectedIdx = 0
	m.selectedCol = streamColComm

	handled, cmd := m.HandleTeaKey(tea.KeyPressMsg{Code: tea.KeyEnter})
	if !handled || cmd == nil {
		t.Fatalf("expected enter to be handled with a command, got handled=%v cmd=%v", handled, cmd != nil)
	}
	if req, ok := cmd().(messages.GlobalFilterRequestedMsg); !ok || req.Action != "comm~^a$" {
		t.Fatalf("expected comm~^a$ GlobalFilterRequestedMsg, got %#v", cmd())
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
	_ = pressLocal(t, &m, "space")
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
	if !pressLocal(t, &m, "space") {
		t.Fatalf("space should pause")
	}

	m.SetFilter(Filter{Comm: &StringFilter{Pattern: "firefox"}})
	if len(m.filtered) != 2 {
		t.Fatalf("expected 2 filtered rows before export, got %d", len(m.filtered))
	}

	if !pressLocal(t, &m, "x") {
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

// TestPausedQuickExportDisabledByExportFlag regresses audit finding M10: with
// -tuiExport=false the paused-stream x shortcut must not write an export CSV,
// must not open the export modal, and must fall through as unhandled.
func TestPausedQuickExportDisabledByExportFlag(t *testing.T) {
	rb := NewRingBuffer()
	rb.Push(StreamEvent{Seq: 1, Comm: "firefox", PID: 10, TID: 100, Syscall: "read", FileName: "/a"})

	exportDir := t.TempDir()
	m := NewModel(rb)
	m.height = 20
	m.SetExportEnabled(false)
	m.setExportDirForTest(exportDir)
	m.Refresh()
	if !pressLocal(t, &m, "space") {
		t.Fatalf("space should pause")
	}

	if pressLocal(t, &m, "x") {
		t.Fatalf("x must fall through as unhandled when export is disabled")
	}
	if m.lastExportPath != "" {
		t.Fatalf("expected no export path when export is disabled, got %q", m.lastExportPath)
	}
	if strings.Contains(m.statusMessage, "Export") {
		t.Fatalf("expected no export status when export is disabled, got %q", m.statusMessage)
	}
	if m.exportModal.Visible() {
		t.Fatalf("x must not open the export modal when export is disabled")
	}
	if pressLocal(t, &m, "X") {
		t.Fatalf("X must fall through as unhandled when export is disabled")
	}
	if m.exportModal.Visible() {
		t.Fatalf("X must not open the export modal when export is disabled")
	}
	if pressLocal(t, &m, "E") {
		t.Fatalf("E must fall through as unhandled when export is disabled")
	}
	if strings.Contains(m.statusMessage, "editor") || strings.Contains(m.statusMessage, "No stream export") {
		t.Fatalf("E must not set an open-in-editor status when export is disabled, got %q", m.statusMessage)
	}

	entries, err := os.ReadDir(exportDir)
	if err != nil {
		t.Fatalf("read export dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected no exported files in export dir, got %d entries", len(entries))
	}
}

func TestPausedExportAsModalSavesWithProvidedFilename(t *testing.T) {
	rb := NewRingBuffer()
	rb.Push(StreamEvent{Seq: 1, Comm: "proc", PID: 1, TID: 1, Syscall: "read"})
	m := NewModel(rb)
	m.height = 20
	m.setExportDirForTest(t.TempDir())
	m.Refresh()
	_ = pressLocal(t, &m, "space")

	if !pressLocal(t, &m, "X") {
		t.Fatalf("X should open export modal while paused")
	}
	if !m.exportModal.Visible() {
		t.Fatalf("expected export modal visible")
	}
	// Replace default value fully and submit.
	m.exportModal = m.exportModal.Open("custom-name")
	if !pressLocal(t, &m, "enter") {
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

func TestPausedOpenLastExportEmitsEditorRequest(t *testing.T) {
	rb := NewRingBuffer()
	rb.Push(StreamEvent{Seq: 1, Comm: "proc", PID: 1, TID: 1, Syscall: "read"})
	m := NewModel(rb)
	m.height = 20
	m.setExportDirForTest(t.TempDir())
	m.Refresh()
	_ = pressLocal(t, &m, "space")
	_ = pressLocal(t, &m, "x")
	if m.lastExportPath == "" {
		t.Fatalf("expected x to export before E")
	}

	req := pressRequest[messages.OpenEditorRequestedMsg](t, &m, "E")
	if req.Path != m.lastExportPath {
		t.Fatalf("expected opened path %q, got %q", m.lastExportPath, req.Path)
	}
	if m.statusMessage != "Opening in editor: "+m.lastExportPath {
		t.Fatalf("expected opening status, got %q", m.statusMessage)
	}
}

func TestOpenLastExportWithoutRequest(t *testing.T) {
	rb := NewRingBuffer()
	rb.Push(StreamEvent{Seq: 1, Comm: "proc", PID: 1, TID: 1, Syscall: "read"})
	m := NewModel(rb)
	m.height = 20
	m.setExportDirForTest(t.TempDir())
	m.Refresh()

	if pressLocal(t, &m, "E") {
		t.Fatalf("E on the live stream must fall through")
	}

	_ = pressLocal(t, &m, "space")
	if !pressLocal(t, &m, "E") {
		t.Fatalf("E while paused should be consumed even without an export")
	}
	if m.statusMessage != "No stream export yet" {
		t.Fatalf("expected no-export status, got %q", m.statusMessage)
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
	_ = pressLocal(t, &m, "space")
	m.moveSelectionTo(0)

	if !pressLocal(t, &m, "/") {
		t.Fatalf("/ should open search modal")
	}
	if !m.searchModal.Visible() {
		t.Fatalf("expected search modal visible")
	}
	if !pressLocal(t, &m, "b") || !pressLocal(t, &m, "e") || !pressLocal(t, &m, "t") || !pressLocal(t, &m, "a") {
		t.Fatalf("expected term typing keys handled")
	}
	if !pressLocal(t, &m, "enter") {
		t.Fatalf("enter should submit search")
	}
	if m.selectedIdx != 1 {
		t.Fatalf("expected first forward beta hit at idx 1, got %d", m.selectedIdx)
	}
	if m.searchDirection != SearchForward {
		t.Fatalf("expected search direction forward")
	}

	if !pressLocal(t, &m, "n") {
		t.Fatalf("n should jump to next hit")
	}
	if m.selectedIdx != 3 {
		t.Fatalf("expected next forward beta hit at idx 3, got %d", m.selectedIdx)
	}

	if !pressLocal(t, &m, "N") {
		t.Fatalf("N should jump opposite direction")
	}
	if m.selectedIdx != 1 {
		t.Fatalf("expected opposite-direction beta hit at idx 1, got %d", m.selectedIdx)
	}

	if !pressLocal(t, &m, "?") {
		t.Fatalf("? should open backward search modal")
	}
	if !pressLocal(t, &m, "enter") {
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
	defer func() { _ = f.Close() }()
	r := csv.NewReader(f)
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("read csv: %v", err)
	}
	return records
}

// TestModelFilterMatchesRenameOnEitherName pins that the Stream tab applies the
// same either-name file semantics as the event loop and the dashboard ingest
// stage. A rename row's FileValue is its newname, so filtering it with plain
// Matches would hide a row the aggregates on every other tab already counted —
// and would drop it from the CSV export too.
func TestModelFilterMatchesRenameOnEitherName(t *testing.T) {
	rb := NewRingBuffer()
	rb.Push(StreamEvent{
		Seq:      1,
		Syscall:  "renameat2",
		Comm:     "mv",
		FileName: "/tmp/new.txt",
		OldName:  "/tmp/old.txt",
	})
	m := NewModel(rb)
	m.height = 20
	m.Refresh()

	m.setFilterForTest(Filter{File: &StringFilter{Pattern: "old.txt"}})
	m.applyFilter()
	if len(m.filtered) != 1 {
		t.Fatalf("a rename matched on its oldname must stay visible in the Stream tab, got %d rows", len(m.filtered))
	}

	m.setFilterForTest(Filter{File: &StringFilter{Pattern: "new.txt"}})
	m.applyFilter()
	if len(m.filtered) != 1 {
		t.Fatalf("a rename matched on its newname must stay visible, got %d rows", len(m.filtered))
	}

	// Widening the file dimension must not become a bypass.
	m.setFilterForTest(Filter{File: &StringFilter{Pattern: "unrelated.txt"}})
	m.applyFilter()
	if len(m.filtered) != 0 {
		t.Fatalf("a pattern matching neither name must hide the row, got %d rows", len(m.filtered))
	}
	m.setFilterForTest(Filter{
		File:    &StringFilter{Pattern: "old.txt"},
		Syscall: &StringFilter{Pattern: "openat"},
	})
	m.applyFilter()
	if len(m.filtered) != 0 {
		t.Fatalf("an oldname match must not bypass the other dimensions, got %d rows", len(m.filtered))
	}
}

// pressLocal sends keyStr to m and reports whether it was consumed. It fails
// the test if the key returns a command: navigation, modal and export keys
// act on local stream state only and must not emit a request to the parent.
func pressLocal(t *testing.T, m *Model, keyStr string) bool {
	t.Helper()
	handled, cmd := m.HandleKey(keyStr)
	if cmd != nil {
		t.Fatalf("key %q: expected no command, got one emitting %#v", keyStr, cmd())
	}
	return handled
}

// pressRequest sends keyStr to m, requires it to be consumed with a command,
// and returns the message the command emits, which must be of type T.
func pressRequest[T tea.Msg](t *testing.T, m *Model, keyStr string) T {
	t.Helper()
	handled, cmd := m.HandleKey(keyStr)
	if !handled {
		t.Fatalf("key %q: expected to be consumed", keyStr)
	}
	if cmd == nil {
		t.Fatalf("key %q: expected a command emitting %T", keyStr, *new(T))
	}
	msg, ok := cmd().(T)
	if !ok {
		t.Fatalf("key %q: expected %T, got %#v", keyStr, *new(T), cmd())
	}
	return msg
}

// Task 4r2: HandleKey takes key names and cannot carry a bracketed paste, so
// HandlePaste is the stream's entry point for one.
func TestHandlePasteFillsTheSearchModalAndSubmitsIt(t *testing.T) {
	rb := NewRingBuffer()
	pushEvents(rb, 10)
	m := NewModel(rb)
	m.height = 20
	m.Refresh()
	if !pressLocal(t, &m, "/") || !m.SearchModalVisible() {
		t.Fatalf("expected / to open the search modal")
	}
	if !m.HandlePaste(tea.PasteMsg{Content: "rea[d]"}) {
		t.Fatalf("expected the paste to be consumed by the search modal")
	}
	if !pressLocal(t, &m, "enter") {
		t.Fatalf("expected enter to submit the pasted pattern")
	}
	if m.searchPattern != "rea[d]" || m.searchRegex == nil {
		t.Fatalf("expected the pasted pattern to be searched, got %q", m.searchPattern)
	}
}

func TestHandlePasteFillsTheExportModal(t *testing.T) {
	rb := NewRingBuffer()
	pushEvents(rb, 3)
	m := NewModel(rb)
	m.height = 20
	m.Refresh()
	pressLocal(t, &m, "space")
	if !pressLocal(t, &m, "X") || !m.ExportModalVisible() {
		t.Fatalf("expected X to open the export modal while paused")
	}
	m.exportModal = m.exportModal.Open("") // drop the default filename so the assertion is exact
	if !m.HandlePaste(tea.PasteMsg{Content: "out.csv"}) {
		t.Fatalf("expected the paste to be consumed by the export modal")
	}
	if got := m.exportModal.textInput.Value(); got != "out.csv" {
		t.Fatalf("export filename = %q, want out.csv", got)
	}
}

// With no modal open every key is a stream command (space pauses, / opens
// search, ...), so a paste is refused and must change nothing.
func TestHandlePasteWithoutModalIsRefused(t *testing.T) {
	rb := NewRingBuffer()
	pushEvents(rb, 3)
	m := NewModel(rb)
	m.Refresh()
	if m.HandlePaste(tea.PasteMsg{Content: " /X"}) {
		t.Fatalf("a paste with no modal open must not be consumed")
	}
	if m.Paused() || m.SearchModalVisible() || m.ExportModalVisible() {
		t.Fatalf("a paste ran stream commands: paused=%v search=%v export=%v",
			m.Paused(), m.SearchModalVisible(), m.ExportModalVisible())
	}
}

// Task 3r2: the FD-trace overlay owns the keyboard like the two stream modals.
// A key it has no meaning for used to report "not handled", so the dashboard
// then ran its own tab/view/reset shortcuts on the screen hidden behind it.
func TestFDTraceOverlayConsumesEveryKey(t *testing.T) {
	rb := NewRingBuffer()
	pushEvents(rb, 5)
	for i := 0; i < 5; i++ {
		rb.Push(StreamEvent{Seq: uint64(100 + i), Syscall: "read", Comm: "proc", PID: 100, FD: 7})
	}
	m := NewModel(rb)
	m.Refresh()
	if !pressLocal(t, &m, "space") || !m.paused {
		t.Fatalf("expected space to pause the stream")
	}
	m.selectedIdx = len(m.filtered) - 1
	if !pressLocal(t, &m, "T") || !m.FDTraceVisible() {
		t.Fatalf("expected T to open the FD-trace overlay on an fd row")
	}
	for _, k := range []string{"tab", "shift+tab", "1", "7", "v", "b", "r", "R", "f", "/", "x", "X", "E", "F", "q!"} {
		if !pressLocal(t, &m, k) {
			t.Fatalf("overlay did not consume %q: it would reach the dashboard behind it", k)
		}
		if !m.FDTraceVisible() {
			t.Fatalf("key %q closed the overlay", k)
		}
	}
	if m.SearchModalVisible() || m.ExportModalVisible() {
		t.Fatalf("a key opened a modal behind the overlay")
	}
	for _, k := range []string{"q", "esc"} {
		m.fdTraceView.visible = true
		if !pressLocal(t, &m, k) || m.FDTraceVisible() {
			t.Fatalf("expected %q to close the overlay", k)
		}
	}
}
