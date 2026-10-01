package dashboard

import (
	"fmt"
	"strings"
	"testing"
	"time"

	coreflamegraph "ior/internal/flamegraph"
	"ior/internal/statsengine"
	common "ior/internal/tui/common"
	"ior/internal/tui/eventstream"
	"ior/internal/tui/messages"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

// tallSnapshot returns a snapshot whose every panel has content: many
// histogram buckets, sparkline series, and ranked syscalls, files and
// processes, so no tab can fit in a small terminal by being empty.
func tallSnapshot() *statsengine.Snapshot {
	var buckets []statsengine.HistogramBucketSnapshot
	for i := range 14 {
		buckets = append(buckets, statsengine.HistogramBucketSnapshot{
			Label: fmt.Sprintf("[%dus,%dus)", 1<<i, 1<<(i+1)),
			Count: uint64(i + 1),
		})
	}
	hist := statsengine.NewHistogramSnapshot(105, buckets)
	var syscalls []statsengine.SyscallSnapshot
	var files []statsengine.FileSnapshot
	var procs []statsengine.ProcessSnapshot
	for i := range 40 {
		syscalls = append(syscalls, statsengine.SyscallSnapshot{Name: fmt.Sprintf("sys%d", i), Count: uint64(100 - i)})
		files = append(files, statsengine.FileSnapshot{Path: fmt.Sprintf("/data/dir%d/file%d", i%5, i), Accesses: uint64(100 - i)})
		procs = append(procs, statsengine.ProcessSnapshot{PID: uint32(1000 + i), Comm: fmt.Sprintf("proc%d", i), Syscalls: uint64(100 - i)})
	}
	series := []float64{10, 20, 15, 30, 18, 35, 22, 40}
	snap := statsengine.NewSnapshot(series, series, series, syscalls, files, procs, hist, hist)
	snap.Elapsed = 95 * time.Second
	snap.TotalSyscalls = 1200
	return &snap
}

// fitCase is one cell of the height-fit matrix: a tab in one of its
// visualization modes (and, for Files, one of its table groupings).
type fitCase struct {
	tab     Tab
	mode    tabVizMode
	grouped bool
	// paused freezes the stream, which turns its selection footer on
	// whether or not the help bar is expanded.
	paused bool
}

func (c fitCase) String() string {
	return fmt.Sprintf("%s/mode=%d/grouped=%v/paused=%v", c.tab, c.mode, c.grouped, c.paused)
}

// fitCases lists every tab in every visualization mode it offers, so the
// bubble, treemap and icicle views are held to the height budget too, not only
// the default tables. The Files tab offers them only with directory grouping,
// which it also gets as a table.
func fitCases() []fitCase {
	var cases []fitCase
	for _, tab := range orderedTabs() {
		for _, mode := range lookupTab(tab).AllowedVizModes {
			grouped := tab == TabFiles && mode != tabVizModeTable
			cases = append(cases, fitCase{tab: tab, mode: mode, grouped: grouped})
			if tab == TabFiles && mode == tabVizModeTable {
				cases = append(cases, fitCase{tab: tab, mode: mode, grouped: true})
			}
			if tab == TabStream {
				cases = append(cases, fitCase{tab: tab, mode: mode, paused: true})
			}
		}
	}
	return cases
}

// TestEveryTabFitsTheTerminalHeight pins that the dashboard View never
// renders more lines than the terminal has rows, for every tab and
// visualization mode, at every height from 1 to 30 rows and four widths (20
// to 200 columns), with and without the expanded help. An over-tall frame
// scrolls the terminal and pushes the chrome status line (filter, refusal
// notice, recording, auto-reset) off the bottom, which is the one line that
// cannot be seen any other way. Whatever the height, the tab bar stays the
// first line, the status line the last, the body in between is the tab's own
// unclipped output (or the notice), and no line is wider than the terminal
// (see assertViewFits).
func TestEveryTabFitsTheTerminalHeight(t *testing.T) {
	widths := []int{20, 60, 100, 200}
	for _, c := range fitCases() {
		for _, help := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/help=%v", c, help), func(t *testing.T) {
				for _, width := range widths {
					for height := 1; height <= 30; height++ {
						assertViewFits(t, c, help, width, height)
					}
				}
			})
		}
	}
}

// The Latency+Gaps panels are at least ~26 columns wide in their compact
// layout, so on narrower terminals they used to soft-wrap their title and
// bucket rows: the panel grew past its row budget, was cut mid-row without its
// bottom border, and the shown counts no longer added up to total= (task
// ps2). Swept from 1 to 28 columns at every height and help state: the frame
// contract holds (no line wider than the terminal), every histogram drawn is
// whole with counts summing to its total, and once the width admits the
// compact layout and the body the tab, a histogram is drawn rather than the
// "terminal too narrow" notice.
func TestLatencyTabFitsNarrowTerminals(t *testing.T) {
	c := fitCase{tab: TabLatency, mode: tabVizModeTable}
	snap := tallSnapshot()
	minWidth := max(histogramMinWidth(snap.LatencyHistogram, latencyHistogramSpec),
		histogramMinWidth(snap.GapHistogram, gapHistogramSpec))
	for _, help := range []bool{false, true} {
		t.Run(fmt.Sprintf("help=%v", help), func(t *testing.T) {
			for width := 1; width <= 28; width++ {
				for height := 1; height <= 30; height++ {
					assertViewFits(t, c, help, width, height)
					m := newFitModel(t, c, help, width, height)
					rows := splitFrameRows(height, lipgloss.Height(m.renderStatusBlock(width)))
					drawn := len(drawnHistograms(t, m.View().Content)) > 0
					if want := width >= minWidth && rows.body >= latencyMinRows; drawn != want {
						t.Fatalf("help=%v %dx%d (body %d, panel needs %d columns): histogram drawn = %v, want %v:\n%s",
							help, width, height, rows.body, minWidth, drawn, want, m.View().Content)
					}
				}
			}
		})
	}
}

// newFitModel returns a dashboard on c's tab and mode at width x height with
// every panel populated: the stats snapshot (tallSnapshot), a flamegraph live
// trie and a stream ring buffer. Without the last two the Flame and Stream
// tabs would render their small empty states and prove nothing. The model is
// sized and the help toggled through Update, as the runtime does, so the
// sub-models' viewports and the stream footer are in sync with the frame.
func newFitModel(t *testing.T, c fitCase, help bool, width, height int) *Model {
	t.Helper()
	rb := eventstream.NewRingBuffer()
	for range 200 {
		rb.Push(eventstream.StreamEvent{Syscall: "read", Comm: "proc", PID: 1234})
	}
	liveTrie := coreflamegraph.NewLiveTrie([]string{"comm", "path"}, "count", "count")
	coreflamegraph.SeedTestLiveFlameData(liveTrie, 0)

	m := NewModelWithConfig(nil, rb, 250, 200, common.DefaultKeyMap())
	m.activeTab = c.tab
	m.filesDirGrouped = c.grouped
	m.setTabVizMode(c.tab, c.mode)
	m.SetLiveTrie(liveTrie)
	m.streamModel.SetSource(rb)
	m.streamModel.Refresh()
	if help {
		next, _ := m.Update(tea.KeyPressMsg{Code: tea.KeyF1})
		m = next.(*Model)
	}
	next, _ := m.Update(tea.WindowSizeMsg{Width: width, Height: height})
	m = next.(*Model)
	if c.paused {
		next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeySpace, Text: " "})
		m = next.(*Model)
		if !m.streamModel.Paused() {
			t.Fatal("space did not pause the stream")
		}
	}
	return tickStats(t, m, messages.StatsTickMsg{Snap: tallSnapshot()})
}

// assertViewFits renders one cell of the matrix and holds it to the frame
// contract (assertFrameFits); a Latency+Gaps frame must also show its
// histograms whole (assertHistogramsWhole).
func assertViewFits(t *testing.T, c fitCase, help bool, width, height int) {
	t.Helper()
	m := newFitModel(t, c, help, width, height)
	label := fmt.Sprintf("%s help=%v %dx%d", c, help, width, height)
	assertFrameFits(t, m, c, label, width, height)
	if c.tab == TabLatency {
		assertHistogramsWhole(t, label, m.View().Content)
	}
}

// assertFrameFits holds m's View output to the frame contract: never taller
// than the terminal, the tab bar (when it has a row) first, the status line
// last, the "terminal too small" notice exactly below the tab's minimum, and
// otherwise the tab's own unclipped output as the body. The whole frame is
// compared with one built from those parts, so a View that dropped, moved or
// clipped any of them fails here rather than passing on the line count alone.
// It returns whether the body is the notice, so callers can compare the body
// kind across state changes.
func assertFrameFits(t *testing.T, m *Model, c fitCase, label string, width, height int) bool {
	t.Helper()
	out := m.View().Content
	if got := lipgloss.Height(out); got > height {
		t.Fatalf("%s: View is %d lines, terminal has %d:\n%s", label, got, height, out)
	}
	lines := strings.Split(out, "\n")
	status := m.renderStatusBlock(width)
	// The status line is the status block's last line. From 20 columns it
	// visibly starts the filter summary; narrower it is cut to the width
	// like every other line, so only its identity is checked there.
	last := plainLine(lines[len(lines)-1])
	if last != plainLine(clipTailLines(status, 1)) || (width >= 20 && !strings.Contains(last, "filter:")) {
		t.Fatalf("%s: last line is not the status line: %q", label, lines[len(lines)-1])
	}
	rows := splitFrameRows(height, lipgloss.Height(status))
	tabBar := renderTabBar(m.activeTab, width)
	if rows.tabBar > 0 && plainLine(lines[0]) != plainLine(tabBar) {
		t.Fatalf("%s: first line is not the tab bar: %q", label, lines[0])
	}
	assertNoticeThreshold(t, m, label, out, width, rows.body)
	want := expectedFrame(rows, tabBar, expectedBody(t, m, label, width, height, rows.body), status)
	if out != want {
		t.Fatalf("%s: View differs from tab bar + tab output + status:\n--- got\n%s\n--- want\n%s", label, out, want)
	}
	assertFrameWidth(t, c, label, lines, rows, width)
	return rows.body > 0 && rows.body < m.minBodyRowsFor(m.activeTab)
}

// plainLine is a rendered line without its styling and the trailing padding
// lipgloss adds when it aligns a block to its widest line.
func plainLine(s string) string {
	return strings.TrimRight(ansi.Strip(s), " ")
}

// assertNoticeThreshold checks that the notice is shown exactly when the body
// has rows, but fewer than the active tab's minimum.
func assertNoticeThreshold(t *testing.T, m *Model, label, out string, width, body int) {
	t.Helper()
	tooSmall := strings.Contains(out, tooSmallNotice(width))
	switch min := m.minBodyRowsFor(m.activeTab); {
	case body >= min && tooSmall:
		t.Fatalf("%s: %d body rows (minimum %d) but the too-small notice is shown:\n%s", label, body, min, out)
	case body > 0 && body < min && !tooSmall:
		t.Fatalf("%s: %d body rows is below the minimum %d but no notice is shown:\n%s", label, body, min, out)
	}
}

// expectedBody is what View must draw as the body of a body-row budget: the
// notice below the tab's minimum, else the active tab rendered the way
// renderBody sizes it (its content viewport capped at the budget) but without
// the final clip. That output must fit the budget on its own, so a tab that
// only fits because clipLines cut its bottom (a panel without its border, a
// table without its hint line) fails instead of passing unnoticed.
func expectedBody(t *testing.T, m *Model, label string, width, height, body int) string {
	t.Helper()
	if body < m.minBodyRowsFor(m.activeTab) {
		return clipLines(tooSmallNotice(width), body)
	}
	_, activeHeight := m.contentViewport(m.activeTab, width, height)
	raw := m.renderActiveContent(width, min(activeHeight, body), &m.streamModel, m.flamegraphModel)
	if got := lipgloss.Height(raw); got > body {
		t.Fatalf("%s: tab drew %d rows into a %d-row body (only the clip saved the frame):\n%s", label, got, body, raw)
	}
	return raw
}

// expectedFrame stacks the parts that have rows in the frame - tab bar, body,
// the tail of the status block - and styles them like View does.
func expectedFrame(rows frameRows, tabBar, body, status string) string {
	var parts []string
	if rows.tabBar > 0 {
		parts = append(parts, tabBar)
	}
	if rows.body > 0 {
		parts = append(parts, body)
	}
	parts = append(parts, clipTailLines(status, rows.status))
	return common.Current().ScreenStyle.Render(strings.Join(parts, "\n"))
}

// assertFrameWidth checks that no line of the frame is wider than the
// terminal, which would soft-wrap into extra rows and break the height
// guarantee. Only the body lines of the Syscalls, Files and Processes table
// views are exempt: their fixed column widths are wider than narrow terminals
// today, which is task cz2 (clamp the table columns to the width), not this
// budget. Their tab bar and status lines are still checked, without the
// trailing blanks View's ScreenStyle pads every line with up to the widest
// (body) line: that padding is the same cz2 overflow, not theirs.
func assertFrameWidth(t *testing.T, c fitCase, label string, lines []string, rows frameRows, width int) {
	t.Helper()
	wide := knownWideTable(c)
	bodyStart, bodyEnd := rows.tabBar, rows.tabBar+rows.body
	for i, line := range lines {
		if wide && i >= bodyStart && i < bodyEnd {
			continue
		}
		measured := line
		if wide {
			measured = plainLine(line)
		}
		if w := lipgloss.Width(measured); w > width {
			t.Fatalf("%s: line %d is %d cells wide, terminal has %d: %q", label, i, w, width, line)
		}
	}
}

// knownWideTable reports whether c is a table view tracked by task cz2.
func knownWideTable(c fitCase) bool {
	switch c.tab {
	case TabSyscalls, TabFiles, TabProcesses:
		return c.mode == tabVizModeTable
	}
	return false
}

func TestClipLines(t *testing.T) {
	for _, tc := range []struct {
		in     string
		height int
		want   string
	}{
		{"a\nb\nc", 2, "a\nb"},
		{"a\nb\nc", 3, "a\nb\nc"},
		{"a\nb\nc", 9, "a\nb\nc"},
		{"a\nb\nc", 1, "a"},
		{"a\nb\nc", 0, "a\nb\nc"}, // <= 0 is unbounded
		{"a\nb\n", 2, "a\nb"},
		{"", 2, ""},
	} {
		if got := clipLines(tc.in, tc.height); got != tc.want {
			t.Errorf("clipLines(%q, %d) = %q, want %q", tc.in, tc.height, got, tc.want)
		}
	}
}

func TestFitBlocksDropsLowPriorityBlocksWhole(t *testing.T) {
	blocks := []string{"a1\na2", "b1", "c1\nc2\nc3"}
	for _, tc := range []struct {
		height int
		want   string
	}{
		{0, "a1\na2\nb1\nc1\nc2\nc3"},
		{6, "a1\na2\nb1\nc1\nc2\nc3"},
		{5, "a1\na2\nb1"}, // c does not fit whole, so it is dropped, not cut
		{3, "a1\na2\nb1"},
		{2, "a1\na2"},
		{1, "a1"}, // even the first block is clipped, never exceeded
	} {
		if got := fitBlocks(blocks, tc.height); got != tc.want {
			t.Errorf("fitBlocks(height=%d) = %q, want %q", tc.height, got, tc.want)
		}
	}
}

// The clamp arithmetic rests on a histogram panel spending exactly
// histogramChromeRows rows besides its buckets.
func TestHistogramChromeRowsMatchesRenderedPanel(t *testing.T) {
	snap := tallSnapshot()
	out := renderHistogram(snap.LatencyHistogram, latencyHistogramSpec, 100, 0)
	if got, want := lipgloss.Height(out), len(snap.LatencyHistogram.Buckets())+histogramChromeRows; got != want {
		t.Fatalf("unbounded histogram is %d rows, want buckets+chrome = %d", got, want)
	}
	for _, height := range []int{5, 6, 9, 12} {
		out := renderHistogram(snap.LatencyHistogram, latencyHistogramSpec, 100, height)
		if got := lipgloss.Height(out); got != height {
			t.Errorf("renderHistogram(height=%d) is %d rows, want exactly the budget", height, got)
		}
	}
	// The compact layout (27 columns leave no room for a 4-cell bar beside
	// the 16-cell labels) has no legend: histogramCompactChromeRows rows of
	// chrome, and the row it saves goes to a bucket.
	const compactWidth = 27
	if layout, ok := planHistogramLayout(snap.LatencyHistogram, latencyHistogramSpec, compactWidth); !ok || !layout.compact {
		t.Fatalf("width %d: layout %+v, ok=%v; want the compact layout", compactWidth, layout, ok)
	}
	for _, height := range []int{4, 5, 9, 12} {
		out := renderHistogram(snap.LatencyHistogram, latencyHistogramSpec, compactWidth, height)
		if got := lipgloss.Height(out); got != height {
			t.Errorf("compact renderHistogram(height=%d) is %d rows, want exactly the budget", height, got)
		}
		if strings.Contains(out, "Scale:") || strings.ContainsAny(out, "█▓▒░") {
			t.Errorf("compact renderHistogram(height=%d) draws bars or the legend:\n%s", height, out)
		}
		if got, want := strings.Count(out, " | "), height-histogramCompactChromeRows; got != want {
			t.Errorf("compact renderHistogram(height=%d) has %d bucket rows, want %d", height, got, want)
		}
	}
}

// The Overview keeps its summary boxes and sparklines when the terminal is
// short and sheds the lower panels first; a tall terminal shows everything.
func TestOverviewShedsLowerPanelsFirst(t *testing.T) {
	snap := tallSnapshot()
	tall := renderOverview(snap, 100, 60)
	for _, tok := range []string{"Syscalls:", "Trends:", "Latency:", "Top syscalls:", "Latency buckets:"} {
		if !strings.Contains(tall, tok) {
			t.Fatalf("tall overview lost %q", tok)
		}
	}
	short := renderOverview(snap, 100, lipgloss.Height(tall)-1)
	if strings.Contains(short, "Latency buckets:") {
		t.Errorf("short overview kept the histogram panel:\n%s", short)
	}
	for _, tok := range []string{"Syscalls:", "Trends:", "Latency:", "Top syscalls:"} {
		if !strings.Contains(short, tok) {
			t.Errorf("short overview dropped higher-priority %q", tok)
		}
	}
	if got := lipgloss.Height(short); got >= lipgloss.Height(tall) {
		t.Errorf("short overview is %d rows, tall is %d", got, lipgloss.Height(tall))
	}
	// Unbounded (height 0) keeps the legacy full layout.
	if got := renderOverview(snap, 100, 0); got != tall {
		t.Errorf("height 0 differs from a tall terminal")
	}
}

// Latency+Gaps splits the height between the two histograms, so at 24 rows
// both are still on screen, each with its leading buckets and a folded tail
// row (the sparkline would cost buckets, so it is dropped).
func TestLatencyGapsSplitsHeightBetweenHistograms(t *testing.T) {
	snap := tallSnapshot()
	out := renderLatencyGapsTab(snap, 100, 21)
	if got := lipgloss.Height(out); got > 21 {
		t.Fatalf("latency+gaps is %d rows, budget 21:\n%s", got, out)
	}
	for _, tok := range []string{"Latency Histogram", "Gap Histogram", "[1us,2us)", "+inf)"} {
		if !strings.Contains(out, tok) {
			t.Errorf("latency+gaps at 21 rows lost %q:\n%s", tok, out)
		}
	}
	// With room to spare the extra rows go to buckets.
	if big := renderLatencyGapsTab(snap, 100, 40); strings.Count(big, " | ") <= strings.Count(out, " | ") {
		t.Errorf("a taller budget did not show more buckets")
	}
}

// When the sparkline and a bucket cannot both fit, the histogram stays and the
// sparkline goes; with one row there is only the first section.
func TestLatencyGapsDegradesOnTinyHeights(t *testing.T) {
	snap := tallSnapshot()
	for height := 1; height <= 14; height++ {
		out := renderLatencyGapsTab(snap, 80, height)
		if got := lipgloss.Height(out); got > height {
			t.Errorf("height %d: rendered %d rows", height, got)
		}
		// From 5 rows up the title line is on screen (1 row is the top border).
		if height >= 5 && !strings.Contains(out, "Latency Histogram") {
			t.Errorf("height %d: latency histogram missing:\n%s", height, out)
		}
	}
	// Below two one-bucket histograms the gap section is left out and the
	// latency section gets every row; its buckets take precedence over the
	// sparkline, which would leave them only two rows.
	out := renderLatencyGapsTab(snap, 80, 9)
	if strings.Contains(out, "Gap") || strings.Contains(out, "sparkline") || strings.Count(out, " | ") != 5 {
		t.Errorf("9 rows should hold the latency histogram (5 bucket rows) only:\n%s", out)
	}
	// Two sections of 5 rows each hold a one-bucket histogram but no sparkline.
	out = renderLatencyGapsTab(snap, 80, 10)
	if !strings.Contains(out, "Gap Histogram") || strings.Contains(out, "sparkline") {
		t.Errorf("10 rows should hold two histogram-only sections:\n%s", out)
	}
}

// A waiting-for-stats panel and a no-data histogram are fixed-size and must
// not be stretched or panic at any budget.
func TestLatencyGapsEmptyHistogramsFit(t *testing.T) {
	snap := statsengine.NewSnapshot(nil, nil, nil, nil, nil, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	for _, height := range []int{0, 1, 6, 12, 30} {
		out := renderLatencyGapsTab(&snap, 80, height)
		if height > 0 && lipgloss.Height(out) > height {
			t.Errorf("height %d: rendered %d rows", height, lipgloss.Height(out))
		}
	}
}

// realSnapshot returns a snapshot with the real 8 latency/gap buckets and the
// given per-bucket counts (the last one is the slowest, [1s,+inf)).
func realSnapshot(counts [8]uint64) *statsengine.Snapshot {
	labels := []string{"[0,1us)", "[1us,10us)", "[10us,100us)", "[100us,1ms)", "[1ms,10ms)", "[10ms,100ms)", "[100ms,1s)", "[1s,+inf)"}
	return labelledSnapshot(labels, counts[:])
}

// labelledSnapshot returns a snapshot whose latency and gap histograms both
// have one bucket per label with the matching count, and a short sparkline.
func labelledSnapshot(labels []string, counts []uint64) *statsengine.Snapshot {
	var buckets []statsengine.HistogramBucketSnapshot
	var total uint64
	for i, c := range counts {
		buckets = append(buckets, statsengine.HistogramBucketSnapshot{Label: labels[i], Count: c})
		total += c
	}
	hist := statsengine.NewHistogramSnapshot(total, buckets)
	series := []float64{10, 20, 15, 30}
	snap := statsengine.NewSnapshot(series, series, series, nil, nil, nil, hist, hist)
	return &snap
}

// drawnHistogram is one histogram panel as it appears in rendered output: its
// title (without the total), the "total=N" the title announces, the sum and
// number of its bucket rows, and whether it is closed by its bottom border.
type drawnHistogram struct {
	title      string
	total, sum uint64
	rows       int
	closed     bool
}

// drawnHistograms finds every histogram panel in out: a title line holding
// "(total=N)", then its "label | ..." bucket rows (whose last field is the
// count), the optional scale legend and the bottom border. A row the panel
// does not end with that border was cut (or soft-wrapped) mid-panel.
func drawnHistograms(t *testing.T, out string) []drawnHistogram {
	t.Helper()
	var panels []drawnHistogram
	cur := -1 // index of the panel whose rows are being read, -1 for none
	for _, line := range strings.Split(ansi.Strip(out), "\n") {
		inner := strings.Trim(line, "│ ")
		if i := strings.Index(inner, "(total="); i >= 0 {
			p := drawnHistogram{title: strings.TrimSpace(inner[:i])}
			if _, err := fmt.Sscanf(inner[i:], "(total=%d)", &p.total); err != nil {
				t.Fatalf("no total in title %q: %v", line, err)
			}
			panels = append(panels, p)
			cur = len(panels) - 1
			continue
		}
		if cur < 0 {
			continue
		}
		if label, counts, ok := strings.Cut(inner, " | "); ok && strings.HasPrefix(label, "[") {
			fields := strings.Fields(counts)
			var n uint64
			if _, err := fmt.Sscanf(fields[len(fields)-1], "%d", &n); err != nil {
				t.Fatalf("no count at the end of %q: %v", line, err)
			}
			panels[cur].sum += n
			panels[cur].rows++
			continue
		}
		if strings.HasPrefix(inner, "Scale:") {
			continue
		}
		panels[cur].closed = strings.HasPrefix(strings.TrimSpace(line), "└")
		cur = -1
	}
	return panels
}

// displayedBucketSum adds up the trailing count column of every bucket row of
// the histogram panel whose title contains title, and returns it with the
// "total=N" the title announces.
func displayedBucketSum(t *testing.T, out, title string) (sum, total uint64) {
	t.Helper()
	for _, p := range drawnHistograms(t, out) {
		if strings.Contains(p.title, title) {
			return p.sum, p.total
		}
	}
	t.Fatalf("no histogram titled %q in:\n%s", title, out)
	return 0, 0
}

// assertHistogramsWhole holds every histogram panel in out to what a reader
// relies on: at least one bucket row, the rows adding up to the title's
// total=, and the bottom border drawn (a panel cut mid-row by a clip, or made
// taller by soft-wrapped rows, fails one of these).
func assertHistogramsWhole(t *testing.T, label, out string) {
	t.Helper()
	for _, p := range drawnHistograms(t, out) {
		if p.rows == 0 || p.sum != p.total || !p.closed {
			t.Fatalf("%s: histogram %q has %d rows summing to %d of total=%d, closed=%v:\n%s",
				label, p.title, p.rows, p.sum, p.total, p.closed, out)
		}
	}
}

// The slowest buckets are the point of a latency tool: whatever the height,
// the bucket rows must add up to the title's total (the hidden ones folded into
// a tail row) and the slow tail must stay on screen.
func TestHistogramSectionNeverDropsTheSlowTail(t *testing.T) {
	snap := realSnapshot([8]uint64{1200, 800, 200, 40, 12, 5, 1, 1})
	for height := 12; height <= 40; height++ {
		for _, tc := range []struct {
			name, title string
			render      func(*statsengine.Snapshot, int, int) string
		}{
			{"latency", "Latency Histogram", renderLatencyTab},
			{"gaps", "Gap Histogram", renderGapsTab},
		} {
			out := tc.render(snap, 100, height)
			if got := lipgloss.Height(out); got > height {
				t.Fatalf("%s h=%d: %d rows", tc.name, height, got)
			}
			if sum, total := displayedBucketSum(t, out, tc.title); sum != total || total != 2259 {
				t.Errorf("%s h=%d: bucket counts sum to %d, title total %d\n%s", tc.name, height, sum, total, out)
			}
		}
		// Both sections of the combined tab (height split between them, 6+ rows
		// each from 12) account for every event too.
		out := renderLatencyGapsTab(snap, 100, height)
		if got := lipgloss.Height(out); got > height {
			t.Fatalf("latency+gaps h=%d: %d rows", height, got)
		}
		for _, title := range []string{"Latency Histogram", "Gap Histogram"} {
			if sum, total := displayedBucketSum(t, out, title); sum != total {
				t.Errorf("latency+gaps h=%d: %s counts sum to %d, total %d\n%s", height, title, sum, total, out)
			}
		}
	}
}

// At 80x24 the Latency+Gaps tab has 11 rows per section: the sparkline goes
// (it would cost buckets) and the two slowest buckets are folded into one
// "[100ms,+inf)" row carrying their events, not dropped.
func TestHistogramSectionFoldsTheTailIntoOneRow(t *testing.T) {
	snap := realSnapshot([8]uint64{1200, 800, 200, 40, 12, 5, 1, 1})
	out := ansi.Strip(renderLatencyTab(snap, 80, 11))
	if !strings.Contains(out, "[100ms,+inf)") || !strings.Contains(out, "[10ms,100ms)") {
		t.Fatalf("no folded tail row:\n%s", out)
	}
	if !strings.Contains(out, "[0,1us)") {
		t.Errorf("fastest bucket missing:\n%s", out)
	}
	// Enough rows for every bucket: nothing is folded, the last one is shown.
	if out := renderLatencyTab(snap, 80, histogramChromeRows+8); !strings.Contains(out, "[1s,+inf)") || !strings.Contains(out, "[100ms,1s)") {
		t.Errorf("buckets folded although they fit:\n%s", out)
	}
	// One row: the whole histogram is the folded row.
	if sum, total := displayedBucketSum(t, renderLatencyTab(snap, 80, 5), "Latency Histogram"); sum != total {
		t.Errorf("one-row histogram counts %d of %d", sum, total)
	}
}

func TestFoldHistogramBuckets(t *testing.T) {
	mk := func(counts ...uint64) []statsengine.HistogramBucketSnapshot {
		var out []statsengine.HistogramBucketSnapshot
		for i, c := range counts {
			out = append(out, statsengine.HistogramBucketSnapshot{Label: fmt.Sprintf("[%dx,%dy)", i, i+1), Count: c})
		}
		return out
	}
	sum := func(bs []statsengine.HistogramBucketSnapshot) (s uint64) {
		for _, b := range bs {
			s += b.Count
		}
		return s
	}
	for _, tc := range []struct {
		name    string
		in      []statsengine.HistogramBucketSnapshot
		rows    int
		wantLen int
		last    string
	}{
		{"unbounded", mk(1, 2, 3), 0, 3, "[2x,3y)"},
		{"fits", mk(1, 2, 3), 3, 3, "[2x,3y)"},
		{"fold", mk(1, 2, 3, 4), 3, 3, "[2x,+inf)"},
		{"trim empty ends first", mk(0, 1, 2, 0), 2, 2, "[2x,3y)"},
		{"trim then fold", mk(0, 1, 2, 3, 0), 2, 2, "[2x,+inf)"},
		{"one row", mk(5, 6, 7), 1, 1, "[0x,+inf)"},
	} {
		got := foldHistogramBuckets(tc.in, tc.rows)
		if len(got) != tc.wantLen || got[len(got)-1].Label != tc.last {
			t.Errorf("%s: got %d rows, last %q; want %d, %q", tc.name, len(got), got[len(got)-1].Label, tc.wantLen, tc.last)
		}
		if sum(got) != sum(tc.in) {
			t.Errorf("%s: folded counts sum to %d, want %d", tc.name, sum(got), sum(tc.in))
		}
	}
}

// The sparkline panel (3 rows) is kept only while every bucket still fits
// beside it; otherwise it is dropped before any bucket is folded.
func TestHistogramSectionDropsSparklineBeforeBuckets(t *testing.T) {
	snap := realSnapshot([8]uint64{1200, 800, 200, 40, 12, 5, 1, 1})
	// 8 buckets + 4 chrome + 3 sparkline = 15 rows hold everything.
	out := renderLatencyTab(snap, 80, 15)
	if !strings.Contains(out, "sparkline") || strings.Count(out, " | ") != 8 {
		t.Errorf("15 rows should hold 8 buckets and the sparkline:\n%s", out)
	}
	// One row less and the sparkline goes, so all 8 buckets stay unfolded.
	out = renderLatencyTab(snap, 80, 14)
	if strings.Contains(out, "sparkline") || strings.Count(out, " | ") != 8 || strings.Contains(out, "[1s,+inf)") == false {
		t.Errorf("14 rows should drop the sparkline and keep all 8 buckets:\n%s", out)
	}
	// 7 rows: sparkline gone, 3 bucket rows (2 heads plus the folded tail).
	out = renderLatencyTab(snap, 80, 7)
	if strings.Contains(out, "sparkline") || strings.Count(out, " | ") != 3 {
		t.Errorf("want 3 bucket rows and no sparkline at 7 rows:\n%s", out)
	}
	// sparklineRows must match what is rendered.
	if got := lipgloss.Height(common.Current().PanelStyle.Width(80).Render("x")); got != sparklineRows {
		t.Errorf("sparklineRows = %d, rendered panel is %d rows", sparklineRows, got)
	}
}

// Real terminals soft-wrap a line wider than the terminal, which makes the
// frame taller than the height guarantee; no line of the Overview or
// Latency+Gaps tab may be wider than the terminal.
// Latency+Gaps is swept from 1 column (its panels give way to a width-cut
// notice), the Overview from 20.
func TestSummaryTabsFitTheTerminalWidth(t *testing.T) {
	for _, tab := range []Tab{TabOverview, TabLatency} {
		from := 20
		if tab == TabLatency {
			from = 1
		}
		for width := from; width <= 200; width++ {
			for _, height := range []int{24, 40} {
				var out string
				if tab == TabOverview {
					out = renderOverview(tallSnapshot(), width, height)
				} else {
					out = renderLatencyGapsTab(tallSnapshot(), width, height)
				}
				if got := lipgloss.Height(out); got > height {
					t.Fatalf("%s %dx%d: %d lines", tab, width, height, got)
				}
				for _, line := range strings.Split(out, "\n") {
					if w := lipgloss.Width(line); w > width {
						t.Fatalf("%s %dx%d: line is %d cells wide: %q", tab, width, height, w, line)
					}
				}
			}
		}
	}
}

// histogramRenderer is one of the histogram tab renderers with the panel
// titles it draws.
type histogramRenderer struct {
	name   string
	render func(*statsengine.Snapshot, int, int) string
	specs  []histogramSpec
}

var histogramRenderers = []histogramRenderer{
	{"latency", renderLatencyTab, []histogramSpec{latencyHistogramSpec}},
	{"gaps", renderGapsTab, []histogramSpec{gapHistogramSpec}},
	{"latency+gaps", renderLatencyGapsTab, []histogramSpec{latencyHistogramSpec, gapHistogramSpec}},
}

// Below the width its compact layout needs, a histogram panel is the width-cut
// "terminal too narrow" notice; from that width on it is drawn whole, with no
// line wider than the terminal (it used to soft-wrap below ~30 columns, task
// ps2), at most height rows, and bucket rows that add up to total=. Swept at
// every width from 1 to 40 and every height up to 30 (and unbounded), with
// the real 8 buckets, with 14 buckets of wider labels and with labels that
// folding widens. A sparkline under a histogram is drawn on one line or not
// at all (its panel is never taller than sparklineRows).
func TestHistogramSectionsFitNarrowWidths(t *testing.T) {
	snaps := map[string]*statsengine.Snapshot{
		"real": realSnapshot([8]uint64{1200, 800, 200, 40, 12, 5, 1, 1}),
		"tall": tallSnapshot(),
		// Labels narrower than their folded form ("[1000000000,1)" folds to
		// "[1000000000,+inf)"), and wide enough to decide the panel's minimum
		// width over its title, so the folded tail row is the widest one a
		// short panel shows and must be measured before it is drawn.
		"folding": labelledSnapshot(
			[]string{"[1000000000,1)", "[1000000001,2)", "[1000000002,3)", "[1000000003,4)", "[1000000004,5)", "[1000000005,6)"},
			[]uint64{9, 8, 7, 6, 5, 4}),
	}
	for snapName, snap := range snaps {
		for _, r := range histogramRenderers {
			for width := 1; width <= 40; width++ {
				for height := 0; height <= 30; height++ {
					label := fmt.Sprintf("%s/%s %dx%d", snapName, r.name, width, height)
					assertHistogramSectionFits(t, label, r, snap, width, height)
				}
			}
		}
	}
}

// assertSparklinesOnOneLine checks that every sparkline panel in out is its
// labelled sparkline on one line followed by the bottom border: a line wider
// than the panel would be wrapped by lipgloss onto further rows.
func assertSparklinesOnOneLine(t *testing.T, label, out string) {
	t.Helper()
	lines := strings.Split(ansi.Strip(out), "\n")
	for i, line := range lines {
		if !strings.Contains(line, "sparkline:") {
			continue
		}
		if i+1 >= len(lines) || !strings.HasPrefix(lines[i+1], "└") {
			t.Fatalf("%s: sparkline line %q is not followed by its bottom border:\n%s", label, line, out)
		}
	}
}

// isSpecTitle reports whether a drawn histogram title is spec's full or short
// title.
func isSpecTitle(title string, spec histogramSpec) bool {
	return title == spec.title || title == spec.shortTitle
}

// assertHistogramSectionFits renders one cell of
// TestHistogramSectionsFitNarrowWidths and checks it.
func assertHistogramSectionFits(t *testing.T, label string, r histogramRenderer, snap *statsengine.Snapshot, width, height int) {
	t.Helper()
	out := r.render(snap, width, height)
	if height > 0 && lipgloss.Height(out) > height {
		t.Fatalf("%s: %d rows:\n%s", label, lipgloss.Height(out), out)
	}
	for _, line := range strings.Split(out, "\n") {
		if w := lipgloss.Width(line); w > width {
			t.Fatalf("%s: line is %d cells wide: %q", label, w, line)
		}
	}
	if height > 0 && height < latencyMinRows {
		return // below the tab minimum the dashboard shows its own notice
	}
	assertHistogramsWhole(t, label, out)
	assertSparklinesOnOneLine(t, label, out)
	// The first section is always drawn: as a histogram from its minimum
	// width on, else as the notice (cut to the width like Flame's).
	first, firstHist := r.specs[0], snap.LatencyHistogram
	if first == gapHistogramSpec {
		firstHist = snap.GapHistogram
	}
	minWidth := histogramMinWidth(firstHist, first)
	drawn := drawnHistograms(t, out)
	if width >= minWidth {
		if len(drawn) == 0 || !isSpecTitle(drawn[0].title, first) {
			t.Fatalf("%s: %q histogram not drawn at its minimum width %d:\n%s", label, first.shortTitle, minWidth, out)
		}
		return
	}
	notice := first.shortTitle + ": terminal too narrow"
	if width > common.MessagePanelChrome {
		notice = common.TruncateRight(notice, width-common.MessagePanelChrome, common.Ellipsis)
	} else {
		notice = common.TruncateRight(notice, width, common.Ellipsis)
	}
	if len(drawn) > 0 && isSpecTitle(drawn[0].title, first) || !strings.Contains(ansi.Strip(out), notice) {
		t.Fatalf("%s: below %d columns want the %q notice:\n%s", label, minWidth, notice, out)
	}
}

// The frame gives the status block its rows first, then the tab bar, and the
// body whatever is left; the parts never add up to more than the terminal.
func TestSplitFrameRowsPrioritisesStatusThenTabBarThenBody(t *testing.T) {
	for _, tc := range []struct {
		height, statusRows int
		want               frameRows
	}{
		{24, 1, frameRows{status: 1, tabBar: 1, body: 22}},
		{24, 2, frameRows{status: 2, tabBar: 1, body: 21}},
		{4, 1, frameRows{status: 1, tabBar: 1, body: 2}},
		{2, 1, frameRows{status: 1, tabBar: 1, body: 0}},
		{1, 1, frameRows{status: 1, tabBar: 0, body: 0}},
		{2, 2, frameRows{status: 2, tabBar: 0, body: 0}},
		{1, 2, frameRows{status: 1, tabBar: 0, body: 0}}, // the help bar loses its upper row
		{0, 1, frameRows{}},
		{-3, 2, frameRows{}},
	} {
		if got := splitFrameRows(tc.height, tc.statusRows); got != tc.want {
			t.Errorf("splitFrameRows(%d, %d) = %+v, want %+v", tc.height, tc.statusRows, got, tc.want)
		}
		if got := splitFrameRows(tc.height, tc.statusRows); got.status+got.tabBar+got.body > max(tc.height, 0) {
			t.Errorf("splitFrameRows(%d, %d) = %+v exceeds the height", tc.height, tc.statusRows, got)
		}
	}
}

func TestClipTailLines(t *testing.T) {
	for _, tc := range []struct {
		in     string
		height int
		want   string
	}{
		{"a\nb\nc", 1, "c"},
		{"a\nb\nc", 2, "b\nc"},
		{"a\nb\nc", 3, "a\nb\nc"},
		{"a\nb\nc", 9, "a\nb\nc"},
		{"a\nb\nc", 0, ""},
		{"a\nb\nc", -1, ""},
		{"", 2, ""},
	} {
		if got := clipTailLines(tc.in, tc.height); got != tc.want {
			t.Errorf("clipTailLines(%q, %d) = %q, want %q", tc.in, tc.height, got, tc.want)
		}
	}
}

// A table spends two rows on its header and hint, keeps at least one data row
// and has a fixed default without a budget. It no longer keeps a minimum
// of its own (it used to hold five rows whatever the terminal had).
func TestTableRowBudget(t *testing.T) {
	for height, want := range map[int]int{0: defaultTableRows, -1: defaultTableRows, 1: 1, 2: 1, 3: 1, 4: 2, 24: 22} {
		if got := tableRowBudget(height); got != want {
			t.Errorf("tableRowBudget(%d) = %d, want %d", height, got, want)
		}
	}
}

// Below a tab's minimum the body is the one-line notice; at the minimum the
// tab itself is drawn. Pinned per tab at the registry values so a change to a
// panel's chrome that outgrows its minimum is caught here, not by a user.
func TestTooSmallNoticeAppearsExactlyBelowTheTabMinimum(t *testing.T) {
	for _, c := range fitCases() {
		m := newFitModel(t, c, false, 100, 40)
		min := m.minBodyRowsFor(c.tab)
		for body := 1; body <= min+1; body++ {
			out := m.renderBody(100, body+2, body)
			if got, want := strings.Contains(out, "terminal too small"), body < min; got != want {
				t.Errorf("%s body=%d (minimum %d): notice shown = %v, want %v:\n%s", c, body, min, got, want, out)
			}
			if got := lipgloss.Height(out); got > body {
				t.Errorf("%s body=%d: %d rows", c, body, got)
			}
		}
	}
}

// renderBody lays the tab out for the body budget, not for the taller content
// viewport of the terminal height, and leaves the clip nothing to cut. In
// View's own geometry the viewport never exceeds the budget today (the chrome
// constants match the status block), so the matrix above cannot tell the cap
// from the clip; this drives renderBody with a 40-row terminal and smaller
// budgets, as a status block taller than its constant would. The Flame tab
// is left out: it ignores the height it is handed and draws at the viewport
// its sub-model was sized to on resize (from contentViewport), which only
// View's real geometry, i.e. the matrix, can exercise.
func TestRenderBodyLaysTheTabOutForTheBudget(t *testing.T) {
	for _, c := range fitCases() {
		if c.tab == TabFlame {
			continue
		}
		m := newFitModel(t, c, false, 100, 40)
		for body := m.minBodyRowsFor(c.tab); body <= 15; body++ {
			want := m.renderActiveContent(100, body, &m.streamModel, m.flamegraphModel)
			got := m.renderBody(100, 40, body)
			if got != want || lipgloss.Height(got) > body {
				t.Fatalf("%s body=%d: renderBody is not the tab laid out for %d rows:\n--- got\n%s\n--- want\n%s", c, body, body, got, want)
			}
		}
	}
}

// The Stream tab's minimum is its panel alone, six rows, whatever the help
// bar, pause or status message: the footer lines below the panel are drawn
// only while the body has rows left for them (eventstream.Model.View), so
// they never decide whether the stream is drawn at all. At the minimum the
// stream fits unclipped; each further row brings back the next footer line,
// except that a status message takes the first spare row ahead of Row/Sel:
// it is how errors such as "Export failed" reach the user.
func TestStreamMinimumIgnoresItsFooter(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		help, paused, status bool
	}{
		{"live", false, false, false},
		{"live with message", false, false, true},
		{"help", true, false, false},
		{"paused", false, true, false},
		{"paused with message", false, true, true},
		{"help with message", true, false, true},
	} {
		m := newFitModel(t, fitCase{tab: TabStream, paused: tc.paused}, tc.help, 100, 40)
		if tc.status {
			m.streamModel.SetStatusMessage("exported")
		}
		if got := m.minBodyRowsFor(TabStream); got != streamTableMinRows {
			t.Fatalf("%s: minimum %d, want %d", tc.name, got, streamTableMinRows)
		}
		footer := tc.help || tc.paused
		for body := streamTableMinRows; body <= streamTableMinRows+2; body++ {
			raw := m.renderActiveContent(100, body, &m.streamModel, m.flamegraphModel)
			if got := lipgloss.Height(raw); got > body {
				t.Errorf("%s: stream is %d rows in a %d-row body:\n%s", tc.name, got, body, raw)
			}
			// The first spare row goes to the message if there is one, else
			// to the Row/Sel line; the second brings Row/Sel above the message.
			wantRow := footer && body >= streamTableMinRows+1
			if tc.status {
				wantRow = footer && body >= streamTableMinRows+2
			}
			if got := strings.Contains(raw, "Row ") || strings.Contains(raw, "Sel "); got != wantRow {
				t.Errorf("%s body=%d: footer line shown = %v, want %v:\n%s", tc.name, body, got, wantRow, raw)
			}
			wantMsg := footer && tc.status && body >= streamTableMinRows+1
			if got := strings.Contains(raw, "exported"); got != wantMsg {
				t.Errorf("%s body=%d: status message shown = %v, want %v:\n%s", tc.name, body, got, wantMsg, raw)
			}
		}
		if out := m.renderBody(100, 40, streamTableMinRows-1); !strings.Contains(out, "terminal too small") {
			t.Errorf("%s: no notice one row below the minimum:\n%s", tc.name, out)
		}
	}
	// End to end: 8 rows with the help collapsed leave the live stream its
	// 6 rows, so View draws it rather than the notice.
	out := newFitModel(t, fitCase{tab: TabStream}, false, 100, 8).View().Content
	if strings.Contains(out, "terminal too small") || !strings.Contains(out, "Stream") {
		t.Errorf("live stream at 100x8 shows the notice:\n%s", out)
	}
}

// streamTransition is a Stream tab state change the user can trigger at any
// terminal size.
type streamTransition struct {
	name  string
	apply func(t *testing.T, m *Model) *Model
}

// pressStreamKey sends key to the dashboard as a printable key press.
func pressStreamKey(t *testing.T, m *Model, key rune) *Model {
	t.Helper()
	next, _ := m.Update(tea.KeyPressMsg{Code: key, Text: string(key)})
	return next.(*Model)
}

// streamTransitions are the pause, the status message (a search result, a
// failed export) and the search modal, alone and combined.
func streamTransitions() []streamTransition {
	pause := func(t *testing.T, m *Model) *Model { return pressStreamKey(t, m, ' ') }
	message := func(_ *testing.T, m *Model) *Model {
		m.streamModel.SetStatusMessage("/zzz @ row 3/200")
		return m
	}
	search := func(t *testing.T, m *Model) *Model {
		m = pressStreamKey(t, m, '/')
		if !m.streamModel.SearchModalVisible() {
			t.Fatal("/ did not open the search modal")
		}
		return m
	}
	return []streamTransition{
		{"pause", pause},
		{"message", message},
		{"search", search},
		{"pause+message", func(t *testing.T, m *Model) *Model { return message(t, pause(t, m)) }},
		{"pause+search", func(t *testing.T, m *Model) *Model { return search(t, pause(t, m)) }},
	}
}

// Pausing the stream, a status message and opening the search modal must not
// swap the Stream body between the table and the "terminal too small" notice:
// a successful search would hide the row it just selected, and an open modal
// hidden behind the notice would still take every key. At every height and a
// few widths the body kind after each transition must equal the live
// stream's, and the frame must keep the contract of the height matrix
// (assertFrameFits), modal included: no line wider than the terminal, nothing
// cut by the clip.
func TestStreamBodyKindSurvivesTransientState(t *testing.T) {
	live := fitCase{tab: TabStream}
	for _, tr := range streamTransitions() {
		for _, help := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/help=%v", tr.name, help), func(t *testing.T) {
				for _, width := range []int{20, 30, 60, 100} {
					for height := 1; height <= 20; height++ {
						label := fmt.Sprintf("%s help=%v %dx%d", tr.name, help, width, height)
						before := assertFrameFits(t, newFitModel(t, live, help, width, height), live, label+" before", width, height)
						m := tr.apply(t, newFitModel(t, live, help, width, height))
						if after := assertFrameFits(t, m, live, label, width, height); after != before {
							t.Fatalf("%s: body notice %v before, %v after:\n%s", label, before, after, m.View().Content)
						}
					}
				}
			})
		}
	}
}

// effectiveFlameClick returns a left click, in dashboard coordinates, that
// changes the flamegraph when it reaches it, found by trying the body cells
// of fresh models of the same size; it fails the test when there is none,
// since a click without effect would prove nothing about the routing.
func effectiveFlameClick(t *testing.T, width, height int) tea.MouseClickMsg {
	t.Helper()
	for y := range height {
		for x := 0; x < width; x += 4 {
			m := newFitModel(t, fitCase{tab: TabFlame}, false, width, height)
			before := m.flamegraphModel.View().Content
			m.flamegraphModel.Update(tea.MouseClickMsg{X: x, Y: y, Button: tea.MouseLeft})
			if m.flamegraphModel.View().Content != before {
				return tea.MouseClickMsg{X: x, Y: y + dashboardTabBarRows, Button: tea.MouseLeft}
			}
		}
	}
	t.Fatalf("no click changes the flamegraph at %dx%d", width, height)
	return tea.MouseClickMsg{}
}

// While the Flame tab shows the "terminal too small" notice the flamegraph is
// not on screen, so a click on the notice must not zoom or select one of its
// invisible frames. Negative control: at a normal size the same routing
// forwards the click and the flamegraph changes.
func TestFlameMouseIsDroppedWhileTheNoticeIsShown(t *testing.T) {
	for _, tc := range []struct {
		height  int
		forward bool
	}{
		{5, false}, // 3 body rows, below flameMinRows
		{30, true},
	} {
		click := effectiveFlameClick(t, 80, tc.height)
		m := newFitModel(t, fitCase{tab: TabFlame}, false, 80, tc.height)
		if got := m.activeBodyDrawn(); got != tc.forward {
			t.Fatalf("height %d: activeBodyDrawn = %v, want %v", tc.height, got, tc.forward)
		}
		before := m.flamegraphModel.View().Content
		m.Update(click)
		if changed := m.flamegraphModel.View().Content != before; changed != tc.forward {
			t.Errorf("height %d: click at (%d,%d) changed the flamegraph = %v, want %v",
				tc.height, click.X, click.Y, changed, tc.forward)
		}
	}
}

// The notice is cut to the width so it can never soft-wrap and add a row.
func TestTooSmallNoticeFitsNarrowTerminals(t *testing.T) {
	for width := 1; width <= 30; width++ {
		if got := lipgloss.Width(tooSmallNotice(width)); got > width {
			t.Errorf("notice is %d cells wide in a %d-cell terminal", got, width)
		}
	}
}

// On a very short terminal the frame degrades in a fixed order: the body goes
// first (a notice, then nothing), then the tab bar; the status line stays.
func TestViewDegradesBodyThenTabBarKeepingTheStatusLine(t *testing.T) {
	c := fitCase{tab: TabSyscalls}
	for _, tc := range []struct {
		height              int
		tabBar, notice, tbl bool
	}{
		{1, false, false, false},
		{2, true, false, false},
		{3, true, true, false},
		{4, true, true, false},
		{5, true, false, true}, // 3 body rows: header, one row and the hint line
	} {
		out := ansi.Strip(newFitModel(t, c, false, 80, tc.height).View().Content)
		if got := strings.Contains(out, "3:Sys"); got != tc.tabBar {
			t.Errorf("height %d: tab bar shown = %v, want %v:\n%s", tc.height, got, tc.tabBar, out)
		}
		if got := strings.Contains(out, "terminal too small"); got != tc.notice {
			t.Errorf("height %d: notice shown = %v, want %v:\n%s", tc.height, got, tc.notice, out)
		}
		if got := strings.Contains(out, "Syscall "); got != tc.tbl {
			t.Errorf("height %d: table shown = %v, want %v:\n%s", tc.height, got, tc.tbl, out)
		}
	}
}
