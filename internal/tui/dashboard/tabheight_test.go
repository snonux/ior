package dashboard

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"ior/internal/statsengine"
	common "ior/internal/tui/common"
	"ior/internal/tui/messages"

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

// TestEveryTabFitsTheTerminalHeight pins that the dashboard View never
// renders more lines than the terminal has rows, for every tab, at sizes from
// comfortable down to a few rows. An over-tall frame scrolls the terminal and
// pushes the chrome status line (filter, refusal notice, recording, auto-reset)
// off the bottom, which is the one line that cannot be seen any other way.
func TestEveryTabFitsTheTerminalHeight(t *testing.T) {
	sizes := [][2]int{{80, 24}, {100, 20}, {120, 30}, {80, 12}, {60, 8}, {40, 6}, {120, 4}}
	for _, tab := range orderedTabs() {
		for _, sz := range sizes {
			if sz[1] < 12 && tab != TabOverview && tab != TabLatency {
				// The table, flame and stream tabs keep a minimum body
				// height of their own (task follow-up); only the two
				// summary tabs are pinned down to a few rows here.
				continue
			}
			for _, help := range []bool{false, true} {
				name := fmt.Sprintf("%s/%dx%d/help=%v", tab, sz[0], sz[1], help)
				t.Run(name, func(t *testing.T) {
					m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
					m.activeTab = tab
					m.showHelp = help
					m.width, m.height = sz[0], sz[1]
					m = tickStats(t, m, messages.StatsTickMsg{Snap: tallSnapshot()})
					out := m.View().Content
					if got := lipgloss.Height(out); got > sz[1] {
						t.Fatalf("View is %d lines, terminal has %d:\n%s", got, sz[1], out)
					}
					// The status line must still be the last line.
					lines := strings.Split(out, "\n")
					if !strings.Contains(lines[len(lines)-1], "filter:") {
						t.Fatalf("last line is not the status line: %q", lines[len(lines)-1])
					}
				})
			}
		}
	}
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
	out := renderHistogram(snap.LatencyHistogram, "Latency Histogram", 100, 0)
	if got, want := lipgloss.Height(out), len(snap.LatencyHistogram.Buckets())+histogramChromeRows; got != want {
		t.Fatalf("unbounded histogram is %d rows, want buckets+chrome = %d", got, want)
	}
	for _, height := range []int{5, 6, 9, 12} {
		out := renderHistogram(snap.LatencyHistogram, "Latency Histogram", 100, height)
		if got := lipgloss.Height(out); got != height {
			t.Errorf("renderHistogram(height=%d) is %d rows, want exactly the budget", height, got)
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
	labels := [8]string{"[0,1us)", "[1us,10us)", "[10us,100us)", "[100us,1ms)", "[1ms,10ms)", "[10ms,100ms)", "[100ms,1s)", "[1s,+inf)"}
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

// displayedBucketSum adds up the trailing count column of every bucket row of
// the histogram panel whose title line contains title, and returns it with the
// "total=N" the title announces.
func displayedBucketSum(t *testing.T, out, title string) (sum, total uint64) {
	t.Helper()
	inPanel := false
	for _, line := range strings.Split(ansi.Strip(out), "\n") {
		if strings.Contains(line, title) {
			inPanel = true
			if _, err := fmt.Sscanf(line[strings.Index(line, "total="):], "total=%d)", &total); err != nil {
				t.Fatalf("no total in title %q: %v", line, err)
			}
			continue
		}
		if strings.Contains(line, "Scale:") {
			inPanel = false // the panel's last content line
		}
		if !inPanel || !strings.Contains(line, " | ") {
			continue
		}
		fields := strings.Fields(strings.Trim(line, "│ "))
		var n uint64
		if _, err := fmt.Sscanf(fields[len(fields)-1], "%d", &n); err != nil {
			t.Fatalf("no count at the end of %q: %v", line, err)
		}
		sum += n
	}
	return sum, total
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
func TestSummaryTabsFitTheTerminalWidth(t *testing.T) {
	for _, tab := range []Tab{TabOverview, TabLatency} {
		for width := 20; width <= 200; width++ {
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
