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
// both are still on screen, each with its sparkline and some buckets.
func TestLatencyGapsSplitsHeightBetweenHistograms(t *testing.T) {
	snap := tallSnapshot()
	out := renderLatencyGapsTab(snap, 100, 21)
	if got := lipgloss.Height(out); got > 21 {
		t.Fatalf("latency+gaps is %d rows, budget 21:\n%s", got, out)
	}
	for _, tok := range []string{"Latency Histogram", "Latency sparkline:", "Gap Histogram", "Gap sparkline:", "[1us,2us)"} {
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
	// latency section gets every row, sparkline included.
	out := renderLatencyGapsTab(snap, 80, 9)
	if strings.Contains(out, "Gap") || !strings.Contains(out, "Latency sparkline:") {
		t.Errorf("9 rows should hold the full latency section only:\n%s", out)
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
