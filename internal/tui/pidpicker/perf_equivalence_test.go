package pidpicker

import (
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"testing"

	common "ior/internal/tui/common"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

// The legacy* functions below are the pre-task-7r2 implementations, copied
// verbatim from `git show 4c828c2^:internal/tui/pidpicker/model.go` (only
// renamed, and the old View body calls them): matchesQuery, cloneProcesses,
// View, renderRows, renderRow, visibleRows, formatProcess and rawProcessLabel.
// The optimised filter and windowed renderer must stay observably identical to
// them, so the tests compare complete rendered strings, not just which rows
// were selected. common.Sanitize, the theme styles, renderHelp and
// footerBindings were not touched by the change and are shared.

func legacyMatchesQuery(process ProcessInfo, query string) bool {
	pidStr := fmt.Sprintf("%d", process.Pid)
	if strings.Contains(strings.ToLower(pidStr), query) {
		return true
	}
	if strings.Contains(strings.ToLower(process.Comm), query) {
		return true
	}
	return strings.Contains(strings.ToLower(process.Cmdline), query)
}

// legacyFilter is the old applyFilter's list building: clone on an empty
// query, matchesQuery otherwise.
func legacyFilter(processes []ProcessInfo, rawQuery string) []ProcessInfo {
	query := strings.TrimSpace(strings.ToLower(rawQuery))
	if query == "" {
		return legacyCloneProcesses(processes)
	}
	filtered := make([]ProcessInfo, 0, len(processes))
	for _, process := range processes {
		if legacyMatchesQuery(process, query) {
			filtered = append(filtered, process)
		}
	}
	return filtered
}

func legacyCloneProcesses(in []ProcessInfo) []ProcessInfo {
	if len(in) == 0 {
		return []ProcessInfo{}
	}
	out := make([]ProcessInfo, len(in))
	copy(out, in)
	return out
}

func (m Model) legacyView() tea.View {
	theme := common.Current()
	var b strings.Builder
	if m.mode == PickerModeTID {
		if m.targetPID > 0 {
			b.WriteString(theme.HeaderStyle.Render(fmt.Sprintf("Select TID for PID %d", m.targetPID)))
		} else {
			b.WriteString(theme.HeaderStyle.Render("Select TID"))
		}
	} else {
		b.WriteString(theme.HeaderStyle.Render("Select PID"))
	}
	b.WriteString("\n")
	b.WriteString(m.input.View())
	b.WriteString("\n\n")

	rows := m.legacyRenderRows()
	b.WriteString(rows)

	if m.notice != "" {
		b.WriteString("\n")
		b.WriteString(theme.ErrorStyle.Render(m.notice))
	}

	if m.lastErr != nil {
		b.WriteString("\n")
		b.WriteString(theme.ErrorStyle.Render("scan error: " + common.Sanitize(m.lastErr.Error())))
	}

	b.WriteString("\n")
	viewWidth, _ := common.EffectiveViewport(m.width, m.height)
	helpStyle := theme.HelpBarStyle.Width(viewWidth)
	b.WriteString(helpStyle.Render(renderHelp(m.footerBindings())))
	return tea.NewView(theme.ScreenStyle.Render(b.String()))
}

func (m Model) legacyRenderRows() string {
	lines := make([]string, 0, len(m.filtered)+1)
	allLabel := allPIDsLabel
	if m.mode == PickerModeTID {
		allLabel = allTIDsLabel
	}
	lines = append(lines, m.legacyRenderRow(0, allLabel))
	for i, process := range m.filtered {
		label := legacyFormatProcess(process)
		lines = append(lines, m.legacyRenderRow(i+1, label))
	}

	maxRows := m.legacyVisibleRows()
	if maxRows > 0 && len(lines) > maxRows {
		start := m.selectedIndex - (maxRows / 2)
		if start < 0 {
			start = 0
		}
		limit := len(lines) - maxRows
		if start > limit {
			start = limit
		}
		lines = lines[start : start+maxRows]
	}
	return strings.Join(lines, "\n")
}

func (m Model) legacyRenderRow(index int, label string) string {
	prefix := "  "
	style := lipgloss.NewStyle()
	if index == m.selectedIndex {
		prefix = "> "
		style = common.Current().HighlightStyle
	}
	return style.Render(prefix + label)
}

func (m Model) legacyVisibleRows() int {
	if m.height <= 0 {
		return 0
	}
	const reservedLines = 6
	rows := m.height - reservedLines
	if rows < 1 {
		return 1
	}
	return rows
}

func legacyFormatProcess(process ProcessInfo) string {
	return common.Sanitize(legacyRawProcessLabel(process))
}

func legacyRawProcessLabel(process ProcessInfo) string {
	if process.ParentPID > 0 && process.ParentPID != process.Pid {
		if process.Cmdline == "" {
			return fmt.Sprintf("%d (pid:%d)  %s", process.Pid, process.ParentPID, process.Comm)
		}
		return fmt.Sprintf("%d (pid:%d)  %s  %s", process.Pid, process.ParentPID, process.Comm, process.Cmdline)
	}
	if process.Cmdline == "" {
		return fmt.Sprintf("%d  %s", process.Pid, process.Comm)
	}
	return fmt.Sprintf("%d  %s  %s", process.Pid, process.Comm, process.Cmdline)
}

// randomCorpus builds processes with mixed-case, multi-byte (CJK, emoji, ZWJ
// sequences), control-character, ANSI/OSC, invalid-UTF-8, empty and very long
// fields, and parent pids that exercise every label format.
func randomCorpus(r *rand.Rand, n int) []ProcessInfo {
	words := []string{"Bash", "sshd", "MySQLd", "java", "Ärger", "İstanbul", "kworker/0:1", "x\ny", "a\x1b[31mb", "", "nginx", "ÖL",
		"日本語", "世界", "한국어", "😀", "👨\u200d👩\u200d👧", "🇩🇪", "e\u0301", "\x1b[31mred\x1b[0m", "\x1b]8;;http://evil\aclick\x1b]8;;\a",
		"\x07\x00\r\t", "\xff\xfe", "\x9b31m", "\u202eRTL", "\u200b"}
	pick := func(k int) string {
		parts := make([]string, r.Intn(k+1))
		for i := range parts {
			parts[i] = words[r.Intn(len(words))]
		}
		return strings.Join(parts, " ")
	}
	out := make([]ProcessInfo, n)
	for i := range out {
		pid := 1 + r.Intn(40000)
		parent := pid
		switch r.Intn(3) {
		case 0:
			parent = 1 + r.Intn(40000)
		case 1:
			parent = 0
		}
		cmdline := pick(4)
		if r.Intn(10) == 0 {
			cmdline = strings.Repeat(pick(6)+" /usr/lib/Long/Path --flag=Value ", 1+r.Intn(40))
		}
		out[i] = ProcessInfo{Pid: pid, ParentPID: parent, Comm: words[r.Intn(len(words))], Cmdline: cmdline}
	}
	return out
}

func TestFilterMatchesLegacyOnRandomCorpus(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	procs := randomCorpus(r, 600)
	queries := []string{"", "  ", "bash", "BASH", " Bash ", "12", "3", "sql", "ärger", "ÄRGER", "i̇", "istanbul", "x\ny",
		"kworker", "nonexistent", "sshd java", "\x1b", "0", "ÖL", "日本", "😀", "👨\u200d", "e\u0301"}
	for _, q := range queries {
		m := New()
		m.processes = procs
		m.input.SetValue(q)
		m = m.applyFilter()
		// The legacy sees what the input really holds (SetValue may rewrite
		// control characters such as newlines).
		want := legacyFilter(procs, m.input.Value())
		if len(m.filtered) != len(want) {
			t.Fatalf("query %q: %d rows, legacy %d", q, len(m.filtered), len(want))
		}
		for i := range want {
			if m.filtered[i] != want[i] {
				t.Fatalf("query %q row %d: %+v, legacy %+v", q, i, m.filtered[i], want[i])
			}
		}
	}
}

// TestFilterFollowsReplacedProcesses pins the derived search text to the
// current processes: a rescan (or a directly assigned slice) must not be
// filtered with the lowercased text of the previous scan.
func TestFilterFollowsReplacedProcesses(t *testing.T) {
	m := New()
	m.processes = []ProcessInfo{{Pid: 1, Comm: "alpha"}, {Pid: 2, Comm: "beta"}}
	m.input.SetValue("alpha")
	m = m.applyFilter()
	if len(m.filtered) != 1 || m.filtered[0].Pid != 1 {
		t.Fatalf("first scan: %+v", m.filtered)
	}
	// Same length, different content.
	m.processes = []ProcessInfo{{Pid: 3, Comm: "gamma"}, {Pid: 4, Comm: "ALPHA"}}
	m = m.applyFilter()
	if len(m.filtered) != 1 || m.filtered[0].Pid != 4 {
		t.Fatalf("replaced scan: %+v", m.filtered)
	}
	// Emptied, then a query that matches nothing.
	m.processes = nil
	m = m.applyFilter()
	if len(m.filtered) != 0 {
		t.Fatalf("empty scan: %+v", m.filtered)
	}
}

func TestQueryDoesNotMatchAcrossFields(t *testing.T) {
	m := New()
	// "12" is split over pid "1" and comm "2x"; "bs" over comm "b" and cmdline "s".
	m.processes = []ProcessInfo{{Pid: 1, Comm: "2x", Cmdline: "s"}, {Pid: 5, Comm: "b", Cmdline: "s"}}
	for _, q := range []string{"12", "bs", "1 2"} {
		m.input.SetValue(q)
		if got := m.applyFilter().filtered; len(got) != 0 {
			t.Fatalf("query %q matched across fields: %+v", q, got)
		}
	}
}

// TestSearchCacheFollowsResliceOfSameBackingArray pins the length half of the
// cache validity check: a longer or shorter slice over the same backing array
// has the same first-element address as the one the cache was built for, yet
// different rows.
func TestSearchCacheFollowsResliceOfSameBackingArray(t *testing.T) {
	buf := []ProcessInfo{{Pid: 1, Comm: "alpha"}, {Pid: 2, Comm: "beta"}, {Pid: 3, Comm: "GAMMA"}}
	m := New()
	m.input.SetValue("gamma")

	m.processes = buf[:2]
	m = m.applyFilter()
	if len(m.filtered) != 0 || len(m.search) != 2 {
		t.Fatalf("two rows: filtered=%+v search=%d", m.filtered, len(m.search))
	}

	m.processes = buf[:3] // longer, same first element
	m = m.applyFilter()
	if len(m.search) != 3 || len(m.filtered) != 1 || m.filtered[0].Pid != 3 {
		t.Fatalf("grown slice: filtered=%+v search=%d (stale cache?)", m.filtered, len(m.search))
	}

	m.processes = buf[:1] // shorter, same first element
	m.input.SetValue("alpha")
	m = m.applyFilter()
	if len(m.search) != 1 || len(m.filtered) != 1 || m.filtered[0].Pid != 1 {
		t.Fatalf("shrunk slice: filtered=%+v search=%d (stale cache?)", m.filtered, len(m.search))
	}

	m.processes = append(buf[:1], ProcessInfo{Pid: 9, Comm: "gamma9"}) // append into spare capacity
	m.input.SetValue("gamma9")
	m = m.applyFilter()
	if len(m.search) != 2 || len(m.filtered) != 1 || m.filtered[0].Pid != 9 {
		t.Fatalf("appended slice: filtered=%+v search=%d (stale cache?)", m.filtered, len(m.search))
	}
}

// TestEmptyQueryRescanDropsStaleSearchCache covers the retention half: the
// cache points into the previous scan, so a rescan under an empty query must
// not keep it (and the old scan's backing array) alive, while the same scan
// keeps its cache for the next keystroke and a later query still works.
func TestEmptyQueryRescanDropsStaleSearchCache(t *testing.T) {
	m := New()
	m.processes = []ProcessInfo{{Pid: 1, Comm: "Alpha"}, {Pid: 2, Comm: "beta"}}
	m.input.SetValue("alpha")
	m = m.applyFilter()
	if m.search == nil || m.searchBase == nil {
		t.Fatal("cache not built for a non-empty query")
	}

	m.input.SetValue("")
	m = m.applyFilter()
	if m.search == nil {
		t.Fatal("clearing the query dropped the cache of the unchanged scan")
	}

	m.processes = []ProcessInfo{{Pid: 3, Comm: "Gamma"}} // rescan, empty query
	m = m.applyFilter()
	if m.search != nil || m.searchBase != nil {
		t.Fatalf("stale cache retained after rescan: search=%v base=%v", m.search, m.searchBase)
	}
	if len(m.filtered) != 1 || m.filtered[0].Pid != 3 {
		t.Fatalf("empty query filtered=%+v", m.filtered)
	}

	m.input.SetValue("gamma")
	m = m.applyFilter()
	if len(m.filtered) != 1 || m.filtered[0].Pid != 3 || len(m.search) != 1 {
		t.Fatalf("lazy rebuild: filtered=%+v search=%d", m.filtered, len(m.search))
	}

	// A rescan under an active query replaces the cache right away.
	m.processes = []ProcessInfo{{Pid: 4, Comm: "GAMMA4"}, {Pid: 5, Comm: "x"}}
	m = m.applyFilter()
	if len(m.search) != 2 || len(m.filtered) != 1 || m.filtered[0].Pid != 4 {
		t.Fatalf("rescan under query: filtered=%+v search=%d", m.filtered, len(m.search))
	}
}

// TestViewMatchesLegacyOnRandomCorpus compares the complete View output (header,
// filter input, rows, notice, scan-error line, footer) of the optimised picker
// with the verbatim pre-7r2 implementation on a seeded random corpus, over
// both modes, widths, heights, filter queries, selections (noSelection
// included), notices and scan errors. Comparing whole strings also pins the
// sanitisation, selection marker and width handling of each rendered row.
func TestViewMatchesLegacyOnRandomCorpus(t *testing.T) {
	r := rand.New(rand.NewSource(11))
	procs := randomCorpus(r, 150)
	queries := []string{"", "  ", "bash", "ÄRGER", "日本", "😀", "12", "e", "\x1b", "zzz-no-match"}
	errs := []error{nil, errors.New("read /proc: denied"), errors.New("bad \x1b]8;;http://evil\aclick\x1b]8;;\a \x1b[8mhidden\x9b31m 日本語")}
	notices := []string{"", "pid 7 exited - pick a process", "pid 7 \x1b[31mred\x1b[0m"}
	heights := []int{0, 1, 6, 7, 8, 12, 30, 200}
	widths := []int{0, 20, 80, 240}
	sizes := []int{0, 1, 5, 40, 150}
	for i := 0; i < 150; i++ {
		m := New()
		if r.Intn(2) == 0 {
			m = NewTIDWithKeys([]int{-1, 0, 4242}[r.Intn(3)], DefaultKeyMap())
		}
		m.height = heights[r.Intn(len(heights))]
		m.width = widths[r.Intn(len(widths))]
		m.processes = procs[:sizes[r.Intn(len(sizes))]]
		m.input.SetValue(queries[r.Intn(len(queries))])
		m = m.applyFilter()
		m.selectedIndex = []int{noSelection, 0, 1, 2, 5, 20, 60, 149, 150, 151}[r.Intn(10)]
		m.lastErr = errs[r.Intn(len(errs))]
		m.notice = notices[r.Intn(len(notices))]

		legacy := m
		legacy.filtered = legacyFilter(m.processes, m.input.Value())
		if len(legacy.filtered) != len(m.filtered) {
			t.Fatalf("iter %d: %d filtered rows, legacy %d", i, len(m.filtered), len(legacy.filtered))
		}
		if got, want := m.View().Content, legacy.legacyView().Content; got != want {
			t.Fatalf("iter %d (mode=%d w=%d h=%d sel=%d query=%q rows=%d):\n got %q\nwant %q",
				i, m.mode, m.width, m.height, m.selectedIndex, m.input.Value(), len(m.processes), got, want)
		}
		if got, want := m.renderRows(), legacy.legacyRenderRows(); got != want {
			t.Fatalf("iter %d: renderRows differ:\n got %q\nwant %q", i, got, want)
		}
	}
}

// TestLegacyComparisonDetectsRenderDifferences guards the comparison itself: a
// corpus with control characters must produce a label that Sanitize changed,
// so a renderer that skipped sanitisation cannot pass unnoticed.
func TestLegacyComparisonDetectsRenderDifferences(t *testing.T) {
	p := ProcessInfo{Pid: 5, ParentPID: 1, Comm: "a", Cmdline: "x\x1b[31m日本\ny"}
	if legacyFormatProcess(p) == legacyRawProcessLabel(p) {
		t.Fatal("corpus entry is not altered by sanitisation; the comparison could not catch a missing Sanitize")
	}
	if got, want := formatProcess(p), legacyFormatProcess(p); got != want {
		t.Fatalf("formatProcess %q, legacy %q", got, want)
	}
}

func TestRenderRowsFormatsOnlyTheWindow(t *testing.T) {
	m := New()
	m.height = 10 // 4 visible rows
	m.processes = make([]ProcessInfo, 5000)
	for i := range m.processes {
		m.processes[i] = ProcessInfo{Pid: i + 1, ParentPID: i + 1, Comm: "p", Cmdline: "cmd"}
	}
	m = m.applyFilter()
	m.selectedIndex = 2500
	lines := strings.Split(m.renderRows(), "\n")
	if len(lines) != 4 {
		t.Fatalf("rendered %d lines, want the 4-row window", len(lines))
	}
	if !strings.Contains(m.renderRows(), "> 2500  p  cmd") {
		t.Fatalf("selected row missing from window: %q", m.renderRows())
	}
}

func benchModel(rows int, height int) Model {
	cmdline := strings.Repeat("/usr/lib/Some/Long/Path --flag=Value ", 28) // about 1 KB
	m := New()
	m.height = height
	m.processes = make([]ProcessInfo, rows)
	for i := range m.processes {
		m.processes[i] = ProcessInfo{Pid: i + 1, ParentPID: i + 1, Comm: "proc", Cmdline: cmdline}
	}
	return m.applyFilter()
}

func BenchmarkView50kRows(b *testing.B) {
	m := benchModel(50000, 40)
	m.selectedIndex = 25000
	b.ResetTimer()
	for b.Loop() {
		_ = m.View()
	}
}

func BenchmarkTypeKey50kRows(b *testing.B) {
	m := benchModel(50000, 40)
	m.input.SetValue("zzz")
	m = m.applyFilter() // warm the search text, like the first keystroke of a session
	b.ResetTimer()
	for b.Loop() {
		_ = m.applyFilter()
	}
}
