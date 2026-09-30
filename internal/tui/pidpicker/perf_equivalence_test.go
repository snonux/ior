package pidpicker

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// The functions below are the pre-task-7r2 implementations, kept verbatim as a
// reference: the optimised filter and windowed renderer must stay observably
// identical to them on any corpus.

func referenceMatchesQuery(process ProcessInfo, query string) bool {
	pidStr := fmt.Sprintf("%d", process.Pid)
	if strings.Contains(strings.ToLower(pidStr), query) {
		return true
	}
	if strings.Contains(strings.ToLower(process.Comm), query) {
		return true
	}
	return strings.Contains(strings.ToLower(process.Cmdline), query)
}

func referenceFilter(processes []ProcessInfo, rawQuery string) []ProcessInfo {
	query := strings.TrimSpace(strings.ToLower(rawQuery))
	out := make([]ProcessInfo, 0, len(processes))
	for _, p := range processes {
		if query == "" || referenceMatchesQuery(p, query) {
			out = append(out, p)
		}
	}
	return out
}

func referenceRenderRows(m Model) string {
	lines := make([]string, 0, len(m.filtered)+1)
	allLabel := allPIDsLabel
	if m.mode == PickerModeTID {
		allLabel = allTIDsLabel
	}
	lines = append(lines, m.renderRow(0, allLabel))
	for i, process := range m.filtered {
		lines = append(lines, m.renderRow(i+1, formatProcess(process)))
	}
	maxRows := m.visibleRows()
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

// randomCorpus builds processes with mixed-case, multi-byte, control-character
// and empty fields, and parent pids that exercise every label format.
func randomCorpus(r *rand.Rand, n int) []ProcessInfo {
	words := []string{"Bash", "sshd", "MySQLd", "java", "Ärger", "İstanbul", "kworker/0:1", "x\ny", "a\x1b[31mb", "", "nginx", "ÖL"}
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
		out[i] = ProcessInfo{Pid: pid, ParentPID: parent, Comm: words[r.Intn(len(words))], Cmdline: pick(4)}
	}
	return out
}

func TestFilterMatchesReferenceOnRandomCorpus(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	procs := randomCorpus(r, 600)
	queries := []string{"", "  ", "bash", "BASH", " Bash ", "12", "3", "sql", "ärger", "ÄRGER", "i̇", "istanbul", "x\ny",
		"kworker", "nonexistent", "sshd java", "\x1b", "0", "ÖL"}
	for _, q := range queries {
		m := New()
		m.processes = procs
		m.input.SetValue(q)
		m = m.applyFilter()
		// The reference sees what the input really holds (SetValue may rewrite
		// control characters such as newlines).
		want := referenceFilter(procs, m.input.Value())
		if len(m.filtered) != len(want) {
			t.Fatalf("query %q: %d rows, reference %d", q, len(m.filtered), len(want))
		}
		for i := range want {
			if m.filtered[i] != want[i] {
				t.Fatalf("query %q row %d: %+v, reference %+v", q, i, m.filtered[i], want[i])
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

func TestRenderRowsMatchesReferenceOnRandomCorpus(t *testing.T) {
	r := rand.New(rand.NewSource(11))
	procs := randomCorpus(r, 120)
	for _, mode := range []PickerMode{PickerModePID, PickerModeTID} {
		for _, height := range []int{0, 1, 7, 8, 12, 30, 200} {
			for _, sel := range []int{noSelection, 0, 1, 2, 5, 60, 119, 120} {
				for _, n := range []int{0, 1, 5, 120} {
					m := New()
					m.mode = mode
					m.height = height
					m.processes = procs[:n]
					m = m.applyFilter()
					m.selectedIndex = sel
					if got, want := m.renderRows(), referenceRenderRows(m); got != want {
						t.Fatalf("mode=%d height=%d sel=%d rows=%d:\n got %q\nwant %q", mode, height, sel, n, got, want)
					}
				}
			}
		}
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
