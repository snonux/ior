package dashboard

import (
	"strings"
	"testing"

	"ior/internal/statsengine"
)

// Attacker-controlled comm and path values (task io2): an OSC 8 hyperlink,
// SGR hidden text, a raw C1 CSI byte, DEL and a newline.
const (
	hostileComm = "ev\x1b[8mil\x7f"
	hostileDir  = "/tmp/\x1b]8;;http://evil\aclick\x1b]8;;\a/\x9b31m\nx"
	hostilePath = hostileDir + "/file"
)

// assertNoControl fails when s still contains a C0/C1 control, DEL or an
// invalid UTF-8 byte that a terminal could interpret.
func assertNoControl(t *testing.T, what, s string) {
	t.Helper()
	if strings.ContainsFunc(s, func(r rune) bool {
		return r < 0x20 || (r >= 0x7f && r <= 0x9f) || r == '�'
	}) {
		t.Fatalf("%s contains a control rune or invalid byte: %q", what, s)
	}
}

func hostileSnapshot() statsengine.Snapshot {
	return statsengine.NewSnapshot(nil, nil, nil,
		[]statsengine.SyscallSnapshot{{Name: "openat", Count: 1}},
		[]statsengine.FileSnapshot{{Path: hostilePath, Accesses: 3, BytesRead: 1}},
		[]statsengine.ProcessSnapshot{{PID: 7, Comm: hostileComm, Syscalls: 3, Bytes: 1}},
		statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
}

func TestDashboardViewsSanitizeTracedLabels(t *testing.T) {
	snap := hostileSnapshot()
	for _, item := range buildFilesTreemapItems(&snap, bubbleMetricCount) {
		assertNoControl(t, "files treemap name", item.Name)
		assertNoControl(t, "files treemap detail", item.Detail)
	}
	for _, item := range buildProcessesTreemapItems(&snap, bubbleMetricCount) {
		if item.Name != "7:ev?[8mil?" {
			t.Fatalf("process treemap name = %q, want %q", item.Name, "7:ev?[8mil?")
		}
	}
	for _, d := range filesDirBubbleData(&snap) {
		assertNoControl(t, "files bubble label", d.Label)
		assertNoControl(t, "files bubble detail", d.Detail)
	}
	for _, d := range processBubbleData(&snap) {
		assertNoControl(t, "process bubble label", d.Label)
	}
	assertNoControl(t, "top files", summarizeTopFiles(&snap))
	assertNoControl(t, "top processes", summarizeTopProcesses(&snap))
	for _, row := range fileRows(snap.Files(), 80) {
		assertNoControl(t, "file row", strings.Join(row, " "))
	}
	for _, row := range dirRows(snapshotDirRows(&snap), 80) {
		assertNoControl(t, "dir row", strings.Join(row, " "))
	}
	for _, row := range processRows(snap.Processes()) {
		assertNoControl(t, "process row", strings.Join(row, " "))
	}
}

// TestProcessLabelKeepsSelectionKeysRaw checks only display labels are
// sanitised: the bubble ID and treemap key must still identify the process.
func TestProcessLabelKeepsSelectionKeysRaw(t *testing.T) {
	snap := hostileSnapshot()
	procs := processBubbleData(&snap)
	if len(procs) != 1 || procs[0].ID != processKey(7, 0) {
		t.Fatalf("bubble ID should be the process key, not the sanitised label, got %#v", procs)
	}
	files := buildFilesTreemapItems(&snap, bubbleMetricCount)
	if len(files) != 1 || files[0].Key != hostileDir {
		t.Fatalf("treemap key should keep the raw dir, got %#v", files)
	}
	if got := processLabel(statsengine.ProcessSnapshot{PID: 9, Comm: "  "}); got != "9" {
		t.Fatalf("processLabel without comm = %q, want 9", got)
	}
}

func TestFilterSummarySanitizesNoticeAndStack(t *testing.T) {
	m := NewModel(nil, nil)
	m.SetFilterNotice("refused " + hostilePath)
	m.SetFilterStack([]string{"comm~" + hostileComm})
	m.SetRecordingStatus("rec " + hostilePath)
	assertNoControl(t, "filter summary", m.filterSummary())
}
