package flamegraph

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"ior/internal/types"
)

// totalsOf sums every counter of the records, the exactness invariant of the
// key cap: folding must move events between records, never lose them.
func totalsOf(iod iorData) Counter {
	var total Counter
	for _, cnt := range iod.records {
		total = total.add(cnt)
	}
	return total
}

func TestAddFoldsNewKeysAtTheCapAndKeepsTotalsExact(t *testing.T) {
	iod := newIorData()
	iod.maxKeys = 3
	var want Counter
	for pid := uint32(1); pid <= 10; pid++ {
		cnt := Counter{Count: 1, Duration: uint64(pid), DurationToPrev: 2 * uint64(pid), Bytes: 100 * uint64(pid)}
		want = want.add(cnt)
		iod.add("/f", types.SYS_ENTER_READ, "c", pid, pid, 0, cnt)
	}

	if got := totalsOf(iod); got != want {
		t.Fatalf("totals = %+v, want %+v: folding must keep them exact", got, want)
	}
	// 3 real keys plus the single overflow key of (read, flags 0).
	if len(iod.records) != 4 {
		t.Fatalf("records = %d, want 4 (3 real + 1 overflow)", len(iod.records))
	}
	overflow, ok := iod.records[recordKey{Path: recordOverflowLabel, TraceID: types.SYS_ENTER_READ, Comm: recordOverflowLabel}]
	if !ok || overflow.Count != 7 {
		t.Fatalf("overflow record = %+v (present %v), want the 7 events past the cap", overflow, ok)
	}
	if iod.foldedEvents != 7 {
		t.Fatalf("foldedEvents = %d, want 7", iod.foldedEvents)
	}
}

// Keys stored before the cap was reached keep aggregating exactly afterwards.
func TestAddKeepsAggregatingExistingKeysAtTheCap(t *testing.T) {
	iod := newIorData()
	iod.maxKeys = 2
	iod.add("/a", types.SYS_ENTER_READ, "c", 1, 1, 0, Counter{Count: 1})
	iod.add("/b", types.SYS_ENTER_READ, "c", 1, 1, 0, Counter{Count: 1})
	iod.add("/c", types.SYS_ENTER_READ, "c", 1, 1, 0, Counter{Count: 1}) // folded
	iod.add("/a", types.SYS_ENTER_READ, "c", 1, 1, 0, Counter{Count: 5}) // existing

	if got := iod.records[recordKey{Path: "/a", TraceID: types.SYS_ENTER_READ, Comm: "c", Pid: 1, Tid: 1}].Count; got != 6 {
		t.Fatalf("/a count = %d, want 6: an existing key must not be folded", got)
	}
	if iod.foldedEvents != 1 {
		t.Fatalf("foldedEvents = %d, want 1", iod.foldedEvents)
	}
}

// The memory bound: however many distinct keys arrive, the map stays within
// the cap plus one overflow key per (tracepoint, flags).
func TestAddBoundsTheMapForManyDistinctKeys(t *testing.T) {
	iod := newIorData()
	iod.maxKeys = 100
	for pid := uint32(0); pid < 10000; pid++ {
		iod.add("/f", types.SYS_ENTER_READ, "c", pid, pid, 0, Counter{Count: 1})
		iod.add("/f", types.SYS_ENTER_WRITE, "c", pid, pid, 0, Counter{Count: 1})
	}
	if limit := iod.maxKeys + 2; len(iod.records) > limit {
		t.Fatalf("records = %d, want <= %d (cap + one overflow key per tracepoint)", len(iod.records), limit)
	}
	if got := totalsOf(iod).Count; got != 20000 {
		t.Fatalf("total count = %d, want 20000", got)
	}
}

// The zero maxKeys of loaded recordings, WriteRecordingFile and fixtures never
// folds: the cap is a property of the live recorder only.
func TestUnboundedIorDataNeverFolds(t *testing.T) {
	iod := newIorData()
	for pid := uint32(0); pid < 1000; pid++ {
		iod.add("/f", types.SYS_ENTER_READ, "c", pid, pid, 0, Counter{Count: 1})
	}
	if len(iod.records) != 1000 || iod.foldedEvents != 0 {
		t.Fatalf("records = %d, folded = %d, want 1000 and 0", len(iod.records), iod.foldedEvents)
	}
}

func TestNewRecorderIsCapped(t *testing.T) {
	if got := NewRecorder("x").data.maxKeys; got != DefaultMaxRecordKeys {
		t.Fatalf("NewRecorder maxKeys = %d, want DefaultMaxRecordKeys (%d)", got, DefaultMaxRecordKeys)
	}
}

// captureStatus replaces statusOut for one test.
func captureStatus(t *testing.T) *bytes.Buffer {
	t.Helper()
	orig := statusOut
	var buf bytes.Buffer
	statusOut = &buf
	t.Cleanup(func() { statusOut = orig })
	return &buf
}

// onlyRecording returns the single .ior.zst of the working directory.
func onlyRecording(t *testing.T) string {
	t.Helper()
	matches, err := filepath.Glob("*.ior.zst")
	if err != nil || len(matches) != 1 {
		t.Fatalf("recordings = %v, %v; want exactly one", matches, err)
	}
	return matches[0]
}

func TestRecorderWarnsOnceWhenTheCapIsHitAndSummarisesAtWrite(t *testing.T) {
	t.Chdir(t.TempDir())
	status := captureStatus(t)
	recorder := NewRecorder("uq2")
	recorder.data.maxKeys = 2

	for i := uint32(1); i <= 6; i++ {
		recorder.AddPair(collapsedTestPair(uint64(i), "api", "/srv/a", types.SYS_ENTER_READ, types.SYS_EXIT_READ, 100*i))
	}
	if n := strings.Count(status.String(), "reached its limit of 2"); n != 1 {
		t.Fatalf("overflow notice printed %d times (status %q), want exactly once, during the run", n, status.String())
	}
	if strings.Contains(status.String(), "folded") && strings.Contains(status.String(), "Wrote") {
		t.Fatalf("summary printed before Write: %q", status.String())
	}

	if err := recorder.Write(); err != nil {
		t.Fatalf("Write: %v", err)
	}
	out := status.String()
	if !strings.Contains(out, "folded 4 event(s)") || !strings.Contains(out, "Wrote") {
		t.Fatalf("status = %q, want the Wrote line and the fold summary (4 events)", out)
	}
}

func TestRecorderStaysSilentUnderTheCap(t *testing.T) {
	t.Chdir(t.TempDir())
	status := captureStatus(t)
	recorder := NewRecorder("uq2quiet")
	recorder.data.maxKeys = 10
	for i := uint32(1); i <= 5; i++ {
		recorder.AddPair(collapsedTestPair(uint64(i), "api", "/srv/a", types.SYS_ENTER_READ, types.SYS_EXIT_READ, 100*i))
	}
	if err := recorder.Write(); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if strings.Contains(status.String(), "limit") || strings.Contains(status.String(), "folded") {
		t.Fatalf("status = %q, want no overflow text for a run under the cap", status.String())
	}
}

// End to end: the recording of a capped run still carries the exact total
// weight, with the folded part under the "[other]" frame.
func TestCappedRecordingKeepsCollapsedTotalsExact(t *testing.T) {
	t.Chdir(t.TempDir())
	captureStatus(t)
	recorder := NewRecorder("uq2e2e")
	recorder.data.maxKeys = 2
	for i := uint32(1); i <= 6; i++ {
		recorder.AddPair(collapsedTestPair(uint64(i), "api", "/srv/a", types.SYS_ENTER_READ, types.SYS_EXIT_READ, 100*i))
	}
	if err := recorder.Write(); err != nil {
		t.Fatalf("Write: %v", err)
	}
	path := onlyRecording(t)

	var out bytes.Buffer
	if err := WriteCollapsedStacks(&out, path, CollapsedOptions{Fields: []string{"comm"}}); err != nil {
		t.Fatalf("WriteCollapsedStacks: %v", err)
	}
	want := "[other] 4\napi 2\n"
	if got := out.String(); got != want {
		t.Fatalf("collapsed = %q, want %q", got, want)
	}
}

func BenchmarkAddDistinctKeysCapped(b *testing.B) {
	iod := newIorData()
	iod.maxKeys = DefaultMaxRecordKeys
	b.ReportAllocs()
	for i := 0; b.Loop(); i++ {
		pid := uint32(i)
		iod.add("/srv/some/path", types.SYS_ENTER_READ, "comm", pid, pid, 0, Counter{Count: 1})
	}
	b.ReportMetric(float64(len(iod.records)), "records")
}
