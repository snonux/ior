package flamegraph

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"ior/internal/file"
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

// pidlessKey is the stage-1 key of a (path, comm, tracepoint, flags) group.
func pidlessKey(path, comm string, id types.TraceId, flags file.Flags) recordKey {
	return recordKey{Path: path, TraceID: id, Comm: comm, Flags: flags}
}

// otherKey is the stage-2 key of a (tracepoint, flags) group.
func otherKey(id types.TraceId, flags file.Flags) recordKey {
	return recordKey{Path: recordOverflowLabel, TraceID: id, Comm: recordOverflowLabel, Flags: flags}
}

// Stage 1: under pid/tid churn the events past the cap land in the pid 0/tid 0
// record of their own path and comm, never in "[other]", and totals stay exact.
func TestAddPidFoldKeepsPathAndCommAtTheCap(t *testing.T) {
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
	// 3 real keys plus the one pid-less key of (/f, c, read).
	if len(iod.records) != 4 {
		t.Fatalf("records = %d, want 4 (3 real + 1 pid-less)", len(iod.records))
	}
	folded, ok := iod.records[pidlessKey("/f", "c", types.SYS_ENTER_READ, 0)]
	if !ok || folded.Count != 7 {
		t.Fatalf("pid-less record = %+v (present %v), want the 7 events past the cap", folded, ok)
	}
	if _, ok := iod.records[otherKey(types.SYS_ENTER_READ, 0)]; ok {
		t.Fatal("an [other] record exists although only pid/tid churned")
	}
	if iod.folds != (foldCounts{pidless: 7}) {
		t.Fatalf("folds = %+v, want 7 stage-1 events", iod.folds)
	}
}

// Stage 2: once the headroom for pid-less keys is used up, events of new
// path/comm combinations go to "[other]", and totals still add up.
func TestAddOtherFoldTakesOverWhenPathAndCommChurn(t *testing.T) {
	iod := newIorData()
	iod.maxKeys = 2 // hard limit 3: two real keys and one pid-less key
	iod.add("/a", types.SYS_ENTER_READ, "c", 1, 1, 0, Counter{Count: 1})
	iod.add("/b", types.SYS_ENTER_READ, "c", 1, 1, 0, Counter{Count: 1})
	iod.add("/c", types.SYS_ENTER_READ, "c", 1, 1, 0, Counter{Count: 1}) // stage 1: new pid-less key
	iod.add("/d", types.SYS_ENTER_READ, "c", 1, 1, 0, Counter{Count: 1}) // stage 2
	iod.add("/c", types.SYS_ENTER_READ, "c", 9, 9, 0, Counter{Count: 1}) // stage 1 again: key exists
	iod.add("/e", types.SYS_ENTER_READ, "c", 1, 1, 0, Counter{Count: 1}) // stage 2

	if got := iod.records[pidlessKey("/c", "c", types.SYS_ENTER_READ, 0)].Count; got != 2 {
		t.Fatalf("pid-less /c count = %d, want 2", got)
	}
	if got := iod.records[otherKey(types.SYS_ENTER_READ, 0)].Count; got != 2 {
		t.Fatalf("[other] count = %d, want 2 (/d and /e)", got)
	}
	if iod.folds != (foldCounts{pidless: 2, other: 2}) {
		t.Fatalf("folds = %+v, want 2 events per stage", iod.folds)
	}
	if got := totalsOf(iod).Count; got != 6 {
		t.Fatalf("total count = %d, want 6", got)
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
	if iod.folds.total() != 1 {
		t.Fatalf("folded events = %d, want 1", iod.folds.total())
	}
}

// boundOf is the documented memory bound for nTrace tracepoints: the hard
// limit (cap + stage-1 headroom) plus one "[other]" record per tracepoint.
func boundOf(iod iorData, nTrace int) int {
	return iod.hardLimit() + nTrace
}

// The memory bound under pid/tid churn only: one path and comm, endless pids.
func TestAddBoundsTheMapUnderPidChurn(t *testing.T) {
	iod := newIorData()
	iod.maxKeys = 100
	for pid := uint32(0); pid < 10000; pid++ {
		iod.add("/f", types.SYS_ENTER_READ, "c", pid, pid, 0, Counter{Count: 1})
		iod.add("/f", types.SYS_ENTER_WRITE, "c", pid, pid, 0, Counter{Count: 1})
	}
	if limit := boundOf(iod, 2); len(iod.records) > limit {
		t.Fatalf("records = %d, want <= %d", len(iod.records), limit)
	}
	if got := totalsOf(iod).Count; got != 20000 {
		t.Fatalf("total count = %d, want 20000", got)
	}
	// One path and comm only: nothing may have needed stage 2.
	if iod.folds.other != 0 {
		t.Fatalf("stage-2 events = %d, want 0 under pid churn only", iod.folds.other)
	}
}

// The memory bound when the path population churns as well (every event has a
// fresh path): stage 1 fills its headroom, everything else goes to [other].
func TestAddBoundsTheMapUnderPathChurn(t *testing.T) {
	iod := newIorData()
	iod.maxKeys = 100
	for i := 0; i < 10000; i++ {
		iod.add(fmt.Sprintf("/tmp/file-%d", i), types.SYS_ENTER_READ, "c", uint32(i), uint32(i), 0, Counter{Count: 1})
	}
	if limit := boundOf(iod, 1); len(iod.records) > limit {
		t.Fatalf("records = %d, want <= %d", len(iod.records), limit)
	}
	if got := totalsOf(iod).Count; got != 10000 {
		t.Fatalf("total count = %d, want 10000", got)
	}
	if want := uint64(10000 - iod.hardLimit()); iod.folds.other != want {
		t.Fatalf("stage-2 events = %d, want %d", iod.folds.other, want)
	}
	if iod.folds.pidless != uint64(stageOneHeadroom(100)) {
		t.Fatalf("stage-1 events = %d, want %d", iod.folds.pidless, stageOneHeadroom(100))
	}
}

// The overflow keys keep the flags: two distinct non-zero flags must not share
// a record, at either stage. (Mutating the fold targets to drop Flags fails
// this test.)
func TestFoldKeepsFlagsSeparate(t *testing.T) {
	const flagsA, flagsB = file.Flags(0x1), file.Flags(0x2)
	// Stage 2: path churn with two flag values.
	iod := newIorData()
	iod.maxKeys = 1 // hard limit 2
	iod.add("/a", types.SYS_ENTER_OPENAT, "c", 1, 1, 0, Counter{Count: 1})
	iod.add("/p1", types.SYS_ENTER_OPENAT, "c", 1, 1, 0, Counter{Count: 1}) // fills the headroom
	iod.add("/b", types.SYS_ENTER_OPENAT, "c", 1, 1, flagsA, Counter{Count: 1})
	iod.add("/c", types.SYS_ENTER_OPENAT, "c", 1, 1, flagsB, Counter{Count: 1})
	for _, flags := range []file.Flags{flagsA, flagsB} {
		if got := iod.records[otherKey(types.SYS_ENTER_OPENAT, flags)].Count; got != 1 {
			t.Fatalf("[other] record for flags %v has count %d, want its own record with 1", flags, got)
		}
	}
	if len(iod.records) != 4 {
		t.Fatalf("records = %d, want 4 (2 stored + one [other] per flags)", len(iod.records))
	}

	// Stage 1: the same path and comm under two flag values, pid churn.
	iod = newIorData()
	iod.maxKeys = 1
	iod.add("/a", types.SYS_ENTER_OPENAT, "c", 1, 1, 0, Counter{Count: 1})
	iod.add("/a", types.SYS_ENTER_OPENAT, "c", 2, 2, flagsA, Counter{Count: 1})
	iod.add("/a", types.SYS_ENTER_OPENAT, "c", 3, 3, flagsB, Counter{Count: 1}) // headroom is 1 and used
	iod.add("/a", types.SYS_ENTER_OPENAT, "c", 4, 4, flagsA, Counter{Count: 1})
	if got := iod.records[pidlessKey("/a", "c", types.SYS_ENTER_OPENAT, flagsA)].Count; got != 2 {
		t.Fatalf("pid-less record for flags A has count %d, want 2", got)
	}
	if got := iod.records[otherKey(types.SYS_ENTER_OPENAT, flagsB)].Count; got != 1 {
		t.Fatalf("[other] record for flags B has count %d, want 1", got)
	}
}

// Under pid churn the default collapsed fields (comm, tracepoint, path) show
// the full attribution of every event, folded or not: stage 1 loses nothing
// that they render.
func TestPidChurnKeepsDefaultCollapsedAttribution(t *testing.T) {
	t.Chdir(t.TempDir())
	captureStatus(t)
	recorder := NewRecorder("uq2pid")
	recorder.data.maxKeys = 2
	for i := uint32(1); i <= 6; i++ {
		recorder.AddPair(collapsedTestPair(uint64(i), "api", "/srv/a", types.SYS_ENTER_READ, types.SYS_EXIT_READ, 100*i))
	}
	if err := recorder.Write(); err != nil {
		t.Fatalf("Write: %v", err)
	}
	var out bytes.Buffer
	if err := WriteCollapsedStacks(&out, onlyRecording(t), CollapsedOptions{}); err != nil {
		t.Fatalf("WriteCollapsedStacks: %v", err)
	}
	if want := "api;enter_read;/srv;/a 6\n"; out.String() != want {
		t.Fatalf("collapsed = %q, want %q: all 6 events keep comm, tracepoint and path", out.String(), want)
	}
}

// The zero maxKeys of loaded recordings, WriteRecordingFile and fixtures never
// folds: the cap is a property of the live recorder only.
func TestUnboundedIorDataNeverFolds(t *testing.T) {
	iod := newIorData()
	for pid := uint32(0); pid < 1000; pid++ {
		iod.add("/f", types.SYS_ENTER_READ, "c", pid, pid, 0, Counter{Count: 1})
	}
	if len(iod.records) != 1000 || iod.folds.total() != 0 {
		t.Fatalf("records = %d, folded = %d, want 1000 and 0", len(iod.records), iod.folds.total())
	}
}

func TestNewRecorderIsCapped(t *testing.T) {
	if got := NewRecorder("x").data.maxKeys; got != DefaultMaxRecordKeys {
		t.Fatalf("NewRecorder maxKeys = %d, want DefaultMaxRecordKeys (%d)", got, DefaultMaxRecordKeys)
	}
}

// NewRecorderWithMaxKeys (-flamegraph-max-keys, task rs2) takes the cap as
// given, both below and above the default, and never builds an unbounded
// live recorder: a non-positive cap falls back to the default.
func TestNewRecorderWithMaxKeysSetsTheCap(t *testing.T) {
	for _, tc := range []struct{ in, want int }{
		{3, 3},
		{DefaultMaxRecordKeys * 4, DefaultMaxRecordKeys * 4},
		{MaxRecordKeysLimit, MaxRecordKeysLimit},
		{0, DefaultMaxRecordKeys},
		{-5, DefaultMaxRecordKeys},
	} {
		r := NewRecorderWithMaxKeys("x", tc.in)
		if got := r.MaxKeys(); got != tc.want {
			t.Fatalf("NewRecorderWithMaxKeys(%d).MaxKeys() = %d, want %d", tc.in, got, tc.want)
		}
		if got := r.data.maxKeys; got != tc.want {
			t.Fatalf("NewRecorderWithMaxKeys(%d) data.maxKeys = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// feedPids adds n events of one path and comm with pids/tids first..first+n-1:
// every event is a new exact key, and all share one stage-1 key.
func feedPids(recorder *Recorder, first, n uint32) {
	for pid := first; pid < first+n; pid++ {
		recorder.AddPair(collapsedTestPair(uint64(pid), "api", "/srv/a", types.SYS_ENTER_READ, types.SYS_EXIT_READ, pid))
	}
}

// A lowered cap folds every new key past it and counts the folded events in
// the end-of-run summary; the notice names the cap and the flag to raise it.
func TestRecorderHonoursALoweredCap(t *testing.T) {
	t.Chdir(t.TempDir())
	status := captureStatus(t)
	recorder := NewRecorderWithMaxKeys("rs2low", 4)
	feedPids(recorder, 1, 10)
	// 4 exact keys plus the one pid-less key absorbing the other 6 events.
	if got := len(recorder.data.records); got != 5 {
		t.Fatalf("records = %d, want 5 (4 exact + 1 pid-less)", got)
	}
	if recorder.data.folds != (foldCounts{pidless: 6}) {
		t.Fatalf("folds = %+v, want 6 stage-1 events", recorder.data.folds)
	}
	if err := recorder.Write(); err != nil {
		t.Fatalf("Write: %v", err)
	}
	out := status.String()
	for _, want := range []string{"reached its limit of 4 distinct", "-flamegraph-max-keys", "6 event(s) into pid 0/tid 0"} {
		if !strings.Contains(out, want) {
			t.Fatalf("status = %q, want it to contain %q", out, want)
		}
	}
}

// A raised cap keeps storing exactly where the default would have folded.
// Filling past the 2^19 default takes about a second, so it is a short-mode
// skip; the lowered-cap test above covers the same mechanism cheaply.
func TestRecorderHonoursARaisedCap(t *testing.T) {
	if testing.Short() {
		t.Skip("fills more than DefaultMaxRecordKeys records")
	}
	captureStatus(t)
	recorder := NewRecorderWithMaxKeys("rs2high", DefaultMaxRecordKeys+100)
	n := uint32(DefaultMaxRecordKeys + 50)
	for pid := uint32(1); pid <= n; pid++ {
		recorder.data.add("/srv/a", types.SYS_ENTER_READ, "api", pid, pid, 0, Counter{Count: 1})
	}
	if got := len(recorder.data.records); got != int(n) {
		t.Fatalf("records = %d, want %d: every key below the raised cap is stored exactly", got, n)
	}
	if total := recorder.data.folds.total(); total != 0 {
		t.Fatalf("folded %d events below the raised cap, want 0", total)
	}
	// Past the raised cap the fold starts as usual.
	for pid := n + 1; pid <= n+60; pid++ {
		recorder.data.add("/srv/a", types.SYS_ENTER_READ, "api", pid, pid, 0, Counter{Count: 1})
	}
	if recorder.data.folds != (foldCounts{pidless: 10}) {
		t.Fatalf("folds = %+v, want the 10 events past the raised cap in stage 1", recorder.data.folds)
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

// feedPaths adds n pairs of one comm, each with its own path and pid, so every
// event is a new key at every level of the fold.
func feedPaths(recorder *Recorder, n uint32) {
	for i := uint32(1); i <= n; i++ {
		recorder.AddPair(collapsedTestPair(uint64(i), "api", fmt.Sprintf("/srv/p%d", i),
			types.SYS_ENTER_READ, types.SYS_EXIT_READ, 100*i))
	}
}

func TestRecorderWarnsOncePerStageAndSummarisesAtWrite(t *testing.T) {
	t.Chdir(t.TempDir())
	status := captureStatus(t)
	recorder := NewRecorder("uq2")
	recorder.data.maxKeys = 2

	// Pid churn only: stage 1 announces itself once, stage 2 not at all.
	for i := uint32(1); i <= 6; i++ {
		recorder.AddPair(collapsedTestPair(uint64(i), "api", "/srv/a", types.SYS_ENTER_READ, types.SYS_EXIT_READ, 100*i))
	}
	if n := strings.Count(status.String(), "reached its limit of 2"); n != 1 {
		t.Fatalf("stage-1 notice printed %d times (status %q), want exactly once, during the run", n, status.String())
	}
	if strings.Contains(status.String(), "ran out of room") {
		t.Fatalf("stage-2 notice printed under pid churn only: %q", status.String())
	}
	if strings.Contains(status.String(), "folded") && strings.Contains(status.String(), "Wrote") {
		t.Fatalf("summary printed before Write: %q", status.String())
	}

	// Path churn: stage 2 announces itself once, too.
	for i := uint32(1); i <= 6; i++ {
		recorder.AddPair(collapsedTestPair(uint64(i), "db", fmt.Sprintf("/srv/q%d", i), types.SYS_ENTER_READ, types.SYS_EXIT_READ, 100*i))
	}
	if n := strings.Count(status.String(), "ran out of room"); n != 1 {
		t.Fatalf("stage-2 notice printed %d times (status %q), want exactly once", n, status.String())
	}
	if n := strings.Count(status.String(), "reached its limit of 2"); n != 1 {
		t.Fatalf("stage-1 notice repeated: printed %d times", n)
	}

	if err := recorder.Write(); err != nil {
		t.Fatalf("Write: %v", err)
	}
	out := status.String()
	for _, want := range []string{"Wrote", "4 event(s) into pid 0/tid 0 records", "(stage 1", "into \"[other]\" records (stage 2"} {
		if !strings.Contains(out, want) {
			t.Fatalf("status = %q, want it to contain %q", out, want)
		}
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

// End to end with path churn: the recording of a capped run still carries the
// exact total weight, with the stage-2 part under the "[other]" frame.
func TestCappedRecordingKeepsCollapsedTotalsExact(t *testing.T) {
	t.Chdir(t.TempDir())
	captureStatus(t)
	recorder := NewRecorder("uq2e2e")
	recorder.data.maxKeys = 2 // hard limit 3: events 1-3 are stored, 4-7 go to [other]
	feedPaths(recorder, 7)
	if err := recorder.Write(); err != nil {
		t.Fatalf("Write: %v", err)
	}

	var out bytes.Buffer
	if err := WriteCollapsedStacks(&out, onlyRecording(t), CollapsedOptions{Fields: []string{"comm"}}); err != nil {
		t.Fatalf("WriteCollapsedStacks: %v", err)
	}
	want := "[other] 4\napi 3\n"
	if got := out.String(); got != want {
		t.Fatalf("collapsed = %q, want %q", got, want)
	}
}

// BenchmarkAddDistinctKeysCapped measures the at-cap path only: the map is
// filled to the cap and the stage-1 headroom before the timer starts, so every
// timed add is a fold into an existing pid-less record (distinct pid/tid, one
// path and comm), which is the case of a pid/tid-churning trace.
func BenchmarkAddDistinctKeysCapped(b *testing.B) {
	iod := newIorData()
	iod.maxKeys = DefaultMaxRecordKeys
	for i := 1; i <= iod.maxKeys; i++ { // pid 1.. : pid 0/tid 0 is the stage-1 key itself
		pid := uint32(i)
		iod.add("/srv/some/path", types.SYS_ENTER_READ, "comm", pid, pid, 0, Counter{Count: 1})
	}
	iod.add("/srv/some/path", types.SYS_ENTER_READ, "comm", uint32(iod.maxKeys+1), 1, 0, Counter{Count: 1}) // creates the pid-less record
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		pid := uint32(iod.maxKeys + 2 + i)
		iod.add("/srv/some/path", types.SYS_ENTER_READ, "comm", pid, pid, 0, Counter{Count: 1})
	}
	b.ReportMetric(float64(len(iod.records)), "records")
}
