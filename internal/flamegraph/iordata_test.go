package flamegraph

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"ior/internal/types"

	"github.com/DataDog/zstd"
)

func counterAt(iod iorData, path pathType, traceID traceIdType, comm commType, pid pidType, tid tidType, flags flagsType) (Counter, bool) {
	key := recordKey{
		Path:    path,
		TraceID: traceID,
		Comm:    comm,
		Pid:     pid,
		Tid:     tid,
		Flags:   flags,
	}
	cnt, ok := iod.records[key]
	return cnt, ok
}

func TestAddPath(t *testing.T) {
	iod := newIorData()
	path := pathType("testPath")
	traceId := types.SYS_ENTER_OPENAT
	comm := commType("testComm")
	pid := pidType(1234)
	tid := tidType(5678)
	flags := flagsType(syscall.O_RDONLY)
	cnt1 := Counter{Count: 1, Duration: 1000, DurationToPrev: 100, Bytes: 64}

	iod.add(path, traceId, comm, pid, tid, flags, cnt1)

	gotCnt, ok := counterAt(iod, path, traceId, comm, pid, tid, flags)
	if !ok || gotCnt != cnt1 {
		t.Errorf("Expected counter %v, got %v (ok=%v)", cnt1, gotCnt, ok)
	}
	cnt2 := Counter{Count: 2, Duration: 2000, DurationToPrev: 200, Bytes: 128}

	iod.add(path, traceId, comm, pid, tid, flags, cnt2)

	resultCnt := cnt1.add(cnt2)
	gotCnt, ok = counterAt(iod, path, traceId, comm, pid, tid, flags)
	if !ok || gotCnt != resultCnt {
		t.Errorf("Expected counter %v, got %v (ok=%v)", resultCnt, gotCnt, ok)
	}
}

func TestMerge(t *testing.T) {
	rdwrFlag := flagsType(syscall.O_RDWR)
	roFlag := flagsType(syscall.O_RDONLY)
	traceId := types.SYS_ENTER_OPENAT
	// Initialize iorData instances with sample data
	iod1 := newIorData()
	iod1.add("path1", traceId, "comm1", 100, 1000, rdwrFlag, Counter{
		Count:          10,
		Duration:       1000,
		DurationToPrev: 100,
		Bytes:          64,
	})
	iod2 := newIorData()
	iod2.add("path1", traceId, "comm1", 100, 1000, roFlag, Counter{
		Count:          20,
		Duration:       2000,
		DurationToPrev: 200,
		Bytes:          128,
	})
	iod3 := newIorData()
	iod3.add("path2", traceId, "comm2", 101, 1000, roFlag, Counter{
		Count:          20,
		Duration:       2000,
		DurationToPrev: 200,
		Bytes:          128,
	})
	iod4 := newIorData()
	iod4.add("path2", traceId, "comm2", 101, 1000, roFlag, Counter{
		Count:          40,
		Duration:       4000,
		DurationToPrev: 400,
		Bytes:          256,
	})

	t.Log("iod1", iod1)
	t.Log("iod2", iod2)
	t.Log("iod3", iod3)
	t.Log("iod4", iod4)
	merged := *iod1.merge(iod2).merge(iod3).merge(iod4)
	t.Log("merged", merged)

	t.Run("Merged correctly", func(t *testing.T) {
		if len(merged.records) != 3 {
			t.Errorf("Expected 3 aggregated records, got %d", len(merged.records))
		}
		if cnt, _ := counterAt(merged, "path1", traceId, "comm1", 100, 1000, rdwrFlag); cnt.Count != 10 {
			t.Errorf("Expected counter 10, got %d", cnt.Count)
		}
		if cnt, _ := counterAt(merged, "path2", traceId, "comm2", 101, 1000, roFlag); cnt.Count != 60 {
			t.Errorf("Expected counter 60, got %d", cnt.Count)
		}
		if cnt, _ := counterAt(merged, "path2", traceId, "comm2", 101, 1000, roFlag); cnt.Bytes != 384 {
			t.Errorf("Expected bytes 384, got %d", cnt.Bytes)
		}
	})

	// t.Run("Iterate over lines", func(t *testing.T) {
	// 	expectedLines := []string{
	// 		"path1 ␞ enter_openat ␞ comm1 ␞ 100 ␞ 1000 ␞ O_RDWR ␞ 10 1000 100 0",
	// 		"path1 ␞ enter_openat ␞ comm1 ␞ 100 ␞ 1000 ␞ O_RDONLY ␞ 20 2000 200 0",
	// 		"path2 ␞ enter_openat ␞ comm2 ␞ 101 ␞ 1000 ␞ O_RDONLY ␞ 60 6000 600 0",
	// 	}
	// 	var lines []string

	// 	for line := range merged.lines() {
	// 		lines = append(lines, line)
	// 	}

	// 	if len(lines) != len(expectedLines) {
	// 		t.Errorf("Expected %d lines, got %d", len(expectedLines), len(lines))
	// 	}

	// 	if !bothArraysHaveSameElements(lines, expectedLines) {
	// 		t.Errorf("Expected lines %v, got %v", expectedLines, lines)
	// 	}
	// })
}

func TestStringByNameUnknownField(t *testing.T) {
	ir := IterRecord{
		Path:    "/tmp/test",
		TraceID: types.SYS_ENTER_OPENAT,
		Comm:    "testComm",
		Pid:     1234,
		Tid:     5678,
		Flags:   flagsType(syscall.O_RDONLY),
		Cnt:     Counter{Count: 1},
	}

	_, err := ir.StringByName("nonexistent")
	if err == nil {
		t.Error("Expected error for unknown field name, got nil")
	}
}

func TestStringByNameValidFields(t *testing.T) {
	ir := IterRecord{
		Path:    "/tmp/test",
		TraceID: types.SYS_ENTER_OPENAT,
		Comm:    "testComm",
		Pid:     1234,
		Tid:     5678,
		Flags:   flagsType(syscall.O_RDONLY),
		Cnt:     Counter{Count: 1},
	}

	validFields := []string{"path", "comm", "tracepoint", "pid", "tid", "flags"}
	for _, name := range validFields {
		t.Run(name, func(t *testing.T) {
			val, err := ir.StringByName(name)
			if err != nil {
				t.Errorf("Expected no error for field %q, got %v", name, err)
			}
			if val == "" {
				t.Errorf("Expected non-empty string for field %q", name)
			}
		})
	}
}

func TestCounterValueByNameUnknownField(t *testing.T) {
	c := Counter{Count: 1, Duration: 100, DurationToPrev: 10, Bytes: 64}

	_, err := c.ValueByName("nonexistent")
	if err == nil {
		t.Error("Expected error for unknown counter name, got nil")
	}
}

func TestCounterValueByNameValidFields(t *testing.T) {
	c := Counter{Count: 1, Duration: 100, DurationToPrev: 10, Bytes: 64}

	tests := map[string]uint64{
		"count":          c.Count,
		"duration":       c.Duration,
		"durationToPrev": c.DurationToPrev,
		"bytes":          c.Bytes,
	}

	for field, want := range tests {
		t.Run(field, func(t *testing.T) {
			got, err := c.ValueByName(field)
			if err != nil {
				t.Fatalf("Expected no error for field %q, got %v", field, err)
			}
			if got != want {
				t.Fatalf("Expected %d for field %q, got %d", want, field, got)
			}
		})
	}
}

func TestMergeEmpty(t *testing.T) {
	traceId := types.SYS_ENTER_OPENAT
	roFlag := flagsType(syscall.O_RDONLY)

	iod := newIorData()
	iod.add("path1", traceId, "comm1", 100, 1000, roFlag, Counter{
		Count:          10,
		Duration:       1000,
		DurationToPrev: 100,
		Bytes:          64,
	})

	empty := newIorData()
	merged := *iod.merge(empty)

	if len(merged.records) != 1 {
		t.Errorf("Expected 1 record, got %d", len(merged.records))
	}
	cnt, ok := counterAt(merged, "path1", traceId, "comm1", 100, 1000, roFlag)
	if !ok {
		t.Fatal("Expected merged counter to exist")
	}
	if cnt.Count != 10 || cnt.Duration != 1000 || cnt.DurationToPrev != 100 || cnt.Bytes != 64 {
		t.Errorf("Expected original counter preserved, got %v", cnt)
	}
}

func TestAddZeroCounter(t *testing.T) {
	iod := newIorData()
	path := pathType("testPath")
	traceId := types.SYS_ENTER_OPENAT
	comm := commType("testComm")
	pid := pidType(1234)
	tid := tidType(5678)
	flags := flagsType(syscall.O_RDONLY)
	zero := Counter{}

	iod.add(path, traceId, comm, pid, tid, flags, zero)

	cnt, ok := counterAt(iod, path, traceId, comm, pid, tid, flags)
	if !ok {
		t.Fatal("Expected entry to exist for zero counter")
	}
	if cnt != zero {
		t.Errorf("Expected zero counter %v, got %v", zero, cnt)
	}
}

func TestSerializeDeserializeRoundTrip(t *testing.T) {
	traceId := types.SYS_ENTER_OPENAT
	rdwrFlag := flagsType(syscall.O_RDWR)
	roFlag := flagsType(syscall.O_RDONLY)

	original := newIorData()
	original.add("path1", traceId, "comm1", 100, 1000, rdwrFlag, Counter{
		Count:          10,
		Duration:       1000,
		DurationToPrev: 100,
		Bytes:          64,
	})
	original.add("path2", traceId, "comm2", 200, 2000, roFlag, Counter{
		Count:          20,
		Duration:       2000,
		DurationToPrev: 200,
		Bytes:          128,
	})

	data, err := original.serialize()
	if err != nil {
		t.Fatalf("serialize failed: %v", err)
	}

	restored := newIorData()
	if err := restored.deserialize(bytes.NewBuffer(data)); err != nil {
		t.Fatalf("deserialize failed: %v", err)
	}

	if len(restored.records) != len(original.records) {
		t.Fatalf("Expected %d records, got %d", len(original.records), len(restored.records))
	}

	cnt1, ok := counterAt(restored, "path1", traceId, "comm1", 100, 1000, rdwrFlag)
	if !ok {
		t.Fatal("Expected path1 counter to exist")
	}
	if cnt1.Count != 10 || cnt1.Duration != 1000 || cnt1.DurationToPrev != 100 || cnt1.Bytes != 64 {
		t.Errorf("path1 counter mismatch: %v", cnt1)
	}

	cnt2, ok := counterAt(restored, "path2", traceId, "comm2", 200, 2000, roFlag)
	if !ok {
		t.Fatal("Expected path2 counter to exist")
	}
	if cnt2.Count != 20 || cnt2.Duration != 2000 || cnt2.DurationToPrev != 200 || cnt2.Bytes != 128 {
		t.Errorf("path2 counter mismatch: %v", cnt2)
	}
}

func TestDeserializeInvalidData(t *testing.T) {
	iod := newIorData()
	var buf bytes.Buffer
	buf.WriteString("this is not valid gob data")
	err := iod.deserialize(&buf)
	if err == nil {
		t.Error("Expected error when deserializing invalid data, got nil")
	}
}

func TestSerializeToFileHostnameErrorReturnsError(t *testing.T) {
	origHostnameFn := hostnameFn
	t.Cleanup(func() { hostnameFn = origHostnameFn })

	hostnameFn = func() (string, error) {
		return "", errors.New("hostname unavailable")
	}

	iod := newIorData()
	err := iod.serializeToFile("test", timestampLayout)
	if err == nil {
		t.Fatal("Expected error when hostname lookup fails, got nil")
	}
	if !strings.Contains(err.Error(), "get hostname") {
		t.Fatalf("Expected get hostname context, got %v", err)
	}
}

func TestSerializedFilenameDefaultsEmptyName(t *testing.T) {
	origHostnameFn := hostnameFn
	t.Cleanup(func() { hostnameFn = origHostnameFn })
	hostnameFn = func() (string, error) { return "host", nil }
	now := time.Date(2026, 9, 30, 8, 5, 9, 0, time.UTC)

	for name, want := range map[string]string{
		"":      "host-default-2026-09-30_08:05:09.ior.zst",
		"flame": "host-flame-2026-09-30_08:05:09.ior.zst",
	} {
		got, err := serializedFilename(name, now, timestampLayout)
		if err != nil || got != want {
			t.Errorf("serializedFilename(%q) = %q, %v; want %q", name, got, err, want)
		}
	}
}

func TestLoadFromFileCorruptDataReturnsContext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corrupt.ior.zst")
	if err := os.WriteFile(path, []byte("not-a-valid-zstd-stream"), 0o600); err != nil {
		t.Fatalf("write corrupt file: %v", err)
	}

	iod := newIorData()
	err := iod.loadFromFile(path)
	if err == nil {
		t.Fatal("Expected corrupt file to return an error")
	}
	if !strings.Contains(err.Error(), "decode ior records from") {
		t.Fatalf("Expected decode context, got %v", err)
	}
}

// TestSerializeToFileSameSecondKeepsEveryRecording is the regression for two
// runs finishing in the same second: they compute the same file name, and the
// second used to truncate the first's temp file and rename over its result.
func TestSerializeToFileSameSecondKeepsEveryRecording(t *testing.T) {
	origHostnameFn, origNowFn := hostnameFn, nowFn
	t.Cleanup(func() { hostnameFn, nowFn = origHostnameFn, origNowFn })
	hostnameFn = func() (string, error) { return "host", nil }
	nowFn = func() time.Time { return time.Date(2026, 9, 30, 13, 53, 24, 0, time.UTC) }
	t.Chdir(t.TempDir())

	const runs = 4
	for i := range runs {
		iod := newIorData()
		iod.add("path", types.SYS_ENTER_OPENAT, "comm", 100, 1000, 0, Counter{Count: uint64(i + 1)})
		if err := iod.serializeToFile("default", timestampLayout); err != nil {
			t.Fatalf("run %d: serializeToFile: %v", i, err)
		}
	}

	want := []string{
		"host-default-2026-09-30_13:53:24.ior.zst",
		"host-default-2026-09-30_13:53:24-1.ior.zst",
		"host-default-2026-09-30_13:53:24-2.ior.zst",
		"host-default-2026-09-30_13:53:24-3.ior.zst",
	}
	entries, err := os.ReadDir(".")
	if err != nil || len(entries) != runs {
		t.Fatalf("directory = %v (err %v), want exactly %d recordings and no temp files", entries, err, runs)
	}
	for i, name := range want {
		restored := newIorData()
		if err := restored.loadFromFile(name); err != nil {
			t.Fatalf("load %s: %v", name, err)
		}
		cnt, ok := counterAt(restored, "path", types.SYS_ENTER_OPENAT, "comm", 100, 1000, 0)
		if !ok || cnt.Count != uint64(i+1) {
			t.Errorf("%s holds counter %+v (found %v), want run %d's Count %d", name, cnt, ok, i, i+1)
		}
	}
}

// publishProbe is a statusOut writer that records whether the recording
// already existed on disk at the moment the status line was written.
type publishProbe struct {
	bytes.Buffer
	existedAtWrite map[string]bool
}

func (p *publishProbe) Write(b []byte) (int, error) {
	for _, name := range []string{"host-default-2026-09-30_13:53:24.ior.zst", "host-default-2026-09-30_13:53:24-1.ior.zst"} {
		_, err := os.Stat(name)
		p.existedAtWrite[name] = err == nil
	}
	return p.Buffer.Write(b)
}

// captureStdout redirects os.Stdout into a pipe for the test and returns a
// function that restores it and yields everything written meanwhile.
func captureStdout(t *testing.T) func() string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = orig })
	return func() string {
		os.Stdout = orig
		_ = w.Close()
		out, _ := io.ReadAll(r)
		_ = r.Close()
		return string(out)
	}
}

// TestSerializeToFileReportsOnStderrAfterPublish pins the console contract of
// a headless -flamegraph run (task mq2): the "Wrote <file>" line goes to the
// status writer (stderr), never to stdout, and only once the file is on disk -
// it used to be a "Writing" line on stdout printed before the write, which
// announced files a broken pipe then prevented. A colliding name gets the
// "already exists; wrote X instead" variant, also on the status writer.
func TestSerializeToFileReportsOnStderrAfterPublish(t *testing.T) {
	origHostnameFn, origNowFn, origStatusOut := hostnameFn, nowFn, statusOut
	t.Cleanup(func() { hostnameFn, nowFn, statusOut = origHostnameFn, origNowFn, origStatusOut })
	hostnameFn = func() (string, error) { return "host", nil }
	nowFn = func() time.Time { return time.Date(2026, 9, 30, 13, 53, 24, 0, time.UTC) }
	probe := &publishProbe{existedAtWrite: map[string]bool{}}
	statusOut = probe
	t.Chdir(t.TempDir())
	stdout := captureStdout(t)

	const first = "host-default-2026-09-30_13:53:24.ior.zst"
	const second = "host-default-2026-09-30_13:53:24-1.ior.zst"
	iod := newIorData()
	if err := iod.serializeToFile("default", timestampLayout); err != nil {
		t.Fatalf("first serializeToFile: %v", err)
	}
	if got, want := probe.String(), "Wrote "+first+"\n"; got != want {
		t.Fatalf("status after first run = %q, want %q", got, want)
	}
	if !probe.existedAtWrite[first] {
		t.Errorf("the Wrote line was written before %s was published", first)
	}

	probe.Reset()
	if err := iod.serializeToFile("default", timestampLayout); err != nil {
		t.Fatalf("second serializeToFile: %v", err)
	}
	if got, want := probe.String(), first+" already exists; wrote "+second+" instead\n"; got != want {
		t.Fatalf("status after colliding run = %q, want %q", got, want)
	}
	if !probe.existedAtWrite[second] {
		t.Errorf("the collision line was written before %s was published", second)
	}

	if out := stdout(); out != "" {
		t.Errorf("stdout = %q, want it empty: stdout is reserved for machine-readable data", out)
	}
}

// TestSerializeToFileFailureLeavesNoTempFile pins that a write that cannot
// even create its temp file reports an error and leaves no ".tmp" debris.
func TestSerializeToFileFailureLeavesNoTempFile(t *testing.T) {
	origHostnameFn := hostnameFn
	t.Cleanup(func() { hostnameFn = origHostnameFn })
	// A hostname containing a path separator points the output into a
	// directory that does not exist, so creating the temp file fails.
	hostnameFn = func() (string, error) { return "no-such-dir/host", nil }
	t.Chdir(t.TempDir())

	iod := newIorData()
	if err := iod.serializeToFile("x", timestampLayout); err == nil {
		t.Fatal("serializeToFile into a missing directory succeeded, want error")
	}
	if entries, _ := os.ReadDir("."); len(entries) != 0 {
		t.Errorf("failed write left %v behind", entries)
	}
}

// writeZstdGob writes the gob encodings of values, in order, through zstd to a
// new .ior.zst, optionally prefixed with raw bytes. It builds fixtures for
// formats this binary no longer writes.
func writeZstdGob(t *testing.T, prefix []byte, values ...any) string {
	t.Helper()
	var raw bytes.Buffer
	raw.Write(prefix)
	enc := gob.NewEncoder(&raw)
	for _, v := range values {
		if err := enc.Encode(v); err != nil {
			t.Fatalf("gob encode fixture: %v", err)
		}
	}
	path := filepath.Join(t.TempDir(), "fixture.ior.zst")
	compressed, err := zstd.Compress(nil, raw.Bytes())
	if err != nil {
		t.Fatalf("compress fixture: %v", err)
	}
	if err := os.WriteFile(path, compressed, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

// TestLoadFromFileRejectsHeaderlessLegacyRecording is the regression for the
// silent mislabelling: a v1.1.0-style recording (bare gob map, openat/read/
// close stored as 788/848/782) used to load fine and print other syscalls'
// names. It must now fail loudly and name the remedy.
func TestLoadFromFileRejectsHeaderlessLegacyRecording(t *testing.T) {
	legacy := map[recordKey]Counter{
		{Path: "/etc/passwd", TraceID: 788, Comm: "cat", Pid: 1, Tid: 1}: {Count: 1},
		{Path: "/etc/passwd", TraceID: 848, Comm: "cat", Pid: 1, Tid: 1}: {Count: 1},
		{Path: "/etc/passwd", TraceID: 782, Comm: "cat", Pid: 1, Tid: 1}: {Count: 1},
	}
	path := writeZstdGob(t, nil, legacy)

	seq, err := LoadFromFile(path)
	if err == nil {
		t.Fatalf("legacy recording loaded (%v), want an error", seq)
	}
	if !errors.Is(err, errLegacyRecording) || !strings.Contains(err.Error(), "re-record") {
		t.Fatalf("error = %v, want errLegacyRecording with a re-record hint", err)
	}

	var out bytes.Buffer
	if err := WriteCollapsedStacks(&out, path, CollapsedOptions{}); err == nil || out.Len() != 0 {
		t.Fatalf("collapsed of legacy recording: err=%v output=%q, want error and no output", err, out.String())
	}
}

// TestLoadFromFileTranslatesForeignTraceIDs simulates a recording written by a
// release whose ID table differs from this build's: the header maps its IDs to
// names, and the reader must land on this build's IDs for those names.
func TestLoadFromFileTranslatesForeignTraceIDs(t *testing.T) {
	// 788/848/782 are the old numbers from the task's probe; none of them is
	// what this build uses for these tracepoints.
	foreign := map[traceIdType]string{
		788: types.SYS_ENTER_OPENAT.String(),
		848: types.SYS_ENTER_READ.String(),
		782: types.SYS_EXIT_CLOSE.String(),
	}
	for id, name := range foreign {
		if cur, _ := types.TraceIDByString(name); cur == id {
			t.Fatalf("fixture is vacuous: this build already uses %d for %s", id, name)
		}
	}
	stored := map[recordKey]Counter{
		{Path: "/f", TraceID: 788, Comm: "cat", Pid: 7, Tid: 7}: {Count: 3, Bytes: 9},
		{Path: "/f", TraceID: 848, Comm: "cat", Pid: 7, Tid: 7}: {Count: 1},
		{Path: "/f", TraceID: 782, Comm: "cat", Pid: 7, Tid: 7}: {Count: 2},
	}
	path := writeZstdGob(t, recordingMagic[:],
		recordingHeader{Version: recordingFormatVersion, Tracepoints: foreign}, stored)

	iod, err := newIorDataFromFile(path)
	if err != nil {
		t.Fatalf("load foreign-table recording: %v", err)
	}
	for _, want := range []struct {
		id  types.TraceId
		cnt uint64
	}{{types.SYS_ENTER_OPENAT, 3}, {types.SYS_ENTER_READ, 1}, {types.SYS_EXIT_CLOSE, 2}} {
		got, ok := counterAt(iod, "/f", want.id, "cat", 7, 7, 0)
		if !ok || got.Count != want.cnt {
			t.Errorf("record for %s = %+v, %v; want count %d", want.id, got, ok, want.cnt)
		}
	}
	if len(iod.records) != 3 {
		t.Errorf("got %d records, want 3", len(iod.records))
	}
}

func TestLoadFromFileRejectsTracepointUnknownToThisBuild(t *testing.T) {
	stored := map[recordKey]Counter{{Path: "/f", TraceID: 5}: {Count: 1}}
	path := writeZstdGob(t, recordingMagic[:], recordingHeader{
		Version: recordingFormatVersion, Tracepoints: map[traceIdType]string{5: "enter_syscall_from_the_future"},
	}, stored)
	_, err := newIorDataFromFile(path)
	if err == nil || !strings.Contains(err.Error(), "enter_syscall_from_the_future") {
		t.Fatalf("error = %v, want one naming the unknown tracepoint", err)
	}
}

func TestLoadFromFileRejectsUnknownFormatVersion(t *testing.T) {
	path := writeZstdGob(t, recordingMagic[:],
		recordingHeader{Version: recordingFormatVersionSampled + 1}, map[recordKey]Counter{})
	_, err := newIorDataFromFile(path)
	if err == nil || !strings.Contains(err.Error(), "unsupported recording format version") {
		t.Fatalf("error = %v, want an unsupported-version error", err)
	}
}

func TestLoadFromFileRejectsRecordMissingFromTracepointTable(t *testing.T) {
	stored := map[recordKey]Counter{{Path: "/f", TraceID: 9}: {Count: 1}}
	path := writeZstdGob(t, recordingMagic[:],
		recordingHeader{Version: recordingFormatVersion, Tracepoints: map[traceIdType]string{}}, stored)
	_, err := newIorDataFromFile(path)
	if err == nil || !strings.Contains(err.Error(), "missing from its tracepoint table") {
		t.Fatalf("error = %v, want a missing-table-entry error", err)
	}
}

// TestGarbageIsNotReportedAsLegacy keeps the legacy verdict honest: random or
// truncated input must stay a plain decode error.
func TestGarbageIsNotReportedAsLegacy(t *testing.T) {
	for name, data := range map[string][]byte{
		"empty":     {},
		"short":     []byte("IOR"),
		"garbage":   []byte("this is not valid gob data"),
		"magic-eof": recordingMagic[:],
	} {
		_, _, err := decodeRecords(bytes.NewReader(data))
		if err == nil || errors.Is(err, errLegacyRecording) {
			t.Errorf("%s: err = %v, want a non-legacy decode error", name, err)
		}
	}
}

// TestUnknownTraceIDPlaceholderSurvivesRoundTrip: an ID missing from the
// writer's table is stored as "unknown_trace_id_<n>" and must read back as the
// same ID rather than fail the whole recording.
func TestUnknownTraceIDPlaceholderSurvivesRoundTrip(t *testing.T) {
	const unknown traceIdType = 4000000
	if _, ok := types.TraceIDByString(unknown.String()); ok {
		t.Fatal("test ID is unexpectedly known")
	}
	original := newIorData()
	original.add("/f", unknown, "c", 1, 1, 0, Counter{Count: 1})
	data, err := original.serialize()
	if err != nil {
		t.Fatal(err)
	}
	restored := newIorData()
	if err := restored.deserialize(bytes.NewBuffer(data)); err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if _, ok := counterAt(restored, "/f", unknown, "c", 1, 1, 0); !ok {
		t.Fatalf("record for %s lost: %v", unknown, restored.records)
	}
}

// TestUnknownTraceIDPlaceholderRejectedWhenReaderKnowsTheID: the writer's
// "unknown_trace_id_<n>" placeholder may only keep n if this build renders n as
// the same placeholder. Here n is a real tracepoint for the reader, so keeping
// it would show enter_openat where the writer meant "unknown": rejected.
func TestUnknownTraceIDPlaceholderRejectedWhenReaderKnowsTheID(t *testing.T) {
	known := types.SYS_ENTER_OPENAT
	stored := map[recordKey]Counter{{Path: "/f", TraceID: 1}: {Count: 1}}
	path := writeZstdGob(t, recordingMagic[:], recordingHeader{
		Version:     recordingFormatVersion,
		Tracepoints: map[traceIdType]string{1: fmt.Sprintf("%s%d", unknownTracePrefix, uint32(known))},
	}, stored)
	iod, err := newIorDataFromFile(path)
	if err == nil {
		t.Fatalf("loaded %v, want the mislabel-prone placeholder rejected", iod.records)
	}
	if !strings.Contains(err.Error(), "unnamed tracepoint") || !strings.Contains(err.Error(), known.String()) {
		t.Fatalf("error = %v, want one naming the unnamed tracepoint and the ID's meaning here", err)
	}
}

// TestUnknownTraceIDPlaceholderRejectsNonCanonicalNumber: "unknown_trace_id_07"
// would render as "unknown_trace_id_7", so it is not the same label and must
// not be accepted as a placeholder.
func TestUnknownTraceIDPlaceholderRejectsNonCanonicalNumber(t *testing.T) {
	stored := map[recordKey]Counter{{Path: "/f", TraceID: 1}: {Count: 1}}
	path := writeZstdGob(t, recordingMagic[:], recordingHeader{
		Version: recordingFormatVersion, Tracepoints: map[traceIdType]string{1: unknownTracePrefix + "0004000000"},
	}, stored)
	if _, err := newIorDataFromFile(path); err == nil {
		t.Fatal("non-canonical placeholder loaded, want an error")
	}
}

// TestLoadFromFileSumsRecordsThatTranslateToOneKey: two writer IDs naming the
// same tracepoint collapse onto one key here; their counts must be added, not
// overwritten.
func TestLoadFromFileSumsRecordsThatTranslateToOneKey(t *testing.T) {
	stored := map[recordKey]Counter{
		{Path: "/f", TraceID: 1, Comm: "c", Pid: 1, Tid: 1}: {Count: 3, Bytes: 10},
		{Path: "/f", TraceID: 2, Comm: "c", Pid: 1, Tid: 1}: {Count: 4, Bytes: 5},
	}
	name := types.SYS_ENTER_OPENAT.String()
	path := writeZstdGob(t, recordingMagic[:], recordingHeader{
		Version: recordingFormatVersion, Tracepoints: map[traceIdType]string{1: name, 2: name},
	}, stored)
	iod, err := newIorDataFromFile(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	got, ok := counterAt(iod, "/f", types.SYS_ENTER_OPENAT, "c", 1, 1, 0)
	if !ok || got.Count != 7 || got.Bytes != 15 || len(iod.records) != 1 {
		t.Fatalf("record = %+v, %v (%d records); want one record with count 7, bytes 15",
			got, ok, len(iod.records))
	}
}

// TestSerializeToFileRoundTripsThroughLoad exercises the real on-disk path
// (zstd, magic, header, records) and the collapsed rendering of it.
func TestSerializeToFileRoundTripsThroughLoad(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	origHost, origStatus := hostnameFn, statusOut
	t.Cleanup(func() { hostnameFn, statusOut = origHost, origStatus })
	hostnameFn = func() (string, error) { return "h", nil }
	statusOut = io.Discard

	iod := newIorData()
	iod.add("/etc/passwd", types.SYS_ENTER_OPENAT, "cat", 1, 1, 0, Counter{Count: 1})
	iod.add("/etc/passwd", types.SYS_ENTER_READ, "cat", 1, 1, 0, Counter{Count: 2})
	if err := iod.serializeToFile("rt", timestampLayout); err != nil {
		t.Fatalf("serializeToFile: %v", err)
	}
	matches, err := filepath.Glob(filepath.Join(dir, "*.ior.zst"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("recordings = %v, %v; want exactly one", matches, err)
	}

	var out bytes.Buffer
	opts := CollapsedOptions{Fields: []string{"comm", "tracepoint"}}
	if err := WriteCollapsedStacks(&out, matches[0], opts); err != nil {
		t.Fatalf("WriteCollapsedStacks: %v", err)
	}
	want := "cat;enter_openat 1\ncat;enter_read 2\n"
	if out.String() != want {
		t.Fatalf("collapsed = %q, want %q", out.String(), want)
	}
}
