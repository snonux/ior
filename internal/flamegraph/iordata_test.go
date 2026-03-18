package flamegraph

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"ior/internal/types"
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
	err := iod.serializeToFile("test")
	if err == nil {
		t.Fatal("Expected error when hostname lookup fails, got nil")
	}
	if !strings.Contains(err.Error(), "get hostname") {
		t.Fatalf("Expected get hostname context, got %v", err)
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

func bothArraysHaveSameElements(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for _, v1 := range a {
		found := false
		for _, v2 := range b {
			if v1 == v2 {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
