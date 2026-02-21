package flamegraph

import (
	"bytes"
	"ior/internal/types"
	"syscall"
	"testing"
)

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

	if iod.paths[path][traceId][comm][pid][tid][flags] != cnt1 {
		t.Errorf("Expected counter %v, got %v", cnt1, iod.paths[path][traceId][comm][pid][tid][flags])
	}
	cnt2 := Counter{Count: 2, Duration: 2000, DurationToPrev: 200, Bytes: 128}

	iod.add(path, traceId, comm, pid, tid, flags, cnt2)

	resultCnt := cnt1.add(cnt2)
	if iod.paths[path][traceId][comm][pid][tid][flags] != resultCnt {
		t.Errorf("Expected counter %v, got %v", resultCnt, iod.paths[path][traceId][comm][pid][tid][flags])
	}
}

func TestMerge(t *testing.T) {
	rdwrFlag := flagsType(syscall.O_RDWR)
	roFlag := flagsType(syscall.O_RDONLY)
	traceId := types.SYS_ENTER_OPENAT
	// Initialize iorData instances with sample data
	iod1 := iorData{paths: pathMap{
		"path1": {traceId: {"comm1": {100: {1000: {rdwrFlag: Counter{
			Count:          10,
			Duration:       1000,
			DurationToPrev: 100,
			Bytes:          64,
		}}}}}}}}
	iod2 := iorData{paths: pathMap{
		"path1": {traceId: {"comm1": {100: {1000: {roFlag: Counter{
			Count:          20,
			Duration:       2000,
			DurationToPrev: 200,
			Bytes:          128,
		}}}}}}}}
	iod3 := iorData{paths: pathMap{
		"path2": {traceId: {"comm2": {101: {1000: {roFlag: Counter{
			Count:          20,
			Duration:       2000,
			DurationToPrev: 200,
			Bytes:          128,
		}}}}}}}}
	iod4 := iorData{paths: pathMap{
		"path2": {traceId: {"comm2": {101: {1000: {roFlag: Counter{
			Count:          40,
			Duration:       4000,
			DurationToPrev: 400,
			Bytes:          256,
		}}}}}}}}

	t.Log("iod1", iod1)
	t.Log("iod2", iod2)
	t.Log("iod3", iod3)
	t.Log("iod4", iod4)
	merged := iod1.merge(iod2).merge(iod3).merge(iod4)
	t.Log("merged", merged)

	t.Run("Merged correctly", func(t *testing.T) {
		if len(merged.paths) != 2 {
			t.Errorf("Expected 2 paths, got %d", len(merged.paths))
		}
		if merged.paths["path1"][traceId]["comm1"][100][1000][rdwrFlag].Count != 10 {
			t.Errorf("Expected counter 10, got %d", merged.paths["path1"][1]["comm1"][100][1000][rdwrFlag].Count)
		}
		if merged.paths["path2"][traceId]["comm2"][101][1000][roFlag].Count != 60 {
			t.Errorf("Expected counter 60, got %d", merged.paths["path2"][1]["comm2"][101][1000][roFlag].Count)
		}
		if merged.paths["path2"][traceId]["comm2"][101][1000][roFlag].Bytes != 384 {
			t.Errorf("Expected bytes 384, got %d", merged.paths["path2"][1]["comm2"][101][1000][roFlag].Bytes)
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

func TestCounterValueByNamePanic(t *testing.T) {
	c := Counter{Count: 1, Duration: 100, DurationToPrev: 10, Bytes: 64}

	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic for unknown counter name, got none")
		}
	}()

	c.ValueByName("nonexistent")
}

func TestMergeEmpty(t *testing.T) {
	traceId := types.SYS_ENTER_OPENAT
	roFlag := flagsType(syscall.O_RDONLY)

	iod := iorData{paths: pathMap{
		"path1": {traceId: {"comm1": {100: {1000: {roFlag: Counter{
			Count:          10,
			Duration:       1000,
			DurationToPrev: 100,
			Bytes:          64,
		}}}}}},
	}}

	empty := newIorData()
	merged := iod.merge(empty)

	if len(merged.paths) != 1 {
		t.Errorf("Expected 1 path, got %d", len(merged.paths))
	}
	cnt := merged.paths["path1"][traceId]["comm1"][100][1000][roFlag]
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

	cnt, ok := iod.paths[path][traceId][comm][pid][tid][flags]
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

	original := iorData{paths: pathMap{
		"path1": {traceId: {"comm1": {100: {1000: {rdwrFlag: Counter{
			Count:          10,
			Duration:       1000,
			DurationToPrev: 100,
			Bytes:          64,
		}}}}}},
		"path2": {traceId: {"comm2": {200: {2000: {roFlag: Counter{
			Count:          20,
			Duration:       2000,
			DurationToPrev: 200,
			Bytes:          128,
		}}}}}},
	}}

	data, err := original.serialize()
	if err != nil {
		t.Fatalf("serialize failed: %v", err)
	}

	restored := newIorData()
	if err := restored.deserialize(bytes.NewBuffer(data)); err != nil {
		t.Fatalf("deserialize failed: %v", err)
	}

	if len(restored.paths) != len(original.paths) {
		t.Fatalf("Expected %d paths, got %d", len(original.paths), len(restored.paths))
	}

	cnt1 := restored.paths["path1"][traceId]["comm1"][100][1000][rdwrFlag]
	if cnt1.Count != 10 || cnt1.Duration != 1000 || cnt1.DurationToPrev != 100 || cnt1.Bytes != 64 {
		t.Errorf("path1 counter mismatch: %v", cnt1)
	}

	cnt2 := restored.paths["path2"][traceId]["comm2"][200][2000][roFlag]
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
