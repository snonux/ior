package flamegraph

import (
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
	cnt1 := Counter{Count: 1, Duration: 1000, DurationToPrev: 100}

	iod.add(path, traceId, comm, pid, tid, flags, cnt1)

	if iod.paths[path][traceId][comm][pid][tid][flags] != cnt1 {
		t.Errorf("Expected counter %v, got %v", cnt1, iod.paths[path][traceId][comm][pid][tid][flags])
	}
	cnt2 := Counter{Count: 2, Duration: 2000, DurationToPrev: 200}

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

	// Initialize two iorData instances with sample data
	iod1 := iorData{paths: pathMap{
		"path1": {traceId: {"comm1": {100: {1000: {rdwrFlag: Counter{
			Count:          10,
			Duration:       1000,
			DurationToPrev: 100,
		}}}}}}}}
	iod2 := iorData{paths: pathMap{
		"path1": {traceId: {"comm1": {100: {1000: {roFlag: Counter{
			Count:          20,
			Duration:       2000,
			DurationToPrev: 200,
		}}}}}}}}
	iod3 := iorData{paths: pathMap{
		"path2": {traceId: {"comm2": {101: {1000: {roFlag: Counter{
			Count:          20,
			Duration:       2000,
			DurationToPrev: 200,
		}}}}}}}}
	iod4 := iorData{paths: pathMap{
		"path2": {traceId: {"comm2": {101: {1000: {roFlag: Counter{
			Count:          40,
			Duration:       4000,
			DurationToPrev: 400,
		}}}}}}}}

	// Merge iod2 into iod1
	t.Log(iod1)
	t.Log(iod2)
	merged := iod1.merge(iod2).merge(iod3).merge(iod4)
	t.Log(merged)

	t.Run("Merged correctly", func(t *testing.T) {
		if len(merged.paths) != 2 {
			t.Errorf("Expected 2 paths, got %d", len(merged.paths))
		}
		if merged.paths["path1"][traceId]["comm1"][100][1000][roFlag].Count != 10 {
			t.Errorf("Expected counter 10, got %d", merged.paths["path1"][1]["comm1"][100][1000][rdwrFlag].Count)
		}
		if merged.paths["path2"][traceId]["comm2"][101][1000][roFlag].Count != 60 {
			t.Errorf("Expected counter 60, got %d", merged.paths["path2"][1]["comm2"][101][1000][roFlag].Count)
		}
	})

	t.Run("Iterate over lines", func(t *testing.T) {
		expectedLines := []string{
			"path1 ␞ enter_openat ␞ comm1 ␞ 100 ␞ 1000 ␞ O_RDWR ␞ 10 1000 100 0",
			"path1 ␞ enter_openat ␞ comm1 ␞ 100 ␞ 1000 ␞ O_RDONLY ␞ 20 2000 200 0",
			"path2 ␞ enter_openat ␞ comm2 ␞ 101 ␞ 1000 ␞ O_RDONLY ␞ 60 6000 600 0",
		}
		var lines []string

		for line := range merged.lines() {
			lines = append(lines, line)
		}

		if len(lines) != len(expectedLines) {
			t.Errorf("Expected %d lines, got %d", len(expectedLines), len(lines))
		}

		if !bothArraysHaveSameElements(lines, expectedLines) {
			t.Errorf("Expected lines %v, got %v", expectedLines, lines)
		}
	})
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
