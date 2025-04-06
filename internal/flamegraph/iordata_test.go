package flamegraph

import (
	"testing"
)

func TestAdd(t *testring.T) {

}

func TestAddPath(t *testing.T) {
	iod := newIorData()
	path := pathType("testPath")
	traceId := traceIdType(1)
	comm := commType("testComm")
	pid := pidType(1234)
	tid := tidType(5678)
	flags := flagsType("O_RDWR")
	cnt1 := counter{count: 1, duration: 1000, durationToPrev: 100}

	iod.addPath(path, traceId, comm, pid, tid, flags, cnt1)

	if iod.paths[path][traceId][comm][pid][tid][flags] != cnt1 {
		t.Errorf("Expected counter %v, got %v", cnt1, iod.paths[path][traceId][comm][pid][tid][flags])
	}
	cnt2 := counter{count: 2, duration: 2000, durationToPrev: 200}

	iod.addPath(path, traceId, comm, pid, tid, flags, cnt2)

	resultCnt := cnt1.add(cnt2)
	if iod.paths[path][traceId][comm][pid][tid][flags] != resultCnt {
		t.Errorf("Expected counter %v, got %v", resultCnt, iod.paths[path][traceId][comm][pid][tid][flags])
	}
}

func TestMerge(t *testing.T) {
	rdwrFlag := flagsType("O_RDWR")
	roFlag := flagsType("O_RDONLY")

	// Initialize two iorData instances with sample data
	iod1 := iorData{paths: pathMap{
		"path1": {1: {"comm1": {100: {1000: {rdwrFlag: counter{
			count:          10,
			duration:       1000,
			durationToPrev: 100,
		}}}}}}}}
	iod2 := iorData{paths: pathMap{
		"path1": {1: {"comm1": {100: {1000: {roFlag: counter{
			count:          20,
			duration:       2000,
			durationToPrev: 200,
		}}}}}}}}
	iod3 := iorData{paths: pathMap{
		"path2": {1: {"comm2": {101: {1000: {roFlag: counter{
			count:          20,
			duration:       2000,
			durationToPrev: 200,
		}}}}}}}}
	iod4 := iorData{paths: pathMap{
		"path2": {1: {"comm2": {101: {1000: {roFlag: counter{
			count:          40,
			duration:       4000,
			durationToPrev: 400,
		}}}}}}}}

	// Merge iod2 into iod1
	t.Log(iod1)
	t.Log(iod2)
	merged := iod1.merge(iod2).merge(iod3).merge(iod4)
	t.Log(merged)

	// Check if the merged data contains data from both iod1 and iod2
	if len(merged.paths) != 2 {
		t.Errorf("Expected 2 paths, got %d", len(merged.paths))
	}

	if merged.paths["path1"][1]["comm1"][100][1000][flagsType("O_RDWR")].count != 10 {
		t.Errorf("Expected counter 10, got %d", merged.paths["path1"][1]["comm1"][100][1000][flagsType("O_RDWR")].count)
	}

	if merged.paths["path2"][1]["comm2"][101][1000][roFlag].count != 60 {
		t.Errorf("Expected counter 60, got %d", merged.paths["path2"][1]["comm2"][101][1000][roFlag].count)
	}
}
