package flamegraph

import "testing"

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
