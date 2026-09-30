package main

import (
	"os"
	"regexp"
	"strconv"
	"testing"
)

// TestRecvflagsManyIovecsExceedsBPFLimit keeps the many-iovec scenario tied to
// the BPF handler's iovec limit. The scenario only proves the "capacity
// unknown, keep the raw return" fallback if (a) it passes more iovecs than
// IOR_RECVMSG_MAX_IOV and (b) its datagram is larger than the iovecs' total
// capacity, so that the raw return (the datagram length) differs from what a
// summed capacity would give. If someone raises the C limit past the scenario's
// iovec count, this fails instead of the scenario silently testing nothing.
func TestRecvflagsManyIovecsExceedsBPFLimit(t *testing.T) {
	src, err := os.ReadFile("../../internal/c/recv.c")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^#define IOR_RECVMSG_MAX_IOV\s+(\d+)`).FindSubmatch(src)
	if m == nil {
		t.Fatal("IOR_RECVMSG_MAX_IOV not found in internal/c/recv.c")
	}
	limit, err := strconv.Atoi(string(m[1]))
	if err != nil {
		t.Fatal(err)
	}
	if recvflagsManyIovCount <= limit {
		t.Errorf("scenario uses %d iovecs, want more than IOR_RECVMSG_MAX_IOV=%d", recvflagsManyIovCount, limit)
	}
	if capacity := recvflagsManyIovCount * recvflagsManyIovEach; recvflagsManyIovLen <= capacity {
		t.Errorf("datagram %d must exceed the iovec capacity %d to distinguish the fallback", recvflagsManyIovLen, capacity)
	}
}
