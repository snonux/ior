package integrationtests

import "testing"

var recvflagsTraceArgs = []string{"-trace-syscalls", "sendmsg,recvfrom,recvmsg,close,socketpair"}

// TestRecvfromRecvmsgFlagsAdjustByteCounts pins that MSG_PEEK and MSG_TRUNC
// change what a receive is worth in bytes. Each receive of the recv-flags
// scenario returns a distinct length, so its Parquet row is identified by
// syscall + ret and its byte count is asserted independently of the others:
//
//   - a MSG_PEEK receive copies but consumes nothing: 0 bytes, while the plain
//     receive that follows is counted in full (100 bytes, not 200 in total);
//   - MSG_TRUNC returns the datagram's real length (300) but only the 10-byte
//     buffer was filled: 10 bytes;
//   - the netlink size-then-read idiom (recvmsg PEEK|TRUNC into a zero-length
//     iovec, then a plain recvmsg) counts the datagram once, not twice;
//   - recvmsg MSG_TRUNC counts the summed iovec capacity (25+15), and falls
//     back to the raw return when the iovec has more entries than BPF sums.
func TestRecvfromRecvmsgFlagsAdjustByteCounts(t *testing.T) {
	rows, _ := runParquetScenarioRows(t, "recv-flags", defaultDuration, recvflagsTraceArgs, nil)
	AssertRowsPresent(t, rows, []ExpectedRow{
		{Syscall: "recvfrom", Comm: "ioworkload", RetVal: ptrTo(int64(100)), Bytes: ptrTo(uint64(0)), MinCount: 1},
		{Syscall: "recvfrom", Comm: "ioworkload", RetVal: ptrTo(int64(100)), Bytes: ptrTo(uint64(100)), MinCount: 1},
		{Syscall: "recvfrom", Comm: "ioworkload", RetVal: ptrTo(int64(300)), Bytes: ptrTo(uint64(10)), MinCount: 1},
		{Syscall: "recvmsg", Comm: "ioworkload", RetVal: ptrTo(int64(200)), Bytes: ptrTo(uint64(0)), MinCount: 1},
		{Syscall: "recvmsg", Comm: "ioworkload", RetVal: ptrTo(int64(200)), Bytes: ptrTo(uint64(200)), MinCount: 1},
		{Syscall: "recvmsg", Comm: "ioworkload", RetVal: ptrTo(int64(400)), Bytes: ptrTo(uint64(40)), MinCount: 1},
		{Syscall: "recvmsg", Comm: "ioworkload", RetVal: ptrTo(int64(90)), Bytes: ptrTo(uint64(90)), MinCount: 1},
	})
}
