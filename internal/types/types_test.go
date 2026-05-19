package types

import (
	"fmt"
	"syscall"
	"testing"
)

func TestSerialization(t *testing.T) {
	openEv1 := OpenEvent{
		EventType: ENTER_OPEN_EVENT,
		TraceId:   SYS_ENTER_OPENAT,
		Time:      123456789,
		Pid:       10,
		Tid:       10,
		Flags:     syscall.O_RDWR,
		Filename:  [MAX_FILENAME_LENGTH]byte{},
		Comm:      [MAX_PROGNAME_LENGTH]byte{},
	}
	copy(openEv1.Filename[:], "testfile.txt")
	copy(openEv1.Comm[:], "testcomm")

	bytes, err := openEv1.Bytes()
	if err != nil {
		t.Error(err)
	}

	openEv2 := NewOpenEvent(bytes)
	assertEquals(t, openEv1.EventType, openEv2.EventType)
	assertEquals(t, openEv1.TraceId, openEv2.TraceId)
	assertEquals(t, openEv1.Time, openEv2.Time)
	assertEquals(t, openEv1.Pid, openEv2.Pid)
	assertEquals(t, openEv1.Tid, openEv2.Tid)
	assertEquals(t, openEv1.Flags, openEv2.Flags)
	assertEquals(t, openEv1.Filename, openEv2.Filename)
	assertEquals(t, openEv1.Comm, openEv2.Comm)
	t.Log("OpenEvent could be serialized correctly")

	retEv1 := RetEvent{
		EventType: EXIT_OPEN_EVENT,
		TraceId:   SYS_EXIT_OPENAT,
		Time:      123456789,
		Ret:       42,
		Pid:       10,
		Tid:       10,
	}
	bytes, err = retEv1.Bytes()
	if err != nil {
		t.Error(err)
	}
	retEv2 := NewRetEvent(bytes)
	if err != nil {
		t.Error(err)
	}

	// Generate for remaining struct elements the assertEquals
	assertEquals(t, retEv1.EventType, retEv2.EventType)
	assertEquals(t, retEv1.TraceId, retEv2.TraceId)
	assertEquals(t, retEv1.Time, retEv2.Time)
	assertEquals(t, retEv1.Ret, retEv2.Ret)
	assertEquals(t, retEv1.Pid, retEv2.Pid)
	assertEquals(t, retEv1.Tid, retEv2.Tid)
	t.Log("RetEvent could be serialized correctly")

}

func TestStringValueAllZeros(t *testing.T) {
	data := make([]byte, MAX_FILENAME_LENGTH)
	result := StringValue(data)
	assertEquals(t, "", result)
	t.Log("StringValue with all-zero bytes returns empty string")
}

func TestStringValueNoNullTerminator(t *testing.T) {
	data := make([]byte, MAX_FILENAME_LENGTH)
	for i := range data {
		data[i] = 'A'
	}
	result := StringValue(data)
	assertEquals(t, MAX_FILENAME_LENGTH, len(result))
	for i := range result {
		assertEquals(t, byte('A'), result[i])
	}
	t.Log("StringValue with no null terminator returns full content")
}

func TestFdEventSerialization(t *testing.T) {
	fdEv1 := FdEvent{
		EventType: ENTER_FD_EVENT,
		TraceId:   SYS_ENTER_READ,
		Time:      987654321,
		Pid:       20,
		Tid:       21,
		Fd:        3,
	}
	bytes, err := fdEv1.Bytes()
	if err != nil {
		t.Error(err)
	}
	fdEv2 := NewFdEvent(bytes)

	assertEquals(t, fdEv1.EventType, fdEv2.EventType)
	assertEquals(t, fdEv1.TraceId, fdEv2.TraceId)
	assertEquals(t, fdEv1.Time, fdEv2.Time)
	assertEquals(t, fdEv1.Pid, fdEv2.Pid)
	assertEquals(t, fdEv1.Tid, fdEv2.Tid)
	assertEquals(t, fdEv1.Fd, fdEv2.Fd)
	t.Log("FdEvent could be serialized correctly")
}

func TestNullEventSerialization(t *testing.T) {
	nullEv1 := NullEvent{
		EventType: ENTER_NULL_EVENT,
		TraceId:   SYS_ENTER_SYNC,
		Time:      111222333,
		Pid:       30,
		Tid:       31,
	}
	bytes, err := nullEv1.Bytes()
	if err != nil {
		t.Error(err)
	}
	nullEv2 := NewNullEvent(bytes)

	assertEquals(t, nullEv1.EventType, nullEv2.EventType)
	assertEquals(t, nullEv1.TraceId, nullEv2.TraceId)
	assertEquals(t, nullEv1.Time, nullEv2.Time)
	assertEquals(t, nullEv1.Pid, nullEv2.Pid)
	assertEquals(t, nullEv1.Tid, nullEv2.Tid)
	t.Log("NullEvent could be serialized correctly")
}

func TestSocketEventSerialization(t *testing.T) {
	socketEv1 := SocketEvent{
		EventType: ENTER_SOCKET_EVENT,
		TraceId:   SYS_ENTER_SOCKET,
		Time:      1234,
		Pid:       30,
		Tid:       31,
		Family:    1,
		Type:      2,
		Protocol:  0,
	}
	bytes, err := socketEv1.Bytes()
	if err != nil {
		t.Error(err)
	}
	socketEv2 := NewSocketEvent(bytes)

	assertEquals(t, socketEv1.EventType, socketEv2.EventType)
	assertEquals(t, socketEv1.TraceId, socketEv2.TraceId)
	assertEquals(t, socketEv1.Time, socketEv2.Time)
	assertEquals(t, socketEv1.Pid, socketEv2.Pid)
	assertEquals(t, socketEv1.Tid, socketEv2.Tid)
	assertEquals(t, socketEv1.Family, socketEv2.Family)
	assertEquals(t, socketEv1.Type, socketEv2.Type)
	assertEquals(t, socketEv1.Protocol, socketEv2.Protocol)
}

func TestSocketpairEventSerialization(t *testing.T) {
	socketpairEv1 := SocketpairEvent{
		EventType: ENTER_SOCKETPAIR_EVENT,
		TraceId:   SYS_ENTER_SOCKETPAIR,
		Time:      2345,
		Pid:       32,
		Tid:       33,
		Family:    1,
		Type:      1,
		Protocol:  0,
		Sv0:       42,
		Sv1:       43,
		Ret:       -1,
	}
	bytes, err := socketpairEv1.Bytes()
	if err != nil {
		t.Error(err)
	}
	socketpairEv2 := NewSocketpairEvent(bytes)

	assertEquals(t, socketpairEv1.EventType, socketpairEv2.EventType)
	assertEquals(t, socketpairEv1.TraceId, socketpairEv2.TraceId)
	assertEquals(t, socketpairEv1.Time, socketpairEv2.Time)
	assertEquals(t, socketpairEv1.Pid, socketpairEv2.Pid)
	assertEquals(t, socketpairEv1.Tid, socketpairEv2.Tid)
	assertEquals(t, socketpairEv1.Family, socketpairEv2.Family)
	assertEquals(t, socketpairEv1.Type, socketpairEv2.Type)
	assertEquals(t, socketpairEv1.Protocol, socketpairEv2.Protocol)
	assertEquals(t, socketpairEv1.Sv0, socketpairEv2.Sv0)
	assertEquals(t, socketpairEv1.Sv1, socketpairEv2.Sv1)
	assertEquals(t, socketpairEv1.Ret, socketpairEv2.Ret)
}

func TestAcceptEventSerialization(t *testing.T) {
	acceptEv1 := AcceptEvent{
		EventType: ENTER_ACCEPT_EVENT,
		TraceId:   SYS_ENTER_ACCEPT4,
		Time:      3456,
		Pid:       34,
		Tid:       35,
		Fd:        9,
		Ret:       -1,
	}
	bytes, err := acceptEv1.Bytes()
	if err != nil {
		t.Error(err)
	}
	acceptEv2 := NewAcceptEvent(bytes)

	assertEquals(t, acceptEv1.EventType, acceptEv2.EventType)
	assertEquals(t, acceptEv1.TraceId, acceptEv2.TraceId)
	assertEquals(t, acceptEv1.Time, acceptEv2.Time)
	assertEquals(t, acceptEv1.Pid, acceptEv2.Pid)
	assertEquals(t, acceptEv1.Tid, acceptEv2.Tid)
	assertEquals(t, acceptEv1.Fd, acceptEv2.Fd)
	assertEquals(t, acceptEv1.Ret, acceptEv2.Ret)
}

func TestPipeEventSerialization(t *testing.T) {
	pipeEv1 := PipeEvent{
		EventType: ENTER_PIPE_EVENT,
		TraceId:   SYS_ENTER_PIPE2,
		Time:      4567,
		Pid:       36,
		Tid:       37,
		Flags:     0x80000,
		Fd0:       10,
		Fd1:       11,
		Ret:       0,
	}
	bytes, err := pipeEv1.Bytes()
	if err != nil {
		t.Error(err)
	}
	pipeEv2 := NewPipeEvent(bytes)

	assertEquals(t, pipeEv1.EventType, pipeEv2.EventType)
	assertEquals(t, pipeEv1.TraceId, pipeEv2.TraceId)
	assertEquals(t, pipeEv1.Time, pipeEv2.Time)
	assertEquals(t, pipeEv1.Pid, pipeEv2.Pid)
	assertEquals(t, pipeEv1.Tid, pipeEv2.Tid)
	assertEquals(t, pipeEv1.Flags, pipeEv2.Flags)
	assertEquals(t, pipeEv1.Fd0, pipeEv2.Fd0)
	assertEquals(t, pipeEv1.Fd1, pipeEv2.Fd1)
	assertEquals(t, pipeEv1.Ret, pipeEv2.Ret)
}

func TestEventfdEventSerialization(t *testing.T) {
	eventfdEv1 := EventfdEvent{
		EventType: ENTER_EVENTFD_EVENT,
		TraceId:   SYS_ENTER_EVENTFD2,
		Time:      5678,
		Pid:       38,
		Tid:       39,
		Flags:     0x800,
		Ret:       12,
	}
	bytes, err := eventfdEv1.Bytes()
	if err != nil {
		t.Error(err)
	}
	eventfdEv2 := NewEventfdEvent(bytes)

	assertEquals(t, eventfdEv1.EventType, eventfdEv2.EventType)
	assertEquals(t, eventfdEv1.TraceId, eventfdEv2.TraceId)
	assertEquals(t, eventfdEv1.Time, eventfdEv2.Time)
	assertEquals(t, eventfdEv1.Pid, eventfdEv2.Pid)
	assertEquals(t, eventfdEv1.Tid, eventfdEv2.Tid)
	assertEquals(t, eventfdEv1.Flags, eventfdEv2.Flags)
	assertEquals(t, eventfdEv1.Ret, eventfdEv2.Ret)
}

func TestEqualsDifferentTypes(t *testing.T) {
	openEv := OpenEvent{EventType: ENTER_OPEN_EVENT, TraceId: SYS_ENTER_OPENAT, Time: 1, Pid: 1, Tid: 1}
	nullEv := NullEvent{EventType: ENTER_NULL_EVENT, TraceId: SYS_ENTER_SYNC, Time: 1, Pid: 1, Tid: 1}
	fdEv := FdEvent{EventType: ENTER_FD_EVENT, TraceId: SYS_ENTER_READ, Time: 1, Pid: 1, Tid: 1, Fd: 1}
	retEv := RetEvent{EventType: EXIT_OPEN_EVENT, TraceId: SYS_EXIT_OPENAT, Time: 1, Pid: 1, Tid: 1}

	assertEquals(t, false, openEv.Equals(&nullEv))
	assertEquals(t, false, openEv.Equals(&fdEv))
	assertEquals(t, false, nullEv.Equals(&openEv))
	assertEquals(t, false, fdEv.Equals(&retEv))
	assertEquals(t, false, retEv.Equals(&openEv))
	t.Log("Equals returns false for different event types")
}

func TestEqualsDifferentValues(t *testing.T) {
	fdEv1 := FdEvent{EventType: ENTER_FD_EVENT, TraceId: SYS_ENTER_READ, Time: 1, Pid: 1, Tid: 1, Fd: 3}
	fdEv2 := FdEvent{EventType: ENTER_FD_EVENT, TraceId: SYS_ENTER_READ, Time: 1, Pid: 1, Tid: 1, Fd: 5}

	assertEquals(t, false, fdEv1.Equals(&fdEv2))

	nullEv1 := NullEvent{EventType: ENTER_NULL_EVENT, TraceId: SYS_ENTER_SYNC, Time: 100, Pid: 1, Tid: 1}
	nullEv2 := NullEvent{EventType: ENTER_NULL_EVENT, TraceId: SYS_ENTER_SYNC, Time: 200, Pid: 1, Tid: 1}

	assertEquals(t, false, nullEv1.Equals(&nullEv2))
	t.Log("Equals returns false for same type but different values")
}

func TestTraceIdUnknownFallback(t *testing.T) {
	unknown := TraceId(0xFFFFFFFF)
	want := fmt.Sprintf("unknown_trace_id_%d", unknown)

	assertEquals(t, want, unknown.String())
	assertEquals(t, want, unknown.Name())
}

func assertEquals[T comparable](t *testing.T, a, b T) {
	if a != b {
		t.Errorf("Expected %v, got %v", a, b)
	}
}
