package types

import (
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

func assertEquals[T comparable](t *testing.T, a, b T) {
	if a != b {
		t.Errorf("Expected %v, got %v", a, b)
	}
}
