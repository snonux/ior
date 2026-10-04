package types

import "testing"

// TestTraceIDByStringInvertsString pins that the reverse lookup is a true
// inverse of TraceId.String for every known tracepoint: recordings persist the
// string and resolve it with this lookup, so a duplicate string (two IDs, one
// name) would silently collapse two tracepoints into one.
func TestTraceIDByStringInvertsString(t *testing.T) {
	if len(traceIdByString) != len(traceId2String) {
		t.Fatalf("reverse map has %d entries, forward map %d: tracepoint strings are not unique",
			len(traceIdByString), len(traceId2String))
	}
	for id, name := range traceId2String {
		got, ok := TraceIDByString(name)
		if !ok || got != id {
			t.Fatalf("TraceIDByString(%q) = %d, %v; want %d, true", name, got, ok, id)
		}
	}
}

func TestTraceIDByStringUnknown(t *testing.T) {
	for _, name := range []string{"", "enter_no_such_syscall", "openat", "unknown_trace_id_7"} {
		if id, ok := TraceIDByString(name); ok {
			t.Errorf("TraceIDByString(%q) = %d, true; want not found", name, id)
		}
	}
}
