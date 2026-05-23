package internal

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"unsafe"

	"ior/internal/generate"
)

// TestSyscallAggregateSchemaMatchesCStruct asserts that the Go
// rawSyscallAggregate struct mirrors the C struct syscall_aggregate defined in
// internal/c/maps.h. If a field is added, removed, or reordered in either
// definition without updating the other, this test fails and prevents silent
// decode corruption at runtime.
func TestSyscallAggregateSchemaMatchesCStruct(t *testing.T) {
	cStruct := parseSyscallAggregateFromMapsH(t)
	goSize := int(unsafe.Sizeof(rawSyscallAggregate{}))
	binarySize := binary.Size(rawSyscallAggregate{})

	// The C struct has 5 scalar fields + 1 array field = 6 members.
	wantFields := []struct {
		cField string
		cType  string
		cArray string
	}{
		{"count", "__u64", ""},
		{"errors", "__u64", ""},
		{"total_duration_ns", "__u64", ""},
		{"min_duration_ns", "__u64", ""},
		{"max_duration_ns", "__u64", ""},
		{"duration_histogram", "__u64", "8"},
	}

	if len(cStruct.Members) != len(wantFields) {
		t.Fatalf("C struct syscall_aggregate has %d fields, want %d; did a field change?",
			len(cStruct.Members), len(wantFields))
	}

	for i, want := range wantFields {
		got := cStruct.Members[i]
		if got.FieldName != want.cField {
			t.Errorf("field %d: C name = %q, want %q", i, got.FieldName, want.cField)
		}
		if got.TypeName != want.cType {
			t.Errorf("field %d (%s): C type = %q, want %q", i, want.cField, got.TypeName, want.cType)
		}
		if got.ArraySize != want.cArray {
			t.Errorf("field %d (%s): C array size = %q, want %q", i, want.cField, got.ArraySize, want.cArray)
		}
	}

	// Total size: 5 x uint64 + 8 x uint64 = 13 x 8 = 104 bytes.
	wantSize := 13 * 8
	if goSize != wantSize {
		t.Errorf("unsafe.Sizeof(rawSyscallAggregate) = %d, want %d", goSize, wantSize)
	}
	if binarySize != wantSize {
		t.Errorf("binary.Size(rawSyscallAggregate) = %d, want %d", binarySize, wantSize)
	}

	// Verify field offsets match C layout expectations (packed, no padding
	// needed since all fields are uint64-aligned).
	assertOffset(t, "Count", unsafe.Offsetof(rawSyscallAggregate{}.Count), 0)
	assertOffset(t, "Errors", unsafe.Offsetof(rawSyscallAggregate{}.Errors), 8)
	assertOffset(t, "TotalDuration", unsafe.Offsetof(rawSyscallAggregate{}.TotalDuration), 16)
	assertOffset(t, "MinDuration", unsafe.Offsetof(rawSyscallAggregate{}.MinDuration), 24)
	assertOffset(t, "MaxDuration", unsafe.Offsetof(rawSyscallAggregate{}.MaxDuration), 32)
	assertOffset(t, "Histogram", unsafe.Offsetof(rawSyscallAggregate{}.Histogram), 40)
}

// parseSyscallAggregateFromMapsH reads internal/c/maps.h and returns the
// parsed C struct definition for syscall_aggregate. Fails the test if the
// struct is not found.
func parseSyscallAggregateFromMapsH(t *testing.T) generate.CStruct {
	t.Helper()

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	mapsH := filepath.Join(filepath.Dir(filename), "c", "maps.h")
	f, err := os.Open(mapsH)
	if err != nil {
		t.Fatalf("open maps.h: %v", err)
	}
	defer f.Close()

	structs, _, err := generate.ParseCTypesInput(f)
	if err != nil {
		t.Fatalf("ParseCTypesInput(maps.h): %v", err)
	}

	for _, s := range structs {
		if s.Name == "syscall_aggregate" {
			return s
		}
	}
	t.Fatal("struct syscall_aggregate not found in maps.h")
	return generate.CStruct{}
}

func assertOffset(t *testing.T, field string, got, want uintptr) {
	t.Helper()
	if got != want {
		t.Errorf("rawSyscallAggregate.%s offset = %d, want %d", field, got, want)
	}
}
