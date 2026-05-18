package generate

import (
	"strings"
	"testing"
)

const testTypesH = `//+build ignore

#define MAX_FILENAME_LENGTH 256
#define MAX_PROGNAME_LENGTH 16

#define ENTER_OPEN_EVENT 1
#define EXIT_OPEN_EVENT 2

#define UNCLASSIFIED 0
#define READ_CLASSIFIED 1

struct open_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
    __s32 flags;
    char filename[MAX_FILENAME_LENGTH];
    char comm[MAX_PROGNAME_LENGTH];
};

struct null_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
};

struct fd_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
    __s32 fd;
};
`

const testDefines = `#define SYS_ENTER_OPENAT 784
#define SYS_EXIT_OPENAT 783
#define SYS_ENTER_EPOLL_WAIT 782
#define SYS_EXIT_EPOLL_WAIT 781
`

func TestParseCTypesInput(t *testing.T) {
	input := testTypesH + testDefines
	structs, constants, err := ParseCTypesInput(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseCTypesInput failed: %v", err)
	}
	if len(structs) != 3 {
		t.Fatalf("expected 3 structs, got %d", len(structs))
	}
	if structs[0].Name != "open_event" {
		t.Errorf("first struct name = %q, want open_event", structs[0].Name)
	}
	if len(structs[0].Members) != 8 {
		t.Errorf("open_event members = %d, want 8", len(structs[0].Members))
	}

	// Check array member
	filenameMember := structs[0].Members[6]
	if filenameMember.FieldName != "filename" || filenameMember.ArraySize != "MAX_FILENAME_LENGTH" {
		t.Errorf("filename member = %+v", filenameMember)
	}

	// Check constants
	expectedConsts := 10 // MAX_FILENAME_LENGTH, MAX_PROGNAME_LENGTH, 2 event types, 2 classified, 4 SYS_
	if len(constants) != expectedConsts {
		t.Errorf("constants = %d, want %d", len(constants), expectedConsts)
	}
}

func TestParseCStructMembers(t *testing.T) {
	input := testTypesH
	structs, _, err := ParseCTypesInput(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}

	fd := structs[2] // fd_event
	if fd.Name != "fd_event" {
		t.Fatalf("third struct = %q, want fd_event", fd.Name)
	}
	if len(fd.Members) != 6 {
		t.Fatalf("fd_event members = %d, want 6", len(fd.Members))
	}
	if fd.Members[5].TypeName != "__s32" || fd.Members[5].FieldName != "fd" {
		t.Errorf("fd member = %+v", fd.Members[5])
	}
}

func TestSnakeToCamel(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"open_event", "OpenEvent"},
		{"trace_id", "TraceId"},
		{"event_type", "EventType"},
		{"fd", "Fd"},
		{"pid", "Pid"},
		{"open_by_handle_at_event", "OpenByHandleAtEvent"},
		{"filename", "Filename"},
	}
	for _, tt := range tests {
		if got := snakeToCamel(tt.input); got != tt.want {
			t.Errorf("snakeToCamel(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestCTypeToGoType(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"char", "byte"},
		{"__s32", "int32"},
		{"__u32", "uint32"},
		{"__s64", "int64"},
		{"__u64", "uint64"},
	}
	for _, tt := range tests {
		if got := cTypeToGoType(tt.input); got != tt.want {
			t.Errorf("cTypeToGoType(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestGenerateTypesGoStructs(t *testing.T) {
	input := testTypesH + testDefines
	structs, constants, err := ParseCTypesInput(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	output := GenerateTypesGo(structs, constants)

	requireContains(t, output, "type OpenEvent struct {")
	requireContains(t, output, "EventType EventType")
	requireContains(t, output, "TraceId TraceId")
	requireContains(t, output, "Time uint64")
	requireContains(t, output, "Pid uint32")
	requireContains(t, output, "Flags int32")
	requireContains(t, output, "Filename [MAX_FILENAME_LENGTH]byte")
	requireContains(t, output, "Comm [MAX_PROGNAME_LENGTH]byte")
}

func TestGenerateTypesGoMethods(t *testing.T) {
	input := testTypesH + testDefines
	structs, constants, err := ParseCTypesInput(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	output := GenerateTypesGo(structs, constants)

	// String method with char array conversion
	requireContains(t, output, `string(o.Filename[:])`)
	requireContains(t, output, `string(o.Comm[:])`)
	requireContains(t, output, "func (o OpenEvent) String() string")

	// Equals method
	requireContains(t, output, "func (o OpenEvent) Equals(other any) bool")
	requireContains(t, output, "other.(*OpenEvent)")

	// Getters
	requireContains(t, output, "func (o *OpenEvent) GetEventType() EventType")
	requireContains(t, output, "func (o *OpenEvent) GetTraceId() TraceId")
	requireContains(t, output, "func (o *OpenEvent) GetPid() uint32")
	requireContains(t, output, "func (o *OpenEvent) GetTid() uint32")
	requireContains(t, output, "func (o *OpenEvent) GetTime() uint64")
}

func TestGenerateTypesGoSyncPool(t *testing.T) {
	input := testTypesH + testDefines
	structs, constants, err := ParseCTypesInput(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	output := GenerateTypesGo(structs, constants)

	requireContains(t, output, "var poolOfOpenEvents = sync.Pool{")
	requireContains(t, output, "func NewOpenEvent(raw []byte) *OpenEvent")
	requireContains(t, output, "return nil")
	requireContains(t, output, "func (o *OpenEvent) Bytes() ([]byte, error)")
	requireContains(t, output, "func (o *OpenEvent) Recycle()")
	requireContains(t, output, "poolOfOpenEvents.Put(o)")
	if strings.Contains(output, "panic(raw)") {
		t.Fatalf("generated constructors must not panic on decode errors")
	}

	requireContains(t, output, "var poolOfNullEvents = sync.Pool{")
	requireContains(t, output, "func NewNullEvent(raw []byte) *NullEvent")

	requireContains(t, output, "var poolOfFdEvents = sync.Pool{")
	requireContains(t, output, "func NewFdEvent(raw []byte) *FdEvent")
}

func TestGenerateTypesGoConstants(t *testing.T) {
	input := testTypesH + testDefines
	structs, constants, err := ParseCTypesInput(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	output := GenerateTypesGo(structs, constants)

	requireContains(t, output, "const MAX_FILENAME_LENGTH = 256")
	requireContains(t, output, "const MAX_PROGNAME_LENGTH = 16")
	requireContains(t, output, "const ENTER_OPEN_EVENT = 1")
	requireContains(t, output, "const SYS_ENTER_OPENAT TraceId  = 784")
	requireContains(t, output, "const SYS_EXIT_OPENAT TraceId  = 783")
}

func TestGenerateTypesGoTraceIdMaps(t *testing.T) {
	input := testTypesH + testDefines
	structs, constants, err := ParseCTypesInput(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	output := GenerateTypesGo(structs, constants)

	requireContains(t, output, "type EventType uint32")
	requireContains(t, output, "type TraceId uint32")
	requireContains(t, output, "var traceId2String = map[TraceId]string{")
	requireContains(t, output, `784: "enter_openat"`)
	requireContains(t, output, `783: "exit_openat"`)
	requireContains(t, output, "var traceId2Name = map[TraceId]string{")
	requireContains(t, output, `784: "openat"`)
	requireContains(t, output, `783: "openat"`)
	requireContains(t, output, "var traceId2Family = map[TraceId]SyscallFamily{")
	requireContains(t, output, `784: FamilyFS`)
	requireContains(t, output, `782: FamilyPolling`)
}

func TestGenerateTypesGoTraceIdMethods(t *testing.T) {
	input := testTypesH + testDefines
	structs, constants, err := ParseCTypesInput(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	output := GenerateTypesGo(structs, constants)

	requireContains(t, output, "func (s TraceId) String() string")
	requireContains(t, output, "func (s TraceId) Name() string")
	requireContains(t, output, "func (s TraceId) Family() SyscallFamily")
	requireContains(t, output, `return fmt.Sprintf("unknown_trace_id_%d", s)`)
}

func TestGenerateTypesGoPackageDecl(t *testing.T) {
	input := testTypesH
	structs, constants, err := ParseCTypesInput(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	output := GenerateTypesGo(structs, constants)

	if !strings.HasPrefix(output, "// Code generated - don't change manually!\npackage types\n") {
		t.Errorf("unexpected package header: %s", output[:80])
	}
}

func TestSnakeToCamelEmpty(t *testing.T) {
	if got := snakeToCamel(""); got != "" {
		t.Errorf("snakeToCamel(\"\") = %q, want \"\"", got)
	}
}

func TestSnakeToCamelLeadingUnderscore(t *testing.T) {
	got := snakeToCamel("__u32")
	if got != "U32" {
		t.Errorf("snakeToCamel(\"__u32\") = %q, want \"U32\"", got)
	}
}

func TestCTypeToGoTypeUnknown(t *testing.T) {
	if got := cTypeToGoType("some_custom_type"); got != "some_custom_type" {
		t.Errorf("cTypeToGoType(\"some_custom_type\") = %q, want \"some_custom_type\"", got)
	}
}

func TestParseMemberInvalid(t *testing.T) {
	tests := []string{
		"not a valid member line",
		"too many words here that do not match",
		"",
		";;;",
	}
	for _, input := range tests {
		_, ok := parseMember(input)
		if ok {
			t.Errorf("parseMember(%q) returned ok=true, want false", input)
		}
	}
}

func TestParseDefineInvalid(t *testing.T) {
	tests := []string{
		"#define ONLY_NAME",
		"#define",
		"",
	}
	for _, input := range tests {
		_, ok := parseDefine(input)
		if ok {
			t.Errorf("parseDefine(%q) returned ok=true, want false", input)
		}
	}
}

func TestAddTypesImportsNoImport(t *testing.T) {
	code := "package types\n\nconst FOO = 1\n"
	got := AddTypesImports(code)
	if got != code {
		t.Errorf("AddTypesImports should not modify code without fmt/sync/binary usage, got:\n%s", got)
	}
}

func TestParseCTypesInputEmpty(t *testing.T) {
	structs, constants, err := ParseCTypesInput(strings.NewReader(""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(structs) != 0 {
		t.Errorf("expected 0 structs, got %d", len(structs))
	}
	if len(constants) != 0 {
		t.Errorf("expected 0 constants, got %d", len(constants))
	}
}
