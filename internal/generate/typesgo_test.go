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
    __s32 dirfd;
    __u32 schema_version;
    __u32 filename_status;
    __u32 schema_reserved;
};

struct open_name_fixup_event {
    __u32 event_type;
    __u32 trace_id;
    __u32 tid;
    char filename[MAX_FILENAME_LENGTH];
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
	if len(structs) != 4 {
		t.Fatalf("expected 4 structs, got %d", len(structs))
	}
	if structs[0].Name != "open_event" {
		t.Errorf("first struct name = %q, want open_event", structs[0].Name)
	}
	if len(structs[0].Members) != 12 {
		t.Errorf("open_event members = %d, want 12", len(structs[0].Members))
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

	fd := structs[3] // fd_event
	if fd.Name != "fd_event" {
		t.Fatalf("fourth struct = %q, want fd_event", fd.Name)
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
	requireContains(t, output, "Dirfd int32")
	requireContains(t, output, "SchemaVersion uint32")
	requireContains(t, output, "FilenameStatus uint32")
	requireContains(t, output, "SchemaReserved uint32")
	requireContains(t, output, "Flags int32")
	requireContains(t, output, "Filename [MAX_FILENAME_LENGTH]byte")
	requireContains(t, output, "Comm [MAX_PROGNAME_LENGTH]byte")
	requireContains(t, output, "type OpenNameFixupEvent struct {")
	requireContains(t, output, "EventType EventType; TraceId TraceId; Tid uint32; Filename [MAX_FILENAME_LENGTH]byte")
}

func TestGenerateTypesGoOmitsGettersForFieldsARecordDoesNotCarry(t *testing.T) {
	structs, constants, err := ParseCTypesInput(strings.NewReader(testTypesH + testDefines))
	if err != nil {
		t.Fatal(err)
	}
	output := GenerateTypesGo(structs, constants)
	start := strings.Index(output, "type OpenNameFixupEvent struct {")
	if start < 0 {
		t.Fatal("generated output has no OpenNameFixupEvent")
	}
	end := strings.Index(output[start:], "type NullEvent struct {")
	if end < 0 {
		t.Fatal("could not isolate generated OpenNameFixupEvent")
	}
	fixup := output[start : start+end]
	for _, getter := range []string{"GetEventType", "GetTraceId", "GetTid"} {
		requireContains(t, fixup, getter)
	}
	for _, getter := range []string{"GetPid", "GetTime"} {
		if strings.Contains(fixup, getter) {
			t.Errorf("compact fixup record unexpectedly has %s", getter)
		}
	}
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

func TestGenerateTypesGoEventfdCodecPreservesKernelPadding(t *testing.T) {
	structs := []CStruct{{
		Name: "eventfd_event",
		Members: []CMember{
			{TypeName: "__u32", FieldName: "event_type"},
			{TypeName: "__u32", FieldName: "trace_id"},
			{TypeName: "__u64", FieldName: "time"},
			{TypeName: "__u32", FieldName: "pid"},
			{TypeName: "__u32", FieldName: "tid"},
			{TypeName: "__s32", FieldName: "flags"},
			{TypeName: "__s64", FieldName: "ret"},
			{TypeName: "__s32", FieldName: "fd"},
			{TypeName: "char", FieldName: "filename", ArraySize: "MAX_FILENAME_LENGTH"},
			{TypeName: "__u32", FieldName: "filename_status"},
			{TypeName: "__u32", FieldName: "schema_version"},
		},
	}}
	output := GenerateTypesGo(structs, nil)

	requireContains(t, output, "if len(raw) != 312 && len(raw) != 48 && len(raw) != 40 && len(raw) != 36")
	requireContains(t, output, "binary.LittleEndian.Uint64(raw[retOffset : retOffset+8])")
	requireContains(t, output, "binary.LittleEndian.Uint32(raw[40:44])")
	requireContains(t, output, "raw := make([]byte, 312)")
	requireContains(t, output, "binary.LittleEndian.PutUint64(raw[32:40], uint64(e.Ret))")
	requireContains(t, output, "binary.LittleEndian.PutUint32(raw[40:44], uint32(e.Fd))")
	requireContains(t, output, "copy(raw[44:300], e.Filename[:])")
}

func TestGenerateTypesGoTwoFdCodecPinsCurrentAndLegacyLayouts(t *testing.T) {
	structs := []CStruct{{
		Name: "two_fd_event",
		Members: []CMember{
			{TypeName: "__u32", FieldName: "event_type"},
			{TypeName: "__u32", FieldName: "trace_id"},
			{TypeName: "__u64", FieldName: "time"},
			{TypeName: "__u32", FieldName: "pid"},
			{TypeName: "__u32", FieldName: "tid"},
			{TypeName: "__s32", FieldName: "fd_a"},
			{TypeName: "__s32", FieldName: "fd_b"},
			{TypeName: "__u64", FieldName: "extra"},
			{TypeName: "char", FieldName: "oldname", ArraySize: "MAX_FILENAME_LENGTH"},
			{TypeName: "char", FieldName: "newname", ArraySize: "MAX_FILENAME_LENGTH"},
			{TypeName: "__u32", FieldName: "oldname_status"},
			{TypeName: "__u32", FieldName: "newname_status"},
			{TypeName: "__u32", FieldName: "schema_version"},
		},
	}}
	output := GenerateTypesGo(structs, nil)

	requireContains(t, output, "if len(raw) != 568 && len(raw) != 564 && len(raw) != 40")
	requireContains(t, output, "if len(raw) != 40")
	requireContains(t, output, "t.SchemaVersion != TWO_FD_EVENT_SCHEMA_VERSION && t.SchemaVersion != TWO_FD_EVENT_PRE_KCMP_OWNER_SCHEMA_VERSION")
	requireContains(t, output, "raw := make([]byte, 568)")
	requireContains(t, output, "copy(raw[40:296], t.Oldname[:])")
	requireContains(t, output, "binary.LittleEndian.PutUint32(raw[560:564], t.SchemaVersion)")
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

// retTypesH exercises the ret-accessor emission: ret_event and accept_event
// carry a scalar `ret`, null_event does not, and pipe_event's `ret` is a
// narrower type that has to be widened to int64.
const retTypesH = `struct null_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
};

struct ret_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __s64 ret;
    __u32 pid;
    __u32 tid;
};

struct accept_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
    __s32 fd;
    __s64 ret;
};

struct pipe_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
    __s32 ret;
};
`

// TestGenerateTypesGoEmitsRetGetter locks in the accessor that lets
// streamrow.New read a return value through event.RetCarrier instead of a
// hand-maintained type switch: every struct with a `ret` member — not just
// ret_event — must get GetRet, so a newly generated kind-specific exit struct
// is covered automatically and cannot silently report ret=0.
func TestGenerateTypesGoEmitsRetGetter(t *testing.T) {
	structs, constants, err := ParseCTypesInput(strings.NewReader(retTypesH + testDefines))
	if err != nil {
		t.Fatal(err)
	}
	output := GenerateTypesGo(structs, constants)

	requireContains(t, output, "func (r *RetEvent) GetRet() int64 {\n\treturn r.Ret\n}")
	requireContains(t, output, "func (a *AcceptEvent) GetRet() int64 {\n\treturn a.Ret\n}")

	// A narrower ret type is widened rather than emitted as a type error.
	requireContains(t, output, "func (p *PipeEvent) GetRet() int64 {\n\treturn int64(p.Ret)\n}")

	if strings.Contains(output, "func (n *NullEvent) GetRet()") {
		t.Fatalf("null_event has no ret member but got a GetRet accessor")
	}
}

// TestGenerateTypesGoRetGetterCoversEveryRetStruct is the generator-side
// invariant: whatever set of structs the C header defines, the number of
// emitted GetRet accessors must equal the number of structs carrying a ret
// member. This is what keeps the fix from rotting as new kinds are added.
func TestGenerateTypesGoRetGetterCoversEveryRetStruct(t *testing.T) {
	structs, constants, err := ParseCTypesInput(strings.NewReader(retTypesH + testDefines))
	if err != nil {
		t.Fatal(err)
	}
	output := GenerateTypesGo(structs, constants)

	want := 0
	for _, s := range structs {
		if _, ok := findRetMember(s.Members); ok {
			want++
		}
	}
	if want == 0 {
		t.Fatal("test input defines no ret-carrying struct")
	}
	if got := strings.Count(output, ") GetRet() int64 {"); got != want {
		t.Fatalf("emitted %d GetRet accessors for %d ret-carrying structs", got, want)
	}
}
