package generate

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// CConstant is one #define parsed from the C sources, emitted as a Go const.
type CConstant struct {
	Name  string
	Value string
}

// CMember is one struct member parsed from the C sources: its type name,
// field name and, for arrays, the element-count expression.
type CMember struct {
	TypeName  string
	FieldName string
	ArraySize string
}

// CStruct is one C struct parsed from the C sources, emitted as a Go struct
// with matching field order and layout.
type CStruct struct {
	Name    string
	Members []CMember
}

// ParseCTypesInput parses C struct definitions and #define constants.
func ParseCTypesInput(r io.Reader) ([]CStruct, []CConstant, error) {
	scanner := bufio.NewScanner(r)
	var structs []CStruct
	var constants []CConstant
	var current *CStruct

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "#define") {
			c, ok := parseDefine(line)
			if ok {
				constants = append(constants, c)
			}
			continue
		}

		if isCommentLine(line) || line == "" {
			continue
		}

		if strings.HasPrefix(line, "struct") && strings.HasSuffix(line, "{") {
			name := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "struct"), "{"))
			current = &CStruct{Name: name}
			continue
		}

		if line == "};" && current != nil {
			structs = append(structs, *current)
			current = nil
			continue
		}

		if current != nil {
			m, ok := parseMember(line)
			if ok {
				current.Members = append(current.Members, m)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("scanning C input: %w", err)
	}
	return structs, constants, nil
}

// GenerateTypesGo produces the generated_types.go content.
func GenerateTypesGo(structs []CStruct, constants []CConstant) string {
	var b strings.Builder

	b.WriteString("// Code generated - don't change manually!\n")
	b.WriteString("package types\n\n")

	writeTypeDefsAndMaps(&b, constants)

	for _, c := range constants {
		constType := ""
		if strings.HasPrefix(c.Name, "SYS_") {
			constType = " TraceId "
		}
		fmt.Fprintf(&b, "const %s%s = %s\n", c.Name, constType, c.Value)
	}

	for _, s := range structs {
		writeGoStruct(&b, s)
	}

	return b.String()
}

// AddTypesImports inserts the import block needed by the generated types code.
func AddTypesImports(code string) string {
	needsImports := strings.Contains(code, "fmt.") ||
		strings.Contains(code, "sync.") ||
		strings.Contains(code, "binary.") ||
		strings.Contains(code, "bytes.")

	if !needsImports {
		return code
	}

	importBlock := `import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync"
)

`
	return strings.Replace(code, "package types\n\n", "package types\n\n"+importBlock, 1)
}

func parseDefine(line string) (CConstant, bool) {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return CConstant{}, false
	}
	return CConstant{Name: fields[1], Value: fields[2]}, true
}

func isCommentLine(line string) bool {
	return strings.HasPrefix(line, "//") || strings.HasPrefix(line, "/*") || strings.HasPrefix(line, "*")
}

var arrayRe = regexp.MustCompile(`^(\w+)\s+(\w+)\[(\w+)\];?$`)
var simpleRe = regexp.MustCompile(`^(\w+)\s+(\w+);?$`)

func parseMember(line string) (CMember, bool) {
	line = strings.TrimSuffix(strings.TrimSpace(line), ";")
	line = strings.TrimSpace(line)

	if m := arrayRe.FindStringSubmatch(line + ";"); m != nil {
		return CMember{TypeName: m[1], FieldName: m[2], ArraySize: m[3]}, true
	}
	if m := simpleRe.FindStringSubmatch(line + ";"); m != nil {
		return CMember{TypeName: m[1], FieldName: m[2]}, true
	}
	return CMember{}, false
}

func writeTypeDefsAndMaps(b *strings.Builder, constants []CConstant) {
	b.WriteString("type EventType uint32\n")
	b.WriteString("type TraceId uint32\n\n")
	writeSyscallFamilyDefs(b)

	var sysConstants []CConstant
	for _, c := range constants {
		if strings.HasPrefix(c.Name, "SYS_") {
			sysConstants = append(sysConstants, c)
		}
	}

	writeTraceIdMap(b, "traceId2String", sysConstants, func(name string) string {
		return strings.ToLower(strings.TrimPrefix(name, "SYS_"))
	})

	writeTraceIdMap(b, "traceId2Name", sysConstants, func(name string) string {
		s := strings.TrimPrefix(name, "SYS_ENTER_")
		s = strings.TrimPrefix(s, "SYS_EXIT_")
		return strings.ToLower(s)
	})
	writeTraceIdFamilyMap(b, sysConstants)

	writeTraceIdStringMethod(b)
	writeTraceIdNameMethod(b)
	writeTraceIdFamilyMethod(b)
	b.WriteString("\n")
}

func writeSyscallFamilyDefs(b *strings.Builder) {
	b.WriteString(`// SyscallFamily is the broad runtime grouping for a syscall tracepoint.
type SyscallFamily string

const (
	FamilyNetwork  SyscallFamily = "Network"
	FamilyMemory   SyscallFamily = "Memory"
	FamilySignals  SyscallFamily = "Signals"
	FamilySched    SyscallFamily = "Sched"
	FamilyIPC      SyscallFamily = "IPC"
	FamilyTime     SyscallFamily = "Time"
	FamilyProcess  SyscallFamily = "Process"
	FamilySecurity SyscallFamily = "Security"
	FamilyFS       SyscallFamily = "FS"
	FamilyPolling  SyscallFamily = "Polling"
	FamilyAIO      SyscallFamily = "AIO"
	FamilyMisc     SyscallFamily = "Misc"
)

`)
}

func writeTraceIdMap(b *strings.Builder, mapName string, constants []CConstant, transform func(string) string) {
	fmt.Fprintf(b, "var %s = map[TraceId]string{\n\t", mapName)
	entries := make([]string, 0, len(constants))
	for _, c := range constants {
		entries = append(entries, fmt.Sprintf("%s: %q", c.Value, transform(c.Name)))
	}
	b.WriteString(strings.Join(entries, ", "))
	b.WriteString(",\n}\n\n")
}

func writeTraceIdFamilyMap(b *strings.Builder, constants []CConstant) {
	b.WriteString("var traceId2Family = map[TraceId]SyscallFamily{\n\t")
	entries := make([]string, 0, len(constants))
	for _, c := range constants {
		tracepoint := strings.ToLower(c.Name)
		tracepoint = strings.TrimPrefix(tracepoint, "sys_")
		family := ClassifySyscallFamily("sys_" + tracepoint)
		entries = append(entries, fmt.Sprintf("%s: %s", c.Value, syscallFamilyConstName(family)))
	}
	b.WriteString(strings.Join(entries, ", "))
	b.WriteString(",\n}\n\n")
}

func syscallFamilyConstName(family SyscallFamily) string {
	switch family {
	case FamilyNetwork:
		return "FamilyNetwork"
	case FamilyMemory:
		return "FamilyMemory"
	case FamilySignals:
		return "FamilySignals"
	case FamilySched:
		return "FamilySched"
	case FamilyIPC:
		return "FamilyIPC"
	case FamilyTime:
		return "FamilyTime"
	case FamilyProcess:
		return "FamilyProcess"
	case FamilySecurity:
		return "FamilySecurity"
	case FamilyFS:
		return "FamilyFS"
	case FamilyPolling:
		return "FamilyPolling"
	case FamilyAIO:
		return "FamilyAIO"
	default:
		return "FamilyMisc"
	}
}

func writeTraceIdStringMethod(b *strings.Builder) {
	b.WriteString(`func (s TraceId) String() string {
	str, ok := traceId2String[s]
	if !ok {
		return fmt.Sprintf("unknown_trace_id_%d", s)
	}
	return str
}

`)
}

func writeTraceIdNameMethod(b *strings.Builder) {
	b.WriteString(`func (s TraceId) Name() string {
	str, ok := traceId2Name[s]
	if !ok {
		return fmt.Sprintf("unknown_trace_id_%d", s)
	}
	return str
}

`)
}

func writeTraceIdFamilyMethod(b *strings.Builder) {
	b.WriteString(`// Family returns the broad syscall family for this tracepoint.
func (s TraceId) Family() SyscallFamily {
	family, ok := traceId2Family[s]
	if !ok {
		return FamilyMisc
	}
	return family
}

`)
}

func writeGoStruct(b *strings.Builder, s CStruct) {
	goName := snakeToCamel(s.Name)
	selfRef := strings.ToLower(goName[:1])

	b.WriteString("\n")
	fmt.Fprintf(b, "type %s struct {\n\t", goName)
	memberDefs := make([]string, 0, len(s.Members))
	for _, m := range s.Members {
		memberDefs = append(memberDefs, goMemberDef(m))
	}
	b.WriteString(strings.Join(memberDefs, "; "))
	b.WriteString(" \n}\n\n")

	writeStringMethod(b, goName, selfRef, s.Members)
	writeEqualsMethod(b, goName, selfRef, s.Members)
	writeGetterMethods(b, goName, selfRef, s.Members)
	writeRetGetterMethod(b, goName, selfRef, s.Members)

	if strings.HasSuffix(goName, "Event") {
		b.WriteString("\n")
		writeSyncPool(b, goName, selfRef)
	}
}

func goMemberDef(m CMember) string {
	goField := snakeToCamel(m.FieldName)
	goType := cTypeToGoType(m.TypeName)

	if goField == "TraceId" {
		goType = "TraceId"
	}
	if goField == "EventType" {
		goType = "EventType"
	}

	if m.ArraySize != "" {
		return fmt.Sprintf("%s [%s]%s", goField, m.ArraySize, goType)
	}
	return fmt.Sprintf("%s %s", goField, goType)
}

func writeStringMethod(b *strings.Builder, goName, selfRef string, members []CMember) {
	fmtParts := make([]string, 0, len(members))
	argParts := make([]string, 0, len(members))
	for _, m := range members {
		goField := snakeToCamel(m.FieldName)
		fmtParts = append(fmtParts, goField+":%v")
		ref := selfRef + "." + goField
		if m.TypeName == "char" && m.ArraySize != "" {
			ref = fmt.Sprintf("string(%s[:])", ref)
		}
		argParts = append(argParts, ref)
	}
	fmt.Fprintf(b, "func (%s %s) String() string {\n", selfRef, goName)
	fmt.Fprintf(b, "\treturn fmt.Sprintf(\"%s\", %s)\n", strings.Join(fmtParts, " "), strings.Join(argParts, ", "))
	b.WriteString("}\n\n")
}

func writeEqualsMethod(b *strings.Builder, goName, selfRef string, members []CMember) {
	fmt.Fprintf(b, "func (%s %s) Equals(other any) bool {\n", selfRef, goName)
	fmt.Fprintf(b, "\totherConcrete, ok := other.(*%s)\n", goName)
	b.WriteString("\tif !ok {\n\t\treturn false\n\t}\n")
	conds := make([]string, 0, len(members))
	for _, m := range members {
		goField := snakeToCamel(m.FieldName)
		conds = append(conds, fmt.Sprintf("%s.%s == otherConcrete.%s", selfRef, goField, goField))
	}
	fmt.Fprintf(b, "\treturn %s\n", strings.Join(conds, " && "))
	b.WriteString("}\n\n")
}

func writeGetterMethods(b *strings.Builder, goName, selfRef string, members []CMember) {
	getters := []struct {
		method     string
		returnType string
		field      string
	}{
		{"GetEventType", "EventType", "EventType"},
		{"GetTraceId", "TraceId", "TraceId"},
		{"GetPid", "uint32", "Pid"},
		{"GetTid", "uint32", "Tid"},
		{"GetTime", "uint64", "Time"},
	}
	for _, g := range getters {
		if !hasMember(members, g.field) {
			continue
		}
		fmt.Fprintf(b, "func (%s *%s) %s() %s {\n\treturn %s.%s\n}\n\n",
			selfRef, goName, g.method, g.returnType, selfRef, g.field)
	}
}

func hasMember(members []CMember, goField string) bool {
	for _, member := range members {
		if snakeToCamel(member.FieldName) == goField {
			return true
		}
	}
	return false
}

// retMemberName is the C field name that carries a syscall return value.
// Every event struct that has it is a "ret carrier" and gets a GetRet
// accessor so consumers (e.g. streamrow.New) can read the return value
// without knowing the concrete type. Keeping this in the generator means a
// newly added kind-specific exit struct is covered automatically instead of
// silently reporting ret=0.
const retMemberName = "ret"

// findRetMember returns the scalar `ret` member of a struct, if any.
func findRetMember(members []CMember) (CMember, bool) {
	for _, m := range members {
		if m.FieldName == retMemberName && m.ArraySize == "" {
			return m, true
		}
	}
	return CMember{}, false
}

// writeRetGetterMethod emits GetRet for structs carrying a ret field. The
// accessor normalises to int64 so all ret carriers share one interface
// (event.RetCarrier).
func writeRetGetterMethod(b *strings.Builder, goName, selfRef string, members []CMember) {
	m, ok := findRetMember(members)
	if !ok {
		return
	}
	expr := selfRef + ".Ret"
	if cTypeToGoType(m.TypeName) != "int64" {
		expr = "int64(" + expr + ")"
	}
	b.WriteString("// GetRet returns the syscall return value carried by this event.\n")
	fmt.Fprintf(b, "func (%s *%s) GetRet() int64 {\n\treturn %s\n}\n\n", selfRef, goName, expr)
}

func writeSyncPool(b *strings.Builder, goName, selfRef string) {
	if goName == "EventfdEvent" {
		writeEventfdSyncPool(b, selfRef)
		return
	}
	if goName == "TwoFdEvent" {
		writeTwoFdSyncPool(b, selfRef)
		return
	}
	fmt.Fprintf(b, "var poolOf%ss = sync.Pool{\n\tNew: func() any { return &%s{} },\n}\n\n", goName, goName)
	fmt.Fprintf(b, "func New%s(raw []byte) *%s {\n", goName, goName)
	if goName == "FdPathEvent" {
		b.WriteString("\tif len(raw) != 300 && len(raw) != 304 {\n\t\treturn nil\n\t}\n")
		b.WriteString("\tif binary.LittleEndian.Uint32(raw[296:300]) != FD_PATH_EVENT_SCHEMA_VERSION {\n\t\treturn nil\n\t}\n")
	}
	fmt.Fprintf(b, "\t%s := poolOf%ss.Get().(*%s)\n", selfRef, goName, goName)
	fmt.Fprintf(b, "\tif err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, %s); err != nil {\n", selfRef)
	fmt.Fprintf(b, "\t\t*%s = %s{}\n", selfRef, goName)
	fmt.Fprintf(b, "\t\tpoolOf%ss.Put(%s)\n", goName, selfRef)
	b.WriteString("\t\treturn nil\n\t}\n")
	fmt.Fprintf(b, "\treturn %s\n}\n\n", selfRef)

	fmt.Fprintf(b, "func (%s *%s) Bytes() ([]byte, error) {\n", selfRef, goName)
	b.WriteString("\tbuf := new(bytes.Buffer)\n")
	fmt.Fprintf(b, "\terr := binary.Write(buf, binary.LittleEndian, %s)\n", selfRef)
	b.WriteString("\tif err != nil {\n\t\treturn nil, err\n\t}\n")
	b.WriteString("\treturn buf.Bytes(), nil\n}\n\n")

	fmt.Fprintf(b, "func (%s *%s) Recycle() {\n\tpoolOf%ss.Put(%s)\n}\n", selfRef, goName, goName, selfRef)
}

// writeEventfdSyncPool emits the eventfd codec with the kernel's explicit C
// padding. eventfd_event places ret at offset 32, fd at offset 40 and the
// identifying filename at offset 44, making the current payload 312 bytes.
// Encoding the Go fields with binary.Write would omit both the internal and
// trailing C padding. The decoder also accepts the three released layouts from
// before filename capture was added.
func writeEventfdSyncPool(b *strings.Builder, selfRef string) {
	b.WriteString("var poolOfEventfdEvents = sync.Pool{\n\tNew: func() any { return &EventfdEvent{} },\n}\n\n")
	b.WriteString("func NewEventfdEvent(raw []byte) *EventfdEvent {\n")
	b.WriteString("\tif len(raw) != 312 && len(raw) != 48 && len(raw) != 40 && len(raw) != 36 {\n\t\treturn nil\n\t}\n")
	fmt.Fprintf(b, "\t%s := poolOfEventfdEvents.Get().(*EventfdEvent)\n", selfRef)
	fmt.Fprintf(b, "\t%s.EventType = EventType(binary.LittleEndian.Uint32(raw[0:4]))\n", selfRef)
	fmt.Fprintf(b, "\t%s.TraceId = TraceId(binary.LittleEndian.Uint32(raw[4:8]))\n", selfRef)
	fmt.Fprintf(b, "\t%s.Time = binary.LittleEndian.Uint64(raw[8:16])\n", selfRef)
	fmt.Fprintf(b, "\t%s.Pid = binary.LittleEndian.Uint32(raw[16:20])\n", selfRef)
	fmt.Fprintf(b, "\t%s.Tid = binary.LittleEndian.Uint32(raw[20:24])\n", selfRef)
	fmt.Fprintf(b, "\t%s.Flags = int32(binary.LittleEndian.Uint32(raw[24:28]))\n", selfRef)
	fmt.Fprintf(b, "\t%s.Fd = -1\n", selfRef)
	fmt.Fprintf(b, "\t%s.Filename = [MAX_FILENAME_LENGTH]byte{}\n", selfRef)
	fmt.Fprintf(b, "\t%s.FilenameStatus = PATH_READ_NULL\n", selfRef)
	fmt.Fprintf(b, "\t%s.SchemaVersion = 0\n", selfRef)
	b.WriteString("\tretOffset := 28\n\tif len(raw) >= 40 {\n\t\tretOffset = 32\n\t}\n")
	fmt.Fprintf(b, "\t%s.Ret = int64(binary.LittleEndian.Uint64(raw[retOffset : retOffset+8]))\n", selfRef)
	b.WriteString("\tif len(raw) == 48 || len(raw) == 312 {\n")
	fmt.Fprintf(b, "\t\t%s.Fd = int32(binary.LittleEndian.Uint32(raw[40:44]))\n", selfRef)
	b.WriteString("\t}\n")
	b.WriteString("\tif len(raw) == 312 {\n")
	fmt.Fprintf(b, "\t\tcopy(%s.Filename[:], raw[44:300])\n", selfRef)
	fmt.Fprintf(b, "\t\t%s.FilenameStatus = binary.LittleEndian.Uint32(raw[300:304])\n", selfRef)
	fmt.Fprintf(b, "\t\t%s.SchemaVersion = binary.LittleEndian.Uint32(raw[304:308])\n", selfRef)
	fmt.Fprintf(b, "\t\tif %s.SchemaVersion != EVENTFD_EVENT_SCHEMA_VERSION {\n\t\t\t%s.Recycle()\n\t\t\treturn nil\n\t\t}\n", selfRef, selfRef)
	b.WriteString("\t}\n")
	fmt.Fprintf(b, "\treturn %s\n}\n\n", selfRef)

	fmt.Fprintf(b, "func (%s *EventfdEvent) Bytes() ([]byte, error) {\n", selfRef)
	b.WriteString("\traw := make([]byte, 312)\n")
	fmt.Fprintf(b, "\tbinary.LittleEndian.PutUint32(raw[0:4], uint32(%s.EventType))\n", selfRef)
	fmt.Fprintf(b, "\tbinary.LittleEndian.PutUint32(raw[4:8], uint32(%s.TraceId))\n", selfRef)
	fmt.Fprintf(b, "\tbinary.LittleEndian.PutUint64(raw[8:16], %s.Time)\n", selfRef)
	fmt.Fprintf(b, "\tbinary.LittleEndian.PutUint32(raw[16:20], %s.Pid)\n", selfRef)
	fmt.Fprintf(b, "\tbinary.LittleEndian.PutUint32(raw[20:24], %s.Tid)\n", selfRef)
	fmt.Fprintf(b, "\tbinary.LittleEndian.PutUint32(raw[24:28], uint32(%s.Flags))\n", selfRef)
	fmt.Fprintf(b, "\tbinary.LittleEndian.PutUint64(raw[32:40], uint64(%s.Ret))\n", selfRef)
	fmt.Fprintf(b, "\tbinary.LittleEndian.PutUint32(raw[40:44], uint32(%s.Fd))\n", selfRef)
	fmt.Fprintf(b, "\tcopy(raw[44:300], %s.Filename[:])\n", selfRef)
	fmt.Fprintf(b, "\tbinary.LittleEndian.PutUint32(raw[300:304], %s.FilenameStatus)\n", selfRef)
	fmt.Fprintf(b, "\tbinary.LittleEndian.PutUint32(raw[304:308], %s.SchemaVersion)\n", selfRef)
	b.WriteString("\treturn raw, nil\n}\n\n")
	fmt.Fprintf(b, "func (%s *EventfdEvent) Recycle() {\n\tpoolOfEventfdEvents.Put(%s)\n}\n", selfRef, selfRef)
}

// writeTwoFdSyncPool emits an exact-size codec for two_fd_event. The C layout
// has four bytes of trailing alignment padding (568 bytes), while binary.Write
// historically produced a compact 564-byte representation. The 40-byte legacy
// layout predates move_mount pathname capture. No other size is accepted.
func writeTwoFdSyncPool(b *strings.Builder, selfRef string) {
	b.WriteString("var poolOfTwoFdEvents = sync.Pool{\n\tNew: func() any { return &TwoFdEvent{} },\n}\n\n")
	b.WriteString("func NewTwoFdEvent(raw []byte) *TwoFdEvent {\n")
	b.WriteString("\tif len(raw) != 568 && len(raw) != 564 && len(raw) != 40 {\n\t\treturn nil\n\t}\n")
	fmt.Fprintf(b, "\t%s := poolOfTwoFdEvents.Get().(*TwoFdEvent)\n", selfRef)
	fmt.Fprintf(b, "\t%s.EventType = EventType(binary.LittleEndian.Uint32(raw[0:4]))\n", selfRef)
	fmt.Fprintf(b, "\t%s.TraceId = TraceId(binary.LittleEndian.Uint32(raw[4:8]))\n", selfRef)
	fmt.Fprintf(b, "\t%s.Time = binary.LittleEndian.Uint64(raw[8:16])\n", selfRef)
	fmt.Fprintf(b, "\t%s.Pid = binary.LittleEndian.Uint32(raw[16:20])\n", selfRef)
	fmt.Fprintf(b, "\t%s.Tid = binary.LittleEndian.Uint32(raw[20:24])\n", selfRef)
	fmt.Fprintf(b, "\t%s.FdA = int32(binary.LittleEndian.Uint32(raw[24:28]))\n", selfRef)
	fmt.Fprintf(b, "\t%s.FdB = int32(binary.LittleEndian.Uint32(raw[28:32]))\n", selfRef)
	fmt.Fprintf(b, "\t%s.Extra = binary.LittleEndian.Uint64(raw[32:40])\n", selfRef)
	fmt.Fprintf(b, "\t%s.Oldname = [MAX_FILENAME_LENGTH]byte{}\n", selfRef)
	fmt.Fprintf(b, "\t%s.Newname = [MAX_FILENAME_LENGTH]byte{}\n", selfRef)
	fmt.Fprintf(b, "\t%s.OldnameStatus = PATH_READ_NULL\n", selfRef)
	fmt.Fprintf(b, "\t%s.NewnameStatus = PATH_READ_NULL\n", selfRef)
	fmt.Fprintf(b, "\t%s.SchemaVersion = 0\n", selfRef)
	b.WriteString("\tif len(raw) != 40 {\n")
	fmt.Fprintf(b, "\t\tcopy(%s.Oldname[:], raw[40:296])\n", selfRef)
	fmt.Fprintf(b, "\t\tcopy(%s.Newname[:], raw[296:552])\n", selfRef)
	fmt.Fprintf(b, "\t\t%s.OldnameStatus = binary.LittleEndian.Uint32(raw[552:556])\n", selfRef)
	fmt.Fprintf(b, "\t\t%s.NewnameStatus = binary.LittleEndian.Uint32(raw[556:560])\n", selfRef)
	fmt.Fprintf(b, "\t\t%s.SchemaVersion = binary.LittleEndian.Uint32(raw[560:564])\n", selfRef)
	fmt.Fprintf(b, "\t\tif %s.SchemaVersion != TWO_FD_EVENT_SCHEMA_VERSION {\n\t\t\t%s.Recycle()\n\t\t\treturn nil\n\t\t}\n", selfRef, selfRef)
	b.WriteString("\t}\n")
	fmt.Fprintf(b, "\treturn %s\n}\n\n", selfRef)

	fmt.Fprintf(b, "func (%s *TwoFdEvent) Bytes() ([]byte, error) {\n", selfRef)
	b.WriteString("\traw := make([]byte, 568)\n")
	fmt.Fprintf(b, "\tbinary.LittleEndian.PutUint32(raw[0:4], uint32(%s.EventType))\n", selfRef)
	fmt.Fprintf(b, "\tbinary.LittleEndian.PutUint32(raw[4:8], uint32(%s.TraceId))\n", selfRef)
	fmt.Fprintf(b, "\tbinary.LittleEndian.PutUint64(raw[8:16], %s.Time)\n", selfRef)
	fmt.Fprintf(b, "\tbinary.LittleEndian.PutUint32(raw[16:20], %s.Pid)\n", selfRef)
	fmt.Fprintf(b, "\tbinary.LittleEndian.PutUint32(raw[20:24], %s.Tid)\n", selfRef)
	fmt.Fprintf(b, "\tbinary.LittleEndian.PutUint32(raw[24:28], uint32(%s.FdA))\n", selfRef)
	fmt.Fprintf(b, "\tbinary.LittleEndian.PutUint32(raw[28:32], uint32(%s.FdB))\n", selfRef)
	fmt.Fprintf(b, "\tbinary.LittleEndian.PutUint64(raw[32:40], %s.Extra)\n", selfRef)
	fmt.Fprintf(b, "\tcopy(raw[40:296], %s.Oldname[:])\n", selfRef)
	fmt.Fprintf(b, "\tcopy(raw[296:552], %s.Newname[:])\n", selfRef)
	fmt.Fprintf(b, "\tbinary.LittleEndian.PutUint32(raw[552:556], %s.OldnameStatus)\n", selfRef)
	fmt.Fprintf(b, "\tbinary.LittleEndian.PutUint32(raw[556:560], %s.NewnameStatus)\n", selfRef)
	fmt.Fprintf(b, "\tbinary.LittleEndian.PutUint32(raw[560:564], %s.SchemaVersion)\n", selfRef)
	b.WriteString("\treturn raw, nil\n}\n\n")
	fmt.Fprintf(b, "func (%s *TwoFdEvent) Recycle() {\n\tpoolOfTwoFdEvents.Put(%s)\n}\n", selfRef, selfRef)
}

func snakeToCamel(s string) string {
	parts := strings.Split(s, "_")
	for i, p := range parts {
		if p == "" {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + p[1:]
	}
	return strings.Join(parts, "")
}

func cTypeToGoType(t string) string {
	switch t {
	case "char":
		return "byte"
	case "__s32":
		return "int32"
	case "__u32":
		return "uint32"
	case "__s64":
		return "int64"
	case "__u64":
		return "uint64"
	default:
		return t
	}
}
