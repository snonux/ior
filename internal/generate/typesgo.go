package generate

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"
)

type CConstant struct {
	Name  string
	Value string
}

type CMember struct {
	TypeName  string
	FieldName string
	ArraySize string
}

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

	writeTraceIdStringMethod(b)
	writeTraceIdNameMethod(b)
	b.WriteString("\n")
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
	writeGetterMethods(b, goName, selfRef)

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

func writeGetterMethods(b *strings.Builder, goName, selfRef string) {
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
		fmt.Fprintf(b, "func (%s *%s) %s() %s {\n\treturn %s.%s\n}\n\n",
			selfRef, goName, g.method, g.returnType, selfRef, g.field)
	}
}

func writeSyncPool(b *strings.Builder, goName, selfRef string) {
	fmt.Fprintf(b, "var poolOf%ss = sync.Pool{\n\tNew: func() interface{} { return &%s{} },\n}\n\n", goName, goName)
	fmt.Fprintf(b, "func New%s(raw []byte) *%s {\n", goName, goName)
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
