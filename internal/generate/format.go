package generate

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

type Field struct {
	Type   string
	Name   string
	Offset int
	Size   int
	Signed bool
}

type Format struct {
	Name           string
	ID             int
	Family         SyscallFamily
	InternalFields []Field
	ExternalFields []Field
}

// FieldNumber returns the 0-based index of a named field in ExternalFields,
// minus 1 (to skip __syscall_nr), matching the Raku behavior where args[0]
// is the first field after __syscall_nr.
func (f *Format) FieldNumber(name string) int {
	for i, field := range f.ExternalFields {
		if field.Name == name {
			return i - 1
		}
	}
	return 0 - 1
}

// ParseFormats parses concatenated sysfs tracepoint format files from r.
// Each section has: name, ID, format fields, print fmt.
func ParseFormats(r io.Reader) ([]Format, error) {
	scanner := bufio.NewScanner(r)
	var formats []Format
	var current *Format
	isExternal := false

	for scanner.Scan() {
		var err error
		current, isExternal, err = applyFormatLine(scanner.Text(), formats, current, isExternal, &formats)
		if err != nil {
			return nil, err
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning input: %w", err)
	}
	return formats, nil
}

// applyFormatLine processes one line from the format file, updating the
// running parse state (current format, isExternal flag, and formats slice).
func applyFormatLine(line string, _ []Format, current *Format, isExternal bool, formats *[]Format) (*Format, bool, error) {
	trimmed := strings.TrimSpace(line)
	switch {
	case strings.HasPrefix(trimmed, "name:"):
		f := Format{}
		f.Name = strings.TrimSpace(strings.TrimPrefix(trimmed, "name:"))
		f.Family = ClassifySyscallFamily(f.Name)
		*formats = append(*formats, f)
		current = &(*formats)[len(*formats)-1]
		isExternal = false

	case strings.HasPrefix(trimmed, "ID:"):
		if current == nil {
			return nil, false, fmt.Errorf("ID without name")
		}
		id, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(trimmed, "ID:")))
		if err != nil {
			return nil, false, fmt.Errorf("parsing ID: %w", err)
		}
		current.ID = id

	case strings.HasPrefix(trimmed, "field:"):
		if current == nil {
			return nil, false, fmt.Errorf("field without name")
		}
		field, err := parseField(trimmed)
		if err != nil {
			return nil, false, fmt.Errorf("parsing field in %s: %w", current.Name, err)
		}
		if field.Name == "__syscall_nr" {
			isExternal = true
		}
		if isExternal {
			current.ExternalFields = append(current.ExternalFields, field)
		} else {
			current.InternalFields = append(current.InternalFields, field)
		}
	}
	return current, isExternal, nil
}

func parseField(line string) (Field, error) {
	// Format: "field:TYPE NAME;	offset:N;	size:N;	signed:N;"
	line = strings.TrimPrefix(line, "field:")
	parts := strings.Split(line, ";")
	if len(parts) < 4 {
		return Field{}, fmt.Errorf("not enough field parts: %q", line)
	}

	decl := strings.TrimSpace(parts[0])
	fieldType, fieldName := splitDeclaration(decl)

	offset, err := parseFieldInt(parts[1], "offset:")
	if err != nil {
		return Field{}, err
	}
	size, err := parseFieldInt(parts[2], "size:")
	if err != nil {
		return Field{}, err
	}
	signedVal, err := parseFieldInt(parts[3], "signed:")
	if err != nil {
		return Field{}, err
	}

	return Field{
		Type:   fieldType,
		Name:   fieldName,
		Offset: offset,
		Size:   size,
		Signed: signedVal != 0,
	}, nil
}

// splitDeclaration splits "const char * filename" into ("const char *", "filename").
func splitDeclaration(decl string) (string, string) {
	tokens := strings.Fields(decl)
	if len(tokens) == 0 {
		return "", ""
	}
	if len(tokens) == 1 {
		return "", tokens[0]
	}
	name := tokens[len(tokens)-1]
	typePart := strings.Join(tokens[:len(tokens)-1], " ")
	return typePart, name
}

func parseFieldInt(s, prefix string) (int, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, prefix)
	s = strings.TrimSpace(s)
	return strconv.Atoi(s)
}
