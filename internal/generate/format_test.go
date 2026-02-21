package generate

import (
	"strings"
	"testing"
)

func mustParseOne(t *testing.T, data string) Format {
	t.Helper()
	formats, err := ParseFormats(strings.NewReader(data))
	if err != nil {
		t.Fatalf("ParseFormats failed: %v", err)
	}
	if len(formats) != 1 {
		t.Fatalf("expected 1 format, got %d", len(formats))
	}
	return formats[0]
}

func TestParseFormatOpenat(t *testing.T) {
	f := mustParseOne(t, FormatOpenat)

	if f.Name != "sys_enter_openat" {
		t.Errorf("name = %q, want sys_enter_openat", f.Name)
	}
	if f.ID != 784 {
		t.Errorf("ID = %d, want 784", f.ID)
	}
	if len(f.InternalFields) != 4 {
		t.Errorf("internal fields = %d, want 4", len(f.InternalFields))
	}
	if len(f.ExternalFields) != 5 {
		t.Errorf("external fields = %d, want 5", len(f.ExternalFields))
	}
	if f.ExternalFields[0].Name != "__syscall_nr" {
		t.Errorf("first external field = %q, want __syscall_nr", f.ExternalFields[0].Name)
	}
	if f.ExternalFields[2].Type != "const char *" {
		t.Errorf("filename type = %q, want 'const char *'", f.ExternalFields[2].Type)
	}
	if f.ExternalFields[2].Name != "filename" {
		t.Errorf("field 2 name = %q, want filename", f.ExternalFields[2].Name)
	}
}

func TestParseFormatExitRead(t *testing.T) {
	f := mustParseOne(t, FormatExitRead)

	if f.Name != "sys_exit_read" {
		t.Errorf("name = %q, want sys_exit_read", f.Name)
	}
	if f.ID != 843 {
		t.Errorf("ID = %d, want 843", f.ID)
	}
	if len(f.ExternalFields) != 2 {
		t.Errorf("external fields = %d, want 2", len(f.ExternalFields))
	}
	if f.ExternalFields[1].Type != "long" {
		t.Errorf("ret type = %q, want long", f.ExternalFields[1].Type)
	}
	if f.ExternalFields[1].Name != "ret" {
		t.Errorf("ret name = %q, want ret", f.ExternalFields[1].Name)
	}
	if !f.ExternalFields[1].Signed {
		t.Error("ret should be signed")
	}
}

func TestParseFormatSync(t *testing.T) {
	f := mustParseOne(t, FormatSync)

	if f.Name != "sys_enter_sync" {
		t.Errorf("name = %q, want sys_enter_sync", f.Name)
	}
	if f.ID != 1027 {
		t.Errorf("ID = %d, want 1027", f.ID)
	}
	if len(f.ExternalFields) != 1 {
		t.Errorf("external fields = %d, want 1 (__syscall_nr only)", len(f.ExternalFields))
	}
}

func TestParseMultiSection(t *testing.T) {
	input := FormatRead + "\n" + FormatExitRead
	formats, err := ParseFormats(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseFormats failed: %v", err)
	}
	if len(formats) != 2 {
		t.Fatalf("expected 2 formats, got %d", len(formats))
	}
	if formats[0].Name != "sys_enter_read" {
		t.Errorf("first = %q", formats[0].Name)
	}
	if formats[1].Name != "sys_exit_read" {
		t.Errorf("second = %q", formats[1].Name)
	}
}

func TestParseFieldDetails(t *testing.T) {
	f := mustParseOne(t, FormatOpenat)

	// common_type: internal field
	ct := f.InternalFields[0]
	if ct.Name != "common_type" || ct.Type != "unsigned short" || ct.Offset != 0 || ct.Size != 2 || ct.Signed {
		t.Errorf("common_type = %+v", ct)
	}

	// dfd: first non-syscall_nr external field
	dfd := f.ExternalFields[1]
	if dfd.Name != "dfd" || dfd.Type != "int" || dfd.Offset != 16 || dfd.Size != 8 {
		t.Errorf("dfd = %+v", dfd)
	}
}

func TestFieldNumber(t *testing.T) {
	f := mustParseOne(t, FormatOpenat)

	if n := f.FieldNumber("filename"); n != 1 {
		t.Errorf("FieldNumber(filename) = %d, want 1", n)
	}
	if n := f.FieldNumber("flags"); n != 2 {
		t.Errorf("FieldNumber(flags) = %d, want 2", n)
	}
	if n := f.FieldNumber("dfd"); n != 0 {
		t.Errorf("FieldNumber(dfd) = %d, want 0", n)
	}
	if n := f.FieldNumber("nonexistent"); n != -1 {
		t.Errorf("FieldNumber(nonexistent) = %d, want -1", n)
	}
}

func TestFieldNumberFcntl(t *testing.T) {
	f := mustParseOne(t, FormatFcntl)

	if n := f.FieldNumber("fd"); n != 0 {
		t.Errorf("FieldNumber(fd) = %d, want 0", n)
	}
	if n := f.FieldNumber("cmd"); n != 1 {
		t.Errorf("FieldNumber(cmd) = %d, want 1", n)
	}
	if n := f.FieldNumber("arg"); n != 2 {
		t.Errorf("FieldNumber(arg) = %d, want 2", n)
	}
}

func TestFieldNumberRename(t *testing.T) {
	f := mustParseOne(t, FormatRename)

	if n := f.FieldNumber("oldname"); n != 0 {
		t.Errorf("FieldNumber(oldname) = %d, want 0", n)
	}
	if n := f.FieldNumber("newname"); n != 1 {
		t.Errorf("FieldNumber(newname) = %d, want 1", n)
	}
}

func TestFieldNumberLinkat(t *testing.T) {
	f := mustParseOne(t, FormatLinkat)

	if n := f.FieldNumber("oldname"); n != 1 {
		t.Errorf("FieldNumber(oldname) = %d, want 1", n)
	}
	if n := f.FieldNumber("newname"); n != 3 {
		t.Errorf("FieldNumber(newname) = %d, want 3", n)
	}
}

func TestParseFormatError(t *testing.T) {
	_, err := ParseFormats(strings.NewReader("field:broken"))
	if err == nil {
		t.Error("expected error for field without name")
	}
}

func TestParseFormatEmptyInput(t *testing.T) {
	formats, err := ParseFormats(strings.NewReader(""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(formats) != 0 {
		t.Errorf("expected 0 formats, got %d", len(formats))
	}
}

func TestParseFormatIDWithoutName(t *testing.T) {
	_, err := ParseFormats(strings.NewReader("ID: 123\n"))
	if err == nil {
		t.Error("expected error for ID without preceding name")
	}
}

func TestParseFormatInvalidID(t *testing.T) {
	input := "name: sys_enter_test\nID: notanumber\n"
	_, err := ParseFormats(strings.NewReader(input))
	if err == nil {
		t.Error("expected error for non-numeric ID")
	}
}

func TestParseFieldNotEnoughParts(t *testing.T) {
	input := "name: sys_enter_test\nID: 100\nfield:unsigned int fd;	offset:16\n"
	_, err := ParseFormats(strings.NewReader(input))
	if err == nil {
		t.Error("expected error for field with fewer than 4 semicolons")
	}
}

func TestSplitDeclarationEmpty(t *testing.T) {
	typePart, namePart := splitDeclaration("")
	if typePart != "" || namePart != "" {
		t.Errorf("splitDeclaration(\"\") = (%q, %q), want (\"\", \"\")", typePart, namePart)
	}
}
