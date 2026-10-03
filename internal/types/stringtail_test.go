package types

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strings"
	"testing"
)

// Since task 79 the BPF handlers terminate string fields instead of zeroing
// them, so the bytes after a string's NUL are stale ring-buffer contents. The
// fast decoders copy whole arrays; these tests pin that what a consumer reads
// through StringValue - and every field laid out after the string - is
// independent of that tail, and that the slow decoders agree byte for byte.

const staleTail = "\xff/etc/shadow-stale-ringbuf-bytes/"

// withStaleTail returns a string field holding s, its NUL, then stale bytes.
func withStaleTail(s string) [MAX_FILENAME_LENGTH]byte {
	var field [MAX_FILENAME_LENGTH]byte
	for i := range field {
		field[i] = staleTail[i%len(staleTail)]
	}
	field[copy(field[:], s)] = 0
	return field
}

func TestFastDecodersIgnoreBytesAfterTheTerminator(t *testing.T) {
	t.Run("OpenEvent", func(t *testing.T) {
		ev := &OpenEvent{EventType: ENTER_OPEN_EVENT, TraceId: SYS_ENTER_OPENAT, Dirfd: 9, SchemaVersion: OPEN_EVENT_SCHEMA_VERSION,
			FilenameStatus: PATH_READ_FAILED, Filename: withStaleTail("")}
		copy(ev.Comm[:], "comm")
		raw := rawBytes(t, ev)
		fast, slow := NewOpenEventFast(raw), NewOpenEvent(raw)
		defer fast.Recycle()
		defer slow.Recycle()
		if got := StringValue(fast.Filename[:]); got != "" || fast.FilenameStatus != PATH_READ_FAILED || fast.Dirfd != 9 ||
			StringValue(fast.Comm[:]) != "comm" || !slow.Equals(fast) {
			t.Fatalf("decoded filename=%q status=%d dirfd=%d comm=%q", got, fast.FilenameStatus, fast.Dirfd, StringValue(fast.Comm[:]))
		}
	})
	t.Run("OpenNameFixupEvent", func(t *testing.T) {
		ev := &OpenNameFixupEvent{EventType: OPEN_NAME_FIXUP_EVENT, TraceId: SYS_ENTER_OPENAT, Tid: 3, Filename: withStaleTail("/recovered")}
		raw := rawBytes(t, ev)
		fast, slow := NewOpenNameFixupEventFast(raw), NewOpenNameFixupEvent(raw)
		defer fast.Recycle()
		defer slow.Recycle()
		if got := StringValue(fast.Filename[:]); got != "/recovered" || !slow.Equals(fast) {
			t.Fatalf("decoded filename=%q", got)
		}
	})
	t.Run("ExecEvent", func(t *testing.T) {
		ev := &ExecEvent{EventType: ENTER_EXEC_EVENT, TraceId: SYS_ENTER_EXECVE, Dirfd: -1, Filename: withStaleTail("/bin/true"),
			SchemaVersion: EXEC_EVENT_SCHEMA_VERSION}
		copy(ev.Comm[:], "sh")
		raw := rawBytes(t, ev)
		fast, slow := NewExecEventFast(raw), NewExecEvent(raw)
		defer fast.Recycle()
		defer slow.Recycle()
		if got := StringValue(fast.Filename[:]); got != "/bin/true" || StringValue(fast.Comm[:]) != "sh" || !slow.Equals(fast) {
			t.Fatalf("decoded filename=%q comm=%q", got, StringValue(fast.Comm[:]))
		}
	})
	t.Run("PathEvent", func(t *testing.T) {
		ev := &PathEvent{EventType: ENTER_PATH_EVENT, TraceId: SYS_ENTER_NEWFSTATAT, Dirfd: 7, PathnameStatus: PATH_READ_OK,
			SchemaVersion: PATH_EVENT_SCHEMA_VERSION, TargetStatus: PATH_TARGET_REQUIRED, Pathname: withStaleTail("/tmp/x")}
		raw := rawBytes(t, ev)
		fast, slow := NewPathEventFast(raw), NewPathEvent(raw)
		defer fast.Recycle()
		defer slow.Recycle()
		if got := StringValue(fast.Pathname[:]); got != "/tmp/x" || fast.Dirfd != 7 || fast.PathnameStatus != PATH_READ_OK || !slow.Equals(fast) {
			t.Fatalf("decoded pathname=%q dirfd=%d status=%d", got, fast.Dirfd, fast.PathnameStatus)
		}
	})
	t.Run("FdPathEvent", func(t *testing.T) {
		ev := &FdPathEvent{EventType: ENTER_FD_PATH_EVENT, TraceId: SYS_ENTER_INOTIFY_ADD_WATCH, Fd: 4, Dirfd: -100,
			PathnameStatus: PATH_READ_NULL, SchemaVersion: FD_PATH_EVENT_SCHEMA_VERSION, Pathname: withStaleTail("")}
		raw := rawBytes(t, ev)
		fast, slow := NewFdPathEventFast(raw), NewFdPathEvent(raw)
		defer fast.Recycle()
		defer slow.Recycle()
		if got := StringValue(fast.Pathname[:]); got != "" || fast.PathnameStatus != PATH_READ_NULL || !slow.Equals(fast) {
			t.Fatalf("decoded pathname=%q status=%d", got, fast.PathnameStatus)
		}
	})
	t.Run("NameEvent", func(t *testing.T) {
		ev := &NameEvent{EventType: ENTER_NAME_EVENT, TraceId: SYS_ENTER_RENAMEAT2, Olddirfd: 3, Newdirfd: 4,
			OldnameStatus: PATH_READ_OK, NewnameStatus: PATH_READ_FAILED, SchemaVersion: NAME_EVENT_SCHEMA_VERSION,
			Oldname: withStaleTail("/old"), Newname: withStaleTail("")}
		raw := rawBytes(t, ev)
		fast, slow := NewNameEventFast(raw), NewNameEvent(raw)
		defer fast.Recycle()
		defer slow.Recycle()
		if StringValue(fast.Oldname[:]) != "/old" || StringValue(fast.Newname[:]) != "" || fast.Olddirfd != 3 || fast.Newdirfd != 4 ||
			fast.NewnameStatus != PATH_READ_FAILED || !slow.Equals(fast) {
			t.Fatalf("decoded %v", fast)
		}
	})
	t.Run("EventfdEvent", func(t *testing.T) {
		ev := &EventfdEvent{EventType: ENTER_EVENTFD_EVENT, TraceId: SYS_ENTER_MEMFD_CREATE, Fd: -1, FilenameStatus: PATH_READ_OK,
			SchemaVersion: EVENTFD_EVENT_SCHEMA_VERSION, Filename: withStaleTail("memfd-name")}
		raw := rawBytes(t, ev)
		fast, slow := NewEventfdEventFast(raw), NewEventfdEvent(raw)
		defer fast.Recycle()
		defer slow.Recycle()
		if got := StringValue(fast.Filename[:]); got != "memfd-name" || fast.FilenameStatus != PATH_READ_OK || !slow.Equals(fast) {
			t.Fatalf("decoded filename=%q status=%d", got, fast.FilenameStatus)
		}
	})
	t.Run("TwoFdEvent", func(t *testing.T) {
		ev := &TwoFdEvent{EventType: ENTER_TWO_FD_EVENT, TraceId: SYS_ENTER_CLOSE_RANGE, FdA: 3, FdB: 9,
			OldnameStatus: PATH_READ_NULL, NewnameStatus: PATH_READ_NULL, SchemaVersion: TWO_FD_EVENT_SCHEMA_VERSION,
			Oldname: withStaleTail(""), Newname: withStaleTail("")}
		raw := rawBytes(t, ev)
		fast, slow := NewTwoFdEventFast(raw), NewTwoFdEvent(raw)
		defer fast.Recycle()
		defer slow.Recycle()
		if StringValue(fast.Oldname[:]) != "" || StringValue(fast.Newname[:]) != "" || fast.FdB != 9 ||
			fast.NewnameStatus != PATH_READ_NULL || !slow.Equals(fast) {
			t.Fatalf("decoded %v", fast)
		}
	})
}

func TestStringValueStopsAtTheFirstNUL(t *testing.T) {
	field := withStaleTail("/a")
	if got := StringValue(field[:]); got != "/a" {
		t.Fatalf("StringValue = %q, want %q", got, "/a")
	}
	empty := withStaleTail("")
	if got := StringValue(empty[:]); got != "" {
		t.Fatalf("StringValue of a terminated-only field = %q, want empty", got)
	}
}

// stringBearingEvents lists a zero value of every generated event type with a
// char[] field; TestStringBearingEventsListIsComplete keeps it in step with
// generated_types.go.
func stringBearingEvents() []fmt.Stringer {
	return []fmt.Stringer{
		&OpenEvent{}, &OpenNameFixupEvent{}, &ExecEvent{}, &NameEvent{}, &PathEvent{},
		&FdPathEvent{}, &EventfdEvent{}, &EventfdNameEvent{}, &TwoFdEvent{},
		&TwoFdNamesEvent{}, &ProcessExecEvent{}, &TaskNewtaskEvent{}, &TaskRenameEvent{},
		&FdEvent{}, &FdNameEvent{},
	}
}

// fillStringFields writes "/s<i>", its NUL, then stale bytes into every
// string field of ev (a pointer to a generated struct) and returns the values
// written, in field order. With terminate false the NUL is left out, as if a
// handler had forgotten the terminator.
func fillStringFields(ev any, terminate bool) []string {
	v := reflect.ValueOf(ev).Elem()
	var written []string
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		if f.Kind() != reflect.Array || f.Type().Elem().Kind() != reflect.Uint8 {
			continue
		}
		s := fmt.Sprintf("/s%d", i)
		for j := 0; j < f.Len(); j++ {
			f.Index(j).SetUint(uint64(staleTail[j%len(staleTail)]))
		}
		for j := 0; j < len(s); j++ {
			f.Index(j).SetUint(uint64(s[j]))
		}
		if terminate {
			f.Index(len(s)).SetUint(0)
		}
		written = append(written, s)
	}
	return written
}

// The generated String() is what fmt's %v renders for an event, e.g. in a log
// line or a TUI row. Since task 79 the bytes after a string's terminator are stale
// ring-buffer data, so String() must render every string field only up to its
// first NUL.
func TestGeneratedStringStopsAtTheTerminator(t *testing.T) {
	for _, ev := range stringBearingEvents() {
		name := reflect.TypeOf(ev).Elem().Name()
		t.Run(name, func(t *testing.T) {
			written := fillStringFields(ev, true)
			if len(written) == 0 {
				t.Fatal("no string field; the list is stale")
			}
			got := ev.String()
			if strings.IndexByte(got, 0) >= 0 || strings.IndexByte(got, 0xff) >= 0 || strings.Contains(got, "shadow") {
				t.Fatalf("String() renders bytes after a terminator: %q", got)
			}
			for _, s := range written {
				if !strings.Contains(got, ":"+s+" ") && !strings.HasSuffix(got, ":"+s) {
					t.Fatalf("String() lost the string %q: %q", s, got)
				}
			}
		})
	}
}

// TestGeneratedStringShowsAMissingTerminator keeps the test above honest:
// without a terminator the stale bytes are part of the string.
func TestGeneratedStringShowsAMissingTerminator(t *testing.T) {
	for _, ev := range stringBearingEvents() {
		fillStringFields(ev, false)
		if got := ev.String(); !strings.Contains(got, "shadow") {
			t.Errorf("%T: an unterminated field did not reach String(): %q", ev, got)
		}
	}
}

// TestStringBearingEventsListIsComplete fails when generated_types.go gains a
// struct with a byte-array field that stringBearingEvents does not list. A
// binary field (binaryFieldSizes: a file handle, the array of a
// registered-ring record; C __u8 arrays) is not a string: it has no
// terminator, is zero-filled by BPF and rendered whole, as hex
// (TestFileHandleFieldRendersAsHex, TestRingFdsFieldRendersAsHex).
func TestStringBearingEventsListIsComplete(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "generated_types.go", nil, 0)
	if err != nil {
		t.Fatalf("parse generated_types.go: %v", err)
	}
	listed := map[string]bool{}
	for _, ev := range stringBearingEvents() {
		listed[reflect.TypeOf(ev).Elem().Name()] = true
	}
	found := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		spec, ok := n.(*ast.TypeSpec)
		if !ok {
			return true
		}
		st, ok := spec.Type.(*ast.StructType)
		if !ok {
			return false
		}
		for _, field := range st.Fields.List {
			if arr, ok := field.Type.(*ast.ArrayType); ok && arr.Len != nil {
				if size, ok := arr.Len.(*ast.Ident); ok && binaryFieldSizes[size.Name] {
					continue
				}
				if ident, ok := arr.Elt.(*ast.Ident); ok && ident.Name == "byte" {
					found[spec.Name.Name] = true
				}
			}
		}
		return false
	})
	for name := range found {
		if !listed[name] {
			t.Errorf("%s has a string field but is not in stringBearingEvents", name)
		}
	}
	for name := range listed {
		if !found[name] {
			t.Errorf("%s is listed in stringBearingEvents but has no string field", name)
		}
	}
}

// binaryFieldSizes are the size constants of the byte arrays that hold binary
// data, not a NUL-terminated string: a file handle and the
// io_uring_rsrc_update array of a registered-ring record. String() renders
// them as hex (TestFileHandleFieldRendersAsHex, TestRingFdsFieldRendersAsHex).
var binaryFieldSizes = map[string]bool{
	"IOR_MAX_HANDLE_SZ":  true,
	"IOR_RING_FDS_BYTES": true,
}

// TestRingFdsFieldRendersAsHex: the array of a registered-ring record is
// binary like a file handle, so String() renders all of it as hex instead of
// cutting it at the first zero byte or handing raw bytes to a terminal.
func TestRingFdsFieldRendersAsHex(t *testing.T) {
	var updates [IOR_RING_FDS_BYTES]byte
	copy(updates[:], []byte{0x1b, 0x00, 0xff, 0x41})
	want := "Updates:1b00ff41" + strings.Repeat("00", IOR_RING_FDS_BYTES-4)
	got := RingFdsEvent{Updates: updates}.String()
	if !strings.HasSuffix(got, want) {
		t.Errorf("RingFdsEvent renders its array as %q, want it to end in %q", got, want)
	}
	if strings.ContainsAny(got, "\x1b\x00") {
		t.Errorf("raw array bytes reached String(): %q", got)
	}
}

// TestFileHandleFieldRendersAsHex: the handle bytes are binary, so String()
// must not hand them to a log line or a terminal raw, nor cut them at the
// first zero byte as it does a string.
func TestFileHandleFieldRendersAsHex(t *testing.T) {
	var fHandle [IOR_MAX_HANDLE_SZ]byte
	copy(fHandle[:], []byte{0x1b, 0x00, 0xff, 0x41})
	want := "FHandle:1b00ff41" + strings.Repeat("00", IOR_MAX_HANDLE_SZ-4)
	events := []fmt.Stringer{
		OpenByHandleAtEvent{FHandle: fHandle},
		FileHandleEvent{FHandle: fHandle},
	}
	for _, ev := range events {
		// The handle is the last field of the open record and is followed
		// by the enter time in the control record: the whole field, to the
		// last byte, either ends the string or ends at the next field.
		got := ev.String()
		if !strings.HasSuffix(got, want) && !strings.Contains(got, want+" ") {
			t.Errorf("%T renders its handle as %q, want it to hold %q", ev, got, want)
		}
		if strings.ContainsAny(got, "\x1b\x00") {
			t.Errorf("%T: raw handle bytes reached String(): %q", ev, got)
		}
	}
}
