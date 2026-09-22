package types

import "testing"

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
		ev := &ExecEvent{EventType: ENTER_EXEC_EVENT, TraceId: SYS_ENTER_EXECVE, Dirfd: -1, Filename: withStaleTail("/bin/true")}
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
