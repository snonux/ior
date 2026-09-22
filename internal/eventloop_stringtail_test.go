package internal

import (
	"fmt"
	"syscall"
	"testing"

	"ior/internal/event"
	"ior/internal/globalfilter"
	"ior/internal/types"

	"golang.org/x/sys/unix"
)

// Task 79 stopped the BPF handlers from zeroing a string field before reading
// into it. A ring-buffer record therefore carries, after a string's NUL
// terminator, whatever bytes an earlier record left in that slot - typically
// fragments of other paths. On a NULL pointer or a failed read only the first
// byte is written. These tests drive every kind that carries a string through
// the real raw-event path (decoder, raw filter, pairing, exit handler) twice:
// once with the zero-filled tail the old handlers produced and once with a
// garbage tail, and require byte-identical rows. The garbage names a path
// ("/etc/shadow") so that a file filter matching it proves the tail is never
// matched against either.

// stringTailGarbage is written after the terminator in the "garbage" variant.
// It contains no NUL, so a decoder that ignored the terminator would pick it
// up as part of the string.
const stringTailGarbage = "\xff/etc/shadow-stale-ringbuf-bytes/"

// stringFill writes s, NUL-terminated, into a fixed-size string field. The
// clean variant zero-fills the rest; the garbage variant fills it with stale
// bytes as a reused ring-buffer slot would.
type stringFill func(dst []byte, s string)

func cleanTail(dst []byte, s string) {
	clear(dst)
	copy(dst, s)
}

func garbageTail(dst []byte, s string) {
	for i := range dst {
		dst[i] = stringTailGarbage[i%len(stringTailGarbage)]
	}
	n := copy(dst, s)
	if n < len(dst) {
		dst[n] = 0
	}
}

// stringTailCase builds the raw records of one syscall, in ring-buffer order.
type stringTailCase struct {
	name  string
	build func(t *testing.T, fill stringFill) [][]byte
}

func mustRaw(t *testing.T, ev interface{ Bytes() ([]byte, error) }) []byte {
	t.Helper()
	raw, err := ev.Bytes()
	if err != nil {
		t.Fatalf("Bytes() error = %v", err)
	}
	return raw
}

func stringTailRetExit(t *testing.T, traceID types.TraceId, ret int64) []byte {
	t.Helper()
	_, raw := makeExitRetEvent(t, defaulTime+openPairLatency, execCommPid, execCommTid, traceID, ret)
	return raw
}

func openStringTailCase(name, filename string, status uint32, ret int64, fixup *string) stringTailCase {
	return stringTailCase{name: name, build: func(t *testing.T, fill stringFill) [][]byte {
		enter := &types.OpenEvent{
			EventType: types.ENTER_OPEN_EVENT, TraceId: types.SYS_ENTER_OPENAT, Time: defaulTime,
			Pid: execCommPid, Tid: execCommTid, Flags: syscall.O_RDONLY, Dirfd: unix.AT_FDCWD,
			SchemaVersion: types.OPEN_EVENT_SCHEMA_VERSION, FilenameStatus: status,
		}
		fill(enter.Filename[:], filename)
		copy(enter.Comm[:], "ioworkload") // bpf_get_current_comm NUL-pads the whole field
		raws := [][]byte{mustRaw(t, enter)}
		if fixup != nil {
			rec := &types.OpenNameFixupEvent{EventType: types.OPEN_NAME_FIXUP_EVENT, TraceId: types.SYS_ENTER_OPENAT, Tid: execCommTid}
			fill(rec.Filename[:], *fixup)
			raws = append(raws, mustRaw(t, rec))
		}
		return append(raws, stringTailRetExit(t, types.SYS_EXIT_OPENAT, ret))
	}}
}

func execStringTailCase(name, filename string) stringTailCase {
	return stringTailCase{name: name, build: func(t *testing.T, fill stringFill) [][]byte {
		enter := &types.ExecEvent{
			EventType: types.ENTER_EXEC_EVENT, TraceId: types.SYS_ENTER_EXECVE, Time: defaulTime,
			Pid: execCommPid, Tid: execCommTid, Dirfd: -1,
		}
		fill(enter.Filename[:], filename)
		copy(enter.Comm[:], "ioworkload")
		return [][]byte{mustRaw(t, enter), stringTailRetExit(t, types.SYS_EXIT_EXECVE, -int64(unix.ENOENT))}
	}}
}

func pathStringTailCase(name, pathname string, status uint32, ret int64) stringTailCase {
	return stringTailCase{name: name, build: func(t *testing.T, fill stringFill) [][]byte {
		enter := &types.PathEvent{
			EventType: types.ENTER_PATH_EVENT, TraceId: types.SYS_ENTER_NEWFSTATAT, Time: defaulTime,
			Pid: execCommPid, Tid: execCommTid, Dirfd: unix.AT_FDCWD, PathnameStatus: status,
			SchemaVersion: types.PATH_EVENT_SCHEMA_VERSION, TargetStatus: types.PATH_TARGET_REQUIRED,
		}
		fill(enter.Pathname[:], pathname)
		return [][]byte{mustRaw(t, enter), stringTailRetExit(t, types.SYS_EXIT_NEWFSTATAT, ret)}
	}}
}

func fdPathStringTailCase(name, pathname string, status uint32) stringTailCase {
	return stringTailCase{name: name, build: func(t *testing.T, fill stringFill) [][]byte {
		enter := &types.FdPathEvent{
			EventType: types.ENTER_FD_PATH_EVENT, TraceId: types.SYS_ENTER_INOTIFY_ADD_WATCH, Time: defaulTime,
			Pid: execCommPid, Tid: execCommTid, Fd: 5, Dirfd: unix.AT_FDCWD, PathnameStatus: status,
			SchemaVersion: types.FD_PATH_EVENT_SCHEMA_VERSION,
		}
		fill(enter.Pathname[:], pathname)
		return [][]byte{mustRaw(t, enter), stringTailRetExit(t, types.SYS_EXIT_INOTIFY_ADD_WATCH, 1)}
	}}
}

func nameStringTailCase(name, oldname, newname string, oldStatus, newStatus uint32) stringTailCase {
	return stringTailCase{name: name, build: func(t *testing.T, fill stringFill) [][]byte {
		enter := &types.NameEvent{
			EventType: types.ENTER_NAME_EVENT, TraceId: types.SYS_ENTER_RENAMEAT2, Time: defaulTime,
			Pid: execCommPid, Tid: execCommTid, Olddirfd: unix.AT_FDCWD, Newdirfd: unix.AT_FDCWD,
			OldnameStatus: oldStatus, NewnameStatus: newStatus, SchemaVersion: types.NAME_EVENT_SCHEMA_VERSION,
		}
		fill(enter.Oldname[:], oldname)
		fill(enter.Newname[:], newname)
		return [][]byte{mustRaw(t, enter), stringTailRetExit(t, types.SYS_EXIT_RENAMEAT2, 0)}
	}}
}

func eventfdStringTailCase(name string, enterID, exitID types.TraceId, filename string, status uint32, ret int64) stringTailCase {
	return stringTailCase{name: name, build: func(t *testing.T, fill stringFill) [][]byte {
		enter := &types.EventfdEvent{
			EventType: types.ENTER_EVENTFD_EVENT, TraceId: enterID, Time: defaulTime,
			Pid: execCommPid, Tid: execCommTid, Flags: 1, Ret: -1, Fd: -1, FilenameStatus: status,
			SchemaVersion: types.EVENTFD_EVENT_SCHEMA_VERSION,
		}
		fill(enter.Filename[:], filename)
		exit := &types.EventfdEvent{
			EventType: types.EXIT_EVENTFD_EVENT, TraceId: exitID, Time: defaulTime + openPairLatency,
			Pid: execCommPid, Tid: execCommTid, Flags: 1, Ret: ret, Fd: -1, FilenameStatus: types.PATH_READ_NULL,
			SchemaVersion: types.EVENTFD_EVENT_SCHEMA_VERSION,
		}
		fill(exit.Filename[:], "") // the exit handler only terminates it
		return [][]byte{mustRaw(t, enter), mustRaw(t, exit)}
	}}
}

func twoFdStringTailCase(name string, enterID, exitID types.TraceId, oldname, newname string, status uint32) stringTailCase {
	return stringTailCase{name: name, build: func(t *testing.T, fill stringFill) [][]byte {
		enter := &types.TwoFdEvent{
			EventType: types.ENTER_TWO_FD_EVENT, TraceId: enterID, Time: defaulTime,
			Pid: execCommPid, Tid: execCommTid, FdA: 81, FdB: 82, Extra: 0x2,
			OldnameStatus: status, NewnameStatus: status, SchemaVersion: types.TWO_FD_EVENT_SCHEMA_VERSION,
		}
		fill(enter.Oldname[:], oldname)
		fill(enter.Newname[:], newname)
		return [][]byte{mustRaw(t, enter), stringTailRetExit(t, exitID, 0)}
	}}
}

func stringTailCases() []stringTailCase {
	recovered := "/usr/lib/locale/locale-archive"
	return []stringTailCase{
		openStringTailCase("open captured", "/tmp/ior-string-tail.txt", types.PATH_READ_OK, 7, nil),
		openStringTailCase("open empty string", "", types.PATH_READ_OK, -int64(unix.ENOENT), nil),
		openStringTailCase("open NULL pointer", "", types.PATH_READ_NULL, -int64(unix.EFAULT), nil),
		openStringTailCase("open failed read", "", types.PATH_READ_FAILED, 7, nil),
		openStringTailCase("open failed read recovered at exit", "", types.PATH_READ_FAILED, 7, &recovered),
		execStringTailCase("exec captured", "/usr/bin/ior-string-tail"),
		execStringTailCase("exec failed read", ""),
		pathStringTailCase("path captured", "/tmp/ior-string-tail.txt", types.PATH_READ_OK, 0),
		pathStringTailCase("path NULL pointer", "", types.PATH_READ_NULL, -int64(unix.EFAULT)),
		pathStringTailCase("path failed read", "", types.PATH_READ_FAILED, -int64(unix.EFAULT)),
		fdPathStringTailCase("fd-path captured", "/tmp/ior-watched", types.PATH_READ_OK),
		fdPathStringTailCase("fd-path failed read", "", types.PATH_READ_FAILED),
		nameStringTailCase("rename captured", "/tmp/ior-old", "/tmp/ior-new", types.PATH_READ_OK, types.PATH_READ_OK),
		nameStringTailCase("rename NULL and failed", "", "", types.PATH_READ_NULL, types.PATH_READ_FAILED),
		eventfdStringTailCase("memfd_create captured", types.SYS_ENTER_MEMFD_CREATE, types.SYS_EXIT_MEMFD_CREATE,
			"ior-memfd", types.PATH_READ_OK, 44),
		eventfdStringTailCase("memfd_create failed read", types.SYS_ENTER_MEMFD_CREATE, types.SYS_EXIT_MEMFD_CREATE,
			"", types.PATH_READ_FAILED, 44),
		eventfdStringTailCase("eventfd2 without a name", types.SYS_ENTER_EVENTFD2, types.SYS_EXIT_EVENTFD2,
			"", types.PATH_READ_NULL, 45),
		twoFdStringTailCase("move_mount captured", types.SYS_ENTER_MOVE_MOUNT, types.SYS_EXIT_MOVE_MOUNT,
			"/ior-source", "/ior-destination", types.PATH_READ_OK),
		twoFdStringTailCase("close_range without names", types.SYS_ENTER_CLOSE_RANGE, types.SYS_EXIT_CLOSE_RANGE,
			"", "", types.PATH_READ_NULL),
	}
}

// stringTailRow feeds the records through a fresh event loop and renders
// everything a row exposes that is derived from a string field.
func stringTailRow(t *testing.T, filter globalfilter.Filter, raws [][]byte) string {
	t.Helper()
	el := newFilteredEventLoop(t, filter)
	out := make(chan *event.Pair, 1)
	for _, raw := range raws {
		el.processRawEvent(raw, out)
	}
	var ep *event.Pair
	select {
	case ep = <-out:
	default:
		return "<no row>"
	}
	defer ep.Recycle()
	fd, hasFD := ep.FileDescriptor()
	return fmt.Sprintf("%s | comm=%q file=%q oldname=%q fd=%d/%v",
		ep.String(), ep.Comm, ep.FileName(), ep.Oldname, fd, hasFD)
}

func TestStringFieldBytesAfterTheTerminatorNeverReachARow(t *testing.T) {
	filters := map[string]globalfilter.Filter{
		"no filter": {},
		// Matches only the stale bytes: must drop the clean and the garbage
		// variant alike (or keep both, for rows without a file).
		"file filter on the stale bytes": {File: &globalfilter.StringFilter{Pattern: "shadow"}},
	}
	for _, tc := range stringTailCases() {
		for filterName, filter := range filters {
			t.Run(tc.name+"/"+filterName, func(t *testing.T) {
				clean := stringTailRow(t, filter, tc.build(t, cleanTail))
				garbage := stringTailRow(t, filter, tc.build(t, garbageTail))
				if garbage != clean {
					t.Fatalf("garbage after the terminator changed the row\n  zeroed tail:  %s\n  garbage tail: %s", clean, garbage)
				}
				t.Logf("row: %s", clean)
				if filterName == "no filter" && clean == "<no row>" {
					t.Fatal("the unfiltered case produced no row; the comparison would be vacuous")
				}
			})
		}
	}
}

// TestStringTailGarbageIsVisibleWithoutTheTerminator keeps the fixture honest:
// if the terminator were missing, the garbage would change the row.
func TestStringTailGarbageIsVisibleWithoutTheTerminator(t *testing.T) {
	unterminated := func(dst []byte, s string) {
		garbageTail(dst, s)
		if len(s) < len(dst) {
			dst[len(s)] = '!'
		}
	}
	tc := pathStringTailCase("path captured", "/tmp/ior-string-tail.txt", types.PATH_READ_OK, 0)
	clean := stringTailRow(t, globalfilter.Filter{}, tc.build(t, cleanTail))
	broken := stringTailRow(t, globalfilter.Filter{}, tc.build(t, unterminated))
	if broken == clean {
		t.Fatalf("an unterminated garbage tail did not change the row: %s", clean)
	}
}
