package internal

import (
	"os"
	"strings"
	"syscall"
	"testing"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

// getcwd's path is an output buffer, so the kernel reads it back at sys_exit
// after a successful return and publishes it as an OPEN_NAME_FIXUP_EVENT that
// precedes the exit record (outputPathSyscalls, internal/generate/classify.go).
// Before, userspace readlink'ed /proc/<tid>/cwd while processing the pair: a
// lagging loop reported wherever the tracee had chdir'ed to since, an exited
// tracee reported nothing, and every getcwd cost a syscall on the event loop.

// feedGetcwdPair drives enter -> [fixup] -> exit through the raw event path in
// ring-buffer order and returns the emitted pair, or nil when it was dropped.
// A nil fixup feeds no control record; fixupTrace is the trace ID the record
// is stamped with.
func feedGetcwdPair(t *testing.T, el *eventLoop, tid uint32, fixup *string, fixupTrace types.TraceId, ret int64) *event.Pair {
	t.Helper()
	out := make(chan *event.Pair, 1)
	_, enterRaw := makeEnterNullEvent(t, defaulTime, execCommPid, tid, types.SYS_ENTER_GETCWD)
	el.processRawEvent(enterRaw, out)
	if fixup != nil {
		el.processRawEvent(makeOpenNameFixupEvent(t, tid, fixupTrace, *fixup), out)
	}
	_, exitRaw := makeExitRetEvent(t, defaulTime+100, execCommPid, tid, types.SYS_EXIT_GETCWD, ret)
	el.processRawEvent(exitRaw, out)
	select {
	case ep := <-out:
		return ep
	default:
		return nil
	}
}

func TestGetcwdRowReportsTheKernelCapturedPath(t *testing.T) {
	realCwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	// The tracee is this very process, whose /proc/<tid>/cwd is realCwd. The
	// captured path deliberately differs: it models a tracee that has since
	// chdir'ed elsewhere, and the row must keep reporting what getcwd returned.
	const captured = "/ior-getcwd-test/before-chdir"
	if realCwd == captured {
		t.Fatalf("test precondition: real cwd must differ from %q", captured)
	}
	tid := uint32(os.Getpid())
	el := newFilteredEventLoop(t, globalfilter.Filter{})
	ep := feedGetcwdPair(t, el, tid, openFixup(captured), types.SYS_ENTER_GETCWD, int64(len(captured)+1))
	if ep == nil {
		t.Fatal("the getcwd pair was dropped")
	}
	defer ep.Recycle()
	if ep.File == nil {
		t.Fatal("getcwd row has no path")
	}
	if got := ep.File.Name(); got != captured {
		t.Fatalf("getcwd row path = %q, want the kernel-captured %q (procfs says %q)", got, captured, realCwd)
	}
}

func TestGetcwdRowWithoutACapturedPath(t *testing.T) {
	const captured = "/srv/data"
	tests := []struct {
		name       string
		fixup      *string
		fixupTrace types.TraceId
		ret        int64
	}{
		// The kernel only captures after a successful return; a stray record
		// must not attach a path to a failed call either.
		{name: "failed call ignores a stray capture", fixup: openFixup(captured), fixupTrace: types.SYS_ENTER_GETCWD, ret: -int64(syscall.ERANGE)},
		{name: "failed call without capture", ret: -int64(syscall.ENOENT)},
		{name: "zero return", fixup: openFixup(captured), fixupTrace: types.SYS_ENTER_GETCWD, ret: 0},
		// A record lost to ring-buffer backpressure, or an enter state the
		// kernel could not record, leaves the row without a path - it must
		// not fall back to guessing from procfs.
		{name: "successful call whose capture was lost", ret: int64(len(captured) + 1)},
		// Only a record stamped with getcwd's own trace ID may attach a path.
		{name: "foreign trace ID", fixup: openFixup(captured), fixupTrace: types.SYS_ENTER_OPENAT, ret: int64(len(captured) + 1)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			el := newFilteredEventLoop(t, globalfilter.Filter{})
			ep := feedGetcwdPair(t, el, uint32(os.Getpid()), tc.fixup, tc.fixupTrace, tc.ret)
			if ep == nil {
				t.Fatal("the getcwd pair was dropped")
			}
			defer ep.Recycle()
			if ep.File != nil {
				t.Fatalf("getcwd row path = %q, want none", ep.File.Name())
			}
			if got := ep.FileName(); got != "N:file" {
				t.Fatalf("getcwd row file name = %q, want N:file", got)
			}
		})
	}
}

func TestGetcwdRowMarksAPathLongerThanTheCapturedField(t *testing.T) {
	// The kernel field holds MAX_FILENAME_LENGTH - 1 bytes plus the NUL; ret
	// still reports the full length, which is how the truncation is detected.
	var ev types.OpenNameFixupEvent
	prefix := "/" + strings.Repeat("d", len(ev.Filename)-2)
	el := newFilteredEventLoop(t, globalfilter.Filter{})
	ep := feedGetcwdPair(t, el, execCommTid, openFixup(prefix), types.SYS_ENTER_GETCWD, 4096)
	if ep == nil {
		t.Fatal("the getcwd pair was dropped")
	}
	defer ep.Recycle()
	if ep.File == nil {
		t.Fatal("truncated getcwd row has no path")
	}
	if got, want := ep.File.Name(), prefix+getcwdTruncatedSuffix; got != want {
		t.Fatalf("truncated getcwd row path = %q, want %q", got, want)
	}
}

func TestGetcwdCaptureIsFilteredAsTheRowPath(t *testing.T) {
	const captured = "/work/project"
	t.Run("matching path keeps the row", func(t *testing.T) {
		el := newFilteredEventLoop(t, globalfilter.Filter{File: &globalfilter.StringFilter{Pattern: "^/work/project$"}})
		ep := feedGetcwdPair(t, el, execCommTid, openFixup(captured), types.SYS_ENTER_GETCWD, int64(len(captured)+1))
		if ep == nil {
			t.Fatal("a getcwd row whose captured path matches -path was dropped")
		}
		ep.Recycle()
	})
	t.Run("other path drops the row", func(t *testing.T) {
		el := newFilteredEventLoop(t, globalfilter.Filter{File: &globalfilter.StringFilter{Pattern: "^/elsewhere$"}})
		if ep := feedGetcwdPair(t, el, execCommTid, openFixup(captured), types.SYS_ENTER_GETCWD, int64(len(captured)+1)); ep != nil {
			defer ep.Recycle()
			t.Fatalf("a getcwd row with path %q passed a non-matching -path filter", ep.FileName())
		}
	})
}

func TestGetcwdFixupLeavesAPendingOpenAlone(t *testing.T) {
	// A getcwd record must never be treated as an open-name recovery: the
	// empty-name open pending on the same tid keeps its empty name.
	el := newFilteredEventLoop(t, globalfilter.Filter{})
	out := make(chan *event.Pair, 1)
	el.processRawEvent(makeOpenEnterEvent(t, "", "ioworkload"), out)
	el.processRawEvent(makeOpenNameFixupEvent(t, execCommTid, types.SYS_ENTER_GETCWD, "/srv/data"), out)
	_, exitRaw := makeExitRetEvent(t, defaulTime+openPairLatency, execCommPid, execCommTid, types.SYS_EXIT_OPENAT, 5)
	el.processRawEvent(exitRaw, out)
	select {
	case ep := <-out:
		defer ep.Recycle()
		if got := ep.File.Name(); got != "" {
			t.Fatalf("a getcwd capture was grafted onto a pending open: file = %q", got)
		}
	default:
		t.Fatal("the open pair was dropped")
	}
}

func TestFinishGetcwdPath(t *testing.T) {
	tests := []struct {
		name     string
		captured file.File
		ret      int64
		want     string // "" means no file
	}{
		{name: "exact", captured: file.NewPathname([]byte("/tmp")), ret: 5, want: "/tmp"},
		{name: "root", captured: file.NewPathname([]byte("/")), ret: 2, want: "/"},
		{name: "truncated", captured: file.NewPathname([]byte("/tmp")), ret: 300, want: "/tmp" + getcwdTruncatedSuffix},
		{name: "capture longer than ret is cut", captured: file.NewPathname([]byte("/tmp/extra")), ret: 5, want: "/tmp"},
		{name: "errno", captured: file.NewPathname([]byte("/tmp")), ret: -int64(syscall.ERANGE)},
		{name: "zero", captured: file.NewPathname([]byte("/tmp")), ret: 0},
		{name: "nothing captured", ret: 5},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := finishGetcwdPath(tc.captured, tc.ret)
			switch {
			case tc.want == "" && got != nil:
				t.Fatalf("finishGetcwdPath = %q, want none", got.Name())
			case tc.want != "" && got == nil:
				t.Fatalf("finishGetcwdPath = none, want %q", tc.want)
			case tc.want != "" && got.Name() != tc.want:
				t.Fatalf("finishGetcwdPath = %q, want %q", got.Name(), tc.want)
			}
		})
	}
}
