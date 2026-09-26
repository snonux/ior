package internal

import (
	"bytes"
	"context"
	"encoding/csv"
	"io"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"ior/internal/event"
	"ior/internal/flags"
	"ior/internal/flamegraph"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

// The -comm filter must hold for the path-carrying pair kinds (stat, access,
// mkdir, unlink, ...), the rename-like name kinds (rename, link, ...) and
// open_by_handle_at exactly as it does for open/read/write, in every headless
// output mode. These kinds carry no comm in their BPF payload, so their raw
// enter filters (matchRawPathEvent / matchRawNameEvent, and none at all for
// open_by_handle_at) can only answer the file dimension; the comm dimension is
// applied at the exit checkpoint (finishPairForTid -> MatchPair) once the
// cached comm is attached. A run of `ior -plain -comm X` or
// `ior -flamegraph -comm X` used to emit these rows from any process.
//
// The tests drive raw ring-buffer records through eventLoop.run - the
// production decode/pair/filter/emit loop - and read back what each mode
// really produces: the CSV rows on stdout for -plain, and the .ior.zst
// recording for -flamegraph.

const (
	pairCommFilterPattern = "curl"
	pairCommMatching      = "curl"
	pairCommOther         = "bash"
)

// commFilterPairKind describes one pair kind and the single row it must
// produce when its comm passes the filter.
type commFilterPairKind struct {
	name string
	// records returns the raw ring-buffer stream for one traced syscall of
	// this kind, issued by execCommTid.
	records func(t *testing.T) [][]byte
	// wantSyscall and wantPath identify the one emitted row.
	wantSyscall types.TraceId
	wantPath    string
}

func pathPairRecords(pathname string, enter, exit types.TraceId) func(t *testing.T) [][]byte {
	return func(t *testing.T) [][]byte {
		t.Helper()
		_, enterRaw := makeEnterPathEvent(t, defaulTime, execCommPid, execCommTid, pathname, enter)
		_, exitRaw := makeExitRetEvent(t, defaulTime+100, execCommPid, execCommTid, exit, 0)
		return [][]byte{enterRaw, exitRaw}
	}
}

func namePairRecords(oldname, newname string, enter, exit types.TraceId) func(t *testing.T) [][]byte {
	return func(t *testing.T) [][]byte {
		t.Helper()
		_, enterRaw := makeEnterNameEvent(t, defaulTime, execCommPid, execCommTid, oldname, newname, enter)
		_, exitRaw := makeExitRetEvent(t, defaulTime+100, execCommPid, execCommTid, exit, 0)
		return [][]byte{enterRaw, exitRaw}
	}
}

// openByHandleAtRecords is the name_to_handle_at + open_by_handle_at sequence.
// name_to_handle_at never produces a row of its own (handlePathExit only parks
// its pathname for the correlation), so the whole sequence yields at most the
// open_by_handle_at row.
func openByHandleAtRecords(pathname string, fd int64) func(t *testing.T) [][]byte {
	return func(t *testing.T) [][]byte {
		t.Helper()
		_, enterName := makeEnterPathEvent(t, defaulTime, execCommPid, execCommTid,
			pathname, types.SYS_ENTER_NAME_TO_HANDLE_AT)
		_, exitName := makeExitRetEvent(t, defaulTime+100, execCommPid, execCommTid,
			types.SYS_EXIT_NAME_TO_HANDLE_AT, 0)
		_, enterOpen := makeEnterOpenByHandleAtEvent(t, defaulTime+200, execCommPid, execCommTid,
			syscall.O_RDONLY)
		_, exitOpen := makeExitRetEvent(t, defaulTime+300, execCommPid, execCommTid,
			types.SYS_EXIT_OPEN_BY_HANDLE_AT, fd)
		return [][]byte{enterName, exitName, enterOpen, exitOpen}
	}
}

func commFilterPairKinds() []commFilterPairKind {
	return []commFilterPairKind{
		{
			name:        "path/newstat",
			records:     pathPairRecords("/etc/hosts", types.SYS_ENTER_NEWSTAT, types.SYS_EXIT_NEWSTAT),
			wantSyscall: types.SYS_ENTER_NEWSTAT, wantPath: "/etc/hosts",
		},
		{
			name:        "path/access",
			records:     pathPairRecords("/etc/ld.so.preload", types.SYS_ENTER_ACCESS, types.SYS_EXIT_ACCESS),
			wantSyscall: types.SYS_ENTER_ACCESS, wantPath: "/etc/ld.so.preload",
		},
		{
			name:        "path/mkdir",
			records:     pathPairRecords("/tmp/newdir", types.SYS_ENTER_MKDIR, types.SYS_EXIT_MKDIR),
			wantSyscall: types.SYS_ENTER_MKDIR, wantPath: "/tmp/newdir",
		},
		{
			name:        "path/unlink",
			records:     pathPairRecords("/tmp/gone.txt", types.SYS_ENTER_UNLINK, types.SYS_EXIT_UNLINK),
			wantSyscall: types.SYS_ENTER_UNLINK, wantPath: "/tmp/gone.txt",
		},
		{
			name:        "name/rename",
			records:     namePairRecords("/tmp/old.txt", "/tmp/new.txt", types.SYS_ENTER_RENAME, types.SYS_EXIT_RENAME),
			wantSyscall: types.SYS_ENTER_RENAME, wantPath: "/tmp/new.txt",
		},
		{
			name:        "name/link",
			records:     namePairRecords("/tmp/target.txt", "/tmp/hardlink.txt", types.SYS_ENTER_LINK, types.SYS_EXIT_LINK),
			wantSyscall: types.SYS_ENTER_LINK, wantPath: "/tmp/hardlink.txt",
		},
		{
			name:        "open_by_handle_at",
			records:     openByHandleAtRecords("/tmp/handle.txt", 70),
			wantSyscall: types.SYS_ENTER_OPEN_BY_HANDLE_AT, wantPath: "/tmp/handle.txt",
		},
	}
}

// newPairCommFilterEventLoop builds a -comm filtered loop whose comm cache
// already names execCommTid as comm, the way the cache looks once the async
// resolver (or an earlier open's payload comm) has labelled the task. The
// resolver is hermetic, so no host /proc entry can relabel the tid.
func newPairCommFilterEventLoop(t *testing.T, plainMode bool, comm string) *eventLoop {
	t.Helper()
	el := mustNewEventLoop(t, eventLoopConfig{
		plainMode: plainMode,
		filter: globalfilter.Filter{
			Comm: &globalfilter.StringFilter{Pattern: pairCommFilterPattern},
		},
		commResolver: newHermeticCommResolver(),
	})
	// run shuts the resolver down itself; this covers a test failing before
	// run is reached. shutdown is idempotent.
	t.Cleanup(el.commResolver.shutdown)
	el.setCachedComm(execCommTid, comm)
	return el
}

// runRawRecords feeds records through the production event loop and returns
// once every one of them has been decoded, paired, filtered and emitted.
func runRawRecords(el *eventLoop, records [][]byte) {
	rawCh := make(chan []byte, len(records))
	for _, raw := range records {
		rawCh <- raw
	}
	close(rawCh)
	el.run(context.Background(), rawCh)
}

// plainRow is one parsed -plain CSV data row.
type plainRow struct {
	comm, syscall, file string
}

// runPlainMode runs records through a -plain event loop with its default
// output callback (CSV on stdout) and returns the parsed data rows. The header
// is checked and stripped.
func runPlainMode(t *testing.T, comm string, records [][]byte) []plainRow {
	t.Helper()
	el := newPairCommFilterEventLoop(t, true, comm)

	stdout, stderr, restore := captureStdoutStderr(t)
	var out bytes.Buffer
	copied := make(chan error, 1)
	go func() {
		_, err := io.Copy(&out, stdout)
		copied <- err
	}()
	// Status lines go to stderr; drain it so a full pipe can never block run.
	go func() { _, _ = io.Copy(io.Discard, stderr) }()
	runRawRecords(el, records)
	restore()
	if err := <-copied; err != nil {
		t.Fatalf("reading captured stdout: %v", err)
	}

	lines, err := csv.NewReader(strings.NewReader(out.String())).ReadAll()
	if err != nil {
		t.Fatalf("plain output is not valid CSV: %v\n%s", err, out.String())
	}
	if len(lines) == 0 || strings.Join(lines[0], ",") != event.EventStreamHeader {
		t.Fatalf("plain output does not start with the stream header:\n%s", out.String())
	}
	rows := make([]plainRow, 0, len(lines)-1)
	for _, fields := range lines[1:] {
		if len(fields) != 7 {
			t.Fatalf("plain row has %d columns, want 7: %q", len(fields), fields)
		}
		rows = append(rows, plainRow{comm: fields[2], syscall: fields[4], file: fields[6]})
	}
	return rows
}

// runFlamegraphMode runs records through a loop wired exactly as -flamegraph
// wires it (maybePrependFlamegraphConfigure), writes the recording and loads it
// back. The working directory is a temp dir because the recorder names its
// output file itself.
func runFlamegraphMode(t *testing.T, comm string, records [][]byte) []flamegraph.IterRecord {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)

	el := newPairCommFilterEventLoop(t, false, comm)
	configure, recorder := maybePrependFlamegraphConfigure(flags.Config{
		FlamegraphOutput: true,
		OutputName:       "commfilter",
	}, nil)
	if recorder == nil {
		t.Fatal("flamegraph mode did not create a recorder")
	}
	configure(el)
	runRawRecords(el, records)

	if err := recorder.Write(); err != nil {
		t.Fatalf("recorder.Write: %v", err)
	}
	matches, err := filepath.Glob(filepath.Join(dir, "*.ior.zst"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("expected exactly one .ior.zst recording in %s, got %v (err %v)", dir, matches, err)
	}
	seq, err := flamegraph.LoadFromFile(matches[0])
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	var got []flamegraph.IterRecord
	for record := range seq {
		got = append(got, record)
	}
	return got
}

func TestPlainModeCommFilterAppliesToPathNameAndHandlePairs(t *testing.T) {
	for _, kind := range commFilterPairKinds() {
		t.Run(kind.name+"/non-matching comm is dropped", func(t *testing.T) {
			rows := runPlainMode(t, pairCommOther, kind.records(t))
			if len(rows) != 0 {
				t.Fatalf("-plain -comm %s emitted %d row(s) of a %q process: %+v",
					pairCommFilterPattern, len(rows), pairCommOther, rows)
			}
		})
		t.Run(kind.name+"/matching comm is kept", func(t *testing.T) {
			rows := runPlainMode(t, pairCommMatching, kind.records(t))
			if len(rows) != 1 {
				t.Fatalf("-plain -comm %s emitted %d rows, want 1: %+v",
					pairCommFilterPattern, len(rows), rows)
			}
			row := rows[0]
			if row.comm != pairCommMatching {
				t.Errorf("row comm = %q, want %q", row.comm, pairCommMatching)
			}
			if row.syscall != kind.wantSyscall.Name() {
				t.Errorf("row syscall = %q, want %q", row.syscall, kind.wantSyscall.Name())
			}
			if !strings.Contains(row.file, kind.wantPath) {
				t.Errorf("row file = %q, want it to name %q", row.file, kind.wantPath)
			}
		})
	}
}

func TestFlamegraphModeCommFilterAppliesToPathNameAndHandlePairs(t *testing.T) {
	for _, kind := range commFilterPairKinds() {
		t.Run(kind.name+"/non-matching comm is dropped", func(t *testing.T) {
			records := runFlamegraphMode(t, pairCommOther, kind.records(t))
			if len(records) != 0 {
				t.Fatalf("-flamegraph -comm %s recorded %d record(s) of a %q process: %+v",
					pairCommFilterPattern, len(records), pairCommOther, records)
			}
		})
		t.Run(kind.name+"/matching comm is kept", func(t *testing.T) {
			records := runFlamegraphMode(t, pairCommMatching, kind.records(t))
			if len(records) != 1 {
				t.Fatalf("-flamegraph -comm %s recorded %d records, want 1: %+v",
					pairCommFilterPattern, len(records), records)
			}
			record := records[0]
			if record.Comm != pairCommMatching {
				t.Errorf("record comm = %q, want %q", record.Comm, pairCommMatching)
			}
			if record.TraceID != kind.wantSyscall {
				t.Errorf("record syscall = %s, want %s", record.TraceID.Name(), kind.wantSyscall.Name())
			}
			if record.Path != kind.wantPath {
				t.Errorf("record path = %q, want %q", record.Path, kind.wantPath)
			}
			if record.Cnt.Count != 1 {
				t.Errorf("record count = %d, want 1", record.Cnt.Count)
			}
		})
	}
}
