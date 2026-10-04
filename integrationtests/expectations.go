package integrationtests

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"testing"

	"ior/internal/file"
	"ior/internal/flamegraph"
	iorparquet "ior/internal/parquet"

	parquetgo "github.com/parquet-go/parquet-go"
)

// ExpectedEvent describes an I/O event that should appear in the test output.
type ExpectedEvent struct {
	PathContains string // substring match on file path
	Tracepoint   string // tracepoint name substring, e.g. "openat"
	Comm         string // expected comm name, e.g. "ioworkload"
	MinCount     uint64 // minimum total occurrences across all matching records
	// Flags is optional. When set, every nonzero bit in Set must be present,
	// every bit in Clear must be absent, and AccessMode (when non-nil) must
	// match the O_ACCMODE portion of the recorded word.
	Flags *ExpectedFlags
}

// ExpectedFlags describes bit-level assertions for a collapsed-output flags
// word. Bit constraints avoid coupling integration tests to unrelated flags
// that the kernel may add while still making O_RDONLY (the zero access mode)
// assertable.
type ExpectedFlags struct {
	AccessMode *int
	Set        int
	Clear      int
}

// ExpectedRow describes one Parquet stream row and the semantic fields that
// must match it. Nil field pointers are ignored so zero values remain
// assertable without making every caller spell every persisted column.
type ExpectedRow struct {
	FileContains string
	Syscall      string
	Comm         string
	MinCount     int

	FD                   *int32
	FDAtLeast            *int32
	RetVal               *int64
	RetValAtLeast        *int64
	IsError              *bool
	Bytes                *uint64
	EpollOp              *string
	EpollTargetFD        *int32
	EpollTargetFDAtLeast *int32
	EpollEvents          *uint32
	AddressSpaceBytes    *uint64
	RequestedSleepNs     *int64
	Nfds                 *int32
	TimeoutNs            *int64
}

// AssertEventsPresent verifies that each expected event is found in the test result.
// Counts are summed across all matching records before comparing to MinCount.
//
// When the records are those of a remembered run (runSources) that lacks
// events its kernel-side loss can explain, the scenario is run again first
// and the assertion made on the run that can be judged (rowpresence.go).
func AssertEventsPresent(t *testing.T, result TestResult, expected []ExpectedEvent) {
	t.Helper()
	result.Records = judgedEventRun(t, result.Records, expected).rows
	for _, exp := range expected {
		matched, totalCount := eventTotals(result.Records, exp)
		if !matched {
			t.Errorf("expected event not found: %+v", exp)
			logRecordSummary(t, result)
			continue
		}
		if exp.MinCount > 0 && totalCount < exp.MinCount {
			t.Errorf("event matching %+v has total count %d, want >= %d",
				exp, totalCount, exp.MinCount)
		}
	}
}

// eventTotals reports whether any record matches exp, and the sum of the
// counts of those that do.
func eventTotals(records []flamegraph.IterRecord, exp ExpectedEvent) (matched bool, total uint64) {
	for _, rec := range records {
		if matchesExpectation(rec, exp) {
			matched = true
			total += rec.Cnt.Count
		}
	}
	return matched, total
}

// judgedEventRun returns the run AssertEventsPresent is to judge for
// records and expected (runSources.judged).
func judgedEventRun(t rowVerdict, records []flamegraph.IterRecord, expected []ExpectedEvent) judgedRun[flamegraph.IterRecord] {
	t.Helper()
	return eventRunSources.judged(t, records, func(records []flamegraph.IterRecord) shortfall {
		return eventShortfall(records, expected)
	})
}

// eventShortfall returns what records lack of expected. The call an
// expectation names is its tracepoint (and comm); the path and the flags are
// what ior says about the call, so events of that tracepoint in the wanted
// number that do not match are wrong, not missing.
func eventShortfall(records []flamegraph.IterRecord, expected []ExpectedEvent) shortfall {
	var short shortfall
	for _, exp := range expected {
		matched, total := eventTotals(records, exp)
		if matched && total >= exp.MinCount {
			continue
		}
		_, recorded := eventTotals(records, ExpectedEvent{Tracepoint: exp.Tracepoint, Comm: exp.Comm})
		short.note(max(exp.MinCount, 1), recorded)
	}
	return short
}

// AssertRowsPresent verifies that every requested semantic row appears at
// least MinCount times. A zero MinCount means one row.
//
// When the rows are those of a remembered run (runSources) that lacks rows
// its kernel-side loss can explain, the scenario is run again first and the
// assertion made on the run that can be judged (rowpresence.go).
func AssertRowsPresent(t *testing.T, rows []iorparquet.Record, expected []ExpectedRow) {
	t.Helper()
	rows = parquetRunSources.judged(t, rows, func(rows []iorparquet.Record) shortfall {
		return rowShortfall(rows, expected)
	}).rows
	for _, exp := range expected {
		if matched, want := matchingRows(rows, exp), wantedRows(exp); matched < want {
			t.Errorf("rows matching %+v = %d, want >= %d", exp, matched, want)
			logRowSummary(t, rows)
		}
	}
}

// wantedRows is the number of rows exp asks for: MinCount, or one.
func wantedRows(exp ExpectedRow) int {
	return max(exp.MinCount, 1)
}

// matchingRows counts the rows that match exp.
func matchingRows(rows []iorparquet.Record, exp ExpectedRow) int {
	var matched int
	for _, row := range rows {
		if matchesRowExpectation(row, exp) {
			matched++
		}
	}
	return matched
}

// rowShortfall returns what rows lack of expected. The call an expectation
// names is its syscall (and comm), together with the descriptor when the
// expectation states one exactly; every other field is what ior says about
// the call, so rows of that call in the wanted number that do not match are
// wrong, not missing.
func rowShortfall(rows []iorparquet.Record, expected []ExpectedRow) shortfall {
	var short shortfall
	for _, exp := range expected {
		want := wantedRows(exp)
		if matchingRows(rows, exp) >= want {
			continue
		}
		call := ExpectedRow{Syscall: exp.Syscall, Comm: exp.Comm, FD: exp.FD}
		short.note(uint64(want), uint64(matchingRows(rows, call)))
	}
	return short
}

// LoadParquetRows reads all persisted stream rows from path.
func LoadParquetRows(path string) (rows []iorparquet.Record, retErr error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open parquet %q: %w", path, err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close parquet %q: %w", path, err))
		}
	}()

	reader := parquetgo.NewGenericReader[iorparquet.Record](f)
	defer func() {
		if err := reader.Close(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close parquet reader: %w", err))
		}
	}()

	buf := make([]iorparquet.Record, 32)
	for {
		n, err := reader.Read(buf)
		rows = append(rows, buf[:n]...)
		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) {
			return rows, nil
		}
		return nil, fmt.Errorf("read parquet rows: %w", err)
	}
}

func logRecordSummary(t *testing.T, result TestResult) {
	t.Helper()
	limit := 20
	if len(result.Records) < limit {
		limit = len(result.Records)
	}
	t.Logf("captured %d records; first %d:", len(result.Records), limit)
	for i := 0; i < limit; i++ {
		rec := result.Records[i]
		t.Logf("  tracepoint=%s comm=%q pid=%d path=%q count=%d", rec.TraceID.String(), rec.Comm, rec.Pid, rec.Path, rec.Cnt.Count)
	}
}

// AssertNoUnexpectedComm verifies all records have the expected comm name.
// Records with empty comm are skipped because BPF may capture events before
// the process name is set in the task struct.
func AssertNoUnexpectedComm(t *testing.T, result TestResult, expectedComm string) {
	t.Helper()
	var count int
	for _, rec := range result.Records {
		if rec.Comm == "" {
			continue
		}
		if rec.Comm != expectedComm {
			count++
			if count <= 5 {
				t.Logf("unexpected comm %q (pid=%d tracepoint=%s path=%q)",
					rec.Comm, rec.Pid, rec.TraceID.String(), rec.Path)
			}
		}
	}
	if count > 0 {
		t.Fatalf("found %d records with unexpected comm (want %q)", count, expectedComm)
	}
}

// AssertNoUnexpectedPID verifies all records belong to the expected PID.
// Accepts int to match os.Getpid() return type.
func AssertNoUnexpectedPID(t *testing.T, result TestResult, expectedPID int) {
	t.Helper()
	pid := uint32(expectedPID)
	var count int
	for _, rec := range result.Records {
		if rec.Pid != pid {
			count++
			if count <= 5 {
				t.Logf("unexpected PID %d (tracepoint=%s path=%q comm=%q)",
					rec.Pid, rec.TraceID.String(), rec.Path, rec.Comm)
			}
		}
	}
	if count > 0 {
		t.Fatalf("found %d records with unexpected PID (want %d)", count, expectedPID)
	}
}

// AssertEventsAbsent verifies that none of the specified events appear in the test result.
// Each ExpectedEvent must have at least one filter field set to avoid accidentally
// matching all records.
func AssertEventsAbsent(t *testing.T, result TestResult, absent []ExpectedEvent) {
	t.Helper()
	for _, exp := range absent {
		if exp.PathContains == "" && exp.Tracepoint == "" && exp.Comm == "" {
			t.Errorf("AssertEventsAbsent: ExpectedEvent must have at least one filter field set: %+v", exp)
			continue
		}
		for _, rec := range result.Records {
			if matchesExpectation(rec, exp) {
				t.Errorf("event should be absent but was found: %+v (path=%q tracepoint=%s comm=%q)",
					exp, rec.Path, rec.TraceID.String(), rec.Comm)
				break
			}
		}
	}
}

func matchesExpectation(rec flamegraph.IterRecord, exp ExpectedEvent) bool {
	if exp.PathContains != "" && !strings.Contains(rec.Path, exp.PathContains) {
		return false
	}
	if exp.Tracepoint != "" && !strings.Contains(rec.TraceID.String(), exp.Tracepoint) {
		return false
	}
	if exp.Comm != "" && rec.Comm != "" && rec.Comm != exp.Comm {
		return false
	}
	return matchesExpectedFlags(rec.Flags, exp.Flags)
}

func matchesExpectedFlags(got file.Flags, expected *ExpectedFlags) bool {
	if expected == nil {
		return true
	}
	if got == file.Flags(-1) {
		return false
	}
	if expected.AccessMode != nil && int(got)&syscall.O_ACCMODE != *expected.AccessMode {
		return false
	}
	if int(got)&expected.Set != expected.Set {
		return false
	}
	return int(got)&expected.Clear == 0
}

func matchesRowExpectation(row iorparquet.Record, exp ExpectedRow) bool {
	if exp.FileContains != "" && !strings.Contains(row.File, exp.FileContains) {
		return false
	}
	if exp.Syscall != "" && row.Syscall != exp.Syscall {
		return false
	}
	// An empty row comm is an unresolved name, not a foreign one: ior resolves
	// comm asynchronously through procfs, so the first rows of a short scenario
	// whose trace set has no open or exec can be emitted before the lookup
	// lands. Tolerate it exactly as matchesExpectation does; a different
	// non-empty comm still rejects the row.
	if exp.Comm != "" && row.Comm != "" && row.Comm != exp.Comm {
		return false
	}
	return matchesOptional(row.FD, exp.FD) &&
		meetsMinimum(row.FD, exp.FDAtLeast) &&
		matchesOptional(row.Ret, exp.RetVal) &&
		meetsMinimum(row.Ret, exp.RetValAtLeast) &&
		matchesOptional(row.IsError, exp.IsError) &&
		matchesOptional(row.Bytes, exp.Bytes) &&
		matchesOptional(row.EpollOp, exp.EpollOp) &&
		matchesOptional(row.EpollTargetFD, exp.EpollTargetFD) &&
		meetsMinimum(row.EpollTargetFD, exp.EpollTargetFDAtLeast) &&
		matchesOptional(row.EpollEvents, exp.EpollEvents) &&
		matchesOptional(row.AddressSpaceBytes, exp.AddressSpaceBytes) &&
		matchesOptional(row.RequestedSleepNS, exp.RequestedSleepNs) &&
		matchesOptional(row.Nfds, exp.Nfds) &&
		matchesOptional(row.TimeoutNS, exp.TimeoutNs)
}

func matchesOptional[T comparable](got T, expected *T) bool {
	return expected == nil || got == *expected
}

func meetsMinimum[T ~int32 | ~int64](got T, expected *T) bool {
	return expected == nil || got >= *expected
}

func logRowSummary(t *testing.T, rows []iorparquet.Record) {
	t.Helper()
	limit := min(len(rows), 20)
	t.Logf("captured %d parquet rows; first %d:", len(rows), limit)
	for i := range limit {
		row := rows[i]
		t.Logf("  syscall=%s comm=%q pid=%d fd=%d ret=%d error=%t file=%q",
			row.Syscall, row.Comm, row.PID, row.FD, row.Ret, row.IsError, row.File)
	}
}
