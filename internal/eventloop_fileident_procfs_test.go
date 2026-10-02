package internal

import (
	"os"
	"syscall"
	"testing"

	"ior/internal/file"
	"ior/internal/globalfilter"
)

// Task 603, the procfs side of the identity check: how often procfs is asked
// again, and what happens to an answer that changed while it was read. Real
// procfs cannot be made to give such answers on demand, so these tests script
// the tracker's reader (fdTracker.readFdIdent).

// procAnswer is one scripted procfs answer: the name, the file it describes
// and whether it was one consistent reading.
type procAnswer struct {
	name   string
	ident  uint32
	stable bool
}

// scriptedProc answers the tracker's procfs reads from a script; the last
// answer repeats. reads counts the readings.
type scriptedProc struct {
	answers []procAnswer
	reads   int
}

func (s *scriptedProc) read(fd int32, _ uint32) (*file.FdFile, bool) {
	answer := s.answers[min(s.reads, len(s.answers)-1)]
	s.reads++
	f := file.NewFd(fd, answer.name, syscall.O_RDWR)
	f.SetIdent(answer.ident)
	f.MarkNameFromProcFS()
	return f, answer.stable
}

// scriptedIdentLoop returns a loop that captures identities and reads procfs
// from the script.
func scriptedIdentLoop(t *testing.T, answers ...procAnswer) (*eventLoop, *scriptedProc) {
	t.Helper()
	el := identLoop(t)
	proc := &scriptedProc{answers: answers}
	el.fdState().readFdIdent = proc.read
	return el, proc
}

const leaderName = "/data/leaders-file.txt"

// A thread on a private descriptor table (unshare(CLONE_FILES)) uses another
// file on the number than /proc/<tgid>/fd shows, for as long as it lives.
// Its rows are refused the answer one by one, but procfs is read again for
// them only once per identRereadIntervalNs; rows of the file procfs does
// show are served from the cache throughout, and a row of a third file is a
// new question and is read for at once.
func TestProcfsIsNotReadAgainForEveryRowItDisagreesWith(t *testing.T) {
	pid := uint32(os.Getpid())
	n := freeFdNumber(t)
	el, proc := scriptedIdentLoop(t, procAnswer{name: leaderName, ident: 100, stable: true})
	requireUnnamedOf(t, feedIdentRow(t, el, readRow(n, 200)).File, 200)
	readNs, stamped := el.fdState().cachedProcFdReadAt(n, pid)
	if !stamped || proc.reads != 1 {
		t.Fatalf("after the first row: reads = %d, stamped = %v, want one stamped read", proc.reads, stamped)
	}

	steps := []struct {
		what        string
		ident       uint32
		afterReadNs uint64
		wantReads   int
		wantName    string
	}{
		{what: "same file, soon after", ident: 200, afterReadNs: 1000, wantReads: 1},
		{what: "the file procfs shows", ident: 100, afterReadNs: 2000, wantReads: 1, wantName: leaderName},
		{what: "same file, just inside the interval", ident: 200, afterReadNs: identRereadIntervalNs - 1, wantReads: 1},
		{what: "same file, interval over", ident: 200, afterReadNs: identRereadIntervalNs, wantReads: 2},
	}
	for _, step := range steps {
		ep := feedIdentRow(t, el, rowAt(n, step.ident, readNs+step.afterReadNs))
		if ep.File.Name() != step.wantName || proc.reads != step.wantReads {
			t.Fatalf("%s: row named %q after %d reads, want %q after %d", step.what, ep.File.Name(), proc.reads, step.wantName, step.wantReads)
		}
	}
	if got := el.fdState().rejectedAnswers; got != 4 {
		t.Fatalf("rejectedAnswers = %d, want 4: every refused row counts, read or not", got)
	}

	readNs, _ = el.fdState().cachedProcFdReadAt(n, pid)
	feedIdentRow(t, el, rowAt(n, 300, readNs+1000))
	if proc.reads != 3 {
		t.Fatalf("row of a third file: reads = %d, want 3 (not rationed by another file's refusal)", proc.reads)
	}
	el.fdState().deleteProcFdCache(n, pid)
	if left := len(el.fdState().refusedFor); left != 0 {
		t.Fatalf("%d refusal notes outlived their cache entry", left)
	}
}

// An answer that changed under the read describes no one file. It is read
// once more; a second reading that holds is used and cached like any other,
// and if that is torn too the answer is not cached - as "unknown identity" it
// would contradict nothing and name every later row of the number. A row
// with an identity is not named after it; a row without one has nothing to
// check it against and takes the name, as it always did.
func TestAnswerThatChangedUnderTheReadIsNotCached(t *testing.T) {
	torn := procAnswer{name: "/data/torn.txt"}
	tests := []struct {
		name       string
		answers    []procAnswer
		rowIdent   uint32
		wantName   string
		wantCached bool
	}{
		{name: "second reading holds", answers: []procAnswer{torn, {name: leaderName, ident: 200, stable: true}},
			rowIdent: 200, wantName: leaderName, wantCached: true},
		{name: "torn twice, row with identity", answers: []procAnswer{torn}, rowIdent: 200},
		{name: "torn twice, row without identity", answers: []procAnswer{torn}, wantName: torn.name},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pid := uint32(os.Getpid())
			n := freeFdNumber(t)
			el, proc := scriptedIdentLoop(t, tc.answers...)

			ep := feedIdentRow(t, el, readRow(n, tc.rowIdent))
			if ep.File.Name() != tc.wantName || identOf(ep.File) != tc.rowIdent {
				t.Fatalf("row file = %v (identity %d), want name %q and identity %d", ep.File, identOf(ep.File), tc.wantName, tc.rowIdent)
			}
			if _, cached := el.fdState().cachedProcFdFile(n, pid); cached != tc.wantCached || proc.reads != 2 {
				t.Fatalf("cached = %v after %d reads, want %v after 2", cached, proc.reads, tc.wantCached)
			}
			requireNothingCounted(t, el)
		})
	}
}

// Without the capture nothing is compared, so procfs is read as before the
// identity existed: one readlink and the flags, no check of the answer, and
// the answer is cached.
func TestProcfsAnswerIsNotCheckedWithoutTheCapture(t *testing.T) {
	pid := uint32(os.Getpid())
	n := freeFdNumber(t)
	el := newFilteredEventLoop(t, globalfilter.Filter{})
	proc := &scriptedProc{answers: []procAnswer{{name: "/data/torn.txt"}}}
	el.fdState().readFdIdent = proc.read
	name, _ := placeFileOn(t, n, "plain.txt")

	if got := feedIdentRow(t, el, readRow(n, 4711)).File.Name(); got != name {
		t.Fatalf("row named %q, want %q from procfs", got, name)
	}
	cached, ok := el.fdState().cachedProcFdFile(n, pid)
	if !ok || cached.Ident() != 0 || proc.reads != 0 {
		t.Fatalf("cache = %v (ok=%v, identity %d) after %d identity reads, want a cached answer without identity and no such read",
			cached, ok, cached.Ident(), proc.reads)
	}
}
