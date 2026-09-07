package internal

import (
	"syscall"
	"testing"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/globalfilter"
	"ior/internal/streamrow"
	"ior/internal/types"
)

// TestAllFilterStagesAgreeOnRenameRows is the fitness test for the
// centralized either-name rule. A rename row carries two legitimate values of
// the file dimension (oldname and newname), and the widening used to be
// re-chosen independently at every filter stage - pair checkpoint, dashboard
// ingest, Stream tab, CSV export - so one stage could silently disagree with
// the others: a `-path <oldname>` rename row counted in the aggregates while
// missing from the very row list those aggregates described. Since the rule
// moved into Matches' file dimension (Candidate.OldFileValue) the stages all
// call the same predicate, and this test locks that in end to end: for a
// table of filters, the event-loop checkpoint (driven through the real raw
// event path), the TUI ingest stage, and the Stream tab / export path must
// all return the same verdict.
func TestAllFilterStagesAgreeOnRenameRows(t *testing.T) {
	const (
		oldname = "/tmp/fitness-old.txt"
		newname = "/tmp/fitness-new.txt"
		other   = "/tmp/fitness-other.txt"
	)

	// Stage fixture: the same shape feedRenamePair pushes through the raw
	// event path, so every stage judges identical dimension values (pid, tid,
	// latency, comm, ret). Duration matches the enter/exit time delta the
	// event loop would compute; DurationToPrev stays zero, as it is for the
	// tid's first pair on the raw path, so a -gap case would need fixture
	// and feed side to both gain a preceding pair before it could be added
	// to the table below.
	fixturePair := func() *event.Pair {
		return &event.Pair{
			EnterEv:  &types.NameEvent{TraceId: types.SYS_ENTER_RENAME, Pid: execCommPid, Tid: execCommTid},
			ExitEv:   &types.RetEvent{TraceId: types.SYS_EXIT_RENAME, Pid: execCommPid, Tid: execCommTid, Ret: 0},
			Comm:     "ioworkload",
			File:     file.NewOldnameNewname([]byte(oldname), []byte(newname)),
			Oldname:  oldname,
			Duration: openPairLatency,
		}
	}

	cases := []struct {
		name        string
		filter      globalfilter.Filter
		wantEmitted bool
	}{
		{
			name:        "oldname path",
			filter:      globalfilter.Filter{File: &globalfilter.StringFilter{Pattern: oldname}},
			wantEmitted: true,
		},
		{
			name:        "newname path",
			filter:      globalfilter.Filter{File: &globalfilter.StringFilter{Pattern: newname}},
			wantEmitted: true,
		},
		{
			name:        "path matching neither name",
			filter:      globalfilter.Filter{File: &globalfilter.StringFilter{Pattern: other}},
			wantEmitted: false,
		},
		{
			name: "oldname path with satisfied latency",
			filter: globalfilter.Filter{
				File:      &globalfilter.StringFilter{Pattern: oldname},
				LatencyNs: &globalfilter.NumericFilter{Op: globalfilter.OpGte, Value: openPairLatency},
			},
			wantEmitted: true,
		},
		{
			name: "oldname path with unsatisfied latency",
			filter: globalfilter.Filter{
				File:      &globalfilter.StringFilter{Pattern: oldname},
				LatencyNs: &globalfilter.NumericFilter{Op: globalfilter.OpGt, Value: 2 * openPairLatency},
			},
			wantEmitted: false,
		},
		{
			name:        "syscall mismatch",
			filter:      globalfilter.Filter{Syscall: &globalfilter.StringFilter{Pattern: "unlinkat"}},
			wantEmitted: false,
		},
		{
			name:        "pid mismatch",
			filter:      globalfilter.Filter{PID: &globalfilter.NumericFilter{Op: globalfilter.OpNeq, Value: execCommPid}},
			wantEmitted: false,
		},
		{
			name:        "errors-only against a successful rename",
			filter:      globalfilter.Filter{ErrorsOnly: true},
			wantEmitted: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Stage 1: the event-loop pair checkpoint, through the real raw
			// event path (enter filter, exit handler, MatchPair).
			el := newFilteredEventLoop(t, tc.filter)
			ep := feedRenamePair(t, el, oldname, newname, 0)
			checkpointKept := ep != nil
			if checkpointKept {
				ep.Recycle()
			}

			// Stage 2: the TUI dashboard ingest stage.
			pair := fixturePair()
			ingested := shouldIngestTracePair(tc.filter, pair)

			// Stage 3: the Stream tab and its CSV export, which filter rows.
			row := streamrow.New(1, pair)
			rowKept := tc.filter.Matches(&row)

			if checkpointKept != tc.wantEmitted {
				t.Errorf("event-loop checkpoint verdict = %v, want %v", checkpointKept, tc.wantEmitted)
			}
			if ingested != tc.wantEmitted {
				t.Errorf("dashboard ingest verdict = %v, want %v", ingested, tc.wantEmitted)
			}
			if rowKept != tc.wantEmitted {
				t.Errorf("stream/export verdict = %v, want %v", rowKept, tc.wantEmitted)
			}
		})
	}
}

// TestRenameRowCarriesItsOldName pins the Candidate plumbing that makes the
// fitness test possible: streamrow.New must copy Pair.Oldname into the row's
// OldFileValue, or the Stream stage would silently lose the alternate name
// even though Matches knows how to read it.
func TestRenameRowCarriesItsOldName(t *testing.T) {
	pair := &event.Pair{
		EnterEv: &types.NameEvent{TraceId: types.SYS_ENTER_RENAMEAT2, Pid: 1, Tid: 1},
		ExitEv:  &types.RetEvent{TraceId: types.SYS_EXIT_RENAMEAT2, Pid: 1, Tid: 1, Ret: 0},
		File:    file.NewOldnameNewname([]byte("/tmp/old.txt"), []byte("/tmp/new.txt")),
		Oldname: "/tmp/old.txt",
	}

	row := streamrow.New(1, pair)
	if got := row.OldFileValue(); got != "/tmp/old.txt" {
		t.Fatalf("row OldFileValue = %q, want the rename source path", got)
	}

	nonRename := &event.Pair{
		EnterEv: &types.FdEvent{TraceId: types.SYS_ENTER_READ, Pid: 1, Tid: 1},
		ExitEv:  &types.RetEvent{TraceId: types.SYS_EXIT_READ, Pid: 1, Tid: 1, Ret: 128},
		File:    file.NewFd(3, "/tmp/read.txt", syscall.O_RDONLY),
	}
	if got := streamrow.New(2, nonRename).OldFileValue(); got != "" {
		t.Fatalf("non-rename row OldFileValue = %q, want empty", got)
	}
}
