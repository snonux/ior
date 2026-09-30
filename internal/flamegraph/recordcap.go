package flamegraph

import (
	"fmt"
	"io"
	"strings"
)

// Bounding the recorder (task uq2).
//
// iorData keeps one Counter per distinct (path, tracepoint, comm, pid, tid,
// flags) key, about 250 bytes of heap each. pid and tid are part of the key on
// purpose (`ior collapsed -fields` picks the frames after the fact, so every
// field must survive into the file), which makes a fork-heavy or thread-churning
// system-wide trace create keys without bound: roughly 6000 keys/s is ~1.3 GB
// over the default 900s -duration. The TUI's LiveTrie has always been capped;
// the recorder was the unbounded one.
//
// The recorder therefore holds a bounded number of records, degrading in two
// stages so the part of the key that churns (pid, tid) goes first and the part
// the default collapsed fields show (comm, tracepoint, path) goes last:
//
//  1. Up to DefaultMaxRecordKeys (the cap) records are stored exactly.
//  2. Stage 1, "pid fold": once the cap is reached, an event whose key is new
//     is folded into the record of the same path, comm, tracepoint and flags
//     with pid 0 and tid 0. Stage-1 records are extra keys of their own, so
//     they may use a headroom of cap/8 beyond the cap (stageOneHeadroom); a
//     stage-1 record that already exists keeps absorbing without limit.
//     Under pid/tid churn this alone keeps full path/comm attribution.
//  3. Stage 2, "[other] fold": only when that stage-1 record would itself be
//     new and the headroom is used up (the path/comm population churns too),
//     the event is folded into a per-(tracepoint, flags) record whose path and
//     comm are "[other]" and whose pid/tid are 0.
//
// Keys that already exist always keep aggregating exactly, so:
//   - totals are exact: every event's count, durations and bytes land in some
//     record, nothing is dropped (the LiveTrie "[other;]" bucket works the same);
//   - the first keys seen win, which favours the long-lived processes and files
//     of a trace over the churn;
//   - the memory is bounded: at most cap + cap/8 (hardLimit) records plus the
//     "[other]" records, one per (tracepoint, flags) combination seen, a few
//     hundred at most.
//
// The fold is reported loudly (the notices of Recorder.announceFolds and the
// summary of Recorder.reportFolds name the stage and the number of events
// folded by it), not buried in the file.
const (
	// DefaultMaxRecordKeys is the recorder's cap on distinct exact keys: 2^19,
	// about 130 MB at ~250 B each, in line with the LiveTrie node cap scale
	// and far above what an ordinary trace produces. The stage-1 headroom and
	// the "[other]" records come on top (see hardLimit).
	DefaultMaxRecordKeys = 1 << 19

	// recordOverflowLabel is the path and comm of the stage-2 keys. Unlike
	// LiveTrie's "[other;]" it cannot be made collision-free (frames of a
	// recording are free-form traced text); a real comm or path spelled
	// "[other]" with pid 0 and tid 0 merely shares a record with the fold.
	// Likewise a real event with pid 0 and tid 0 shares its record with the
	// stage-1 fold of the same path and comm.
	recordOverflowLabel = "[other]"
)

// foldCounts says how many events each fold stage absorbed.
type foldCounts struct {
	// pidless is the events folded into pid 0/tid 0 records (stage 1).
	pidless uint64
	// other is the events folded into "[other]" records (stage 2).
	other uint64
}

// total is the number of folded events of both stages.
func (f foldCounts) total() uint64 { return f.pidless + f.other }

// stageOneHeadroom is how many stage-1 records may exist beyond the cap: the
// distinct (path, comm, flags, tracepoint) combinations that the cap-filling
// pid/tid churn lands on. It is cap/8, and at least 1 so tiny test caps work.
func stageOneHeadroom(maxKeys int) int {
	return max(maxKeys/8, 1)
}

// pidlessTarget returns the stage-1 key of key: the same path, tracepoint,
// comm and flags with the pid and tid erased. It equals key for an event that
// has no pid and tid anyway.
func pidlessTarget(key recordKey) recordKey {
	key.Pid, key.Tid = 0, 0
	return key
}

// foldTarget returns the stage-2 key that absorbs key: same tracepoint and
// flags, placeholder path and comm, no pid/tid.
func foldTarget(key recordKey) recordKey {
	return recordKey{
		Path:    recordOverflowLabel,
		TraceID: key.TraceID,
		Comm:    recordOverflowLabel,
		Flags:   key.Flags,
	}
}

// full reports whether a NEW key must be folded instead of stored. A zero
// maxKeys means unbounded (recordings loaded from disk, WriteRecordingFile and
// tests building fixtures).
func (iod *iorData) full() bool {
	return iod.maxKeys > 0 && len(iod.records) >= iod.maxKeys
}

// hardLimit is the record count at which even new stage-1 records are refused
// and events go to "[other]": the cap plus the stage-1 headroom.
func (iod *iorData) hardLimit() int {
	return iod.maxKeys + stageOneHeadroom(iod.maxKeys)
}

// fold redirects a new key, found while full, to the record that absorbs it
// and counts the events it carried. Stage 1 is preferred: the pid-less key of
// the same path and comm is used when it exists already (free) or may still be
// created within the headroom. Otherwise the event goes to its "[other]" key,
// which is admitted even past the hard limit: there are only
// (tracepoints x flags) of them.
func (iod *iorData) fold(key recordKey, cnt Counter) recordKey {
	target := pidlessTarget(key)
	if _, exists := iod.records[target]; exists || len(iod.records) < iod.hardLimit() {
		if target != key { // a new pid-0/tid-0 key is merely stored, not folded
			iod.folds.pidless += cnt.Count
		}
		return target
	}
	iod.folds.other += cnt.Count
	return foldTarget(key)
}

// recorderPidFoldNotice is the one-time stderr line printed when the cap is
// first hit (stage 1), while the trace is still running (a run can last 900s
// and the recording is only written at the end, so the warning cannot wait for
// Write).
func recorderPidFoldNotice(limit int) string {
	return fmt.Sprintf("ior: flamegraph recorder reached its limit of %d distinct "+
		"(path, comm, pid, tid, flags) records; events of further new pid/tid combinations are "+
		"folded into pid 0/tid 0 records of the same path and comm (counts and totals stay exact, "+
		"only their pid/tid detail is lost)", limit)
}

// recorderOtherFoldNotice is the one-time stderr line printed when stage 2
// starts: the path/comm population churns too, so the attribution of the
// folded events is lost, not just their pid/tid.
func recorderOtherFoldNotice(limit int) string {
	return fmt.Sprintf("ior: flamegraph recorder also ran out of room for pid 0/tid 0 "+
		"records (limit %d+%d); events of further new path/comm combinations are folded into %q "+
		"records (counts and totals stay exact, only their path/comm/pid/tid detail is lost)",
		limit, stageOneHeadroom(limit), recordOverflowLabel)
}

// recorderFoldSummary is the end-of-run line naming how many events each stage
// folded. It counts events, not the distinct keys they would have created:
// remembering those would defeat the cap.
func recorderFoldSummary(limit int, f foldCounts) string {
	var parts []string
	if f.pidless > 0 {
		parts = append(parts, fmt.Sprintf("%d event(s) into pid 0/tid 0 records of their path and comm "+
			"(stage 1, pid/tid detail lost)", f.pidless))
	}
	if f.other > 0 {
		parts = append(parts, fmt.Sprintf("%d event(s) into %q records "+
			"(stage 2, path/comm/pid/tid detail lost)", f.other, recordOverflowLabel))
	}
	return fmt.Sprintf("ior: flamegraph recorder folded %s after reaching its limit of %d distinct "+
		"records; totals are exact", strings.Join(parts, " and "), limit)
}

// announceNewFolds prints the one-time notice of each stage that started to
// fold since the counts in before were taken.
func (r *Recorder) announceNewFolds(w io.Writer, before foldCounts) {
	now := r.data.folds
	if before.pidless == 0 && now.pidless > 0 {
		_, _ = fmt.Fprintln(w, recorderPidFoldNotice(r.data.maxKeys))
	}
	if before.other == 0 && now.other > 0 {
		_, _ = fmt.Fprintln(w, recorderOtherFoldNotice(r.data.maxKeys))
	}
}

// reportFolds prints the end-of-run summary to w when anything was folded.
// Nothing is printed for a run that stayed under the cap.
func (r *Recorder) reportFolds(w io.Writer) {
	if r.data.folds.total() == 0 {
		return
	}
	_, _ = fmt.Fprintln(w, recorderFoldSummary(r.data.maxKeys, r.data.folds))
}
