package flamegraph

import (
	"fmt"
	"io"
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
// The recorder now holds at most DefaultMaxRecordKeys distinct keys. Once that
// many exist, an event whose key is new is folded into an overflow key that
// keeps its tracepoint and flags but names the path and comm "[other]" and uses
// pid and tid 0. Keys that already exist keep aggregating exactly, so:
//   - totals are exact: every event's count, durations and bytes land in some
//     record, nothing is dropped (the LiveTrie "[other;]" bucket works the same);
//   - only the per-path/comm/pid/tid attribution of the late-arriving keys is
//     lost, and the first keys seen win, which favours the long-lived
//     processes and files of a trace over the churn;
//   - the extra memory is bounded by the number of (tracepoint, flags)
//     combinations, a few hundred at most.
//
// The fold is reported loudly (recorderOverflowNotice, Recorder.announceFold and
// Recorder.reportFolds), not buried in the file.
const (
	// DefaultMaxRecordKeys is the recorder's cap on distinct keys: 2^19,
	// about 130 MB at ~250 B each, in line with the LiveTrie node cap scale
	// and far above what an ordinary trace produces.
	DefaultMaxRecordKeys = 1 << 19

	// recordOverflowLabel is the path and comm of the overflow keys. Unlike
	// LiveTrie's "[other;]" it cannot be made collision-free (frames of a
	// recording are free-form traced text); a real comm or path spelled
	// "[other]" with pid 0 and tid 0 merely shares a record with the fold.
	recordOverflowLabel = "[other]"
)

// foldTarget returns the overflow key that absorbs key: same tracepoint and
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

// fold redirects a new key to its overflow key and counts the events it
// carried. The overflow key is admitted even though the map is at its cap:
// there are only (tracepoints x flags) of them.
func (iod *iorData) fold(key recordKey, cnt Counter) recordKey {
	iod.foldedEvents += cnt.Count
	return foldTarget(key)
}

// recorderOverflowNotice is the one-time stderr line printed when the cap is
// first hit, while the trace is still running (a run can last 900s and the
// recording is only written at the end, so the warning cannot wait for Write).
func recorderOverflowNotice(limit int) string {
	return fmt.Sprintf("ior: flamegraph recorder reached its limit of %d distinct "+
		"(path, comm, pid, tid, flags) records; events of further new combinations are "+
		"folded into %q records (counts and totals stay exact, only their attribution is lost)",
		limit, recordOverflowLabel)
}

// recorderFoldSummary is the end-of-run line naming how many events were
// folded. It counts events, not the distinct keys they would have created:
// remembering those would defeat the cap.
func recorderFoldSummary(limit int, events uint64) string {
	return fmt.Sprintf("ior: flamegraph recorder folded %d event(s) into %q records after "+
		"reaching its limit of %d distinct records; totals are exact, per-path/comm/pid/tid "+
		"detail of those events is not (see `ior collapsed`'s %q frames)",
		events, recordOverflowLabel, limit, recordOverflowLabel)
}

// announceFold prints the one-time overflow notice to w.
func (r *Recorder) announceFold(w io.Writer) {
	_, _ = fmt.Fprintln(w, recorderOverflowNotice(r.data.maxKeys))
}

// reportFolds prints the end-of-run summary to w when anything was folded.
// Nothing is printed for a run that stayed under the cap.
func (r *Recorder) reportFolds(w io.Writer) {
	if r.data.foldedEvents == 0 {
		return
	}
	_, _ = fmt.Fprintln(w, recorderFoldSummary(r.data.maxKeys, r.data.foldedEvents))
}
