package runtime

import (
	"errors"
	"fmt"

	"ior/internal/parquet"
)

// RecorderWarningText turns one recorder.Record result into the stream
// warning text it deserves, or "" when it is not news.
//
// The TUI owns a single recorder for its lifetime, but a recording only runs
// while the user has started one, so most results are not news:
//   - ErrRecorderNotActive: idle, cleanly stopped, or a Stop racing Record.
//   - ErrRecorderQueueFull: a row shed during an overflow that was already
//     announced; only the first shed row of a recording comes back as
//     ErrRecorderStartedDropping, which is warned about.
//   - any other error: a dead recording's LastError, which Record repeats on
//     every call until the next Start - across trace sessions, too. The
//     recorder itself decides whether it is news: TakeFailure returns it
//     once, and not at all if Stop already handed it to the TUI (which shows
//     it on the error screen).
//
// Keeping the "report once" state in the recorder rather than here means a
// failure is reported by whichever trace session first sees it, and no
// per-session guard can be burned by a stale or idle result. A failure no
// event reaches before the user opens the record modal again is claimed and
// shown there instead (Start would discard it); one neither an event nor the
// modal reaches is claimed by the TUI's quit path and becomes the exit error.
//
// TakeFailure marks the failure reported, so the caller must deliver the text
// this returns or the failure is lost: that is why the TUI's session view runs
// this inside the same gate that pushes the warning (see WarningRecorder).
func RecorderWarningText(rec RowRecorder, err error) string {
	switch {
	case err == nil, errors.Is(err, parquet.ErrRecorderNotActive):
	case errors.Is(err, parquet.ErrRecorderStartedDropping):
		return "Parquet recorder queue full: rows are being dropped"
	case errors.Is(err, parquet.ErrRecorderQueueFull):
	default:
		// Record may return the failure while the session is still being
		// torn down, when TakeFailure yields nil; a later Record (in this or
		// a later session) then reports it.
		if failure := rec.TakeFailure(); failure != nil {
			return fmt.Sprintf("Parquet recorder failed: %v", failure)
		}
	}
	return ""
}
