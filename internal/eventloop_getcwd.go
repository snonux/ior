package internal

import (
	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/types"
)

// getcwdTruncatedSuffix marks a getcwd path longer than the captured field
// (MAX_FILENAME_LENGTH - 1 bytes). It is appended to the captured prefix so
// that the row never presents a shorter, different - but plausible looking -
// directory as the caller's cwd.
const getcwdTruncatedSuffix = "..."

// applyCapturedOutputPath stores the path an output-path syscall returned to
// its caller on the still-pending pair and reports whether fixup was one.
//
// getcwd's path only exists once the call has returned: args[0] is an output
// buffer. The generated enter handler therefore stashes the buffer pointer and
// the exit handler, after a successful return, reads the string back and
// publishes it as an OPEN_NAME_FIXUP_EVENT reserved before the exit record
// (outputPathSyscalls in internal/generate/classify.go). It is the directory
// the kernel resolved for this very call, unlike /proc/<tid>/cwd read while
// processing the pair, which ior used before: that was wrong once the tracee
// had chdir'ed on while the loop lagged, empty once it had exited, and cost a
// readlink on the event loop per getcwd.
//
// The null_event enter has no field to splice the string into, so the path
// goes straight onto the pair; handleNullExit validates it against the return
// value (finishGetcwdPath). The trace ID check on both sides keeps a fixup for
// some other syscall from grafting a path onto this pair, and vice versa.
func applyCapturedOutputPath(pair *event.Pair, fixup *types.OpenNameFixupEvent) bool {
	if fixup.GetTraceId() != types.SYS_ENTER_GETCWD {
		return false
	}
	if nullEv, ok := pair.EnterEv.(*types.NullEvent); ok && nullEv.GetTraceId() == types.SYS_ENTER_GETCWD {
		pair.File = file.NewPathname(fixup.Filename[:])
	}
	return true
}

// finishGetcwdPath returns the file a completed getcwd row reports, given the
// path captured by applyCapturedOutputPath (nil when none arrived) and the raw
// syscall return: the copied byte count including the NUL, or a negative
// errno.
//
//   - A failed call (ret <= 0) reports no path, whatever was captured.
//   - No captured path (a fixup lost to ring-buffer backpressure, an enter
//     state the kernel could not record, a still-failing read) reports none.
//   - A path longer than the captured field is reported as its captured prefix
//     plus getcwdTruncatedSuffix: ret says how long it really was.
//   - A captured string longer than ret says is cut to ret - 1 bytes, the
//     part the kernel returned: anything beyond it was not this call's result.
func finishGetcwdPath(captured file.File, ret int64) file.File {
	if ret <= 0 || captured == nil {
		return nil
	}
	name := captured.Name()
	pathLen := ret - 1
	switch {
	case int64(len(name)) < pathLen:
		return file.NewPathname([]byte(name + getcwdTruncatedSuffix))
	case int64(len(name)) > pathLen:
		return file.NewPathname([]byte(name[:pathLen]))
	}
	return captured
}
