package flamegraph

import (
	"fmt"
	"strings"

	"ior/internal/atomicfile"
)

// probeNameChars is atomicfile.ProbeNameChars; tests replace it to simulate a
// filesystem (vfat, SMB) that rejects ':', which a test directory cannot.
var probeNameChars = atomicfile.ProbeNameChars

// ValidateName rejects a -name value that cannot work as the middle part of a
// recording name. The name is a base name, not a path: the recording is always
// written to the working directory as <hostname>-<name>-<timestamp>.ior.zst,
// so a '/' would be read as a directory that does not exist (the trace ran to
// the end, then failed to create its file; that was the original defect) or,
// worse, as one that does and is unrelated to where the user meant the file to
// go. Rejecting it up front costs a clear message; the user changes directory
// or moves the file.
func ValidateName(name string) error {
	if strings.ContainsAny(name, "/\x00") {
		return fmt.Errorf("-name %q must be a base name without '/': recordings are written to the "+
			"working directory as <hostname>-<name>-<timestamp>%s (change directory instead)", name, serializedExt)
	}
	return nil
}

// Prepare checks, at startup and before any BPF work, everything that would
// otherwise only fail when the trace ends and the recording is written - by
// which time up to -duration (900s by default) of tracing is lost with
// nothing saved:
//
//   - the name is a valid base name (ValidateName) and the finished file name
//     fits the filesystem's 255-byte NAME_MAX;
//   - the working directory accepts new files (a real temp file is created and
//     removed: unwritable directories, NFS root_squash, read-only mounts);
//   - the filesystem accepts every character the recording name will contain
//     that some filesystems refuse (checkNameChars): the time of day has ':'
//     and -name may carry any of ? * " < > | \. vfat, exFAT and many SMB
//     shares reject them with EINVAL. When the ':' of the time of day is the
//     only problem the recorder switches to a colon-free timestamp and says
//     so on statusOut, instead of failing.
//
// A nil Recorder (no -flamegraph) has nothing to prepare. It is called once,
// before the trace starts; Write is otherwise unaffected. Nothing is left
// behind on success or failure.
func (r *Recorder) Prepare() error {
	if r == nil {
		return nil
	}
	if err := ValidateName(r.name); err != nil {
		return err
	}
	sample, err := serializedFilename(r.name, nowFn(), r.layout)
	if err != nil {
		return err
	}
	// The "-N" collision suffix truncates the stem to stay in range, so only
	// the base name has to fit.
	if len(sample) > atomicfile.NameMax {
		return fmt.Errorf("-name is too long: the recording name would be %d bytes (%s), "+
			"the filesystem allows %d", len(sample), sample, atomicfile.NameMax)
	}
	if err := atomicfile.Probe(sample); err != nil {
		return fmt.Errorf("-flamegraph output would fail at the end of the trace: %w", err)
	}
	return r.checkNameChars(sample)
}

// checkNameChars probes the characters sample actually contains that some
// filesystems refuse (atomicfile.RiskyNameChars), not a fixed ':', so a name
// with '?' on vfat fails now and not at the final rename. Only EINVAL/EILSEQ
// (atomicfile.IsNameRejected) mean a naming rule; any other probe error
// (ENOSPC, EIO, EMFILE, ...) is returned as it is, because switching layouts
// would not help and would hide the real problem behind a wrong note.
//
// A rejection is cured by the colon-free timestamp only if the time of day was
// the culprit. The probe therefore reruns for the characters left after the
// switch: if those are still refused the -name itself is the problem and the
// error says so; otherwise the switch stands and a status note explains it.
func (r *Recorder) checkNameChars(sample string) error {
	chars := atomicfile.RiskyNameChars(sample)
	if chars == "" {
		return nil
	}
	err := probeNameChars(sample, chars)
	if err == nil {
		return nil
	}
	if !atomicfile.IsNameRejected(err) || r.layout == timestampLayoutPortable {
		return fmt.Errorf("-flamegraph output would fail at the end of the trace: %w", err)
	}
	portable, nameErr := serializedFilename(r.name, nowFn(), timestampLayoutPortable)
	if nameErr != nil {
		return nameErr
	}
	if rest := atomicfile.RiskyNameChars(portable); rest != "" {
		if err := probeNameChars(portable, rest); err != nil {
			return fmt.Errorf("-name %q contains characters this filesystem rejects; "+
				"the recording would fail at the end of the trace: %w", r.name, err)
		}
	}
	r.layout = timestampLayoutPortable
	_, _ = fmt.Fprintf(statusOut,
		"Note: %v; the recording name uses '-' in the time of day instead\n", err)
	return nil
}
