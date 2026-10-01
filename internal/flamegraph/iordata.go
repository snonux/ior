package flamegraph

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"iter"
	"os"
	"strings"
	"time"

	"ior/internal/atomicfile"
	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/sampling"
	"ior/internal/types"

	"github.com/DataDog/zstd" // Go stdlib does not include zstd; third-party dep required
)

type pathType = string
type traceIdType = types.TraceId
type commType = string
type pidType = uint32
type tidType = uint32
type flagsType = file.Flags

// serializedExt is the extension of every recording; atomicfile keeps it last
// when it has to add a "-N" suffix to avoid overwriting an existing file.
const serializedExt = ".ior.zst"

// Timestamp layouts of the generated recording name. The default keeps ':' in
// the time of day, as recordings always were; the portable layout is used when
// the output directory's filesystem rejects ':' (vfat, exFAT, many SMB shares;
// see Recorder.Prepare). Both are fixed width, so names still sort by time.
const (
	timestampLayout         = "2006-01-02_15:04:05"
	timestampLayoutPortable = "2006-01-02_15-04-05"
)

var hostnameFn = os.Hostname

// nowFn supplies the timestamp in recording names; tests pin it to force the
// same-second collision that the publish step must survive.
var nowFn = time.Now

// statusOut receives the "Wrote <file>" line. It is stderr because stdout is
// reserved for machine-readable data; tests replace it to capture the line and
// to check that it is only written once the file is published.
var statusOut io.Writer = os.Stderr

// recordKey identifies one aggregated row. TraceID is this build's numeric ID
// in memory; on disk it is accompanied by the tracepoint name (see
// iorformat.go) because the number is build-specific.
type recordKey struct {
	Path    pathType
	TraceID traceIdType
	Comm    commType
	Pid     pidType
	Tid     tidType
	Flags   flagsType
}

type iorData struct {
	records map[recordKey]Counter
	// sampling is the run's sampling outcome. A recording of a run that
	// sampled has fewer records than invocations; this says which syscalls
	// and how many there really were. Persisted in the header (iorformat.go).
	sampling sampling.Summary
	// maxKeys caps the exactly stored records: once len(records) reaches it, a
	// new key is folded in two stages (recordcap.go): first into the pid-less
	// record of its path and comm, then into an "[other]" record. Zero means
	// unbounded, which is what data loaded from disk and test fixtures use;
	// NewRecorder/NewRecorderWithMaxKeys set the cap (-flamegraph-max-keys).
	maxKeys int
	// folds counts the events (Counter.Count) each fold stage absorbed.
	folds foldCounts
}

func newIorData() iorData {
	return iorData{records: make(map[recordKey]Counter)}
}

func newIorDataFromFile(filename string) (iorData, error) {
	iod := newIorData()
	if err := iod.loadFromFile(filename); err != nil {
		return iorData{}, err
	}
	return iod, nil
}

// LoadFromFile loads an .ior.zst file and returns an iterator over all records.
// Use LoadRecording when the recording's sampling marker matters.
func LoadFromFile(filename string) (iter.Seq[IterRecord], error) {
	records, _, err := LoadRecording(filename)
	return records, err
}

// LoadRecording loads an .ior.zst file and returns an iterator over all
// records together with the sampling outcome of the run that wrote it. The
// Summary is the zero value (not Active) for a recording that traced every
// syscall in full; otherwise the counts of the sampled syscalls in the records
// are a sample, and the Summary holds their exact totals.
func LoadRecording(filename string) (iter.Seq[IterRecord], sampling.Summary, error) {
	iod, err := newIorDataFromFile(filename)
	if err != nil {
		return nil, sampling.Summary{}, fmt.Errorf("load ior data from %s: %w", filename, err)
	}
	return iod.iter(), iod.sampling, nil
}

// addEventPair aggregates ev into the record. The path is ev.FileValue(), not
// FileName(): a pair without a file persists an empty path (shown as the
// "[unknown]" frame by `ior collapsed -fields path`) instead of the "N:file"
// display placeholder, which would read as a real file; a real file named
// "N:file" keeps that name (task pq2).
func (iod *iorData) addEventPair(ev *event.Pair) {
	cnt := Counter{Count: 1, Duration: ev.Duration, DurationToPrev: ev.DurationToPrev, Bytes: ev.Bytes}
	iod.add(ev.FileValue(), ev.EnterEv.GetTraceId(), strings.TrimSpace(ev.Comm), ev.EnterEv.GetPid(),
		ev.EnterEv.GetTid(), ev.Flags(), cnt)
}

func (iod *iorData) add(path pathType, traceId traceIdType, comm commType,
	pid pidType, tid tidType, flags flagsType, addCnt Counter) {

	key := recordKey{
		Path:    path,
		TraceID: traceId,
		Comm:    comm,
		Pid:     pid,
		Tid:     tid,
		Flags:   flags,
	}
	cnt, ok := iod.records[key]
	if !ok && iod.full() {
		// At the cap a new key is redirected to its pid-less key or, failing
		// that, its "[other]" key, either of which may or may not exist yet;
		// existing keys above keep aggregating exactly.
		key = iod.fold(key, addCnt)
		cnt, ok = iod.records[key]
	}
	if !ok {
		iod.records[key] = addCnt
		return
	}
	iod.records[key] = cnt.add(addCnt)
}

func (iod *iorData) merge(other iorData) *iorData {
	for key, cnt := range other.records {
		iod.add(key.Path, key.TraceID, key.Comm, key.Pid, key.Tid, key.Flags, cnt)
	}
	return iod
}

// serializeToFile writes the records to
// <hostname>-<flamegraphName>-<timestamp>.ior.zst in the working directory
// (flamegraphName defaults to "default"; layout is the time.Format layout of
// the timestamp). Recorder.Prepare has already checked at startup that this
// name can be created, so a failure here is a genuine late surprise (disk
// full, directory removed) and not a misconfiguration. The data goes to a
// uniquely named .tmp sibling first and is published only once fully flushed,
// so a reader never sees a partial file; on any failure the temp file is
// removed.
//
// The timestamp is accurate to the second, so two runs finishing in the same
// second (or the repeated DST hour) compute the same name. Publishing never
// replaces an existing file: the later run lands under "<name>-1.ior.zst"
// (then -2, ...) and the console says so, instead of silently overwriting the
// earlier recording.
func (iod *iorData) serializeToFile(flamegraphName, layout string) error {
	filename, err := serializedFilename(flamegraphName, nowFn(), layout)
	if err != nil {
		return err
	}
	published, err := atomicfile.WriteFile(filename, serializedExt, func(w io.Writer) error {
		return iod.encodeCompressed(w, filename)
	})
	if err != nil {
		return err
	}
	// Status goes to statusOut (stderr; stdout is reserved for
	// machine-readable data) and only after the file is published, so it never
	// announces a file that was not written. A failed status write (closed
	// pipe) is deliberately ignored: the recording is already safely on disk.
	if published != filename {
		_, _ = fmt.Fprintln(statusOut, filename, "already exists; wrote", published, "instead")
	} else {
		_, _ = fmt.Fprintln(statusOut, "Wrote", published)
	}
	return nil
}

// serializedFilename builds the output name
// <hostname>-<flamegraphName>-<now>.ior.zst, substituting "default" for an
// empty flamegraphName; layout formats now (timestampLayout or
// timestampLayoutPortable).
func serializedFilename(flamegraphName string, now time.Time, layout string) (string, error) {
	hostname, err := hostnameFn()
	if err != nil {
		return "", fmt.Errorf("get hostname: %w", err)
	}
	if flamegraphName == "" {
		flamegraphName = "default"
	}
	return fmt.Sprintf("%s-%s-%s%s", hostname, flamegraphName,
		now.Format(layout), serializedExt), nil
}

// encodeCompressed writes the recording stream (magic, header with the
// tracepoint-name table, records; see iorformat.go) through a zstd writer into
// w and closes that writer, which flushes the final zstd frame and releases the
// native zstd context. name only labels errors.
func (iod *iorData) encodeCompressed(w io.Writer, name string) error {
	encoder := zstd.NewWriter(w)
	if err := encodeRecords(encoder, iod.records, iod.sampling); err != nil {
		_ = encoder.Close() // release the native zstd context
		return fmt.Errorf("encode ior records: %w", err)
	}
	if err := encoder.Close(); err != nil {
		return fmt.Errorf("close zstd writer for %s: %w", name, err)
	}
	return nil
}

func (iod *iorData) loadFromFile(filename string) (retErr error) {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("open %s: %w", filename, err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close file %s: %w", filename, err))
		}
	}()

	decoder := zstd.NewReader(file)
	defer func() {
		if err := decoder.Close(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close zstd reader for %s: %w", filename, err))
		}
	}()

	// decodeRecords translates the stored tracepoint names to this build's IDs
	// and rejects headerless (pre-format-version) recordings, whose numeric IDs
	// would otherwise render as the wrong syscalls without any error.
	records, samples, err := decodeRecords(decoder)
	if err != nil {
		return fmt.Errorf("decode ior records from %s: %w", filename, err)
	}
	iod.records = records
	iod.sampling = samples
	return nil
}

// serialize returns the uncompressed recording stream (same layout as inside
// the .ior.zst, see iorformat.go).
func (iod *iorData) serialize() ([]byte, error) {
	var buf bytes.Buffer
	err := encodeRecords(&buf, iod.records, iod.sampling)
	return buf.Bytes(), err
}

func (iod *iorData) deserialize(buf *bytes.Buffer) error {
	records, samples, err := decodeRecords(bytes.NewReader(buf.Bytes()))
	if err != nil {
		return err
	}
	iod.records = records
	iod.sampling = samples
	return nil
}

// IterRecord is a single record returned by the iterator.
type IterRecord struct {
	Path    string
	TraceID types.TraceId
	Comm    string
	Pid     uint32
	Tid     uint32
	Flags   file.Flags
	Cnt     Counter
}

// StringByName returns the string representation of a field by name.
// Returns an error if the field name is not recognized.
func (ir IterRecord) StringByName(name string) (string, error) {
	switch name {
	case "path":
		return strings.Join(strings.Split(ir.Path, "/"), ";/"), nil
	case "comm":
		return ir.Comm, nil
	case "tracepoint":
		return ir.TraceID.String(), nil
	case "pid":
		return fmt.Sprint(ir.Pid), nil
	case "tid":
		return fmt.Sprint(ir.Tid), nil
	case "flags":
		return ir.Flags.String(), nil
	default:
		return "", fmt.Errorf("unknown field %q in record", name)
	}
}

func (iod *iorData) iter() iter.Seq[IterRecord] {
	return func(yield func(IterRecord) bool) {
		for key, cnt := range iod.records {
			record := IterRecord{
				Path:    key.Path,
				TraceID: key.TraceID,
				Comm:    key.Comm,
				Pid:     key.Pid,
				Tid:     key.Tid,
				Flags:   key.Flags,
				Cnt:     cnt,
			}
			if !yield(record) {
				return
			}
		}
	}
}
