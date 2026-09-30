package flamegraph

import (
	"bytes"
	"encoding/gob"
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

var hostnameFn = os.Hostname

// nowFn supplies the timestamp in recording names; tests pin it to force the
// same-second collision that the publish step must survive.
var nowFn = time.Now

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
func LoadFromFile(filename string) (iter.Seq[IterRecord], error) {
	iod, err := newIorDataFromFile(filename)
	if err != nil {
		return nil, fmt.Errorf("load ior data from %s: %w", filename, err)
	}
	return iod.iter(), nil
}

func (iod *iorData) addEventPair(ev *event.Pair) {
	cnt := Counter{Count: 1, Duration: ev.Duration, DurationToPrev: ev.DurationToPrev, Bytes: ev.Bytes}
	iod.add(ev.FileName(), ev.EnterEv.GetTraceId(), strings.TrimSpace(ev.Comm), ev.EnterEv.GetPid(),
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
// (flamegraphName defaults to "default"). The data goes to a uniquely named
// .tmp sibling first and is published only once fully flushed, so a reader
// never sees a partial file; on any failure the temp file is removed.
//
// The timestamp is accurate to the second, so two runs finishing in the same
// second (or the repeated DST hour) compute the same name. Publishing never
// replaces an existing file: the later run lands under "<name>-1.ior.zst"
// (then -2, ...) and the console says so, instead of silently overwriting the
// earlier recording.
func (iod *iorData) serializeToFile(flamegraphName string) error {
	filename, err := serializedFilename(flamegraphName, nowFn())
	if err != nil {
		return err
	}
	published, err := atomicfile.WriteFile(filename, serializedExt, func(w io.Writer) error {
		return iod.encodeCompressed(w, filename)
	})
	if err != nil {
		return err
	}
	// Status goes to stderr (stdout is reserved for machine-readable data) and
	// only after the file is published, so it never announces a file that was
	// not written. A failed status write (closed pipe) is deliberately
	// ignored: the recording is already safely on disk.
	if published != filename {
		_, _ = fmt.Fprintln(os.Stderr, filename, "already exists; wrote", published, "instead")
	} else {
		_, _ = fmt.Fprintln(os.Stderr, "Wrote", published)
	}
	return nil
}

// serializedFilename builds the output name
// <hostname>-<flamegraphName>-<now>.ior.zst, substituting "default" for an
// empty flamegraphName.
func serializedFilename(flamegraphName string, now time.Time) (string, error) {
	hostname, err := hostnameFn()
	if err != nil {
		return "", fmt.Errorf("get hostname: %w", err)
	}
	if flamegraphName == "" {
		flamegraphName = "default"
	}
	return fmt.Sprintf("%s-%s-%s%s", hostname, flamegraphName,
		now.Format("2006-01-02_15:04:05"), serializedExt), nil
}

// encodeCompressed gob-encodes the records through a zstd writer into w and
// closes that writer, which flushes the final zstd frame and releases the
// native zstd context. name only labels errors.
func (iod *iorData) encodeCompressed(w io.Writer, name string) error {
	encoder := zstd.NewWriter(w)
	if err := gob.NewEncoder(encoder).Encode(iod.records); err != nil {
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

	var records map[recordKey]Counter
	if err := gob.NewDecoder(decoder).Decode(&records); err != nil {
		return fmt.Errorf("decode ior records from %s: %w", filename, err)
	}
	if records == nil {
		records = make(map[recordKey]Counter)
	}
	iod.records = records
	return nil
}

func (iod *iorData) serialize() ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(iod.records)
	return buf.Bytes(), err
}

func (iod *iorData) deserialize(buf *bytes.Buffer) error {
	var records map[recordKey]Counter
	if err := gob.NewDecoder(bytes.NewReader(buf.Bytes())).Decode(&records); err != nil {
		return err
	}
	if records == nil {
		records = make(map[recordKey]Counter)
	}
	iod.records = records
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
