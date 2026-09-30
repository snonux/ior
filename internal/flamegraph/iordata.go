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

var hostnameFn = os.Hostname

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
// (flamegraphName defaults to "default"). The data goes to a .tmp sibling
// first and is renamed into place only once fully flushed, so a reader never
// sees a partial file; on any failure the temp file is removed.
func (iod *iorData) serializeToFile(flamegraphName string) error {
	filename, err := serializedFilename(flamegraphName, time.Now())
	if err != nil {
		return err
	}
	fmt.Println("Writing", filename)
	tmpFilename := fmt.Sprintf("%s.tmp", filename)

	if err := iod.writeTempFile(tmpFilename); err != nil {
		return err
	}
	if err := os.Rename(tmpFilename, filename); err != nil {
		// Don't leave the complete but unpublished temp file behind.
		_ = os.Remove(tmpFilename)
		return fmt.Errorf("rename %s to %s: %w", tmpFilename, filename, err)
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
	return fmt.Sprintf("%s-%s-%s.ior.zst", hostname, flamegraphName,
		now.Format("2006-01-02_15:04:05")), nil
}

// writeTempFile creates tmpFilename and writes the zstd-compressed gob
// encoding of the records to it, closing the file before returning so its
// content is flushed and ready to rename. On error the file is closed (if
// still open) and removed.
func (iod *iorData) writeTempFile(tmpFilename string) (retErr error) {
	out, err := os.Create(tmpFilename)
	if err != nil {
		return fmt.Errorf("create temp file %s: %w", tmpFilename, err)
	}
	fileClosed := false
	defer func() {
		// Close file on error paths; on success it is already closed.
		// Capture the close error and join it with retErr so filesystem issues
		// (e.g. full disk detected only on close) are not silently discarded.
		if retErr == nil {
			return
		}
		if !fileClosed {
			if closeErr := out.Close(); closeErr != nil {
				retErr = errors.Join(retErr, fmt.Errorf("close temp file %s: %w", tmpFilename, closeErr))
			}
		}
		// Don't leave a partial temp file behind.
		_ = os.Remove(tmpFilename)
	}()

	if err := iod.encodeCompressed(out, tmpFilename); err != nil {
		return err
	}
	// The encoder is closed, so the final zstd frame is in the file; closing
	// the file flushes OS buffers. Both must complete before rename.
	fileClosed = true
	if err := out.Close(); err != nil {
		return fmt.Errorf("close temp file %s: %w", tmpFilename, err)
	}
	return nil
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
