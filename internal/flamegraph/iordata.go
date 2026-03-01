package flamegraph

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"io"
	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/types"
	"iter"
	"os"
	"strings"
	"time"

	// Is there a zstd library part of Go 1.25
	"github.com/DataDog/zstd"
)

type pathType = string
type traceIdType = types.TraceId
type commType = string
type pidType = uint32
type tidType = uint32
type flagsType = file.Flags
type pathMap map[pathType]map[traceIdType]map[commType]map[pidType]map[tidType]map[flagsType]Counter

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

func cloneString(s string) string {
	// Clone the string by creating a new string with the same content
	// This is a workaround to avoid using unsafe package
	return string([]byte(s))
}

func (iod iorData) addEventPair(ev *event.Pair) {
	cnt := Counter{Count: 1, Duration: ev.Duration, DurationToPrev: ev.DurationToPrev, Bytes: ev.Bytes}
	iod.add(ev.FileName(), ev.EnterEv.GetTraceId(), strings.TrimSpace(ev.Comm), ev.EnterEv.GetPid(),
		ev.EnterEv.GetTid(), ev.Flags(), cnt)
}

func (iod iorData) add(path pathType, traceId traceIdType, comm commType,
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

func (iod iorData) merge(other iorData) iorData {
	for key, cnt := range other.records {
		iod.add(key.Path, key.TraceID, key.Comm, key.Pid, key.Tid, key.Flags, cnt)
	}
	return iod
}

func (iod iorData) serializeToFile(flamegraphName string) error {
	hostname, err := os.Hostname()
	if err != nil {
		panic(err)
	}
	if flamegraphName == "" {
		flamegraphName = "default"
	}

	filename := fmt.Sprintf("%s-%s-%s.ior.zst", hostname, flamegraphName,
		time.Now().Format("2006-01-02_15:04:05"))
	fmt.Println("Writing", filename)
	tmpFilename := fmt.Sprintf("%s.tmp", filename)

	file, err := os.Create(tmpFilename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := zstd.NewWriter(file)
	defer encoder.Close()

	gobEncoder := gob.NewEncoder(encoder)
	if err := gobEncoder.Encode(iod.records); err != nil {
		return err
	}
	if err := encoder.Flush(); err != nil {
		return err
	}

	return os.Rename(tmpFilename, filename)
}

func (iod *iorData) loadFromFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	decoder := zstd.NewReader(file)
	defer decoder.Close()

	var records map[recordKey]Counter
	if err := gob.NewDecoder(decoder).Decode(&records); err == nil && len(records) > 0 {
		iod.records = records
		return nil
	}

	// Fallback path for legacy payloads and empty-map ambiguity.
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	decoder = zstd.NewReader(file)
	defer decoder.Close()

	var buffer bytes.Buffer
	if _, err = io.Copy(&buffer, decoder); err != nil {
		return err
	}
	return iod.deserialize(&buffer)
}

func (iod iorData) serialize() ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(iod.records)
	return buf.Bytes(), err
}

func (iod *iorData) deserialize(buf *bytes.Buffer) error {
	raw := append([]byte(nil), buf.Bytes()...)
	dec := gob.NewDecoder(bytes.NewReader(raw))
	var records map[recordKey]Counter
	if err := dec.Decode(&records); err == nil && len(records) > 0 {
		iod.records = records
		return nil
	}

	var legacy pathMap
	if err := gob.NewDecoder(bytes.NewReader(raw)).Decode(&legacy); err != nil {
		return err
	}

	iod.records = make(map[recordKey]Counter)
	for path, traceIDMap := range legacy {
		for traceID, commMap := range traceIDMap {
			for comm, pidMap := range commMap {
				for pid, tidMap := range pidMap {
					for tid, flagsMap := range tidMap {
						for f, cnt := range flagsMap {
							iod.add(path, traceID, comm, pid, tid, f, cnt)
						}
					}
				}
			}
		}
	}
	if len(iod.records) == 0 && records != nil {
		iod.records = records
	}
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

func (iod iorData) iter() iter.Seq[IterRecord] {
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
