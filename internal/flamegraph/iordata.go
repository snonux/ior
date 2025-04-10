package flamegraph

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"io"
	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/flags"
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

type iorData struct {
	paths pathMap // Make sure this field is accessible from outside
}

func newIorData() iorData {
	return iorData{paths: make(pathMap)}
}

func newIorDataFromFile(filename string) (iorData, error) {
	iod := newIorData()
	if err := iod.loadFromFile(filename); err != nil {
		return iorData{}, err
	}
	return iod, nil
}

func cloneString(s string) string {
	// Clone the string by creating a new string with the same content
	// This is a workaround to avoid using unsafe package
	return string([]byte(s))
}

func (iod iorData) addEventPair(ev *event.Pair) {
	cnt := Counter{Count: 1, Duration: ev.Duration, DurationToPrev: ev.DurationToPrev}
	iod.add(ev.FileName(), ev.EnterEv.GetTraceId(), strings.TrimSpace(ev.Comm), ev.EnterEv.GetPid(),
		ev.EnterEv.GetTid(), ev.Flags(), cnt)
}

func (iod iorData) add(path pathType, traceId traceIdType, comm commType,
	pid pidType, tid tidType, flags flagsType, addCnt Counter) {

	pathMap, ok := iod.paths[path]
	if !ok {
		pathMap = make(map[traceIdType]map[commType]map[pidType]map[tidType]map[flagsType]Counter)
		iod.paths[path] = pathMap
	}
	traceIdMap, ok := iod.paths[path][traceId]
	if !ok {
		traceIdMap = make(map[commType]map[pidType]map[tidType]map[flagsType]Counter)
		iod.paths[path][traceId] = traceIdMap
	}
	commMap, ok := iod.paths[path][traceId][comm]
	if !ok {
		commMap = make(map[pidType]map[tidType]map[flagsType]Counter)
		iod.paths[path][traceId][comm] = commMap
	}
	pidMap, ok := iod.paths[path][traceId][comm][pid]
	if !ok {
		pidMap = make(map[tidType]map[flagsType]Counter)
		iod.paths[path][traceId][comm][pid] = pidMap
	}
	tidMap, ok := iod.paths[path][traceId][comm][pid][tid]
	if !ok {
		tidMap = make(map[flagsType]Counter)
		iod.paths[path][traceId][comm][pid][tid] = tidMap
	}
	cnt, ok := iod.paths[path][traceId][comm][pid][tid][flags]
	if !ok {
		iod.paths[path][traceId][comm][pid][tid][flags] = addCnt
	} else {
		iod.paths[path][traceId][comm][pid][tid][flags] = cnt.add(addCnt)
	}
}

func (iod iorData) merge(other iorData) iorData {
	for path, traceIdMap := range other.paths {
		if _, ok := iod.paths[path]; !ok {
			iod.paths[path] = make(map[traceIdType]map[commType]map[pidType]map[tidType]map[flagsType]Counter)
		}
		for traceId, commMap := range traceIdMap {
			if _, ok := iod.paths[path][traceId]; !ok {
				iod.paths[path][traceId] = make(map[commType]map[pidType]map[tidType]map[flagsType]Counter)
			}
			for comm, pidMap := range commMap {
				if _, ok := iod.paths[path][traceId][comm]; !ok {
					iod.paths[path][traceId][comm] = make(map[pidType]map[tidType]map[flagsType]Counter)
				}
				for pid, tidMap := range pidMap {
					if _, ok := iod.paths[path][traceId][comm][pid]; !ok {
						iod.paths[path][traceId][comm][pid] = make(map[tidType]map[flagsType]Counter)
					}
					for tid, flagsMap := range tidMap {
						if _, ok := iod.paths[path][traceId][comm][pid][tid]; !ok {
							iod.paths[path][traceId][comm][pid][tid] = make(map[flagsType]Counter)
						}
						for flags, cnt := range flagsMap {
							iod.add(path, traceId, comm, pid, tid, flags, cnt)
						}
					}
				}
			}
		}
	}
	return iod
}

func (iod iorData) serializeToFile() error {
	hostname, err := os.Hostname()
	if err != nil {
		panic(err)
	}

	filename := fmt.Sprintf("%s-%s-%s.ior.zst", hostname, flags.Get().FlamegraphName,
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

	bytes, err := iod.serialize()
	if err != nil {
		return err
	}

	if _, err := encoder.Write(bytes); err != nil {
		return err
	}

	return os.Rename(tmpFilename, filename)
}

func (iod iorData) loadFromFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	decoder := zstd.NewReader(file)
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
	err := enc.Encode(iod.paths)
	return buf.Bytes(), err
}

func (iod *iorData) deserialize(buf *bytes.Buffer) error {
	dec := gob.NewDecoder(buf)
	return dec.Decode(&iod.paths)
}

// Record returned by the iterator
type iterRecord struct {
	path    pathType
	traceId traceIdType
	comm    commType
	pid     pidType
	tid     tidType
	flags   flagsType
	cnt     Counter
}

func (ir iterRecord) StringByName(name string) string {
	switch name {
	case "path":
		return ir.path
	case "comm":
		return ir.comm
	case "tracepoint":
		return ir.traceId.String()
	case "pid":
		return fmt.Sprint(ir.pid)
	case "tid":
		return fmt.Sprint(ir.tid)
	case "flags":
		return ir.flags.String()
	case "count":
		return fmt.Sprint(ir.cnt.Count)
	case "duration":
		return fmt.Sprint(ir.cnt.Duration)
	case "durationToPrev":
		return fmt.Sprint(ir.cnt.DurationToPrev)
	case "bytes":
		return fmt.Sprint(ir.cnt.Bytes)
	default:
		panic(fmt.Sprintln("No", name, "in record"))
	}
}

func (iod iorData) iter() iter.Seq[iterRecord] {
	return func(yield func(iterRecord) bool) {
		for path, traceIdMap := range iod.paths {
			for traceId, commMap := range traceIdMap {
				for comm, pidMap := range commMap {
					for pid, tidMap := range pidMap {
						for tid, flagsMap := range tidMap {
							for flags, cnt := range flagsMap {
								record := iterRecord{
									path:    path,
									traceId: traceId,
									comm:    comm,
									pid:     pid,
									tid:     tid,
									flags:   flags,
									cnt:     cnt,
								}
								if !yield(record) {
									// Stop iteration if yield returns false
									return
								}
							}
						}
					}
				}
			}
		}
	}
}
