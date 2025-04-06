package flamegraph

import (
	"fmt"
	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/flags"
	"ior/internal/types"
	"iter"
	"log"
	"os"
	"strings"
	"time"

	"github.com/DataDog/zstd"
)

const recordSeparator = " ␞ "

type pathType = string
type traceIdType = types.TraceId
type commType = string
type pidType = uint32
type tidType = uint32
type flagsType = file.Flags
type pathMap map[pathType]map[traceIdType]map[commType]map[pidType]map[tidType]map[flagsType]counter

type iorData struct {
	paths pathMap
}

// TODO: Name flag for iorData (outfile format: hostname-name-timestamp.ior.zst)
// TODO: Output path for iorData flag
// TODO: Add helper to convert .ior data file to collapsed format
func newIorData() iorData {
	return iorData{paths: make(pathMap)}
}

func (iod iorData) add(ev *event.Pair) {
	cnt := counter{count: 1, duration: ev.Duration, durationToPrev: ev.DurationToPrev}
	iod.addPath(ev.FileName(), ev.EnterEv.GetTraceId(), ev.Comm, ev.EnterEv.GetPid(),
		ev.EnterEv.GetTid(), ev.Flags(), cnt)
}

func (iod iorData) addPath(path pathType, traceId traceIdType, comm commType,
	pid pidType, tid tidType, flags flagsType, addCnt counter) {

	pathMap, ok := iod.paths[path]
	if !ok {
		pathMap = make(map[traceIdType]map[commType]map[pidType]map[tidType]map[flagsType]counter)
		iod.paths[path] = pathMap
	}
	traceIdMap, ok := iod.paths[path][traceId]
	if !ok {
		traceIdMap = make(map[commType]map[pidType]map[tidType]map[flagsType]counter)
		iod.paths[path][traceId] = traceIdMap
	}
	commMap, ok := iod.paths[path][traceId][comm]
	if !ok {
		commMap = make(map[pidType]map[tidType]map[flagsType]counter)
		iod.paths[path][traceId][comm] = commMap
	}
	pidMap, ok := iod.paths[path][traceId][comm][pid]
	if !ok {
		pidMap = make(map[tidType]map[flagsType]counter)
		iod.paths[path][traceId][comm][pid] = pidMap
	}
	tidMap, ok := iod.paths[path][traceId][comm][pid][tid]
	if !ok {
		tidMap = make(map[flagsType]counter)
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
			iod.paths[path] = make(map[traceIdType]map[commType]map[pidType]map[tidType]map[flagsType]counter)
		}
		for traceId, commMap := range traceIdMap {
			if _, ok := iod.paths[path][traceId]; !ok {
				iod.paths[path][traceId] = make(map[commType]map[pidType]map[tidType]map[flagsType]counter)
			}
			for comm, pidMap := range commMap {
				if _, ok := iod.paths[path][traceId][comm]; !ok {
					iod.paths[path][traceId][comm] = make(map[pidType]map[tidType]map[flagsType]counter)
				}
				for pid, tidMap := range pidMap {
					if _, ok := iod.paths[path][traceId][comm][pid]; !ok {
						iod.paths[path][traceId][comm][pid] = make(map[tidType]map[flagsType]counter)
					}
					for tid, flagsMap := range tidMap {
						if _, ok := iod.paths[path][traceId][comm][pid][tid]; !ok {
							iod.paths[path][traceId][comm][pid][tid] = make(map[flagsType]counter)
						}
						for flags, cnt := range flagsMap {
							iod.addPath(path, traceId, comm, pid, tid, flags, cnt)
						}
					}
				}
			}
		}
	}
	return iod
}

func (iod iorData) commit() error {
	hostname, err := os.Hostname()
	if err != nil {
		panic(err)
	}

	filename := fmt.Sprintf("%s-%s-%s.ior.zst", hostname, flags.Get().FlamegraphName,
		time.Now().Format("2006-01-02_15:04:05"))
	log.Println("Writing", filename)
	tmpFilename := fmt.Sprintf("%s.tmp", filename)

	file, err := os.Create(tmpFilename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := zstd.NewWriter(file)
	defer encoder.Close()

	for line := range iod.lines() {
		if _, err := encoder.Write([]byte(line + "\n")); err != nil {
			return err
		}
	}

	return os.Rename(tmpFilename, filename)
}

func (iod iorData) lines() iter.Seq[string] {
	return func(yield func(string) bool) {
		for path, traceIdMap := range iod.paths {
			for traceId, commMap := range traceIdMap {
				for comm, pidMap := range commMap {
					for pid, tidMap := range pidMap {
						for tid, flagsMap := range tidMap {
							for flags, cnt := range flagsMap {
								joinedStr := strings.Join([]string{
									path,
									traceId.String(),
									comm,
									fmt.Sprint(pid),
									fmt.Sprint(tid),
									flags.String(),
									fmt.Sprintf("%d %d %d %d", cnt.count, cnt.duration, cnt.durationToPrev, cnt.bytes),
								},
									recordSeparator)
								if !yield(joinedStr) {
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
