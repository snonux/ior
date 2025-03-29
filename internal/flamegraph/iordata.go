package flamegraph

import (
	"encoding/json"
	"fmt"
	"ior/internal/event"
	"ior/internal/types"
	"os"
	"time"
)

const fileSuffix = ".ior"

// e.g.    pathType ¶ traceid ¶ comm ¶ pid ¶ tid ¶ flags ¶ counter
type pathType = string
type traceIdType = types.TraceId
type commType = string
type pidType = uint32
type tidType = uint32
type flagsType = string
type pathMap map[pathType]map[traceIdType]map[commType]map[pidType]map[tidType]map[flagsType]counter
type iorData struct{ paths pathMap }

// TODO: Flag to enable iorData
// TODO: Name flag for iorData (outfile format: hostname-name-timestamp.ior.zst)
// TODO: Output path for iorData flag
// TODO: Add helper to convert .ior data file to collapsed format
func newIorData() iorData { return iorData{paths: make(pathMap)} }

func (iod iorData) add(ev *event.Pair) {
	// type Pair struct {
	// 	EnterEv, ExitEv Event
	// 	File            file.File
	// 	Comm            string
	// 	Duration        uint64

	//	// To calculate the time difference from the previoud event.
	//	PrevPair       *Pair
	//	durationToPrev uint64
	//	}
	// TODO: Add duration to prev to counter
	cnt := counter{
		count:    1,
		duration: ev.Duration,
	}
	iod.addPath(ev.File.Name(), ev.EnterEv.GetTraceId(), ev.Comm,
		ev.EnterEv.GetPid(), ev.EnterEv.GetTid(), ev.File.FlagsString(), cnt)
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

func (iod iorData) commit() error {
	currentTime := time.Now().Format("2006-01-02_15:04:05")
	hostname, err := os.Hostname()
	if err != nil {
		panic(err)
	}
	filename := fmt.Sprintf("%s-%s.%s", hostname, currentTime, fileSuffix)
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	return encoder.Encode(iod.paths)
}
