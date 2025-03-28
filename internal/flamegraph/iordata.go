package flamegraph

import (
	"encoding/json"
	"fmt"
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
type flagsType = int32

type pathMap map[pathType]map[traceIdType]map[commType]map[pidType]map[tidType]map[flagsType]counter

type iorData struct {
	paths pathMap
}

func newIorData() iorData {
	return iorData{paths: make(pathMap)}
}

func (id iorData) addPath(path pathType, traceId traceIdType, comm commType, pid pidType, tid tidType, flags flagsType, cnt counter) {
	if _, ok := id.paths[path]; !ok {
		id.paths[path] = make(map[traceIdType]map[commType]map[pidType]map[tidType]map[flagsType]counter)
	}
	if _, ok := id.paths[path][traceId]; !ok {
		id.paths[path][traceId] = make(map[commType]map[pidType]map[tidType]map[flagsType]counter)
	}
	if _, ok := id.paths[path][traceId][comm]; !ok {
		id.paths[path][traceId][comm] = make(map[pidType]map[tidType]map[flagsType]counter)
	}
	if _, ok := id.paths[path][traceId][comm][pid]; !ok {
		id.paths[path][traceId][comm][pid] = make(map[tidType]map[flagsType]counter)
	}
	if _, ok := id.paths[path][traceId][comm][pid][tid]; !ok {
		id.paths[path][traceId][comm][pid][tid] = make(map[flagsType]counter)
	}
	if _, ok := id.paths[path][traceId][comm][pid][tid][flags]; !ok {
		id.paths[path][traceId][comm][pid][tid][flags] = cnt
	} else {
		// iorData.paths[path][traceId][comm][pid][tid][flags] += cnt
	}
}

func (id iorData) commit() error {
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
	return encoder.Encode(id.paths)
}
