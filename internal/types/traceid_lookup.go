package types

import (
	"strings"
	"sync"
)

var (
	enterTraceByNameOnce sync.Once
	enterTraceByName     map[string]TraceId
	enterTraceIDsOnce    sync.Once
	enterTraceIDs        []TraceId
)

// EnterTraceIDByName resolves a syscall name (for example, "futex") to the
// corresponding sys_enter trace ID.
func EnterTraceIDByName(name string) (TraceId, bool) {
	enterTraceByNameOnce.Do(initEnterTraceByName)
	id, ok := enterTraceByName[strings.ToLower(strings.TrimSpace(name))]
	return id, ok
}

func initEnterTraceByName() {
	enterTraceByName = make(map[string]TraceId)
	for traceID, name := range traceId2Name {
		if !strings.HasPrefix(traceID.String(), "enter_") {
			continue
		}
		enterTraceByName[strings.ToLower(name)] = traceID
	}
}

// EnterTraceIDs returns all known sys_enter trace IDs.
func EnterTraceIDs() []TraceId {
	enterTraceIDsOnce.Do(initEnterTraceIDs)
	return append([]TraceId(nil), enterTraceIDs...)
}

func initEnterTraceIDs() {
	enterTraceIDs = make([]TraceId, 0, len(traceId2Name)/2)
	for traceID := range traceId2Name {
		if strings.HasPrefix(traceID.String(), "enter_") {
			enterTraceIDs = append(enterTraceIDs, traceID)
		}
	}
}

// traceIdByString is the inverse of traceId2String ("enter_openat" -> ID). It
// is built at package initialisation (Go orders it after traceId2String), so
// no locking is needed. The tracepoint string, unlike the numeric ID, is stable
// across ior releases and kernels: the IDs are the generation host's kernel
// event IDs and change whenever the tracepoint set does, which is why
// persisted data must carry the string and resolve it back with this lookup.
var traceIdByString = invertTraceIdStrings()

func invertTraceIdStrings() map[string]TraceId {
	m := make(map[string]TraceId, len(traceId2String))
	for id, name := range traceId2String {
		m[name] = id
	}
	return m
}

// TraceIDByString resolves a full tracepoint string as returned by
// TraceId.String (for example "enter_openat" or "exit_openat") to the trace ID
// this build uses for it.
func TraceIDByString(name string) (TraceId, bool) {
	id, ok := traceIdByString[name]
	return id, ok
}
