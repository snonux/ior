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
