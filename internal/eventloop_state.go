package internal

import (
	"sort"

	"ior/internal/event"
	"ior/internal/file"
)

type fdTracker struct {
	files map[int32]file.File
}

func newFDTracker(files map[int32]file.File) *fdTracker {
	if files == nil {
		files = make(map[int32]file.File)
	}
	return &fdTracker{files: files}
}

func (t *fdTracker) get(fd int32) (file.File, bool) {
	f, ok := t.files[fd]
	return f, ok
}

func (t *fdTracker) set(fd int32, f file.File) {
	t.files[fd] = f
}

func (t *fdTracker) delete(fd int32) {
	delete(t.files, fd)
}

func (t *fdTracker) closeRangeFrom(first int32) {
	for fd := range t.files {
		if fd >= first {
			delete(t.files, fd)
		}
	}
}

func (e *eventLoop) resolveFdFile(fd int32, pid uint32) file.File {
	if fdFile, ok := e.fdState().get(fd); ok {
		return fdFile
	}
	if fd < 0 {
		return file.NewFd(fd, "", -1)
	}

	if cached, ok := e.cachedProcFdFile(fd, pid); ok {
		return cached
	}

	// Cache first procfs resolution to avoid repeated /proc lookups for hot unknown FDs.
	discovered := file.NewFdWithPid(fd, pid)
	e.setProcFdCache(fd, pid, discovered)
	return discovered
}

func (e *eventLoop) cachedProcFdFile(fd int32, pid uint32) (*file.FdFile, bool) {
	key := procFdCacheKey(pid, fd)
	cache, ok := e.procFdCacheState()[key]
	if ok {
		e.procFdCacheAgeState()[key] = e.nextCacheAge()
	}
	return cache, ok
}

func (e *eventLoop) setProcFdCache(fd int32, pid uint32, resolved *file.FdFile) {
	key := procFdCacheKey(pid, fd)
	e.procFdCacheState()[key] = resolved
	e.procFdCacheAgeState()[key] = e.nextCacheAge()
	e.pruneProcFdCache()
}

func (e *eventLoop) deleteProcFdCache(fd int32, pid uint32) {
	e.deleteProcFdCacheKey(procFdCacheKey(pid, fd))
}

func (e *eventLoop) deleteProcFdCacheFrom(first int32, pid uint32) {
	cache := e.procFdCacheState()
	for key := range cache {
		cachePid := uint32(key >> 32)
		cacheFd := int32(uint32(key))
		if cachePid == pid && cacheFd >= first {
			e.deleteProcFdCacheKey(key)
		}
	}
}

func (e *eventLoop) procFdCacheState() map[uint64]*file.FdFile {
	if e.procFdCache == nil {
		e.procFdCache = make(map[uint64]*file.FdFile)
	}
	return e.procFdCache
}

func (e *eventLoop) procFdCacheAgeState() map[uint64]uint64 {
	if e.procFdCacheAges == nil {
		e.procFdCacheAges = make(map[uint64]uint64)
	}
	return e.procFdCacheAges
}

func (e *eventLoop) enterEventAgeState() map[uint32]uint64 {
	if e.enterEvAges == nil {
		e.enterEvAges = make(map[uint32]uint64)
	}
	return e.enterEvAges
}

func (e *eventLoop) enterEventState() map[uint32]*event.Pair {
	if e.enterEvs == nil {
		e.enterEvs = make(map[uint32]*event.Pair)
	}
	return e.enterEvs
}

func (e *eventLoop) setEnterEvent(enterEv event.Event) {
	tid := enterEv.GetTid()
	pair := event.NewPair(enterEv)
	if prev, ok := e.enterEventState()[tid]; ok && prev != nil {
		prev.Recycle()
	}
	e.enterEventState()[tid] = pair
	e.enterEventAgeState()[tid] = e.nextCacheAge()
	e.prunePendingEnterEvents()
}

func (e *eventLoop) consumeEnterEvent(tid uint32) (*event.Pair, bool) {
	pair, ok := e.enterEventState()[tid]
	if !ok {
		return nil, false
	}
	delete(e.enterEventState(), tid)
	delete(e.enterEventAgeState(), tid)
	return pair, true
}

func (e *eventLoop) prunePendingEnterEvents() {
	state := e.enterEventState()
	limit := e.pendingEnterLimit()
	if len(state) <= limit {
		return
	}
	trimOldestPendingPairs(state, e.enterEventAgeState(), trimTarget(limit))
}

func trimOldestPendingPairs(state map[uint32]*event.Pair, ages map[uint32]uint64, targetSize int) {
	excess := len(state) - targetSize
	if excess <= 0 {
		return
	}
	type pendingPairAge struct {
		tid uint32
		age uint64
	}
	oldest := make([]pendingPairAge, 0, len(state))
	for tid := range state {
		age := ages[tid]
		oldest = append(oldest, pendingPairAge{tid: tid, age: age})
	}
	sort.Slice(oldest, func(i, j int) bool { return oldest[i].age < oldest[j].age })
	for _, entry := range oldest[:excess] {
		if pair, ok := state[entry.tid]; ok && pair != nil {
			pair.Recycle()
		}
		delete(state, entry.tid)
		delete(ages, entry.tid)
	}
}

func (e *eventLoop) pruneProcFdCache() {
	state := e.procFdCacheState()
	limit := e.procFdCacheLimit()
	if len(state) <= limit {
		return
	}
	trimOldestProcFdEntries(state, e.procFdCacheAgeState(), trimTarget(limit))
}

func trimOldestProcFdEntries(state map[uint64]*file.FdFile, ages map[uint64]uint64, targetSize int) {
	excess := len(state) - targetSize
	if excess <= 0 {
		return
	}
	type procFdAge struct {
		key uint64
		age uint64
	}
	oldest := make([]procFdAge, 0, len(state))
	for key := range state {
		age := ages[key]
		oldest = append(oldest, procFdAge{key: key, age: age})
	}
	sort.Slice(oldest, func(i, j int) bool { return oldest[i].age < oldest[j].age })
	for _, entry := range oldest[:excess] {
		delete(state, entry.key)
		delete(ages, entry.key)
	}
}

func (e *eventLoop) deleteProcFdCacheKey(key uint64) {
	delete(e.procFdCacheState(), key)
	delete(e.procFdCacheAgeState(), key)
}

func (e *eventLoop) nextCacheAge() uint64 {
	e.cacheAge++
	return e.cacheAge
}

func (e *eventLoop) pendingEnterLimit() int {
	if e.maxPendingEnterEvs > 0 {
		return e.maxPendingEnterEvs
	}
	return defaultMaxPendingEnterEvs
}

func (e *eventLoop) procFdCacheLimit() int {
	if e.maxProcFdCacheSize > 0 {
		return e.maxProcFdCacheSize
	}
	return defaultMaxProcFdCacheSize
}

func trimTarget(limit int) int {
	target := limit - limit/cacheTrimDivisor
	if target < 1 {
		return 1
	}
	return target
}

func procFdCacheKey(pid uint32, fd int32) uint64 {
	return uint64(pid)<<32 | uint64(uint32(fd))
}
