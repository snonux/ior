package internal

import (
	"cmp"
	"slices"

	"ior/internal/event"
	"ior/internal/file"
)

// fdTracker holds the process's open file-descriptor table and a procfs
// resolution cache for fds that were opened before tracing started.
type fdTracker struct {
	files        map[int32]file.File
	procFdCache  map[uint64]*file.FdFile // procfs-resolved metadata for unknown FDs
	procFdAges   map[uint64]uint64       // access age per cache entry, for LRU eviction
	maxCacheSize int                     // max entries before eviction; 0 = defaultMaxProcFdCacheSize
	age          uint64                  // monotonic counter for LRU ordering
}

// pendingHandleTracker holds unresolved name_to_handle_at pathnames keyed by
// TID until the corresponding open_by_handle_at exit consumes them.
type pendingHandleTracker struct {
	paths        map[uint32]string
	pathAges     map[uint32]uint64
	maxCacheSize int
	age          uint64
}

func newFDTracker(files map[int32]file.File) *fdTracker {
	if files == nil {
		files = make(map[int32]file.File)
	}
	return &fdTracker{
		files:       files,
		procFdCache: make(map[uint64]*file.FdFile),
		procFdAges:  make(map[uint64]uint64),
	}
}

func newPendingHandleTracker() *pendingHandleTracker {
	return &pendingHandleTracker{
		paths:    make(map[uint32]string),
		pathAges: make(map[uint32]uint64),
	}
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

// resolve returns the file.File for fd, checking the fd table first, then the
// procfs cache, and finally resolving via procfs and caching the result.
func (t *fdTracker) resolve(fd int32, pid uint32) file.File {
	if fdFile, ok := t.get(fd); ok {
		return fdFile
	}
	if fd < 0 {
		return file.NewFd(fd, "", -1)
	}
	if cached, ok := t.cachedProcFdFile(fd, pid); ok {
		return cached
	}
	// Cache first procfs resolution to avoid repeated /proc lookups for hot unknown FDs.
	discovered := file.NewFdWithPid(fd, pid)
	t.setProcFdCache(fd, pid, discovered)
	return discovered
}

func (t *fdTracker) cachedProcFdFile(fd int32, pid uint32) (*file.FdFile, bool) {
	if t.procFdCache == nil {
		return nil, false
	}
	key := procFdCacheKey(pid, fd)
	cache, ok := t.procFdCache[key]
	if ok {
		t.age++
		t.procFdAges[key] = t.age
	}
	return cache, ok
}

func (t *fdTracker) setProcFdCache(fd int32, pid uint32, resolved *file.FdFile) {
	if t.procFdCache == nil {
		t.procFdCache = make(map[uint64]*file.FdFile)
		t.procFdAges = make(map[uint64]uint64)
	}
	key := procFdCacheKey(pid, fd)
	t.age++
	t.procFdCache[key] = resolved
	t.procFdAges[key] = t.age
	t.pruneCache()
}

func (t *fdTracker) deleteProcFdCache(fd int32, pid uint32) {
	t.deleteCacheKey(procFdCacheKey(pid, fd))
}

func (t *fdTracker) deleteProcFdCacheFrom(first int32, pid uint32) {
	if t.procFdCache == nil {
		return
	}
	for key := range t.procFdCache {
		cachePid := uint32(key >> 32)
		cacheFd := int32(uint32(key))
		if cachePid == pid && cacheFd >= first {
			t.deleteCacheKey(key)
		}
	}
}

func (t *fdTracker) pruneCache() {
	if t.procFdCache == nil {
		return
	}
	limit := t.cacheLimit()
	if len(t.procFdCache) <= limit {
		return
	}
	trimOldestProcFdEntries(t.procFdCache, t.procFdAges, trimTarget(limit))
}

func (t *fdTracker) cacheLimit() int {
	if t.maxCacheSize > 0 {
		return t.maxCacheSize
	}
	return defaultMaxProcFdCacheSize
}

// deleteCacheKey removes a cache entry by its composite key.
// delete on a nil map is a no-op in Go, so this is safe even before any cache entries are set.
func (t *fdTracker) deleteCacheKey(key uint64) {
	delete(t.procFdCache, key)
	delete(t.procFdAges, key)
}

func (t *pendingHandleTracker) set(tid uint32, pathname string) {
	if t.paths == nil {
		t.paths = make(map[uint32]string)
		t.pathAges = make(map[uint32]uint64)
	}
	t.age++
	t.paths[tid] = pathname
	t.pathAges[tid] = t.age
	t.prune()
}

func (t *pendingHandleTracker) consume(tid uint32) (string, bool) {
	pathname, ok := t.paths[tid]
	if !ok {
		return "", false
	}
	delete(t.paths, tid)
	delete(t.pathAges, tid)
	return pathname, true
}

func (t *pendingHandleTracker) delete(tid uint32) {
	delete(t.paths, tid)
	delete(t.pathAges, tid)
}

func (t *pendingHandleTracker) prune() {
	if t.paths == nil {
		return
	}
	limit := t.limit()
	if len(t.paths) <= limit {
		return
	}
	trimOldestPendingHandles(t.paths, t.pathAges, trimTarget(limit))
}

func (t *pendingHandleTracker) limit() int {
	if t.maxCacheSize > 0 {
		return t.maxCacheSize
	}
	return defaultMaxPendingHandleEntries
}

// pairTracker holds the state for matching sys_enter events to their sys_exit
// counterparts and computing inter-syscall durations per TID.
type pairTracker struct {
	enters    map[uint32]*event.Pair // pending enter events, keyed by TID
	enterAges map[uint32]uint64      // insertion order per TID, for LRU eviction
	prevTimes map[uint32]uint64      // previous pair's exit time per TID, for DurationToPrev
	maxSize   int                    // max pending enter events before pruning; 0 = default
	age       uint64                 // monotonic counter for LRU ordering
}

func newPairTracker() pairTracker {
	return pairTracker{
		enters:    make(map[uint32]*event.Pair),
		enterAges: make(map[uint32]uint64),
		prevTimes: make(map[uint32]uint64),
	}
}

// set stores enterEv as a pending enter event for its TID, recycling any
// prior unmatched enter for the same TID, then prunes if over the limit.
// Maps are initialized lazily on first write; consume is safe on a nil map because
// Go map reads on nil return the zero value.
func (p *pairTracker) set(enterEv event.Event) {
	if p.enters == nil {
		p.enters = make(map[uint32]*event.Pair)
		p.enterAges = make(map[uint32]uint64)
		p.prevTimes = make(map[uint32]uint64)
	}
	tid := enterEv.GetTid()
	pair := event.NewPair(enterEv)
	if prev, ok := p.enters[tid]; ok && prev != nil {
		prev.Recycle()
	}
	p.age++
	p.enters[tid] = pair
	p.enterAges[tid] = p.age
	p.prune()
}

// consume removes and returns the pending enter pair for tid.
// Reading a nil map returns the zero value in Go, so this is safe before any set call.
func (p *pairTracker) consume(tid uint32) (*event.Pair, bool) {
	pair, ok := p.enters[tid]
	if !ok {
		return nil, false
	}
	delete(p.enters, tid)
	delete(p.enterAges, tid)
	return pair, true
}

// prevTime returns the exit time of the previous pair for tid, used to compute DurationToPrev.
func (p *pairTracker) prevTime(tid uint32) uint64 {
	return p.prevTimes[tid]
}

// setPrevTime records the exit time of the most recent completed pair for tid.
func (p *pairTracker) setPrevTime(tid uint32, t uint64) {
	if p.prevTimes == nil {
		p.prevTimes = make(map[uint32]uint64)
	}
	p.prevTimes[tid] = t
}

func (p *pairTracker) prune() {
	limit := p.limit()
	if len(p.enters) <= limit {
		return
	}
	trimOldestPendingPairs(p.enters, p.enterAges, trimTarget(limit))
}

func (p *pairTracker) limit() int {
	if p.maxSize > 0 {
		return p.maxSize
	}
	return defaultMaxPendingEnterEvs
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
		oldest = append(oldest, pendingPairAge{tid: tid, age: ages[tid]})
	}
	slices.SortFunc(oldest, func(a, b pendingPairAge) int { return cmp.Compare(a.age, b.age) })
	for _, entry := range oldest[:excess] {
		if pair, ok := state[entry.tid]; ok && pair != nil {
			pair.Recycle()
		}
		delete(state, entry.tid)
		delete(ages, entry.tid)
	}
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
		oldest = append(oldest, procFdAge{key: key, age: ages[key]})
	}
	slices.SortFunc(oldest, func(a, b procFdAge) int { return cmp.Compare(a.age, b.age) })
	for _, entry := range oldest[:excess] {
		delete(state, entry.key)
		delete(ages, entry.key)
	}
}

func trimOldestPendingHandles(state map[uint32]string, ages map[uint32]uint64, targetSize int) {
	excess := len(state) - targetSize
	if excess <= 0 {
		return
	}
	type pendingHandleAge struct {
		tid uint32
		age uint64
	}
	oldest := make([]pendingHandleAge, 0, len(state))
	for tid := range state {
		oldest = append(oldest, pendingHandleAge{tid: tid, age: ages[tid]})
	}
	slices.SortFunc(oldest, func(a, b pendingHandleAge) int { return cmp.Compare(a.age, b.age) })
	for _, entry := range oldest[:excess] {
		delete(state, entry.tid)
		delete(ages, entry.tid)
	}
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
