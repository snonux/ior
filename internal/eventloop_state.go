package internal

import (
	"cmp"
	"slices"

	"ior/internal/event"
	"ior/internal/file"
)

// fdTracker holds the traced processes' open file-descriptor tables and a
// procfs resolution cache for fds that were opened before tracing started.
//
// Both maps are keyed by (pid, fd) via fdKey, never by the bare descriptor
// number: a descriptor is only meaningful inside the process that owns it, and
// low numbers (3, 6, ...) are near-universal, so a flat fd key made whichever
// process registered last own the entry and printed its filename on every
// other process's rows - and let one process's close(6) evict another's
// mapping. The pid here is the tgid the kernel stamps on every event
// (bpf_get_current_pid_tgid() >> 32), which is exactly the granularity at
// which Linux shares a descriptor table between threads.
type fdTracker struct {
	files        map[uint64]file.File    // open descriptors, keyed by (pid, fd)
	fileAges     map[uint64]uint64       // access age per fd entry, for LRU eviction
	maxFiles     int                     // max fd entries before eviction; 0 = defaultMaxFdTableEntries
	procFdCache  map[uint64]*file.FdFile // procfs-resolved metadata for unknown FDs
	procFdAges   map[uint64]uint64       // access age per cache entry, for LRU eviction
	maxCacheSize int                     // max entries before eviction; 0 = defaultMaxProcFdCacheSize
	// pidPresent is a conservative over-approximation of the pids that own at
	// least one entry in either map: entries are added on set/setProcFdCache
	// and removed only by deletePid. A pid whose entries were all closed but
	// that has not exited yet stays in the set, so deletePid may scan a pid
	// with nothing left - never the reverse: an entry cannot exist for a pid
	// missing from the set. Its whole purpose is the common sched_process_exit
	// case: a task exit for a process that never registered a descriptor (most
	// tasks on a system-wide trace) becomes O(1) instead of a full scan of both
	// maps on the single event-loop goroutine.
	pidPresent map[uint32]struct{}
	age        uint64 // monotonic counter for LRU ordering
}

// pendingHandleTracker holds unresolved name_to_handle_at pathnames keyed by
// TID until the corresponding open_by_handle_at exit consumes them.
type pendingHandleTracker struct {
	paths        map[uint32]string
	pathAges     map[uint32]uint64
	maxCacheSize int
	age          uint64
}

// ensureInit makes any tracker usable: every map is allocated, and the
// pid-presence set is seeded from whatever entries already exist. It is the
// one place the tracker's map representation and invariants are spelled
// out for the hand-built / injected case (the constructors produce fully
// usable trackers, and the individual mutators lazily allocate their own
// map, so the zero value is safe - but a hand-built tracker carrying
// entries without a presence set would make deletePid's nil-set guard
// silently skip eviction, which is what the seeding closes).
//
// Unlike newFDTracker, ensureInit does NOT stamp LRU ages for pre-existing
// files - those entries keep age 0 and evict first until touched, exactly
// the behaviour the old configuredFDTracker had for hand-built trackers.
// The constructors add the insertion-order stamping (see newFDTracker).
func (t *fdTracker) ensureInit() {
	if t.files == nil {
		t.files = make(map[uint64]file.File)
	}
	if t.fileAges == nil {
		// Pre-sized to the injected entry count: the constructors are the hot
		// path here, and the old code pre-allocated the same capacity.
		t.fileAges = make(map[uint64]uint64, len(t.files))
	}
	if t.procFdCache == nil {
		t.procFdCache = make(map[uint64]*file.FdFile)
	}
	if t.procFdAges == nil {
		t.procFdAges = make(map[uint64]uint64)
	}
	if t.pidPresent == nil {
		pidPresent := make(map[uint32]struct{})
		for key := range t.files {
			pid, _ := fdKeyParts(key)
			pidPresent[pid] = struct{}{}
		}
		for key := range t.procFdCache {
			pid, _ := fdKeyParts(key)
			pidPresent[pid] = struct{}{}
		}
		t.pidPresent = pidPresent
	}
}

func newFDTracker(files map[uint64]file.File) *fdTracker {
	t := &fdTracker{files: files}
	t.ensureInit()
	// An injected map comes with no ages, so stamp insertion order here:
	// ages of zero would otherwise make the LRU order degenerate on the
	// first eviction under the cap.
	if len(t.fileAges) < len(t.files) {
		age := uint64(0)
		for key := range t.files {
			age++
			t.fileAges[key] = age
		}
	}
	return t
}

func newPendingHandleTracker() *pendingHandleTracker {
	t := &pendingHandleTracker{}
	t.ensureInit()
	return t
}

// ensureInit makes any pending-handle tracker usable by allocating its maps.
// The constructor and the set() method both go through it, so a zero value
// is safe too; the method exists so the loop's injection seam
// (configured* helpers) can complete a hand-built tracker without spelling
// out its map fields.
func (t *pendingHandleTracker) ensureInit() {
	if t.paths == nil {
		t.paths = make(map[uint32]string)
	}
	if t.pathAges == nil {
		t.pathAges = make(map[uint32]uint64)
	}
}

func (t *fdTracker) get(fd int32, pid uint32) (file.File, bool) {
	key := fdKey(pid, fd)
	f, ok := t.files[key]
	if ok {
		// Entries can only be created by set, which allocates fileAges, but a
		// directly-constructed tracker could hold a files entry without ages
		// metadata - guard so a hit can never panic on the nil map.
		if t.fileAges == nil {
			t.fileAges = make(map[uint64]uint64)
		}
		t.age++
		t.fileAges[key] = t.age
	}
	return f, ok
}

func (t *fdTracker) set(fd int32, pid uint32, f file.File) {
	if t.files == nil {
		t.files = make(map[uint64]file.File)
	}
	if t.fileAges == nil {
		t.fileAges = make(map[uint64]uint64)
	}
	if t.pidPresent == nil {
		t.pidPresent = make(map[uint32]struct{})
	}
	key := fdKey(pid, fd)
	t.age++
	t.files[key] = f
	t.fileAges[key] = t.age
	t.pidPresent[pid] = struct{}{}
	t.pruneFiles()
}

func (t *fdTracker) delete(fd int32, pid uint32) {
	key := fdKey(pid, fd)
	delete(t.files, key)
	delete(t.fileAges, key)
}

// closeRange removes pid's tracked fds in the inclusive range [first, last], as
// closed by close_range(2). A negative last means "no upper bound": close_range's
// last argument is an unsigned int, so the common close-everything form ~0U
// arrives here as a negative __s32 and must close every tracked fd >= first.
// Only the calling process's descriptors are evicted: close_range cannot touch
// another process's table, and evicting by bare fd number dropped unrelated
// processes' still-open mappings.
func (t *fdTracker) closeRange(first, last int32, pid uint32) {
	for _, key := range fdKeysInRange(t.files, first, last, pid) {
		delete(t.files, key)
		delete(t.fileAges, key)
	}
}

// addFlagsRange adds descriptor flags to pid's tracked fds in the inclusive
// range [first, last]. It updates both authoritative entries and cached procfs
// resolutions because either may satisfy the next lookup.
func (t *fdTracker) addFlagsRange(first, last int32, pid uint32, flags int32) {
	for _, key := range fdKeysInRange(t.files, first, last, pid) {
		if fdFile, ok := t.files[key].(*file.FdFile); ok {
			fdFile.AddFlags(flags)
		}
	}
	for _, key := range fdKeysInRange(t.procFdCache, first, last, pid) {
		t.procFdCache[key].AddFlags(flags)
	}
}

// deletePid removes every entry of pid from the fd table and the procfs
// cache. Called from handleProcessExitEvent on a sched_process_exit control
// record: a process that exited owns no descriptors anymore, so its slice of
// the (pid, fd) key space is pure garbage until this runs. Scanning the maps
// is O(size), but the pidPresent set skips the common case - a task exit for a
// process that never registered a descriptor - in O(1); a present pid may
// still have nothing left (its entries were closed, it has not exited yet,
// but another of its threads exits), which only costs the scan it would have
// paid anyway. The alternative (a pid-indexed secondary map updated on every
// set/delete) would add a map mutation to the per-syscall hot path.
func (t *fdTracker) deletePid(pid uint32) {
	if t.pidPresent == nil {
		return
	}
	if _, ok := t.pidPresent[pid]; !ok {
		return
	}
	for _, key := range pidKeys(t.files, pid) {
		delete(t.files, key)
		delete(t.fileAges, key)
	}
	for _, key := range pidKeys(t.procFdCache, pid) {
		t.deleteCacheKey(key)
	}
	delete(t.pidPresent, pid)
}

// dropOnExec forgets the descriptors of pid that a successful execve(2) closed.
// Called from handleProcessExecEvent on a sched_process_exec control record:
// the kernel closes every FD_CLOEXEC descriptor of the exec'ing process
// (do_close_on_exec), so an entry that stayed here would keep labelling the
// new program's rows with the old program's file whenever it reuses that
// descriptor number through a syscall ior does not trace (socket, recvmsg
// SCM_RIGHTS, ... under the default FS-only trace set).
//
// Only pid's slice is touched. Threads share their process's table and all
// but the exec'ing one are killed by de_thread, and the table is keyed by
// tgid; a process sharing the table via CLONE_FILES without being a thread
// gets its own copy before the closes (unshare_files in begin_new_exec), so
// its entries, keyed by its own tgid, are unaffected.
//
// The fd table keeps an entry only when its close-on-exec state is known to
// be clear (survivesExec). Unknown state is dropped on purpose: the costs are
// asymmetric. Dropping a descriptor that in fact survived costs one lazy
// procfs re-resolution on its next use (resolve -> /proc/<pid>/fd/<fd>),
// which answers correctly for a live descriptor; keeping one the kernel
// closed mislabels every later row on that number with a name procfs would
// never have reported.
//
// The procfs cache is dropped for pid wholesale. Its entries are snapshots
// taken at first use - possibly an empty name for a descriptor that did not
// exist yet - so their close-on-exec bit is no stronger than a guess about
// the current table, and re-reading procfs after exec is cheap and exact.
//
// pidPresent is left alone: it may over-approximate (see its field comment),
// and a surviving entry must keep pid registered for deletePid.
func (t *fdTracker) dropOnExec(pid uint32) {
	if t.pidPresent == nil {
		return
	}
	if _, ok := t.pidPresent[pid]; !ok {
		return
	}
	for _, key := range pidKeys(t.files, pid) {
		if !survivesExec(t.files[key]) {
			delete(t.files, key)
			delete(t.fileAges, key)
		}
	}
	for _, key := range pidKeys(t.procFdCache, pid) {
		t.deleteCacheKey(key)
	}
}

// survivesExec reports whether a tracked descriptor is known to stay open
// across execve(2): only an *FdFile whose FD_CLOEXEC state is known and clear
// qualifies. Any other File, or an unknown state, counts as closed (see
// dropOnExec for why unknown resolves that way).
func survivesExec(f file.File) bool {
	fdFile, ok := f.(*file.FdFile)
	if !ok {
		return false
	}
	set, known := fdFile.CloseOnExec()
	return known && !set
}

// pidKeys returns the composite keys of m that belong to pid. Collected first
// so the caller can delete while iterating (see fdKeysInRange).
func pidKeys[V any](m map[uint64]V, pid uint32) []uint64 {
	var keys []uint64
	for key := range m {
		if keyPid, _ := fdKeyParts(key); keyPid == pid {
			keys = append(keys, key)
		}
	}
	return keys
}

// pruneFiles evicts the least recently used fd entries once the table exceeds
// its cap. Unlike the flat map this replaced, the (pid, fd) key space grows
// with the number of traced processes and nothing reclaims the entries of a
// process that exited (see the note on defaultMaxFdTableEntries), so the cap is
// what bounds it. Eviction is safe rather than merely lossy: resolve falls back
// to the procfs cache and then to /proc/<pid>/fd, which still answers correctly
// for a descriptor that is genuinely still open.
func (t *fdTracker) pruneFiles() {
	limit := t.filesLimit()
	if len(t.files) <= limit {
		return
	}
	trimOldestFdEntries(t.files, t.fileAges, trimTarget(limit))
}

func (t *fdTracker) filesLimit() int {
	if t.maxFiles > 0 {
		return t.maxFiles
	}
	return defaultMaxFdTableEntries
}

// resolve returns the file.File for fd, checking the fd table first, then the
// procfs cache, and finally resolving via procfs and caching the result.
func (t *fdTracker) resolve(fd int32, pid uint32) file.File {
	if fdFile, ok := t.get(fd, pid); ok {
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
	key := fdKey(pid, fd)
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
	if t.pidPresent == nil {
		t.pidPresent = make(map[uint32]struct{})
	}
	key := fdKey(pid, fd)
	t.age++
	t.procFdCache[key] = resolved
	t.procFdAges[key] = t.age
	t.pidPresent[pid] = struct{}{}
	t.pruneCache()
}

func (t *fdTracker) deleteProcFdCache(fd int32, pid uint32) {
	t.deleteCacheKey(fdKey(pid, fd))
}

// deleteProcFdCacheRange drops cached procfs resolutions for pid's fds in the
// inclusive range [first, last]. A negative last means "no upper bound" (see
// closeRange for why close_range's last argument can arrive negative).
func (t *fdTracker) deleteProcFdCacheRange(first, last int32, pid uint32) {
	for _, key := range fdKeysInRange(t.procFdCache, first, last, pid) {
		t.deleteCacheKey(key)
	}
}

// fdKeysInRange returns the keys of m that belong to pid and whose descriptor
// number falls in the inclusive range [first, last]; a negative last means "no
// upper bound" (see closeRange for why close_range's last argument can arrive
// negative). A negative first means the opposite extreme: close_range's first
// argument is unsigned too, so a value above INT32_MAX wraps negative, and no
// descriptor number can be >= it - the range closes nothing. Collecting first
// keeps the caller from deleting while ranging over its own map through a
// helper.
func fdKeysInRange[V any](m map[uint64]V, first, last int32, pid uint32) []uint64 {
	if first < 0 {
		return nil
	}
	var keys []uint64
	for key := range m {
		keyPid, keyFd := fdKeyParts(key)
		if keyPid != pid || keyFd < first {
			continue
		}
		if last >= 0 && keyFd > last {
			continue
		}
		keys = append(keys, key)
	}
	return keys
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
	enters       map[uint32]*event.Pair // pending enter events, keyed by TID
	enterAges    map[uint32]uint64      // insertion order per TID, for LRU eviction
	prevTimes    map[uint32]uint64      // previous pair's exit time per TID, for DurationToPrev
	prevTimeAges map[uint32]uint64      // insertion order per TID, for prevTimes LRU eviction
	maxSize      int                    // max pending enter events before pruning; 0 = default
	age          uint64                 // monotonic counter for LRU ordering
}

func newPairTracker() pairTracker {
	return pairTracker{
		enters:       make(map[uint32]*event.Pair),
		enterAges:    make(map[uint32]uint64),
		prevTimes:    make(map[uint32]uint64),
		prevTimeAges: make(map[uint32]uint64),
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
		p.prevTimeAges = make(map[uint32]uint64)
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

// evictTid drops every trace the tracker still holds for a task the kernel
// reported dead: its parked enter event, if it was killed inside a syscall so
// that no sys_exit will ever arrive for it, and its previous-exit timestamp.
//
// Both maps are keyed by tid and the kernel hands tid numbers out again, so an
// entry that outlives its owner belongs to whichever task is handed that
// number next. Leaving the enter behind is worse than a stale label: the next
// owner's exit consumes it and the pair is emitted with the dead task's
// filename, arguments and enter timestamp - a row for a syscall that never
// happened. Leaving prevTimes behind gives the new owner's first pair a
// DurationToPrev measured from the dead task's last syscall, which -gap
// filters on.
//
// The parked enter is recycled rather than emitted; see handleProcessExitEvent
// for why dropping it is the only truthful option and why it is not counted.
func (p *pairTracker) evictTid(tid uint32) {
	if pair, ok := p.consume(tid); ok && pair != nil {
		pair.Recycle()
	}
	delete(p.prevTimes, tid)
	delete(p.prevTimeAges, tid)
}

// pending returns the still-unmatched enter pair for tid without consuming it,
// so a control record can amend the enter event in place before its exit
// arrives (handleOpenNameFixupEvent). It deliberately does not touch the LRU
// age: peeking is not use, and letting a fixup refresh the entry would let a
// stream of them keep genuinely stale enters alive.
func (p *pairTracker) pending(tid uint32) (*event.Pair, bool) {
	pair, ok := p.enters[tid]
	if !ok || pair == nil {
		return nil, false
	}
	return pair, true
}

// prevTime returns the exit time of the previous pair for tid, used to compute DurationToPrev.
func (p *pairTracker) prevTime(tid uint32) uint64 {
	return p.prevTimes[tid]
}

// setPrevTime records the exit time of the most recent completed pair for tid
// and ages the entry for LRU eviction, so the map stays bounded on
// thread-churning traces where TIDs are never reused.
func (p *pairTracker) setPrevTime(tid uint32, t uint64) {
	if p.prevTimes == nil {
		p.prevTimes = make(map[uint32]uint64)
		p.prevTimeAges = make(map[uint32]uint64)
	}
	p.age++
	p.prevTimes[tid] = t
	p.prevTimeAges[tid] = p.age
	p.prunePrevTimes()
}

// prunePrevTimes evicts the oldest prevTimes entries when over the limit,
// keeping the per-TID duration metadata bounded like the pending enters.
func (p *pairTracker) prunePrevTimes() {
	limit := p.limit()
	if len(p.prevTimes) <= limit {
		return
	}
	trimLRU(p.prevTimes, p.prevTimeAges, trimTarget(limit), nil)
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

// trimLRU evicts the oldest entries from state (and their corresponding ages
// entries) until len(state) == targetSize. Keys are compared by their age
// value in ages; smaller age means older. The optional cleanup callback is
// called with each evicted value before it is removed from state — use it to
// recycle pooled objects (e.g. event.Pair.Recycle).
func trimLRU[K comparable, V any](state map[K]V, ages map[K]uint64, targetSize int, cleanup func(V)) {
	excess := len(state) - targetSize
	if excess <= 0 {
		return
	}
	type entry struct {
		key K
		age uint64
	}
	oldest := make([]entry, 0, len(state))
	for k := range state {
		oldest = append(oldest, entry{key: k, age: ages[k]})
	}
	slices.SortFunc(oldest, func(a, b entry) int { return cmp.Compare(a.age, b.age) })
	for _, e := range oldest[:excess] {
		if cleanup != nil {
			cleanup(state[e.key])
		}
		delete(state, e.key)
		delete(ages, e.key)
	}
}

func trimOldestPendingPairs(state map[uint32]*event.Pair, ages map[uint32]uint64, targetSize int) {
	// Recycle evicted pairs back to the pool before deletion.
	trimLRU(state, ages, targetSize, func(pair *event.Pair) {
		if pair != nil {
			pair.Recycle()
		}
	})
}

func trimOldestProcFdEntries(state map[uint64]*file.FdFile, ages map[uint64]uint64, targetSize int) {
	trimLRU(state, ages, targetSize, nil)
}

func trimOldestFdEntries(state map[uint64]file.File, ages map[uint64]uint64, targetSize int) {
	trimLRU(state, ages, targetSize, nil)
}

func trimOldestPendingHandles(state map[uint32]string, ages map[uint32]uint64, targetSize int) {
	trimLRU(state, ages, targetSize, nil)
}

func trimTarget(limit int) int {
	target := limit - limit/cacheTrimDivisor
	if target < 1 {
		return 1
	}
	return target
}

// fdKey packs a (pid, fd) pair into the composite key used by both fdTracker
// maps. fd is folded through uint32 so negative descriptor numbers round-trip.
func fdKey(pid uint32, fd int32) uint64 {
	return uint64(pid)<<32 | uint64(uint32(fd))
}

// fdKeyParts is the inverse of fdKey.
func fdKeyParts(key uint64) (uint32, int32) {
	return uint32(key >> 32), int32(uint32(key))
}
