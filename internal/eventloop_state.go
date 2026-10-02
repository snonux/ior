package internal

import (
	"cmp"
	"slices"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/types"
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
//
// A tgid is not always the owner of its table, though: two processes that
// clone(CLONE_FILES) share one. The pid every method takes is therefore
// translated to a *table id* first (tableID, see eventloop_fdshare.go): the
// tgid itself for an ordinary process, the tgid of the table's holder for a
// CLONE_FILES sharer, so the sharers read and write the same entries. The pid is
// still the real one for procfs reads (/proc/<pid>/fd serves every sharer the
// shared table). Not modelled, for lack of a signal that names them: a table a
// *thread* made private with unshare(CLONE_FILES) (a null-kind syscall record
// without its flags) and, under -tid, the writes of sibling threads the filter
// hides - see AGENTS.md.
type fdTracker struct {
	files        map[uint64]file.File    // open descriptors, keyed by (pid, fd)
	fileAges     map[uint64]uint64       // access age per fd entry, for LRU eviction
	maxFiles     int                     // max fd entries before eviction; 0 = defaultMaxFdTableEntries
	procFdCache  map[uint64]*file.FdFile // procfs-resolved metadata for unknown FDs
	procFdAges   map[uint64]uint64       // access age per cache entry, for LRU eviction
	maxCacheSize int                     // max entries before eviction; 0 = defaultMaxProcFdCacheSize
	// procFdReadAt is when each cache entry's readlink returned, on the host's
	// boot clock, the scale of the BPF record timestamps (bootClockNs takes a
	// time namespace's offset out of the reading; absent: unknown). A
	// close row may use a cache entry only if it was read before the close
	// entered (task jr2, eventloop_procfs_close.go). It lives beside the cache
	// rather than in file.FdFile so the per-row files keep their size.
	procFdReadAt map[uint64]uint64
	// pidIndex maps each pid to the exact set of its keys in files and in
	// procFdCache. The per-process operations - the exec record's dropOnExec,
	// the exit record's deletePid, close_range's closeRange and friends - run
	// on the single event-loop goroutine, and scanning both capped maps
	// (32768 + 8192 entries) for every one of them cost about a millisecond
	// per exec or exit; through the index they cost O(descriptors of that
	// pid). The index is exact, not an over-approximation: every insertion
	// goes through set/setProcFdCache (indexFileKey/indexCacheKey) and every
	// removal (close, exit, exec, LRU eviction) through
	// removeFileKey/deleteCacheKey, and a pid whose sets both become empty is
	// dropped from the index.
	pidIndex map[uint32]*pidFdKeys
	// idlePidKeys recycles the pidFdKeys of pids that just lost their last
	// entry. Without it a process that keeps opening and closing its only
	// tracked descriptor - a common pattern - would allocate a fresh entry and
	// its map on every open; with it, that churn, and a short-lived process
	// replacing one that exited, reuse the emptied entry. A parked entry only
	// ever holds small sets (maxRecycledSetSize bounds each one); the
	// maxIdlePidKeys cap only bounds how many entries are parked.
	idlePidKeys []*pidFdKeys
	age         uint64 // monotonic counter for LRU ordering
	// inheritSkipped counts forks whose parent held more than
	// maxInheritedEntries fd-table plus procfs-cache entries, or whose copy
	// would not fit in ior's tracker maps (filesLimit/cacheLimit; see
	// inheritFits), and so passed none on (see inherit; copyTable also counts
	// the same skip for an exec or CLOSE_RANGE_UNSHARE leaving a shared
	// table). Printed in the end-of-run statistics when non-zero
	// (eventLoop.fdCopySkipStatLine).
	inheritSkipped uint64
	// share maps the tgids that share a table (CLONE_FILES) onto it, and
	// records the tables no longer tracked because an invisible task writes them.
	share fdTableShare
}

// maxIdlePidKeys bounds how many emptied entries fdTracker.idlePidKeys holds.
// A handful covers a few processes opening and closing concurrently; further
// emptied entries are left to the garbage collector. The size of each parked
// set is bounded separately, by maxRecycledSetSize.
const maxIdlePidKeys = 16

// maxRecycledSetSize is the largest peak size a pidFdKeys set may have
// reached and still be kept when its entry is parked on idlePidKeys. Go maps
// never shrink and ranging over one costs O(allocated buckets), not O(len):
// reusing the emptied set of a process that once held 30k descriptors would
// make every later short-lived pid's exec/exit scan those buckets (~100us
// instead of ~0.5us), permanently, since parked entries are reused LIFO.
// Sets that ever grew past this are discarded on parking and re-allocated
// lazily; 64 covers the typical process (stdio, a few files and sockets).
// The same threshold decides when a live pid's set is worth shrinking (see
// shrinkKeySet).
const maxRecycledSetSize = 64

// pidFdKeys is one pid's slice of the fdTracker key space: the fdKey keys it
// owns in the fd table and in the procfs cache. Each set is allocated on
// first use, so a pid that only ever appears in one map costs one map. The
// peak fields record the largest size each set reached since it was
// allocated (or last rebuilt); shrinkKeySet and parkPidEntry use them to
// tell an oversized bucket array from a small one (see maxRecycledSetSize).
type pidFdKeys struct {
	files     map[uint64]struct{}
	cache     map[uint64]struct{}
	peakFiles int
	peakCache int
}

// handleKey identifies a file handle the way the kernel does: by the type the
// filesystem encoded it with and the size bytes that are the handle. It is the
// key the name of a handle is filed under, and it is comparable, so two
// records carry the same handle exactly when their keys are equal. bytes past
// size are always zero (handleKeyOf), which is what makes that hold.
//
// The mount is deliberately not part of the key; see handleKeyOf.
type handleKey struct {
	handleType int32
	size       uint32
	bytes      [types.IOR_MAX_HANDLE_SZ]byte
}

// takenHandle is the handle a name_to_handle_at returned, parked under the
// calling thread from the FILE_HANDLE_EVENT control record until the call's
// exit record claims it. time is the control record's, which equals the exit
// record's (both are the BPF exit handler's single clock read).
type takenHandle struct {
	key  handleKey
	time uint64
}

// handleTracker remembers which pathname a file handle was taken of, so that
// an open_by_handle_at can be named after the file its handle belongs to.
//
// names is keyed by the handle itself, not by a thread or process: a handle is
// valid system-wide, is routinely passed to another thread or process, and can
// be opened any number of times, so an entry is never consumed by an open. It
// is replaced when name_to_handle_at returns the same handle again (the latest
// name wins) and evicted least-recently-used first above the cap; a lookup
// counts as use.
//
// taken is the short-lived per-thread half: see takenHandle. An entry normally
// lives from the control record to the exit record a few records later, and
// is dropped with its thread (dropTaken). One whose exit record was lost
// stays until the thread's next name_to_handle_at exit, which discards it
// because the times differ.
type handleTracker struct {
	names        map[handleKey]string
	nameAges     map[handleKey]uint64
	taken        map[uint32]takenHandle
	maxCacheSize int
	age          uint64
}

// ensureInit makes any tracker usable: every map is allocated, and the
// per-pid index is built from whatever entries already exist. It is the
// one place the tracker's map representation and invariants are spelled
// out for the hand-built / injected case (the constructors produce fully
// usable trackers, and the individual mutators lazily allocate their own
// map, so the zero value is safe - but a hand-built tracker carrying
// entries without an index would make the per-pid operations, which only
// consult the index, silently skip them; the seeding closes that).
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
	if t.procFdReadAt == nil {
		t.procFdReadAt = make(map[uint64]uint64)
	}
	if t.pidIndex == nil {
		t.pidIndex = make(map[uint32]*pidFdKeys)
		for key := range t.files {
			t.indexFileKey(key)
		}
		for key := range t.procFdCache {
			t.indexCacheKey(key)
		}
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

func newHandleTracker() *handleTracker {
	t := &handleTracker{}
	t.ensureInit()
	return t
}

// ensureInit makes any handle tracker usable by allocating its maps. The
// constructor and the mutators all go through it, so a zero value is safe
// too; the method exists so the loop's injection seam (configured* helpers)
// can complete a hand-built tracker without spelling out its map fields.
func (t *handleTracker) ensureInit() {
	if t.names == nil {
		t.names = make(map[handleKey]string)
	}
	if t.nameAges == nil {
		t.nameAges = make(map[handleKey]uint64)
	}
	if t.taken == nil {
		t.taken = make(map[uint32]takenHandle)
	}
}

func (t *fdTracker) get(fd int32, pid uint32) (file.File, bool) {
	key := t.key(pid, fd)
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
	if t.isBlind(pid) {
		// A table an invisible task writes cannot be kept in step by this
		// trace; storing the name would bring back the stale answers that
		// markBlind exists to prevent (lookups go to procfs instead).
		return
	}
	if t.files == nil {
		t.files = make(map[uint64]file.File)
	}
	if t.fileAges == nil {
		t.fileAges = make(map[uint64]uint64)
	}
	key := t.key(pid, fd)
	t.age++
	t.files[key] = f
	t.fileAges[key] = t.age
	t.indexFileKey(key)
	// The fd table now answers for this number, so a procfs cache entry for it
	// is shadowed and, since the traced syscall just rebound the descriptor,
	// stale. Left in place it would resurface once the table entry goes (exec
	// closing a cloexec fd, LRU eviction, close) and name the previous file
	// (task kr2).
	if _, shadowed := t.procFdCache[key]; shadowed { // keep the common miss to one lookup
		t.deleteCacheKey(key)
	}
	t.pruneFiles()
}

func (t *fdTracker) delete(fd int32, pid uint32) {
	t.removeFileKey(t.key(pid, fd))
}

// tracksExactly reports whether the fd table (not the procfs cache) holds f
// itself - the same pointer - for (pid, fd). Fd-table entries come from
// syscalls ior traced, so their name was captured at the time of the syscall.
// Procfs-resolved answers (resolve's fallback and its cache) are read when
// the event is processed, which lags the syscall, so by then the number may
// name a different file than it did. It does not refresh the LRU age: a
// provenance check must not make an entry look recently used.
func (t *fdTracker) tracksExactly(fd int32, pid uint32, f file.File) bool {
	tracked, ok := t.files[t.key(pid, fd)]
	return ok && tracked == f
}

// forget drops everything known about (pid, fd) from both the fd table and
// the procfs cache, so the next use of that number resolves from scratch.
func (t *fdTracker) forget(fd int32, pid uint32) {
	t.delete(fd, pid)
	t.deleteProcFdCache(fd, pid)
}

// indexFileKey records key in its pid's fd-table set.
func (t *fdTracker) indexFileKey(key uint64) {
	keys := t.pidEntry(key)
	if keys.files == nil {
		keys.files = make(map[uint64]struct{})
	}
	keys.files[key] = struct{}{}
	keys.peakFiles = max(keys.peakFiles, len(keys.files))
}

// indexCacheKey records key in its pid's procfs-cache set.
func (t *fdTracker) indexCacheKey(key uint64) {
	keys := t.pidEntry(key)
	if keys.cache == nil {
		keys.cache = make(map[uint64]struct{})
	}
	keys.cache[key] = struct{}{}
	keys.peakCache = max(keys.peakCache, len(keys.cache))
}

// pidEntry returns the index entry of key's pid, taking a recycled one from
// idlePidKeys or allocating it (and the index itself, for a zero-value
// tracker) on first use. Only the insertion paths call it; removals go
// through unindexKey so they never allocate.
func (t *fdTracker) pidEntry(key uint64) *pidFdKeys {
	if t.pidIndex == nil {
		t.pidIndex = make(map[uint32]*pidFdKeys)
	}
	pid, _ := fdKeyParts(key)
	if keys, ok := t.pidIndex[pid]; ok {
		return keys
	}
	var keys *pidFdKeys
	if n := len(t.idlePidKeys); n > 0 {
		keys = t.idlePidKeys[n-1]
		t.idlePidKeys[n-1] = nil
		t.idlePidKeys = t.idlePidKeys[:n-1]
	} else {
		keys = &pidFdKeys{}
	}
	t.pidIndex[pid] = keys
	return keys
}

// unindexKey removes key from its pid's fd-table set (cache false) or
// procfs-cache set (cache true). Once the pid owns nothing in either map it
// is dropped from the index, so the index stays exactly as large as the set
// of pids with entries, and its emptied entry is offered to parkPidEntry for
// the next pid to reuse.
func (t *fdTracker) unindexKey(key uint64, cache bool) {
	pid, _ := fdKeyParts(key)
	keys, ok := t.pidIndex[pid]
	if !ok {
		return
	}
	if cache {
		delete(keys.cache, key)
		keys.cache, keys.peakCache = shrinkKeySet(keys.cache, keys.peakCache)
	} else {
		delete(keys.files, key)
		keys.files, keys.peakFiles = shrinkKeySet(keys.files, keys.peakFiles)
	}
	if len(keys.files) != 0 || len(keys.cache) != 0 {
		return
	}
	delete(t.pidIndex, pid)
	t.parkPidEntry(keys)
}

// shrinkKeySet returns set, or a right-sized copy of it once it has fallen
// far below its peak, along with the peak to record. Go maps never shrink,
// so a live process that once held ~30k descriptors and now holds two would
// otherwise pay a ~30k-bucket scan on every closeRange/dropOnExec/deletePid.
// The rebuild triggers only when the peak exceeded maxRecycledSetSize and
// fewer than peak/8 keys remain, so its O(len) copy is paid for by the
// more than 7*peak/8 deletions since the peak: amortised O(1) per removal.
// An emptied set becomes nil, to be allocated again on first use.
//
// Callers of unindexKey may be ranging over the old set (deletePid,
// dropOnExec). Swapping it is safe: a range evaluates its map operand once,
// the old map is no longer mutated, so the loop still yields each remaining
// key exactly once, and the copy holds exactly those keys, so the removals
// the loop goes on to make land in the new set.
func shrinkKeySet(set map[uint64]struct{}, peak int) (map[uint64]struct{}, int) {
	if peak <= maxRecycledSetSize || len(set) >= peak/8 {
		return set, peak
	}
	if len(set) == 0 {
		return nil, 0
	}
	fresh := make(map[uint64]struct{}, len(set))
	for key := range set {
		fresh[key] = struct{}{}
	}
	return fresh, len(fresh)
}

// parkPidEntry puts an emptied index entry on idlePidKeys, unless the list is
// full (the entry is then left to the garbage collector). A set whose peak
// exceeded maxRecycledSetSize is dropped first, so a recycled entry never
// carries the oversized bucket array of a once-busy process. shrinkKeySet
// already nils such a set when it empties; the check here keeps the parking
// guarantee independent of that.
//
// Callers may still be ranging over the entry's sets (deletePid, dropOnExec):
// that is safe because a range evaluates its map operand once, and parking
// only happens on the removal that emptied both sets, after which no
// insertion can hand the entry out before the loops finish.
func (t *fdTracker) parkPidEntry(keys *pidFdKeys) {
	if len(t.idlePidKeys) >= maxIdlePidKeys {
		return
	}
	if keys.peakFiles > maxRecycledSetSize {
		keys.files, keys.peakFiles = nil, 0
	}
	if keys.peakCache > maxRecycledSetSize {
		keys.cache, keys.peakCache = nil, 0
	}
	t.idlePidKeys = append(t.idlePidKeys, keys)
}

// removeFileKey is the one removal path for fd-table entries: close, close_range,
// process exit, exec and LRU eviction all go through it so the entry, its age
// and its index slot can never disagree.
func (t *fdTracker) removeFileKey(key uint64) {
	delete(t.files, key)
	delete(t.fileAges, key)
	t.unindexKey(key, false)
}

// pidKeySets returns the index entry of pid's table (its own, or the one it
// shares), or nil when that table owns no entry in either map (the common case
// for a task exit on a system-wide trace).
func (t *fdTracker) pidKeySets(pid uint32) *pidFdKeys {
	return t.pidIndex[t.tableID(pid)]
}

// closeRange removes pid's tracked fds in the inclusive range [first, last], as
// closed by close_range(2). A negative last means "no upper bound": close_range's
// last argument is an unsigned int, so the common close-everything form ~0U
// arrives here as a negative __s32 and must close every tracked fd >= first.
// Only the calling process's descriptors are evicted: close_range cannot touch
// another process's table, and evicting by bare fd number dropped unrelated
// processes' still-open mappings.
func (t *fdTracker) closeRange(first, last int32, pid uint32) {
	keys := t.pidKeySets(pid)
	if keys == nil {
		return
	}
	for _, key := range fdKeysInRange(keys.files, first, last) {
		t.removeFileKey(key)
	}
}

// addFlagsRange adds descriptor flags to pid's tracked fds in the inclusive
// range [first, last]. It updates both authoritative entries and cached procfs
// resolutions because either may satisfy the next lookup.
func (t *fdTracker) addFlagsRange(first, last int32, pid uint32, flags int32) {
	keys := t.pidKeySets(pid)
	if keys == nil {
		return
	}
	for _, key := range fdKeysInRange(keys.files, first, last) {
		if fdFile, ok := t.files[key].(*file.FdFile); ok {
			fdFile.AddFlags(flags)
		}
	}
	for _, key := range fdKeysInRange(keys.cache, first, last) {
		t.procFdCache[key].AddFlags(flags)
	}
}

// dropTable removes every entry of the table with the given id from the fd
// table and the procfs cache and forgets that the table was blind. It is the
// end of a table's life (its last user exited, or a recycled pid's leftovers
// are cleared); deletePid decides when that is the case (eventloop_fdshare.go:
// a table other processes still share outlives one holder). The per-pid index
// makes this O(entries of the table), and O(1) for the common case - a process
// that never registered a descriptor. The price is paid on the syscall path:
// every registration and removal also updates the pid's index set (a small-map
// insert or delete), and a pid entering the index takes a recycled entry or,
// when none is idle, allocates one plus the set it needs. That is far cheaper
// than the full scan of both capped maps it replaced (see
// BenchmarkDeletePidFullTable, BenchmarkFdSetDeleteChurn and
// BenchmarkFdNewPidLifecycle).
func (t *fdTracker) dropTable(id uint32) {
	t.dropTableEntries(id)
	delete(t.share.blind, id)
}

// dropTableEntries is dropTable without the blind mark (markBlind keeps it).
func (t *fdTracker) dropTableEntries(id uint32) {
	keys := t.pidIndex[id]
	if keys == nil {
		return
	}
	// Deleting from the set being ranged over is well-defined in Go, and
	// removeFileKey/deleteCacheKey drop the pid from the index once both sets
	// are empty; keys stays valid for the rest of the loop.
	for key := range keys.files {
		t.removeFileKey(key)
	}
	for key := range keys.cache {
		t.deleteCacheKey(key)
	}
}

// maxInheritedEntries bounds what one fork may copy: a parent tracking more
// fd-table plus procfs-cache entries than this passes none of them on, and its
// child resolves through procfs as before task gr2. The copy costs O(entries)
// per fork on the single event-loop goroutine, and the child's copy is freed
// again on its exit, so an unbounded copy made a parent with 1000 tracked
// descriptors forking 1000 times per second (fork+exec, where the child drops
// most of it at once) cost about half a core and overrun the ring buffer.
// BenchmarkForkStorm (inherit plus the exit-time deletePid, per fork): 1.2 us
// for 8 entries, 11 us for 64, 28 us for 128 (the cap), and, before the cap
// existed, 0.27 ms for 1024 and 3.7-7.8 ms for 8192. 128 covers the descriptors
// of the usual forker (a shell, a build tool, a supervisor, a modest server:
// stdio, pipes, files, sockets) at under ~35 us per fork. The cost of skipping
// is only the degraded name of an inherited descriptor, never a wrong one, so
// a large table is where the compromise is cheapest. A lazy per-fd copy
// (resolve on the child's first lookup against the parent's table) would be O(1)
// per fork but cannot keep the snapshot semantic when the parent closes or
// reopens a descriptor after the fork, short of copying on the parent's write,
// which is unbounded again; hence the cap.
const maxInheritedEntries = 128

// inherit makes child's slice of the fd table and of the procfs cache a copy
// of parent's, the way fork(2) gives a new process a copy of its creator's
// descriptor table (dup_fd). It is what keeps a forked child's rows named after
// the traced name of an inherited descriptor ("pipe:0:3:4", "memfd:name",
// "eventfd:0") instead of the degraded procfs form ("pipe:[N]",
// "/memfd:name (deleted)", "anon_inode:[eventfd]") or, once the child has gone,
// an unresolvable E:name - the table is keyed by tgid, so without the copy every
// new process starts with no entries at all.
//
// Whatever child already owns is dropped first: a new process's tgid is its
// own fresh tid, so entries under it can only belong to a previous owner of the
// number whose exit record was lost (the same staleness retireRecycledTid
// clears for the tid-keyed state).
//
// Both maps are copied as they are. Each copy is its own FdFile (Dup) that
// refers to the *same open file description object* as the parent's entry (task
// nr2), as the kernel's fork does: the status word (F_SETFL O_NONBLOCK/O_APPEND,
// F_GETFL) is one word across both tables, so a change either process makes
// through any descriptor of that description is seen by the other and by every
// dup of it. FD_CLOEXEC belongs to the descriptor, not the description, so it is
// per copy: a child's fcntl(F_SETFD), dup3 or ioctl(FIOCLEX) must not show on
// the parent's descriptor. Entries whose close-on-exec state is known to be set
// are dropped by the child's exec record as for any process (dropOnExec). The
// copy is a snapshot of the table: what the parent closes or reopens after the
// fork does not reach the child's entries (the description's status word, being
// shared, still follows).
//
// Nothing is copied when the parent holds more than maxInheritedEntries entries
// (see there for why and what it costs), nor when the copy would not fit under
// the table's cap: a fork must never trigger the LRU pruning, which trims the
// table well below its cap and would evict the parent's and other processes'
// entries to make room for copies nobody has used yet (a 1024-descriptor
// parent with 32 live children filled the 32768-entry table and lost its own).
// inheritSkipped counts the forks that copied nothing for either reason; their
// children resolve through procfs, the pre-gr2 behaviour.
//
// LRU: the copies are stamped with age 0, the oldest, instead of the newest age
// set stamps on an entry. A fork is not a use of the descriptor, and an entry
// never touched is by definition the least recently used: when a later set has to
// prune, the unused copies of every child go first, before anything a process
// really used. The child's own lookups (get, cachedProcFdFile) stamp what it
// does use.
//
// The copy writes straight into the maps, so nothing is evicted while the
// parent's sets are being ranged over and no snapshot of the parent is needed.
func (t *fdTracker) inherit(parent, child uint32) {
	if parent == child {
		// Not a fork: the "child" is the creator itself (a record that says so
		// is malformed); dropping its entries first would erase the table.
		return
	}
	t.deletePid(child)
	// After deletePid(child): it may have handed a table the parent still
	// shares over to a new holder, which the parent's table id must reflect.
	t.copyTable(t.tableID(parent), child)
}

// copyTable gives child (a pid with no table of its own yet) a copy of the table
// with id src, under the rules inherit describes: bounded by
// maxInheritedEntries and by the table caps, one FdFile per descriptor sharing
// the source's open file description (Dup), age 0.
// It is also how a process that leaves a shared table (exec, CLOSE_RANGE_UNSHARE;
// see detachShared, unshareFiles) gets its private one.
func (t *fdTracker) copyTable(src, child uint32) {
	keys := t.pidIndex[src]
	if keys == nil {
		return
	}
	if !t.inheritFits(keys) {
		t.inheritSkipped++
		return
	}
	dst := t.pidEntry(fdKey(child, 0))
	if dst.files == nil && len(keys.files) > 0 {
		dst.files = make(map[uint64]struct{}, len(keys.files))
	}
	if dst.cache == nil && len(keys.cache) > 0 {
		dst.cache = make(map[uint64]struct{}, len(keys.cache))
	}
	for key := range keys.files {
		_, fd := fdKeyParts(key)
		childKey := fdKey(child, fd)
		t.files[childKey] = copyForChild(t.files[key], fd)
		t.fileAges[childKey] = 0
		t.indexFileKey(childKey)
	}
	for key := range keys.cache {
		fdFile := t.procFdCache[key]
		if fdFile == nil {
			continue
		}
		_, fd := fdKeyParts(key)
		childKey := fdKey(child, fd)
		t.procFdCache[childKey] = fdFile.Dup(fd)
		t.procFdAges[childKey] = 0
		t.copyProcFdReadAt(key, childKey)
		t.indexCacheKey(childKey)
	}
	if len(dst.files) == 0 && len(dst.cache) == 0 {
		// Nothing copyable (only nil cache entries): keep the index exact, a
		// pid with no entries must not stay in it.
		delete(t.pidIndex, child)
		t.parkPidEntry(dst)
	}
}

// inheritFits reports whether a parent's entries may be copied: at most
// maxInheritedEntries of them, and room for all of them in both maps without
// reaching their caps (see inherit).
func (t *fdTracker) inheritFits(parent *pidFdKeys) bool {
	if len(parent.files)+len(parent.cache) > maxInheritedEntries {
		return false
	}
	return len(t.files)+len(parent.files) <= t.filesLimit() &&
		len(t.procFdCache)+len(parent.cache) <= t.cacheLimit()
}

// copyForChild returns the entry a forked child starts with for descriptor fd:
// a Dup of a mutable FdFile (own descriptor state, shared open file description;
// see inherit), the value itself for the immutable kinds (pathname, anonymous
// mapping, ... files carry no per-descriptor state).
func copyForChild(f file.File, fd int32) file.File {
	if fdFile, ok := f.(*file.FdFile); ok && fdFile != nil {
		return fdFile.Dup(fd)
	}
	return f
}

// dropOnExec forgets the descriptors of pid that a successful execve(2) closed.
// Called from handleProcessExecEvent on a sched_process_exec control record:
// the kernel closes every FD_CLOEXEC descriptor of the exec'ing process
// (do_close_on_exec), so an entry that stayed here would keep labelling the
// new program's rows with the old program's file whenever it reuses that
// descriptor number through a syscall ior does not trace (socket, recvmsg
// SCM_RIGHTS, ... under the default FS-only trace set).
//
// Only pid's slice is touched, through the per-pid index, so an exec costs
// O(entries of pid) rather than a scan of both capped maps. Threads share
// their process's table and all but the exec'ing one are killed by
// de_thread, and the table is keyed by tgid; a process sharing the table via
// CLONE_FILES without being a thread gets its own copy before the closes
// (unshare_files in begin_new_exec); detachShared models that, so the sharers'
// entries are unaffected.
//
// Both maps keep an entry only when its close-on-exec state is known to be
// clear (survivesExec). Procfs cache entries carry that state too: the fdinfo
// flags word NewFdWithPid parses includes O_CLOEXEC, and later traced
// fcntl/ioctl FIOCLEX/FIONCLEX/dup3/close_range updates reach the cached
// object because resolve hands it out. An unresolvable cache entry has unknown flags and is dropped.
//
// Unknown state is dropped on purpose: the costs are asymmetric. Keeping an
// entry the kernel closed mislabels every later row on that number with the
// old program's file. Dropping one that in fact survived falls back to a
// lazy procfs re-resolution on its next use (resolve -> /proc/<pid>/fd/<fd>).
// That fallback is not free of error either - it reads procfs after the
// fact, so for a short-lived program the read can fail (empty name), and
// the number may already name a different file opened by an untraced
// syscall - but it never invents a name the process no longer has.
func (t *fdTracker) dropOnExec(pid uint32) {
	// The kernel unshares a shared table before it closes anything
	// (unshare_files in begin_new_exec): the closes below must hit pid's own
	// copy, not the table its former sharers keep using.
	t.detachShared(pid)
	keys := t.pidKeySets(pid)
	if keys == nil {
		return
	}
	for key := range keys.files {
		if !survivesExec(t.files[key]) {
			t.removeFileKey(key)
		}
	}
	for key := range keys.cache {
		if !survivesExec(t.procFdCache[key]) {
			t.deleteCacheKey(key)
		}
	}
}

// survivesExec reports whether a tracked descriptor is known to stay open
// across execve(2): only a non-nil *FdFile whose FD_CLOEXEC state is known
// and clear qualifies. Any other File, or an unknown state, counts as closed
// (see dropOnExec for why unknown resolves that way).
func survivesExec(f file.File) bool {
	fdFile, ok := f.(*file.FdFile)
	if !ok || fdFile == nil {
		return false
	}
	set, known := fdFile.CloseOnExec()
	return known && !set
}

// pruneFiles evicts the least recently used fd entries once the table exceeds
// its cap. Unlike the flat map this replaced, the (pid, fd) key space grows
// with the number of traced processes, and the syscall stream alone does not
// reclaim a dead process's entries (the sched_process_exit record usually
// does; see the note on defaultMaxFdTableEntries), so the cap is what bounds
// it. Eviction is lossy, not wrong: resolve falls back to /proc/<pid>/fd,
// which identifies a descriptor that is genuinely still open correctly, but
// reports it in procfs's own form, so a name ior captured from the syscall
// ("pipe:0:3:4", "memfd:name", "eventfd:0") degrades to "pipe:[N]",
// "/memfd:name (deleted)" or "anon_inode:[eventfd]" for the later rows of that
// descriptor. (set clears the shadowed procfs cache entry, so no stale cached
// name can resurface here, task kr2.) Victims leave through removeFileKey so
// the per-pid index forgets them too.
func (t *fdTracker) pruneFiles() {
	limit := t.filesLimit()
	if len(t.files) <= limit {
		return
	}
	for _, key := range lruVictims(t.files, t.fileAges, trimTarget(limit)) {
		t.removeFileKey(key)
	}
}

func (t *fdTracker) filesLimit() int {
	if t.maxFiles > 0 {
		return t.maxFiles
	}
	return defaultMaxFdTableEntries
}

// resolve returns the file.File for fd, checking the fd table first, then the
// procfs cache, and finally resolving via procfs and caching the result with
// its read time. Close rows do not come here (resolveClosing, task jr2).
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
	discovered := file.NewFdWithPid(fd, pid)
	// Cache a successful resolution to avoid repeated /proc lookups for hot
	// unknown FDs. A failed one (readlink error: empty name, unknown flags) is
	// returned for this row but never cached: the number was not open at that
	// instant - typically an EBADF close loop - and a stored failure would
	// leave every later descriptor that lands on it (opened by an untraced
	// syscall such as pipe(2)) nameless with O_NONE for as long as the entry
	// lives, although procfs answers correctly by then. Re-reading costs one
	// failing readlink(2) (~4.5 us) per event on a number that procfs cannot
	// answer, which is cheap next to a permanently wrong row. The hottest such
	// stream, syscalls answering EBADF, never gets here: exit handlers go
	// through resolveOnExit, which skips procfs for it (see
	// eventloop_procfs_ebadf.go).
	if discovered.Name() != "" {
		// Stamped after the readlink returned: a close row may reuse this
		// answer only if it was read before that close began (task jr2,
		// eventloop_procfs_close.go). One clock_gettime(2) next to a readlink.
		t.setProcFdCacheRead(fd, pid, discovered, bootClockNs())
	}
	return discovered
}

func (t *fdTracker) cachedProcFdFile(fd int32, pid uint32) (*file.FdFile, bool) {
	if t.procFdCache == nil {
		return nil, false
	}
	key := t.key(pid, fd)
	cache, ok := t.procFdCache[key]
	if ok {
		t.age++
		t.procFdAges[key] = t.age
	}
	return cache, ok
}

// cachedProcFdReadAt returns when the cache entry for (pid, fd) was read from
// procfs, or false when there is no entry or its read time is unknown.
func (t *fdTracker) cachedProcFdReadAt(fd int32, pid uint32) (uint64, bool) {
	readNs, ok := t.procFdReadAt[t.key(pid, fd)]
	return readNs, ok
}

// setProcFdCache caches resolved without a read time: a close row will not use
// it (see procFdReadAt). The procfs path stamps its answers through
// setProcFdCacheRead instead.
func (t *fdTracker) setProcFdCache(fd int32, pid uint32, resolved *file.FdFile) {
	t.storeProcFdCache(fd, pid, resolved, 0, false)
}

// setProcFdCacheRead caches resolved as read from procfs at readNs (boot
// clock, taken after the read returned).
func (t *fdTracker) setProcFdCacheRead(fd int32, pid uint32, resolved *file.FdFile, readNs uint64) {
	t.storeProcFdCache(fd, pid, resolved, readNs, true)
}

// storeProcFdCache is the one insertion path for procfs cache entries; stamped
// says whether readNs is a read time to record or the entry has none.
func (t *fdTracker) storeProcFdCache(fd int32, pid uint32, resolved *file.FdFile, readNs uint64, stamped bool) {
	if t.isBlind(pid) {
		return // see set: a blind table keeps no answers, procfs is read each time
	}
	if t.procFdCache == nil {
		t.procFdCache = make(map[uint64]*file.FdFile)
		t.procFdAges = make(map[uint64]uint64)
	}
	if t.procFdReadAt == nil {
		t.procFdReadAt = make(map[uint64]uint64)
	}
	key := t.key(pid, fd)
	t.age++
	t.procFdCache[key] = resolved
	t.procFdAges[key] = t.age
	if stamped {
		t.procFdReadAt[key] = readNs
	} else {
		delete(t.procFdReadAt, key) // a replaced entry must not keep the old stamp
	}
	t.indexCacheKey(key)
	t.pruneCache()
}

// copyProcFdReadAt gives the cache entry at dst the read time of the one at
// src, or none when src has none (copyTable and rekeyTable copy entries).
// Clearing dst is defensive: deleteCacheKey drops a stamp with its entry, and
// both callers write to a pid that holds no entries (copyTable's child,
// rekeyTable's to), so dst never has a stamp today. It keeps a stale stamp
// from surviving should a caller ever overwrite an entry.
func (t *fdTracker) copyProcFdReadAt(src, dst uint64) {
	if readNs, ok := t.procFdReadAt[src]; ok {
		t.procFdReadAt[dst] = readNs
		return
	}
	delete(t.procFdReadAt, dst)
}

func (t *fdTracker) deleteProcFdCache(fd int32, pid uint32) {
	t.deleteCacheKey(t.key(pid, fd))
}

// deleteProcFdCacheRange drops cached procfs resolutions for pid's fds in the
// inclusive range [first, last]. A negative last means "no upper bound" (see
// closeRange for why close_range's last argument can arrive negative).
func (t *fdTracker) deleteProcFdCacheRange(first, last int32, pid uint32) {
	keys := t.pidKeySets(pid)
	if keys == nil {
		return
	}
	for _, key := range fdKeysInRange(keys.cache, first, last) {
		t.deleteCacheKey(key)
	}
}

// fdKeysInRange returns the keys of one pid's index set whose descriptor
// number falls in the inclusive range [first, last]; a negative last means "no
// upper bound" (see closeRange for why close_range's last argument can arrive
// negative). A negative first means the opposite extreme: close_range's first
// argument is unsigned too, so a value above INT32_MAX wraps negative, and no
// descriptor number can be >= it - the range closes nothing. Collecting first
// keeps the caller from mutating the set it is filtering through a helper.
func fdKeysInRange(pidKeys map[uint64]struct{}, first, last int32) []uint64 {
	if first < 0 {
		return nil
	}
	var keys []uint64
	for key := range pidKeys {
		_, keyFd := fdKeyParts(key)
		if keyFd < first || (last >= 0 && keyFd > last) {
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
	for _, key := range lruVictims(t.procFdCache, t.procFdAges, trimTarget(limit)) {
		t.deleteCacheKey(key)
	}
}

func (t *fdTracker) cacheLimit() int {
	if t.maxCacheSize > 0 {
		return t.maxCacheSize
	}
	return defaultMaxProcFdCacheSize
}

// deleteCacheKey is the one removal path for procfs cache entries (the
// counterpart of removeFileKey), keeping the entry, its age, its procfs read
// time and its index slot in step. delete on a nil map is a no-op in Go, so
// this is safe even before any cache entries are set.
func (t *fdTracker) deleteCacheKey(key uint64) {
	delete(t.procFdCache, key)
	delete(t.procFdAges, key)
	delete(t.procFdReadAt, key)
	t.unindexKey(key, true)
}

// store files name under the handle key, replacing what the handle was known
// as: name_to_handle_at returned it again, and the pathname of the latest call
// is the freshest name ior has for that file. An empty name (resolvePathEvent
// produced none) is no name to give a row, but it still supersedes the old
// entry, which is dropped rather than left to be mistaken for the current
// one: a missing name leaves the row to procfs, a stale one would be wrong.
func (t *handleTracker) store(key handleKey, name string) {
	if name == "" {
		delete(t.names, key)
		delete(t.nameAges, key)
		return
	}
	t.ensureInit()
	t.age++
	t.names[key] = name
	t.nameAges[key] = t.age
	t.prune()
}

// lookup returns the name the handle key was taken of. A hit refreshes the
// entry's LRU age: a handle that is still being opened is worth keeping, and
// the entry stays where it is, because the next open of the same handle - by
// this thread or any other - is the same file. A failed open is no reason to
// drop it either: the handle itself is not what failed in the common cases
// (a bad mount fd, a missing capability), and a retry should be named.
func (t *handleTracker) lookup(key handleKey) (string, bool) {
	name, ok := t.names[key]
	if !ok {
		return "", false
	}
	t.age++
	t.nameAges[key] = t.age
	return name, true
}

// park records the handle a name_to_handle_at of tid returned, as its control
// record reported it at time, for claim to pick up at the call's exit record.
// It replaces what the tid had parked: one thread runs one syscall at a time,
// so an older entry is a leftover of a call whose exit record was lost.
//
// The map is capped like names. Overflowing it takes that many threads with a
// lost exit record and no exit of their own, so the whole map is dropped
// rather than tracked by age: what is lost is at most the name of handles
// whose exit records are in flight at that moment.
func (t *handleTracker) park(tid uint32, key handleKey, time uint64) {
	t.ensureInit()
	if len(t.taken) >= t.limit() {
		clear(t.taken)
	}
	t.taken[tid] = takenHandle{key: key, time: time}
}

// claim removes and returns the handle parked for tid, provided it was parked
// by the call whose exit record carries time. The parked entry is dropped in
// any case: the exit of a name_to_handle_at ends the only call it could
// belong to.
//
// The time check is what makes the pairing exact rather than positional. The
// control record and the exit record of one call carry the same clock read,
// and a later call of the tid has a later one, so a handle whose own exit
// record was lost can never be filed under the pathname of the next call.
func (t *handleTracker) claim(tid uint32, time uint64) (handleKey, bool) {
	parked, ok := t.taken[tid]
	if !ok {
		return handleKey{}, false
	}
	delete(t.taken, tid)
	if parked.time != time {
		return handleKey{}, false
	}
	return parked.key, true
}

// dropTaken forgets the handle parked for tid. It is the tracker's only
// per-thread state, so it is all a dead or recycled tid has to give up; the
// names stay, because a handle outlives the task that took it.
func (t *handleTracker) dropTaken(tid uint32) {
	delete(t.taken, tid)
}

func (t *handleTracker) prune() {
	limit := t.limit()
	if len(t.names) <= limit {
		return
	}
	trimLRU(t.names, t.nameAges, trimTarget(limit), nil)
}

func (t *handleTracker) limit() int {
	if t.maxCacheSize > 0 {
		return t.maxCacheSize
	}
	return defaultMaxHandleEntries
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
	// execCallers indexes the exec enters parked by non-leader threads:
	// pid -> the callers' tids. Several threads of one process can sit in
	// execve at once (all but one are killed by de_thread), so a pid keeps
	// a small set rather than one tid: evicting one caller must not hide
	// another. It lets an execve exit whose exec record was lost find its
	// enter (parkedExecCaller). Entries are hints: the pair they name may
	// since have been consumed or LRU-trimmed, so a lookup re-validates,
	// and indexExecCaller drops dead hints once execCallerHints outgrows
	// the pending-enter limit.
	execCallers     map[uint32][]uint32
	execCallerHints int // total tids across execCallers
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
	p.setWithFile(enterEv, nil)
}

// setWithFile is set for an enter whose target was already resolved when the
// enter arrived (see eventLoop.storeEnter): the pending pair carries target as
// its File, so the exit handler sees the enter-time resolution even if a
// control record processed in between changed the fd table.
func (p *pairTracker) setWithFile(enterEv event.Event, target file.File) {
	if p.enters == nil {
		p.enters = make(map[uint32]*event.Pair)
		p.enterAges = make(map[uint32]uint64)
		p.prevTimes = make(map[uint32]uint64)
		p.prevTimeAges = make(map[uint32]uint64)
	}
	tid := enterEv.GetTid()
	pair := event.NewPair(enterEv)
	pair.File = target
	if prev, ok := p.enters[tid]; ok && prev != nil {
		prev.Recycle()
	}
	p.age++
	p.enters[tid] = pair
	p.enterAges[tid] = p.age
	p.indexExecCaller(enterEv)
	p.prune()
}

// indexExecCaller records enterEv in execCallers when it is an exec enter of
// a non-leader thread (tid != pid), the only enter whose exit arrives under
// another tid. Once the index holds more hints than the pending-enter limit,
// hints whose pair is gone are dropped, which keeps it bounded by the live
// exec enters.
func (p *pairTracker) indexExecCaller(enterEv event.Event) {
	if _, isExec := enterEv.(*types.ExecEvent); !isExec || enterEv.GetTid() == enterEv.GetPid() {
		return
	}
	if p.execCallers == nil {
		p.execCallers = make(map[uint32][]uint32)
	}
	pid, tid := enterEv.GetPid(), enterEv.GetTid()
	if !slices.Contains(p.execCallers[pid], tid) {
		p.execCallers[pid] = append(p.execCallers[pid], tid)
		p.execCallerHints++
	}
	if p.execCallerHints <= p.limit() {
		return
	}
	for pid, tids := range p.execCallers {
		live := tids[:0]
		for _, tid := range tids {
			if p.isParkedExecCaller(pid, tid) {
				live = append(live, tid)
			} else {
				p.execCallerHints--
			}
		}
		if len(live) == 0 {
			delete(p.execCallers, pid)
		} else {
			p.execCallers[pid] = live
		}
	}
}

// forgetExecCaller removes the hint pid -> tid, if present.
func (p *pairTracker) forgetExecCaller(pid, tid uint32) {
	tids := p.execCallers[pid]
	i := slices.Index(tids, tid)
	if i < 0 {
		return
	}
	p.execCallerHints--
	if len(tids) == 1 {
		delete(p.execCallers, pid)
		return
	}
	p.execCallers[pid] = slices.Delete(tids, i, i+1)
}

// isParkedExecCaller reports whether tid still holds a parked exec enter of
// process pid.
func (p *pairTracker) isParkedExecCaller(pid, tid uint32) bool {
	pair, ok := p.enters[tid]
	if !ok || pair == nil {
		return false
	}
	_, isExec := pair.EnterEv.(*types.ExecEvent)
	return isExec && pair.EnterEv.GetPid() == pid
}

// parkedExecCaller returns the tid of a non-leader thread of pid whose exec
// enter is still parked, preferring the most recently parked one, and
// forgets that hint; stale hints met on the way are dropped. ok is false when
// no live hint is left. Normally at most one caller is still parked by the
// time the exec's exit arrives: the others were killed by de_thread, and
// their exit records evicted them first.
func (p *pairTracker) parkedExecCaller(pid uint32) (tid uint32, ok bool) {
	tids := p.execCallers[pid]
	for i := len(tids) - 1; i >= 0; i-- {
		tid = tids[i]
		p.forgetExecCaller(pid, tid)
		if p.isParkedExecCaller(pid, tid) {
			return tid, true
		}
	}
	return 0, false
}

// consume removes and returns the pending enter pair for tid, dropping its
// execCallers hint if it had one.
// Reading a nil map returns the zero value in Go, so this is safe before any set call.
func (p *pairTracker) consume(tid uint32) (*event.Pair, bool) {
	pair, ok := p.enters[tid]
	if !ok {
		return nil, false
	}
	delete(p.enters, tid)
	delete(p.enterAges, tid)
	if pair != nil && pair.EnterEv != nil {
		p.forgetExecCaller(pair.EnterEv.GetPid(), tid)
	}
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

// moveExecCaller carries a non-leader exec's per-tid state from the caller's
// pre-exec tid (oldTid) to the leader tid it continues under (newTid); see
// eventLoop.applyExecTidChange for when that happens.
//
// Whatever newTid still holds belongs to the dead leader and is dropped first
// (its own exit record normally evicted it already; this covers a lost one).
// The enter parked under oldTid is then moved only when it is an exec enter,
// i.e. the execve the task is still inside: its exit arrives under newTid and
// must find it there. Any other enter under oldTid is left over from a lost
// exit record, can never pair any more, and is recycled. The gap baseline
// moves too, because applyDerivedPairValues and finalizeTracepointPair key it
// by the exit's tid: the execve row keeps its gap to the caller's previous
// syscall, and the new program's first syscall measures its gap from the
// execve's return.
func (p *pairTracker) moveExecCaller(oldTid, newTid uint32) {
	p.evictTid(newTid)
	if pair, ok := p.consume(oldTid); ok && pair != nil {
		if _, isExec := pair.EnterEv.(*types.ExecEvent); isExec {
			p.age++
			p.enters[newTid] = pair
			p.enterAges[newTid] = p.age
		} else {
			pair.Recycle()
		}
	}
	if prev, ok := p.prevTimes[oldTid]; ok {
		delete(p.prevTimes, oldTid)
		delete(p.prevTimeAges, oldTid)
		p.setPrevTime(newTid, prev)
	}
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
	for _, key := range lruVictims(state, ages, targetSize) {
		if cleanup != nil {
			cleanup(state[key])
		}
		delete(state, key)
		delete(ages, key)
	}
}

// lruVictims returns the keys trimLRU would evict to shrink state to
// targetSize, oldest first, without removing them. The fdTracker uses it
// directly so each eviction goes through its own removal helper, which also
// maintains the per-pid index.
func lruVictims[K comparable, V any](state map[K]V, ages map[K]uint64, targetSize int) []K {
	excess := len(state) - targetSize
	if excess <= 0 {
		return nil
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
	victims := make([]K, excess)
	for i, e := range oldest[:excess] {
		victims[i] = e.key
	}
	return victims
}

func trimOldestPendingPairs(state map[uint32]*event.Pair, ages map[uint32]uint64, targetSize int) {
	// Recycle evicted pairs back to the pool before deletion.
	trimLRU(state, ages, targetSize, func(pair *event.Pair) {
		if pair != nil {
			pair.Recycle()
		}
	})
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
