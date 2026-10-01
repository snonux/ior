package internal

// Descriptor tables that more than one process uses (task hr2).
//
// fdTracker keys its entries by tgid, which is the owner of the table for a
// thread group but not for two processes that clone(CLONE_FILES): they share a
// single table, and whatever one of them closes, opens or dup2()s changes what
// the other's descriptor numbers mean. A per-tgid table cannot express that: the
// other process kept answering with the name the number had before (a read of
// fd 3 labelled /etc/hostname while the kernel had long since pointed it at
// /etc/os-release). fdTableShare adds the missing indirection, from tgid to
// table id, and the tracker translates every pid it is given (tableID) before it
// touches an entry.
//
// Three situations, by what the trace can see:
//
//   - The CLONE_FILES child is in scope (system-wide, -comm, a -pid that names
//     the child): its syscalls arrive under its own tgid, and sharing the table id
//     makes them act on the creator's entries too. shareTable.
//   - The child is out of scope (-pid/-tid target creating it): its syscalls are
//     filtered out in the kernel, so nothing tells this trace what it does to the
//     creator's table. The only truthful answer is to stop answering from tracked
//     state: markBlind drops the table's entries and keeps it empty; every lookup
//     then reads /proc/<pid>/fd (resolve), which is the live shared table. The
//     price is one successful procfs resolution per event on such a process
//     (NewFdWithPid, 6 to 13 us measured, depending on host and descriptor type; the
//     4.5 us figure is only the cost of a failing readlink) and the procfs spelling of anonymous descriptors
//     (pipe:[N]) instead of the traced one - the state before task gr2. The child's
//     exit is filtered out too, so nothing ever says the invisible sharer is gone:
//     a blind table stays blind for the life of its holder (until the holder
//     execs, which gives it a private table, or exits; the mark moves with the
//     table when the holder hands it over).
//   - A member leaves the sharing: it execs (the kernel copies the table before
//     closing close-on-exec descriptors, detachShared; de_thread has killed every
//     other thread by then, so the exec'ing process alone uses the new table), it
//     calls close_range with CLOSE_RANGE_UNSHARE (unshareFiles, see below), or it
//     exits (deletePid; the table lives on for the remaining users, handed to one
//     of them so that no table id is left dangling on a tgid the kernel may
//     reuse).
//
// close_range(CLOSE_RANGE_UNSHARE) privatises the table of the *calling thread*
// only. Which tgids that frees is knowable only for a single-threaded caller, and
// the event stream does not say how many threads a process has, so
// unshareFiles is applied for a thread-group leader only (the event loop skips
// calls by any other thread: their unshare leaves the tgid's table, and its
// sharers, exactly as they were) and the leader is assumed to be alone. A leader
// that is not alone is the one wrong case; it errs on the side of correct names:
// a blind table stays blind (the caller joins it as a blind private table),
// because a sibling thread may still share the table with an invisible process.
//
// Not modelled. The numbers match the limitations list in AGENTS.md:
//
// Same wrong names as before hr2 (each tgid had its own table then):
//
//   - (1) A *thread* that unshares its own table (unshare(CLONE_FILES), or
//     CLOSE_RANGE_UNSHARE from a non-leader thread) stays mapped to its process's
//     table: the tracker is keyed by tgid and the stream has no per-thread table.
//   - (2) -tid: the filter hides the sibling threads that write the shared table.
//   - (4) A -pid target that was itself created with CLONE_FILES by a creator the
//     trace never saw (a record exists only for children of in-scope creators)
//     has an aliased table nobody has blinded, so a sibling's writes go
//     unnoticed. Before hr2 the same writes went unnoticed too.
//
// New with hr2 (a wrong-name mode that did not exist before):
//
//   - (3) unshare(CLONE_FILES) by a CLONE_FILES child *process*: unshare is a
//     null-kind record that carries no flags, so the call cannot even be
//     recognised. The child stays aliased to the creator's table after the kernel
//     has given it a copy, so its later close/open of a shared number overwrites
//     the creator's entry.
//   - (5) A leader that calls close_range(CLOSE_RANGE_UNSHARE) while sibling
//     threads still share the old table is treated as alone (see above): the
//     siblings' later rows on those numbers keep the leader's view.

// fdTableShare is the sharing state of an fdTracker; the zero value means every
// tgid owns its table, which is what nearly every process does.
type fdTableShare struct {
	// tableOf maps a tgid that shares someone else's table to that table's id
	// (the tgid the entries are keyed by). A tgid absent from it owns the table
	// keyed by its own number. A table id is never itself a key here.
	tableOf map[uint32]uint32
	// sharers is the inverse: table id -> the tgids that map onto it, not
	// counting the id's own tgid. A tgid whose set is empty has no entry.
	sharers map[uint32]map[uint32]struct{}
	// blind holds the ids of tables an invisible task writes (see markBlind).
	blind map[uint32]struct{}
}

// tableID returns the id of the table pid uses: the pid itself unless it shares
// another process's table. The empty-map fast path keeps the cost of an
// unshared trace to one length check per lookup.
func (t *fdTracker) tableID(pid uint32) uint32 {
	if len(t.share.tableOf) == 0 {
		return pid
	}
	if id, ok := t.share.tableOf[pid]; ok {
		return id
	}
	return pid
}

// key is the map key of (pid, fd): the descriptor number inside the table pid
// uses, not inside pid's own (possibly shared) slot. Every pid-taking method
// goes through it or through pidKeySets.
func (t *fdTracker) key(pid uint32, fd int32) uint64 {
	return fdKey(t.tableID(pid), fd)
}

// isBlind reports whether the table pid uses is one markBlind gave up on.
func (t *fdTracker) isBlind(pid uint32) bool {
	if len(t.share.blind) == 0 {
		return false
	}
	_, ok := t.share.blind[t.tableID(pid)]
	return ok
}

// shareTable makes child use creator's descriptor table, as clone(CLONE_FILES)
// does for a new process: from now on an entry either process registers or
// removes is the other's too. Whatever child held before is a dead previous
// owner's leftover (its exit record was lost) and goes first.
func (t *fdTracker) shareTable(child, creator uint32) {
	if child == creator {
		return
	}
	t.deletePid(child)
	id := t.tableID(creator)
	if t.share.tableOf == nil {
		t.share.tableOf = make(map[uint32]uint32)
	}
	if t.share.sharers == nil {
		t.share.sharers = make(map[uint32]map[uint32]struct{})
	}
	t.share.tableOf[child] = id
	if t.share.sharers[id] == nil {
		t.share.sharers[id] = make(map[uint32]struct{})
	}
	t.share.sharers[id][child] = struct{}{}
}

// deletePid ends pid's use of its table: the process exited, or its number is
// being recycled and whatever it left is stale. A table other processes still
// share stays (handed to one of them when pid was the one it was keyed by);
// an unshared table is dropped with all its entries (dropTable).
func (t *fdTracker) deletePid(pid uint32) {
	if id, ok := t.share.tableOf[pid]; ok {
		t.unlinkSharer(pid, id)
		return
	}
	if len(t.share.sharers[pid]) > 0 {
		t.handOverTable(pid)
		return
	}
	t.dropTable(pid)
}

// unlinkSharer removes pid, a tgid that maps onto table id, from the sharing.
func (t *fdTracker) unlinkSharer(pid, id uint32) {
	delete(t.share.tableOf, pid)
	members := t.share.sharers[id]
	delete(members, pid)
	if len(members) == 0 {
		delete(t.share.sharers, id)
	}
}

// handOverTable re-keys the table held under id onto the smallest of its
// sharers, which becomes its new holder, and returns that heir. The holder
// cannot simply leave the table keyed by its number: the kernel reuses tgids,
// and a new process with that number would silently read the old table. The
// choice of heir is arbitrary but deterministic; every other sharer is pointed
// at it. The tracked entries and the blind mark move with the table. O(entries
// of the table), paid once per holder exit or exec while others still share.
func (t *fdTracker) handOverTable(id uint32) uint32 {
	members := t.share.sharers[id]
	delete(t.share.sharers, id)
	var heir uint32
	for m := range members {
		if heir == 0 || m < heir {
			heir = m
		}
	}
	t.dropTable(heir) // an aliasing pid owns no entries; clear anything stale
	t.rekeyTable(id, heir)
	if _, blind := t.share.blind[id]; blind {
		delete(t.share.blind, id)
		t.share.blind[heir] = struct{}{}
	}
	delete(t.share.tableOf, heir)
	delete(members, heir)
	for m := range members {
		t.share.tableOf[m] = heir
	}
	if len(members) > 0 {
		t.share.sharers[heir] = members
	}
	return heir
}

// rekeyTable moves every fd-table and procfs-cache entry of table from to table
// to (which must hold none), keeping ages and index in step. Writes go straight
// into the maps, so a move never prunes.
func (t *fdTracker) rekeyTable(from, to uint32) {
	keys := t.pidIndex[from]
	if keys == nil {
		return
	}
	fileKeys, cacheKeys := collectKeys(keys.files), collectKeys(keys.cache)
	for _, key := range fileKeys {
		_, fd := fdKeyParts(key)
		moved := fdKey(to, fd)
		t.files[moved] = t.files[key]
		t.fileAges[moved] = t.fileAges[key]
		t.indexFileKey(moved)
		t.removeFileKey(key)
	}
	for _, key := range cacheKeys {
		_, fd := fdKeyParts(key)
		moved := fdKey(to, fd)
		t.procFdCache[moved] = t.procFdCache[key]
		t.procFdAges[moved] = t.procFdAges[key]
		t.indexCacheKey(moved)
		t.deleteCacheKey(key)
	}
}

// collectKeys copies a key set into a slice, so the caller may mutate the set.
func collectKeys(set map[uint64]struct{}) []uint64 {
	keys := make([]uint64, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	return keys
}

// leaveSharing takes pid out of the sharing of its table, if any: it reports
// the id of the table pid left and whether there was one. The former sharers keep
// that table (re-keyed onto an heir when pid held it, handOverTable).
func (t *fdTracker) leaveSharing(pid uint32) (id uint32, shared bool) {
	if id, isSharer := t.share.tableOf[pid]; isSharer {
		t.unlinkSharer(pid, id)
		return id, true
	}
	if len(t.share.sharers[pid]) > 0 {
		return t.handOverTable(pid), true
	}
	return pid, false
}

// detachShared gives pid a table of its own when it shares one, the way the
// kernel does for a process that execs (unshare_files in begin_new_exec): the new
// table starts as a copy of the shared one (bounded like a fork's copy,
// copyTable) and the former sharers keep the original. Exec first kills every
// other thread (de_thread), so the process alone uses the new table and nothing
// of it can still be shared with an invisible task: a blind table is therefore
// no longer blind for the exec'ing process (an exec'ing creator no longer shares
// with its out-of-scope CLONE_FILES child), and its entries were purged, so it
// starts empty.
func (t *fdTracker) detachShared(pid uint32) {
	id, shared := t.leaveSharing(pid)
	if !shared {
		delete(t.share.blind, pid)
		return
	}
	t.copyTable(id, pid)
}

// unshareFiles models close_range(CLOSE_RANGE_UNSHARE) by a thread-group leader
// (the caller checks that; see the file comment for why leaders only): the leader
// gets a private copy of the table and leaves the sharing, like detachShared. The
// difference is the blind mark. Unlike exec, an unsharing leader may have
// siblings, which still share the old table with whatever invisible process
// blinded it, so a blind table is never trusted again here: the leader stays
// blind with an empty table of its own and keeps answering from procfs. That
// costs the speed-up of tracked names, never the correctness of names.
func (t *fdTracker) unshareFiles(pid uint32) {
	wasBlind := t.isBlind(pid)
	id, shared := t.leaveSharing(pid)
	switch {
	case !shared:
		return // alone with its table: nothing to copy, a blind mark stays
	case wasBlind:
		t.markBlind(pid)
	default:
		t.copyTable(id, pid)
	}
}

// markBlind stops tracking the table pid uses: its entries are dropped, and
// set/setProcFdCache refuse new ones, so every lookup resolves through procfs
// (resolve) and sees the live table the invisible task is also writing. Called
// for the creator of an out-of-scope CLONE_FILES child. Idempotent. The mark
// ends with the table (dropTable), when its holder execs (detachShared) or when
// it is handed over to a sharer (handOverTable moves it).
func (t *fdTracker) markBlind(pid uint32) {
	id := t.tableID(pid)
	t.dropTableEntries(id)
	if t.share.blind == nil {
		t.share.blind = make(map[uint32]struct{})
	}
	t.share.blind[id] = struct{}{}
}
