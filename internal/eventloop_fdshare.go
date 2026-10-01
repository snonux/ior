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
//     price is one readlink per event on such a process (about 4.5 us) and the
//     procfs spelling of anonymous descriptors (pipe:[N]) instead of the traced
//     one - the state before task gr2 - for as long as the process lives.
//   - A member leaves the sharing: it execs (the kernel copies the table before
//     closing close-on-exec descriptors, detachShared), it calls close_range with
//     CLOSE_RANGE_UNSHARE (same), or it exits (deletePid; the table lives on for
//     the remaining users, handed to one of them so that no table id is left
//     dangling on a tgid the kernel may reuse).
//
// Not modelled: a *thread* that unshares its own table (unshare(CLONE_FILES) or
// CLOSE_RANGE_UNSHARE from a thread of a multi-threaded process) stays mapped to
// its process's table, because the tracker is keyed by tgid and the event stream
// has no per-thread table to key it by; unshare is also a null-kind record that
// carries no flags, so the call cannot even be recognised. The same holds for
// -tid, where the filter hides the sibling threads that write the shared table.
// These stay the pre-hr2 behaviour (see AGENTS.md).

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

// sharesTable reports whether pid's table has another tgid using it.
func (t *fdTracker) sharesTable(pid uint32) bool {
	if _, ok := t.share.tableOf[pid]; ok {
		return true
	}
	return len(t.share.sharers[pid]) > 0
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

// detachShared gives pid a table of its own when it shares one, the way the
// kernel does for a process that execs (unshare_files in begin_new_exec) or
// calls close_range(CLOSE_RANGE_UNSHARE): the new table starts as a copy of the
// shared one (bounded like a fork's copy, copyTable) and the former sharers keep
// the original. A process that shares nothing keeps its table, except that a
// blind one is no longer blind: a table this process alone uses has no invisible
// writer left (an exec'ing creator no longer shares with its out-of-scope
// CLONE_FILES child), and its entries were purged, so it starts empty.
func (t *fdTracker) detachShared(pid uint32) {
	id, isSharer := t.share.tableOf[pid]
	switch {
	case isSharer:
		t.unlinkSharer(pid, id)
	case len(t.share.sharers[pid]) > 0:
		id = t.handOverTable(pid)
	default:
		delete(t.share.blind, pid)
		return
	}
	t.copyTable(id, pid)
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
