package probemanager

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"sync"
)

// Link abstracts an attached tracepoint link.
//
// Destroy is final. It must be called at most once on a link, and when it has
// returned the link is gone - also when it returned an error. The manager
// therefore takes a link off its entry before it destroys it
// (probeEntry.takeLinks), records the error, and never keeps a link to try
// its destroy again; whoever else holds a Link has to do the same (the
// release closures of attachHandProbe in internal/ior_bpfsetup.go).
//
// That is the contract of the real link, *bpf.BPFLink of libbpfgo
// v0.9.2-libbpf-1.5.1, which internal/ior_bpfsetup.go hands out unwrapped. It
// was read from the sources, not tested against a detach that fails:
//
//   - libbpf 1.5.1, src/libbpf.c, bpf_link__destroy (line 10666): calls
//     link->detach and then frees the link (link->dealloc, or free) whatever
//     detach returned. The error is only passed on.
//   - the same file, bpf_link_perf_detach (line 10789), the detach of a
//     tracepoint link: closes the perf event fd and the link fd also when its
//     PERF_EVENT_IOC_DISABLE ioctl failed, and closing them is what detaches
//     the program. (A raw tracepoint link's detach, bpf_link__detach_fd, line
//     10695, is nothing but that close.) So a tracepoint whose Destroy
//     reported an error is detached in the kernel all the same.
//   - libbpfgo, link.go, BPFLink.Destroy (lines 70-81): returns that errno
//     BEFORE it clears its pointer to the freed link. A second Destroy hands
//     the freed struct to bpf_link__destroy again: a use after free and a
//     double free.
//
// So a link that "could not be destroyed" and is still attached does not
// exist, and there is nothing to retry (task z13 assumed both). Were a kernel
// ever to keep a program attached past the close of those fds, the manager
// could not help it either: the link struct is freed, and nothing is left to
// call.
//
// What the manager cannot prevent is libbpfgo's own second destroy: its
// Module.Close (module.go, lines 194-198) destroys every link of the module
// whose pointer is still set, which includes one whose Destroy failed.
type Link interface {
	Destroy() error
}

// Program abstracts a loadable BPF program that can attach to a tracepoint.
type Program interface {
	AttachTracepoint(category, name string) (Link, error)
}

// RawTracepointProgram is implemented by programs that can also attach as a
// raw_tracepoint (SEC "raw_tracepoint/<name>"), whose context is the
// tracepoint's TP_PROTO arguments rather than the formatted record.
//
// It is a separate interface, not a second method of Program, because only the
// hand-written probes need it: the syscall probe manager attaches classic
// tracepoints only, and widening Program would force every implementation of
// it to carry a method it never calls.
type RawTracepointProgram interface {
	AttachRawTracepoint(name string) (Link, error)
}

// Attacher resolves BPF programs by name.
type Attacher interface {
	GetProgram(name string) (Program, error)
}

// ProbeState is an immutable view used by callers/UI.
type ProbeState struct {
	Syscall string
	Active  bool
	Error   string
}

type probeEntry struct {
	syscall string
	enterTP string
	exitTP  string

	// enterLink and exitLink are the links the manager still has to destroy.
	// A link leaves the entry before its Destroy is called (takeLinks), so
	// none is ever destroyed twice.
	enterLink Link
	exitLink  Link
	attachMu  sync.Mutex

	// active says that the probe is attached: it holds a link. The one
	// moment the two differ is inside a Detach, which has taken the links
	// and commits "inactive" only after it destroyed them and reported the
	// change (commitDetach).
	active  bool
	lastErr error
}

// takeLinks removes both links from the entry and returns them, so the caller
// holds the only reference when it destroys them: Destroy is final (Link) and
// must not reach a link a second time, whatever happens meanwhile. The caller
// holds the manager lock.
func (e *probeEntry) takeLinks() (enterLink, exitLink Link) {
	enterLink, exitLink = e.enterLink, e.exitLink
	e.enterLink, e.exitLink = nil, nil
	return enterLink, exitLink
}

// Manager tracks probe attach/detach state for grouped syscall tracepoints.
type Manager struct {
	mu       sync.Mutex
	attacher Attacher
	probes   map[string]*probeEntry
	closed   bool
	// changeHook is told of every runtime change of a probe pair (see
	// SetChangeHook); nil until someone listens.
	changeHook func()
}

// NewManager creates a new probe manager that resolves programs via attacher.
func NewManager(attacher Attacher) *Manager {
	return &Manager{
		attacher: attacher,
		probes:   make(map[string]*probeEntry),
	}
}

// SetChangeHook registers hook to be told whenever Attach or Detach changes
// which tracepoints of a syscall are attached, from the moment it is set (the
// startup attaches of AttachAll normally run before anybody listens). A nil
// hook stops the reports. Close reports nothing: it ends the session, and
// whoever listened is being torn down with it.
//
// When it is called is the contract (task o03, internal/eventloop_restart.go).
// hook is called at every moment from which on the syscall is seen differently
// than before, always under the probe's own attach mutex, so the opposite
// change of the same syscall cannot begin before hook has returned:
//
//   - Attach calls it BEFORE it attaches anything, and a second time AFTER the
//     attempt: with both tracepoints attached, or with the attach failed. A
//     failed attach is reported twice as well because it may have had the
//     enter tracepoint attached for a moment (the exit attach failed and the
//     enter link was destroyed again): for the kernel that is an attach
//     followed by a detach, and a detach is reported when it is over. That
//     holds also when the destroy of the enter link reported an error: the
//     tracepoint is detached all the same (Link).
//   - Detach calls it AFTER both links were destroyed, and only when the
//     probe had a link to destroy. A destroy that reported an error is
//     reported like one that did not, and for the same reason: its tracepoint
//     is detached too, so the old attachment has seen its last syscall.
//
// Neither change leaves a pair half attached behind. A failed attach ends
// with no tracepoint of the syscall attached and a detach does so always,
// whatever their destroys returned, so outside an Attach or Detach that is
// under way a pair is attached as a whole or not at all - as far as the
// manager can know: that a tracepoint is detached when its Destroy reported
// an error is libbpf 1.5 as read from its source (Link), not something a test
// has seen.
//
// So what the listener notes in hook - the event loop clears the kernel's
// restart_pending_map and stamps the boot clock - is noted after the old
// attachment saw its last syscall (Detach), before the new one sees its first
// (Attach, first report) and once more when the new one is complete (Attach,
// second report). The first report of an attach cannot stand for the attach
// itself: the two tracepoints are attached one after the other, enter first,
// and a syscall that runs meanwhile - its enter before the enter tracepoint
// is attached, or its exit before the exit tracepoint is - goes unseen in part
// and can leave something behind that is younger than the first note. The
// second note is younger than all of that.
//
// What no report can do is coincide with the kernel's attach. From the moment
// the enter tracepoint is attached the new attachment produces records, and
// the note that is younger than the half-seen syscalls is taken only when the
// attach call for the exit tracepoint has returned and hook runs. A listener
// that acts on those records before hook has noted anything acts without the
// second note; how much that leaves open is the listener's to say (for the
// event loop: "Runtime probe changes", the residual).
//
// hook runs on the goroutine that called Attach or Detach (in the TUI a
// command goroutine, never the event loop) and without the manager lock, so it
// may call back into the manager's read methods; it must not call Attach,
// Detach or Toggle of the same syscall, whose mutex is held.
func (m *Manager) SetChangeHook(hook func()) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.changeHook = hook
}

// reportChange calls the change hook, if one is set. The caller holds the
// attach mutex of the probe that changes, and not the manager lock.
func (m *Manager) reportChange() {
	m.mu.Lock()
	hook := m.changeHook
	m.mu.Unlock()
	if hook != nil {
		hook()
	}
}

// Register registers the enter/exit tracepoint pair for a syscall key.
func (m *Manager) Register(syscall string, pair TracepointPair) {
	if m == nil || syscall == "" {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	entry, ok := m.probes[syscall]
	if !ok {
		entry = &probeEntry{syscall: syscall}
		m.probes[syscall] = entry
	}
	entry.enterTP = pair.Enter
	entry.exitTP = pair.Exit
}

// AttachAll registers and attaches all tracepoint pairs selected by shouldAttach.
//
// If onAttachError is non-nil, per-syscall attach failures are reported through
// the callback and AttachAll continues with the remaining tracepoints. This is
// the desired mode in production: when running a binary built on a newer kernel
// against an older one, some syscalls' tracepoints may be absent and the
// corresponding attach call returns ENOENT. The error is recorded on the
// probe entry (visible via States()) regardless of the callback.
//
// If onAttachError is nil, AttachAll preserves the strict legacy behavior and
// returns the first attach error to the caller. Tests rely on this mode.
func (m *Manager) AttachAll(shouldAttach func(string) bool, tpNames []string, onAttachError func(syscall string, err error)) error {
	if m == nil {
		return errors.New("probe manager is nil")
	}
	if shouldAttach == nil {
		shouldAttach = func(string) bool { return true }
	}

	groups := GroupTracepoints(tpNames)
	for syscall, pair := range groups {
		m.Register(syscall, pair)
		if !shouldAttach(pair.Enter) && !shouldAttach(pair.Exit) {
			continue
		}
		if err := m.Attach(syscall); err != nil {
			if onAttachError == nil {
				return err
			}
			onAttachError(syscall, err)
		}
	}
	return nil
}

// Toggle flips a syscall probe between attached and detached states.
func (m *Manager) Toggle(syscall string) error {
	if m == nil {
		return errors.New("probe manager is nil")
	}
	if syscall == "" {
		return errors.New("syscall is required")
	}

	m.mu.Lock()
	entry, err := m.entryLocked(syscall)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	active := entry.active
	m.mu.Unlock()

	if active {
		return m.Detach(syscall)
	}
	return m.Attach(syscall)
}

// Attach attaches enter/exit tracepoints for a registered syscall.
func (m *Manager) Attach(syscall string) error {
	if syscall == "" {
		return errors.New("syscall is required")
	}

	m.mu.Lock()
	entry, err := m.entryLocked(syscall)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	m.mu.Unlock()
	entry.attachMu.Lock()
	defer entry.attachMu.Unlock()

	// Re-acquire the lock after the per-entry mutex to prevent races with
	// concurrent Detach calls on the same syscall.
	enterTP, exitTP, attacher, err := m.snapshotAttachParams(syscall)
	if err != nil {
		return err
	}
	if attacher == nil {
		return nil // entry was already active
	}

	// Reported before the first tracepoint is attached (SetChangeHook): what
	// the listener notes must be older than anything the new attachment sees.
	m.reportChange()
	enterLink, exitLink, attachErr := attachPair(attacher, enterTP, exitTP)
	// And again once the attempt is over, whatever came of it: a syscall that
	// ran while only one of the two tracepoints was attached was seen in part,
	// and what the listener notes now is younger than that. Still under
	// attachMu, and before the new state is committed, like Detach's report.
	m.reportChange()
	return m.commitAttach(syscall, enterLink, exitLink, attachErr)
}

// snapshotAttachParams re-validates the entry under the manager lock and
// returns the tracepoint names and attacher needed for attachPair. It returns
// (nil attacher, nil error) when the probe is already active.
//
// It re-looks the entry up by name rather than taking the one Attach already
// resolved. The *probeEntry pointer itself is stable - entries are only ever
// added to m.probes, never removed - which is why passing it in looked
// harmless and was in fact dead: the parameter was shadowed by this lookup
// before it was ever read. What the lookup is actually for is the state around
// the pointer, re-read under m.mu after Attach released it to take attachMu:
// entryLocked re-checks m.closed, so a Close that landed in that window is
// reported instead of attaching to a closed manager, and entry.active is read
// here under m.mu rather than anywhere outside it.
func (m *Manager) snapshotAttachParams(syscall string) (enterTP, exitTP string, attacher Attacher, err error) {
	m.mu.Lock()
	entry, err := m.entryLocked(syscall)
	if err != nil {
		m.mu.Unlock()
		return "", "", nil, err
	}
	if entry.active {
		m.mu.Unlock()
		return "", "", nil, nil
	}
	enterTP = entry.enterTP
	exitTP = entry.exitTP
	attacher = m.attacher
	m.mu.Unlock()
	return enterTP, exitTP, attacher, nil
}

// commitAttach stores what attachPair returned under the manager lock: the
// link pair, which makes the probe active, or the attach error, with which it
// stays inactive and without a link (a failed attachPair returns none). On a
// concurrent manager close it destroys the links instead.
//
// The entry's own links need no merging with the new ones: Attach got here
// only for an inactive entry, which has none, and it still holds attachMu.
//
// Like snapshotAttachParams it resolves the entry by name under m.mu rather
// than accepting a *probeEntry: attachPair ran with m.mu released, so this has
// to re-check that the manager was not closed underneath it before publishing
// the links - otherwise Close would have already walked the entries and the
// links stored here would leak. The links destroyed on that path were never
// stored on the entry, so this is their one Destroy (Link); what it returns is
// joined into the error, with the attach error if there was one.
func (m *Manager) commitAttach(syscall string, enterLink, exitLink Link, attachErr error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, err := m.entryLocked(syscall)
	if err != nil {
		return errors.Join(
			err,
			attachErr,
			destroyLink(fmt.Sprintf("cleanup enter %s", syscall), enterLink),
			destroyLink(fmt.Sprintf("cleanup exit %s", syscall), exitLink),
		)
	}
	entry.enterLink = enterLink
	entry.exitLink = exitLink
	entry.lastErr = attachErr
	entry.active = enterLink != nil || exitLink != nil
	return attachErr
}

// Detach detaches enter/exit tracepoints for a registered syscall. Afterwards
// the probe is inactive and holds no link, whatever the destroys returned: a
// Destroy is final (Link), so one that reports an error leaves nothing to
// keep and nothing to retry. The error is recorded on the probe (States) and
// returned, and the next Attach attaches both tracepoints afresh.
func (m *Manager) Detach(syscall string) error {
	if syscall == "" {
		return errors.New("syscall is required")
	}

	m.mu.Lock()
	entry, err := m.entryLocked(syscall)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	m.mu.Unlock()
	entry.attachMu.Lock()
	defer entry.attachMu.Unlock()

	enterLink, exitLink, err := m.takeLinksToDetach(syscall)
	if err != nil {
		return err
	}
	enterErr, exitErr := destroyLinkPair(enterLink, exitLink)
	if enterLink != nil || exitLink != nil {
		// Reported once the links are gone and before attachMu is released
		// (SetChangeHook): what the listener notes is younger than anything
		// the old attachment saw, and a re-attach cannot start before it.
		m.reportChange()
	}
	return m.commitDetach(entry, detachError(syscall, enterErr, exitErr))
}

// takeLinksToDetach re-validates the entry under the manager lock - Detach
// released it to take attachMu, and a Close may have landed in that window -
// and takes its links off it (probeEntry.takeLinks). From here on Detach
// holds the only reference to them: a Close that starts now finds none on the
// entry and waits on attachMu for the detach to finish. The entry stays
// active until commitDetach.
func (m *Manager) takeLinksToDetach(syscall string) (enterLink, exitLink Link, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, err := m.entryLocked(syscall)
	if err != nil {
		return nil, nil, err
	}
	enterLink, exitLink = entry.takeLinks()
	return enterLink, exitLink, nil
}

// destroyLinkPair destroys both BPF links concurrently, each exactly once,
// and returns each link's error. The caller must have taken the links off
// their entry (probeEntry.takeLinks): they are gone afterwards, also the one
// whose Destroy returned an error (Link).
//
// The two Destroy calls run in parallel because each one closes a
// perf-event tracepoint fd whose release waits for an RCU grace period
// (~30ms); grace periods only overlap when the waits are concurrent, so a
// serial enter-then-exit destroy pays for two of them where one suffices.
func destroyLinkPair(enterLink, exitLink Link) (enterErr, exitErr error) {
	var wg sync.WaitGroup
	if exitLink != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			exitErr = exitLink.Destroy()
		}()
	}
	if enterLink != nil {
		enterErr = enterLink.Destroy()
	}
	wg.Wait() // also orders the write to exitErr before the caller's read
	return enterErr, exitErr
}

// detachError combines what the two destroys of a Detach returned into the
// error of that Detach, or nil when neither failed.
func detachError(syscall string, enterErr, exitErr error) error {
	switch {
	case enterErr != nil && exitErr != nil:
		return fmt.Errorf("detach enter %s: %w; detach exit %s: %w", syscall, enterErr, syscall, exitErr)
	case enterErr != nil:
		return fmt.Errorf("detach enter %s: %w", syscall, enterErr)
	case exitErr != nil:
		return fmt.Errorf("detach exit %s: %w", syscall, exitErr)
	}
	return nil
}

// commitDetach marks the entry inactive under the manager lock and records
// detachErr, the combined error of the destroys (nil when both succeeded),
// which it returns. The links left the entry before they were destroyed
// (takeLinksToDetach), so the probe is off either way: there is no
// half-detached state to keep.
func (m *Manager) commitDetach(entry *probeEntry, detachErr error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry.active = false
	entry.lastErr = detachErr
	return detachErr
}

// States returns a stable snapshot of all known probe states.
func (m *Manager) States() []ProbeState {
	if m == nil {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	out := make([]ProbeState, 0, len(m.probes))
	for syscall, entry := range m.probes {
		state := ProbeState{
			Syscall: syscall,
			Active:  entry.active,
		}
		if entry.lastErr != nil {
			state.Error = entry.lastErr.Error()
		}
		out = append(out, state)
	}
	slices.SortFunc(out, func(a, b ProbeState) int { return cmp.Compare(a.Syscall, b.Syscall) })
	return out
}

// ActiveCount returns the number of active probes and total registered probes.
func (m *Manager) ActiveCount() (active, total int) {
	if m == nil {
		return 0, 0
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	total = len(m.probes)
	for _, entry := range m.probes {
		if entry.active {
			active++
		}
	}
	return active, total
}

// IsActive reports whether the syscall probe is currently active.
func (m *Manager) IsActive(syscall string) bool {
	if m == nil || syscall == "" {
		return false
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	entry, ok := m.probes[syscall]
	if !ok {
		return false
	}
	return entry.active
}

// Close detaches all registered probes and marks the manager closed.
// It returns the first detach error encountered (subsequent errors are
// recorded on the probe entry but not returned).
func (m *Manager) Close() error {
	return m.CloseWithProgress(nil)
}

// maxConcurrentDetach bounds how many probe entries Close detaches at once.
// Every in-flight Destroy blocks an OS thread in close(2) for a grace period,
// so an unbounded fan-out over a large tracepoint set (367 pairs with all
// families) could hit a container's pids limit, which is fatal to the Go
// runtime. 256 entries (up to 512 links) covers the default file-system set at
// once; larger sets are detached through a sliding window of 256 entries (a
// new entry starts as soon as one finishes), still far below the serial cost.
const maxConcurrentDetach = 256

// CloseWithProgress detaches all registered probes and reports exact progress
// over the active syscall probe pairs. The callback receives an initial
// (0, total) update followed by one update after each active pair is detached.
// Inactive registered probes do not contribute to total because they require
// no kernel cleanup.
//
// Entries are detached concurrently (see detachAll), so the updates arrive in
// bursts rather than at a steady pace, and never overlap: the callback is
// invoked serially with a strictly increasing completed count.
func (m *Manager) CloseWithProgress(progress func(completed, total int)) error {
	if m == nil {
		return nil
	}
	entries, ok := m.snapshotAndMarkClosed()
	if !ok {
		return nil // already closed
	}

	total := 0
	for _, item := range entries {
		if item.active {
			total++
		}
	}
	if progress != nil {
		progress(0, total)
	}
	return m.detachAll(entries, total, progress, maxConcurrentDetach)
}

// detachAll detaches every entry, at most limit at a time, and returns the
// first error in snapshot order, which snapshotAndMarkClosed sorts by syscall
// name so the result is deterministic. Destroying a tracepoint link waits for an RCU
// grace period, and grace periods only merge when the waits overlap, so
// detaching serially cost ~30ms per link (7.5s for the default file-system
// set, 21s with all families) while a concurrent detach costs roughly one
// grace period as long as the waits overlap. limit is a sliding window (a
// semaphore), not a batch size: as soon as one entry finishes the next starts.
// progress is called after each entry that was active,
// under a mutex, so callbacks are serialized and the count is monotonic.
func (m *Manager) detachAll(entries []pairEntry, total int, progress func(completed, total int), limit int) error {
	errs := make([]error, len(entries))
	sem := make(chan struct{}, limit)
	var wg sync.WaitGroup
	var progressMu sync.Mutex
	completed := 0
	for i, item := range entries {
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = m.detachProbeEntry(item)
			<-sem
			if !item.active {
				return
			}
			progressMu.Lock()
			defer progressMu.Unlock()
			completed++
			if progress != nil {
				progress(completed, total)
			}
		}()
	}
	wg.Wait()
	return firstNonNil(errs)
}

// firstNonNil returns the first non-nil error of errs, or nil.
func firstNonNil(errs []error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// pairEntry groups a probe entry with its syscall name for use during Close.
// active is the entry's active flag when Close took its snapshot: the pairs
// Close counts as the ones to detach. That includes a pair a Detach is
// destroying at that moment (its links are off the entry already, see
// probeEntry.active); Close waits for that Detach and destroys nothing itself.
type pairEntry struct {
	syscall string
	entry   *probeEntry
	active  bool
}

// snapshotAndMarkClosed atomically marks the manager as closed and returns a
// snapshot of all probe entries, sorted by syscall name. The sort makes the
// order of detach errors (and thus Close's "first error") deterministic instead
// of following Go's random map iteration. Returns (nil, false) if already closed.
func (m *Manager) snapshotAndMarkClosed() ([]pairEntry, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, false
	}
	entries := make([]pairEntry, 0, len(m.probes))
	for syscall, entry := range m.probes {
		entries = append(entries, pairEntry{
			syscall: syscall,
			entry:   entry,
			active:  entry.active,
		})
	}
	m.closed = true
	slices.SortFunc(entries, func(a, b pairEntry) int { return cmp.Compare(a.syscall, b.syscall) })
	return entries, true
}

// detachProbeEntry waits on the per-entry mutex even when the close snapshot
// saw no links. An Attach or Toggle may already hold that mutex while blocked
// in the module-backed attach call; Close must not return and let the caller
// release the module until that work has finished and commitAttach has cleaned
// up any links it could not publish to the now-closed manager.
//
// detachAll runs this concurrently for different entries; the per-entry mutex
// still serializes it against an Attach or Toggle of the same entry.
//
// The manager is marked closed before this function runs. A Close called
// re-entrantly by a destroy/progress callback therefore returns at once rather
// than trying to acquire this mutex again.
//
// It destroys the links that are on the entry once it has the mutex, and only
// those: a link an earlier Detach or a failed attach already destroyed is not
// there any more, whether or not its Destroy reported an error (Link).
func (m *Manager) detachProbeEntry(item pairEntry) error {
	item.entry.attachMu.Lock()
	defer item.entry.attachMu.Unlock()

	m.mu.Lock()
	enterLink, exitLink := item.entry.takeLinks()
	item.entry.active = false
	item.entry.lastErr = nil
	m.mu.Unlock()

	enterErr, exitErr := destroyLinkPair(enterLink, exitLink)
	errForSyscall := enterErr
	if errForSyscall == nil {
		errForSyscall = exitErr
	}
	m.setLastError(item.syscall, errForSyscall)
	return errForSyscall
}

func (m *Manager) entryLocked(syscall string) (*probeEntry, error) {
	if m.closed {
		return nil, errors.New("probe manager is closed")
	}
	if m.attacher == nil {
		return nil, errors.New("probe manager has no attacher")
	}
	entry, ok := m.probes[syscall]
	if !ok {
		return nil, fmt.Errorf("unknown syscall %q", syscall)
	}
	return entry, nil
}

func (m *Manager) setLastError(syscall string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.probes[syscall]
	if !ok {
		return
	}
	entry.lastErr = err
}

// attachPair attaches the enter tracepoint and then the exit tracepoint. It
// returns both links or an error, never a link with an error: when the exit
// attach fails it destroys the enter link again and returns none.
//
// That holds also when this destroy reports an error, which is then joined
// to the attach error. Destroy is final (Link): the enter tracepoint is
// detached and its link freed all the same, so handing the link back - as
// task z13 first did, for the manager to keep and destroy again - would have
// a freed link destroyed a second time. The next attach of the syscall
// starts from nothing and finds no enter program of an earlier attempt
// beside its own.
func attachPair(attacher Attacher, enterTP, exitTP string) (Link, Link, error) {
	enterLink, err := attachOne(attacher, enterTP)
	if err != nil {
		return nil, nil, err
	}

	exitLink, err := attachOne(attacher, exitTP)
	if err != nil {
		return nil, nil, errors.Join(err, destroyLink("cleanup enter link after exit attach failure", enterLink))
	}
	return enterLink, exitLink, nil
}

// destroyLink destroys link, if there is one, and wraps its error with
// action. Like every Destroy it is final (Link): the caller must not keep the
// link, whatever this returns.
func destroyLink(action string, link Link) error {
	if link == nil {
		return nil
	}
	if err := link.Destroy(); err != nil {
		return fmt.Errorf("%s: %w", action, err)
	}
	return nil
}

func attachOne(attacher Attacher, tracepoint string) (Link, error) {
	if tracepoint == "" {
		return nil, nil
	}
	progName := "handle_" + tracepoint
	prog, err := attacher.GetProgram(progName)
	if err != nil {
		return nil, fmt.Errorf("get program %s: %w", progName, err)
	}
	link, err := prog.AttachTracepoint("syscalls", tracepoint)
	if err != nil {
		return nil, fmt.Errorf("attach %s: %w", tracepoint, err)
	}
	return link, nil
}
