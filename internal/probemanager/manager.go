package probemanager

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
)

// Link abstracts an attached tracepoint link.
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

	enterLink Link
	exitLink  Link
	attachMu  sync.Mutex

	active  bool
	lastErr error
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
//     followed by a detach, and a detach is reported when it is over. If that
//     enter link could not be destroyed either, there was no detach: the
//     enter tracepoint stays attached while the probe counts as inactive with
//     no links. For the listener that is the enter-only state described under
//     Detach below, and as harmless.
//   - Detach calls it AFTER both links were destroyed, and only when the
//     probe had a link to destroy. A destroy that failed is reported like one
//     that succeeded. It leaves the pair half attached, and with the enter
//     link gone and the exit link left the syscall's calls do run unseen at
//     their enter; the pair stays that way until the next Detach of the
//     syscall, which reports again (an Attach of a probe that still has a
//     link is a no-op). The mirror state, the enter link left and the exit
//     link gone, lasts as long. Why the listener's outcome is right meanwhile
//     is its business ("Runtime probe changes" in
//     internal/eventloop_restart.go: the exit tracepoint that is still
//     attached ends the wait of the row; with only the enter tracepoint left
//     the syscall emits no exit, so nothing of it becomes pending).
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

// commitAttach stores the newly attached link pair under the manager lock,
// recording any attach error or cleaning up on a concurrent manager close.
//
// Like snapshotAttachParams it resolves the entry by name under m.mu rather
// than accepting a *probeEntry: attachPair ran with m.mu released, so this has
// to re-check that the manager was not closed underneath it before publishing
// the links - otherwise Close would have already walked the entries and the
// two links stored here would leak.
func (m *Manager) commitAttach(syscall string, enterLink, exitLink Link, attachErr error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, err := m.entryLocked(syscall)
	if err != nil {
		return errors.Join(
			err,
			destroyLink(fmt.Sprintf("cleanup enter %s", syscall), enterLink),
			destroyLink(fmt.Sprintf("cleanup exit %s", syscall), exitLink),
		)
	}
	if attachErr != nil {
		entry.lastErr = attachErr
		entry.active = entry.enterLink != nil || entry.exitLink != nil
		return attachErr
	}
	entry.enterLink = enterLink
	entry.exitLink = exitLink
	entry.lastErr = nil
	entry.active = enterLink != nil || exitLink != nil
	return nil
}

// Detach detaches enter/exit tracepoints for a registered syscall.
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

	// Re-acquire the lock after the per-entry mutex to prevent races with
	// concurrent Attach calls on the same syscall.
	m.mu.Lock()
	entry, err = m.entryLocked(syscall)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	enterLink := entry.enterLink
	exitLink := entry.exitLink
	m.mu.Unlock()

	errs, enterErr, exitErr := destroyLinkPair(syscall, enterLink, exitLink)
	if enterLink != nil || exitLink != nil {
		// Reported once the links are gone and before attachMu is released
		// (SetChangeHook): what the listener notes is younger than anything
		// the old attachment saw, and a re-attach cannot start before it.
		m.reportChange()
	}
	return m.commitDetach(entry, enterErr, exitErr, errs)
}

// destroyLinkPair destroys both BPF links concurrently and collects any errors
// into a slice. It returns each link's error separately so partial-success can
// be recorded.
//
// The two Destroy calls run in parallel because each one closes a
// perf-event tracepoint fd whose release waits for an RCU grace period
// (~30ms); grace periods only overlap when the waits are concurrent, so a
// serial enter-then-exit destroy pays for two of them where one suffices.
func destroyLinkPair(syscall string, enterLink, exitLink Link) (errs []string, enterErr, exitErr error) {
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
	wg.Wait() // also orders the write to exitErr before the reads below
	if enterErr != nil {
		errs = append(errs, fmt.Sprintf("detach enter %s: %v", syscall, enterErr))
	}
	if exitErr != nil {
		errs = append(errs, fmt.Sprintf("detach exit %s: %v", syscall, exitErr))
	}
	return errs, enterErr, exitErr
}

// commitDetach updates entry link pointers and active flag under the manager
// lock, then returns a combined error if any link destroy failed.
func (m *Manager) commitDetach(entry *probeEntry, enterErr, exitErr error, errs []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if enterErr == nil {
		entry.enterLink = nil
	}
	if exitErr == nil {
		entry.exitLink = nil
	}
	entry.active = entry.enterLink != nil || entry.exitLink != nil
	if len(errs) == 0 {
		entry.lastErr = nil
		return nil
	}
	combined := errors.New(strings.Join(errs, "; "))
	entry.lastErr = combined
	return combined
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
		if item.hasLinks {
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
// progress is called after each entry that had links,
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
			if !item.hasLinks {
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
type pairEntry struct {
	syscall  string
	entry    *probeEntry
	hasLinks bool
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
			syscall:  syscall,
			entry:    entry,
			hasLinks: entry.enterLink != nil || entry.exitLink != nil,
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
func (m *Manager) detachProbeEntry(item pairEntry) error {
	item.entry.attachMu.Lock()
	defer item.entry.attachMu.Unlock()

	m.mu.Lock()
	enterLink := item.entry.enterLink
	exitLink := item.entry.exitLink
	item.entry.enterLink = nil
	item.entry.exitLink = nil
	item.entry.active = false
	item.entry.lastErr = nil
	m.mu.Unlock()

	_, enterErr, exitErr := destroyLinkPair(item.syscall, enterLink, exitLink)
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
