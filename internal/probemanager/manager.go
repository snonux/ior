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
}

// NewManager creates a new probe manager that resolves programs via attacher.
func NewManager(attacher Attacher) *Manager {
	return &Manager{
		attacher: attacher,
		probes:   make(map[string]*probeEntry),
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
	enterTP, exitTP, attacher, err := m.snapshotAttachParams(syscall, entry)
	if err != nil {
		return err
	}
	if attacher == nil {
		return nil // entry was already active
	}

	enterLink, exitLink, attachErr := attachPair(attacher, enterTP, exitTP)
	return m.commitAttach(syscall, entry, enterLink, exitLink, attachErr)
}

// snapshotAttachParams re-validates the entry under the manager lock and
// returns the tracepoint names and attacher needed for attachPair. It returns
// (nil attacher, nil error) when the probe is already active.
func (m *Manager) snapshotAttachParams(syscall string, entry *probeEntry) (enterTP, exitTP string, attacher Attacher, err error) {
	m.mu.Lock()
	entry, err = m.entryLocked(syscall)
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

// commitAttach stores the newly attached link pair in entry under the manager
// lock, recording any attach error or cleaning up on a concurrent manager close.
func (m *Manager) commitAttach(syscall string, entry *probeEntry, enterLink, exitLink Link, attachErr error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var err error
	entry, err = m.entryLocked(syscall)
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

	enterErr, exitErr, errs := destroyLinkPair(syscall, enterLink, exitLink)
	return m.commitDetach(entry, enterErr, exitErr, errs)
}

// destroyLinkPair destroys both BPF links and collects any errors into a slice.
// It returns each link's error separately so partial-success can be recorded.
func destroyLinkPair(syscall string, enterLink, exitLink Link) (enterErr, exitErr error, errs []string) {
	if enterLink != nil {
		if err := enterLink.Destroy(); err != nil {
			enterErr = err
			errs = append(errs, fmt.Sprintf("detach enter %s: %v", syscall, err))
		}
	}
	if exitLink != nil {
		if err := exitLink.Destroy(); err != nil {
			exitErr = err
			errs = append(errs, fmt.Sprintf("detach exit %s: %v", syscall, err))
		}
	}
	return enterErr, exitErr, errs
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
	if m == nil {
		return nil
	}
	entries, ok := m.snapshotAndMarkClosed()
	if !ok {
		return nil // already closed
	}

	var firstErr error
	for _, item := range entries {
		if err := m.detachProbeEntry(item); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// pairEntry groups a probe entry with its syscall name for use during Close.
type pairEntry struct {
	syscall  string
	entry    *probeEntry
	hasLinks bool
}

// snapshotAndMarkClosed atomically marks the manager as closed and returns a
// snapshot of all probe entries. Returns (nil, false) if already closed.
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
	return entries, true
}

// detachProbeEntry destroys the BPF links for a single probe entry under its
// per-entry mutex, clears the link pointers, and records any error.
func (m *Manager) detachProbeEntry(item pairEntry) error {
	if item.hasLinks {
		item.entry.attachMu.Lock()
		defer item.entry.attachMu.Unlock()
	}

	m.mu.Lock()
	enterLink := item.entry.enterLink
	exitLink := item.entry.exitLink
	item.entry.enterLink = nil
	item.entry.exitLink = nil
	item.entry.active = false
	item.entry.lastErr = nil
	m.mu.Unlock()

	var errForSyscall error
	if enterLink != nil {
		if err := enterLink.Destroy(); err != nil {
			errForSyscall = err
		}
	}
	if exitLink != nil {
		if err := exitLink.Destroy(); err != nil && errForSyscall == nil {
			errForSyscall = err
		}
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
