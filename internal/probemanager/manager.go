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
func (m *Manager) AttachAll(shouldAttach func(string) bool, tpNames []string) error {
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
			return err
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

	m.mu.Lock()
	entry, err = m.entryLocked(syscall)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	if entry.active {
		m.mu.Unlock()
		return nil
	}
	enterTP := entry.enterTP
	exitTP := entry.exitTP
	attacher := m.attacher
	m.mu.Unlock()

	enterLink, exitLink, attachErr := attachPair(attacher, enterTP, exitTP)

	m.mu.Lock()
	defer m.mu.Unlock()
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

	m.mu.Lock()
	entry, err = m.entryLocked(syscall)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	enterLink := entry.enterLink
	exitLink := entry.exitLink
	m.mu.Unlock()

	var errs []string
	enterErr := error(nil)
	if enterLink != nil {
		if err := enterLink.Destroy(); err != nil {
			enterErr = err
			errs = append(errs, fmt.Sprintf("detach enter %s: %v", syscall, err))
		}
	}
	exitErr := error(nil)
	if exitLink != nil {
		if err := exitLink.Destroy(); err != nil {
			exitErr = err
			errs = append(errs, fmt.Sprintf("detach exit %s: %v", syscall, err))
		}
	}

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
func (m *Manager) Close() error {
	if m == nil {
		return nil
	}

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	type pairEntry struct {
		syscall  string
		entry    *probeEntry
		hasLinks bool
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
	m.mu.Unlock()

	var firstErr error
	for _, item := range entries {
		if item.hasLinks {
			item.entry.attachMu.Lock()
		}
		var errForSyscall error
		m.mu.Lock()
		enterLink := item.entry.enterLink
		exitLink := item.entry.exitLink
		item.entry.enterLink = nil
		item.entry.exitLink = nil
		item.entry.active = false
		item.entry.lastErr = nil
		m.mu.Unlock()

		if enterLink != nil {
			if err := enterLink.Destroy(); err != nil {
				errForSyscall = err
				if firstErr == nil {
					firstErr = err
				}
			}
		}
		if exitLink != nil {
			if err := exitLink.Destroy(); err != nil {
				if errForSyscall == nil {
					errForSyscall = err
				}
				if firstErr == nil {
					firstErr = err
				}
			}
		}
		m.setLastError(item.syscall, errForSyscall)
		if item.hasLinks {
			item.entry.attachMu.Unlock()
		}
	}
	return firstErr
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
