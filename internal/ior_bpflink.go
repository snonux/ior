package internal

import (
	"errors"
	"sync"
	"sync/atomic"

	"ior/internal/probemanager"

	bpf "github.com/aquasecurity/libbpfgo"
)

// errNoLibbpfLink is what newLibbpfLink reports for an attach that returned
// neither a link nor an error. libbpfgo v0.9.2-libbpf-1.5.1 never does.
var errNoLibbpfLink = errors.New("libbpfgo returned neither a link nor an error")

// destroyBPFLink is libbpfgo's BPFLink.Destroy, the one call libbpfLink makes
// on a link. It is a variable only so that tests can count the calls and make
// one fail without a kernel (ior_bpflink_test.go).
var destroyBPFLink = (*bpf.BPFLink).Destroy

// attachBPFTracepoint and attachBPFRawTracepoint are libbpfgo's two attach
// calls, the only ones ior makes (attachLibbpfTracepoint,
// attachLibbpfRawTracepoint). They are variables for the same reason as
// destroyBPFLink: tests watch the calls without a kernel.
var (
	attachBPFTracepoint    = (*bpf.BPFProg).AttachTracepoint
	attachBPFRawTracepoint = (*bpf.BPFProg).AttachRawTracepoint
)

// libbpfAttachMu serialises every attach ior makes through libbpfgo (task
// 223).
//
// libbpfgo v0.9.2-libbpf-1.5.1 keeps the links of a module on a list and
// appends to it in each attach, without a lock (prog.go, lines 385 and 405:
// `p.module.links = append(p.module.links, bpfLink)`). Two attaches at once
// are therefore a data race on that slice: at best one of the two entries is
// lost, at worst the list's header is written half and half and the next
// append lands outside its array.
//
// ior can attach two programs at once. The probe manager holds only the
// attach mutex of the probe it changes, and the TUI runs each single toggle
// of the probes modal as a command of its own, on a goroutine of its own:
// two probes toggled on one after the other are two attaches of different
// syscalls under way together (the modal refuses a single toggle only while
// a family batch or an all-on/all-off walk runs, which are loops on one
// goroutine, as the startup attach is).
//
// It is one mutex for the process, not one per module. A process has one
// module per trace session, and two only while a TUI restart tears the old
// session down; attaches of one session ran one after the other already
// except for those toggles, so nothing that mattered ran in parallel before.
// A package variable also needs no constructor that a struct literal of the
// seam's types could forget.
//
// Destroys are not serialised. libbpfgo's BPFLink.Destroy touches the link
// alone (link.go, lines 70-81: bpf_link__destroy on its C link, then its own
// pointer) and never the module's list, and the probe manager destroys the
// two links of a pair, and at Close hundreds of them, at the same time on
// purpose: their grace periods merge only when they overlap
// (probemanager.destroyLinkPair). GetProgram takes no lock either: it looks
// the program up in the loaded object and allocates a BPFProg of its own.
var libbpfAttachMu sync.Mutex

// attachLibbpfTracepoint attaches prog to the classic tracepoint
// category/name, one attach at a time (libbpfAttachMu), and hands out the
// link wrapped and its program listed as attached (libbpfLinkOf).
func attachLibbpfTracepoint(prog *bpf.BPFProg, category, name string) (probemanager.Link, error) {
	libbpfAttachMu.Lock()
	defer libbpfAttachMu.Unlock()
	return libbpfLinkOf(prog)(attachBPFTracepoint(prog, category, name))
}

// attachLibbpfRawTracepoint is attachLibbpfTracepoint for the raw tracepoint
// name.
func attachLibbpfRawTracepoint(prog *bpf.BPFProg, name string) (probemanager.Link, error) {
	libbpfAttachMu.Lock()
	defer libbpfAttachMu.Unlock()
	return libbpfLinkOf(prog)(attachBPFRawTracepoint(prog, name))
}

// attachedProgram names one loaded program for the list of attached ones:
// the module it belongs to and its file descriptor, which is all that ever
// leaves the seam of a program (libbpfAttachedProgramFDs). The zero value
// names no program and is never listed.
type attachedProgram struct {
	module *bpf.Module
	fd     int
}

// attachedProgramOf names prog. A nil program (the tests' seam without a
// kernel) and one the kernel did not load have no name.
func attachedProgramOf(prog *bpf.BPFProg) attachedProgram {
	if prog == nil {
		return attachedProgram{}
	}
	fd := prog.FileDescriptor()
	if fd < 0 {
		return attachedProgram{}
	}
	return attachedProgram{module: prog.GetModule(), fd: fd}
}

// attachedProgramSet lists, per module, the programs that have a live link:
// the ones the kernel can run, and so the only ones it can skip (task 723,
// skippedRunCounter). A program enters with the link ior hands out for it
// (libbpfLinkOf) and leaves when that link's Destroy returned
// (libbpfLink.Destroy), so the list follows the probe manager's attaches and
// detaches at runtime and the hand-attached probes alike, without asking the
// manager: its lock is held across attaches that take milliseconds, and the
// event loop reads this list while it decides about a fold.
//
// The mutex guards two map operations and is never held across a system
// call. A module's entry goes with its last link, so a closed module leaves
// nothing behind: teardown destroys every link before it closes the module.
type attachedProgramSet struct {
	mu sync.Mutex
	// links counts the live links of each program, by module and fd. ior
	// attaches every program once; the count only keeps a second link of
	// the same program from being unlisted by the first one's Destroy.
	links map[*bpf.Module]map[int]int
}

// libbpfAttached is the list for the process. One list serves every module:
// each asks for its own programs.
var libbpfAttached attachedProgramSet

func (s *attachedProgramSet) add(prog attachedProgram) {
	if prog.module == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.links == nil {
		s.links = map[*bpf.Module]map[int]int{}
	}
	if s.links[prog.module] == nil {
		s.links[prog.module] = map[int]int{}
	}
	s.links[prog.module][prog.fd]++
}

func (s *attachedProgramSet) remove(prog attachedProgram) {
	if prog.module == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ofModule := s.links[prog.module]
	if ofModule[prog.fd] > 1 {
		ofModule[prog.fd]--
		return
	}
	delete(ofModule, prog.fd)
	if len(ofModule) == 0 {
		delete(s.links, prog.module)
	}
}

// fds returns the descriptors of module's attached programs, in a slice of
// the caller's own.
func (s *attachedProgramSet) fds(module *bpf.Module) []int {
	s.mu.Lock()
	defer s.mu.Unlock()
	ofModule := s.links[module]
	if len(ofModule) == 0 {
		return nil
	}
	fds := make([]int, 0, len(ofModule))
	for fd := range ofModule {
		fds = append(fds, fd)
	}
	return fds
}

// libbpfAttachedProgramFDs returns the file descriptor of every program of
// module that has a live link at this moment: the syscall probes the probe
// manager has attached and the hand-attached ones. The descriptors are all
// that leaves the seam of a program, and all one is used for is reading the
// program's skipped runs (skippedRunCounter). They belong to the module and
// are valid until it is closed.
func libbpfAttachedProgramFDs(module *bpf.Module) []int {
	return libbpfAttached.fds(module)
}

// libbpfLink is the probemanager.Link ior hands out for every link it attaches
// through libbpfgo (libbpfTracepointProgram). It keeps libbpfgo's Module.Close
// from destroying a link a second time after its Destroy reported an error
// (task 123).
//
// The facts, libbpfgo v0.9.2-libbpf-1.5.1 with libbpf 1.5.1:
//
//   - libbpf, src/libbpf.c, bpf_link__destroy (line 10666) frees the link
//     whatever its detach returned and only passes the error on.
//   - libbpfgo, link.go, BPFLink.Destroy (lines 70-81) returns that errno
//     BEFORE it clears its private pointer to the freed link.
//   - libbpfgo, module.go, Module.Close (lines 194-198) calls Destroy on
//     every link the module ever handed out whose pointer is still set
//     (line 195). After a failed Destroy that is a use after free and a
//     double free; a bare Module.Close then dies with SIGSEGV in
//     bpf_link__destroy.
//
// Destroy therefore overwrites the BPFLink with its zero value when libbpfgo
// reported an error. That clears the private pointer - the struct can be
// assigned from outside its package although no field can be named - and
// Module.Close skips the link and releases everything else as usual:
// programs, maps, ring buffers, the object. Nothing is lost by it: the C
// struct is freed and the link's fds are closed (which is what detaches the
// program), so the Go struct describes nothing any more, and ior holds no
// other reference to it than this wrapper, which drops it.
//
// Caveat: a zeroed BPFLink has a nil prog, and Module.linkExist (module.go,
// lines 460-468) calls link.prog.Name() on every link of the module. Only
// Module.AttachPrograms reaches it. ior attaches each program by name and
// calls neither AttachPrograms nor DetachPrograms (which would destroy the
// module's links behind the wrappers' backs);
// TestIorNeverCallsTheModuleWideAttachOrDetach pins both.
//
// Once libbpfgo clears the pointer before it returns the errno, the zeroing
// changes nothing that Module.Close looks at and can be removed;
// TestBareLibbpfgoLinkKeepsItsPointerAfterAFailedDestroy fails then.
//
// A failing Destroy does not occur in practice, but it can be provoked: close
// the link's fds behind libbpf's back and Destroy returns EBADF. For a classic
// tracepoint (a perf link, bpf_link_perf_detach, line 10789) only the
// PERF_EVENT_IOC_DISABLE ioctl can fail - the results of its two close(2)
// calls are ignored. For a raw tracepoint the detach is one close(2) of the
// link fd (bpf_link__detach_fd, line 10695), whose failure is the error. The
// root tests in ior_bpflink_root_test.go do exactly that to the real module.
type libbpfLink struct {
	// link is the libbpfgo link until Destroy takes it. The swap is atomic so
	// that Destroy reaches libbpfgo at most once per link however it is
	// called; its callers promise one call already (probemanager.Link).
	link atomic.Pointer[bpf.BPFLink]
	// program is the attached program the link keeps listed
	// (attachedProgramSet); the zero value for a link no program was named
	// for (newLibbpfLink).
	program attachedProgram
}

// newLibbpfLink wraps the result of a libbpfgo attach for which no program
// is listed as attached (libbpfLinkOf of no program).
func newLibbpfLink(link *bpf.BPFLink, err error) (probemanager.Link, error) {
	return libbpfLinkOf(nil)(link, err)
}

// libbpfLinkOf returns the function that wraps the result of a libbpfgo
// attach of prog; it takes the attach call's two results as they come, so
// that no bare link is ever held in a variable (the attach functions are
// pinned to `return libbpfLinkOf(prog)(attachBPF...(...))`). A failed attach
// hands out no link, as an untyped nil: libbpfgo returns a nil *bpf.BPFLink
// then, which must become neither a non-nil probemanager.Link nor a wrapper
// around nothing. A link that is handed out lists prog as attached until its
// Destroy (attachedProgramSet).
func libbpfLinkOf(prog *bpf.BPFProg) func(*bpf.BPFLink, error) (probemanager.Link, error) {
	return func(link *bpf.BPFLink, err error) (probemanager.Link, error) {
		if err != nil {
			return nil, err
		}
		if link == nil {
			return nil, errNoLibbpfLink
		}
		wrapped := &libbpfLink{program: attachedProgramOf(prog)}
		wrapped.link.Store(link)
		libbpfAttached.add(wrapped.program)
		return wrapped, nil
	}
}

// Destroy destroys the link once and passes libbpfgo's error on. When there is
// one it first zeroes the BPFLink, so that Module.Close leaves the freed link
// alone (see libbpfLink); a successful Destroy has cleared the pointer itself
// and the struct is not touched. A second Destroy, and one on a nil or empty
// wrapper, does nothing and returns nil - at once, also while a first call is
// still inside libbpf: it does not wait for it. The callers promise one call
// per link and teardown waits for them, so nothing relies on such a wait.
//
// The program leaves the list of attached ones after libbpfgo returned,
// whatever it returned (the link is gone either way): until then the kernel
// may still run the program, or skip it, and a sweep of the skipped runs
// must still read it.
func (l *libbpfLink) Destroy() error {
	if l == nil {
		return nil
	}
	link := l.link.Swap(nil)
	if link == nil {
		return nil
	}
	err := destroyBPFLink(link)
	libbpfAttached.remove(l.program)
	if err != nil {
		*link = bpf.BPFLink{}
	}
	return err
}
