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
// link wrapped (libbpfLink).
func attachLibbpfTracepoint(prog *bpf.BPFProg, category, name string) (probemanager.Link, error) {
	libbpfAttachMu.Lock()
	defer libbpfAttachMu.Unlock()
	return newLibbpfLink(attachBPFTracepoint(prog, category, name))
}

// attachLibbpfRawTracepoint is attachLibbpfTracepoint for the raw tracepoint
// name.
func attachLibbpfRawTracepoint(prog *bpf.BPFProg, name string) (probemanager.Link, error) {
	libbpfAttachMu.Lock()
	defer libbpfAttachMu.Unlock()
	return newLibbpfLink(attachBPFRawTracepoint(prog, name))
}

// libbpfProgramFDs returns the file descriptor of every program of module
// that the kernel loaded, attached or not. It is the one place that walks
// the module's programs (libbpfgo's iterator, which the scans of
// ior_bpflink_test.go pin to this function): the descriptors are all that
// leaves it, and all a descriptor is used for is reading the program's
// skipped runs (skippedRunCounter). They belong to the module and are valid
// until it is closed. A nil module has none.
func libbpfProgramFDs(module *bpf.Module) []int {
	if module == nil {
		return nil
	}
	var fds []int
	iter := module.Iterator()
	for prog := iter.NextProgram(); prog != nil; prog = iter.NextProgram() {
		if fd := prog.FileDescriptor(); fd >= 0 {
			fds = append(fds, fd)
		}
	}
	return fds
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
}

// newLibbpfLink wraps the result of a libbpfgo attach. A failed attach hands
// out no link, as an untyped nil: libbpfgo returns a nil *bpf.BPFLink then,
// which must become neither a non-nil probemanager.Link nor a wrapper around
// nothing.
func newLibbpfLink(link *bpf.BPFLink, err error) (probemanager.Link, error) {
	if err != nil {
		return nil, err
	}
	if link == nil {
		return nil, errNoLibbpfLink
	}
	wrapped := &libbpfLink{}
	wrapped.link.Store(link)
	return wrapped, nil
}

// Destroy destroys the link once and passes libbpfgo's error on. When there is
// one it first zeroes the BPFLink, so that Module.Close leaves the freed link
// alone (see libbpfLink); a successful Destroy has cleared the pointer itself
// and the struct is not touched. A second Destroy, and one on a nil or empty
// wrapper, does nothing and returns nil - at once, also while a first call is
// still inside libbpf: it does not wait for it. The callers promise one call
// per link and teardown waits for them, so nothing relies on such a wait.
func (l *libbpfLink) Destroy() error {
	if l == nil {
		return nil
	}
	link := l.link.Swap(nil)
	if link == nil {
		return nil
	}
	err := destroyBPFLink(link)
	if err != nil {
		*link = bpf.BPFLink{}
	}
	return err
}
