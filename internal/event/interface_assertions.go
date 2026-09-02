package event

import "ior/internal/types"

// --- compile-time interface satisfaction assertions ---
//
// Every generated concrete event type in internal/types must satisfy the Event
// interface (which composes EventIdentity and EventLifecycle). These assertions
// live in the event package rather than in the generated file so they are not
// overwritten by mage generate. The event package already imports types, so no
// new import cycle is introduced.

var (
	// *types.OpenEvent is the most common event type; it carries open-syscall
	// enter-event data (fd, flags, pathname).
	_ Event = (*types.OpenEvent)(nil)

	// *types.NullEvent is used for tracepoints that carry no extra payload
	// beyond the base header fields.
	_ Event = (*types.NullEvent)(nil)

	// *types.FdEvent carries a single file-descriptor field (close, dup, etc.).
	_ Event = (*types.FdEvent)(nil)

	// *types.RetEvent is the default exit-side event: every syscall exit that
	// is not pinned to a kind-specific struct decodes as a RetEvent carrying
	// the kernel return value. The exceptions are the exits that need extra
	// payload alongside the return value — accept/accept4 (AcceptEvent),
	// pipe/pipe2 (PipeEvent), socketpair (SocketpairEvent) and the
	// eventfd/pidfd family (EventfdEvent) — and those carry ret too, so every
	// generated exit handler records the return value.
	_ Event = (*types.RetEvent)(nil)

	// *types.NameEvent carries a single filename field (unlink, mkdir, etc.).
	_ Event = (*types.NameEvent)(nil)

	// *types.PathEvent carries a pathname field for path-only syscalls.
	_ Event = (*types.PathEvent)(nil)

	// *types.FcntlEvent carries the fcntl command and argument fields.
	_ Event = (*types.FcntlEvent)(nil)

	// *types.Dup3Event carries the old and new file-descriptor fields for dup3.
	_ Event = (*types.Dup3Event)(nil)

	// *types.OpenByHandleAtEvent carries the mount-fd and flags for
	// open_by_handle_at syscalls.
	_ Event = (*types.OpenByHandleAtEvent)(nil)

	// *types.SocketEvent carries socket domain/type/protocol metadata.
	_ Event = (*types.SocketEvent)(nil)

	// *types.SocketpairEvent carries socketpair domain/type/protocol metadata.
	_ Event = (*types.SocketpairEvent)(nil)

	// *types.AcceptEvent carries listening-fd input and accepted-fd return metadata.
	_ Event = (*types.AcceptEvent)(nil)

	// *types.PipeEvent carries pipe flags plus the two returned pipe descriptors.
	_ Event = (*types.PipeEvent)(nil)

	// *types.EventfdEvent carries eventfd flags and the returned descriptor.
	_ Event = (*types.EventfdEvent)(nil)

	// *types.EpollCtlEvent carries epoll control metadata (epfd/op/target-fd/events).
	_ Event = (*types.EpollCtlEvent)(nil)

	// *types.PollEvent carries poll/select argument metadata (nfds and timeout).
	_ Event = (*types.PollEvent)(nil)

	// *types.MemEvent carries memory-operation metadata (addr/length/flags).
	_ Event = (*types.MemEvent)(nil)

	// *types.SleepEvent carries requested sleep duration metadata.
	_ Event = (*types.SleepEvent)(nil)

	// *types.TwoFdEvent carries operations that include two fd inputs.
	_ Event = (*types.TwoFdEvent)(nil)
)

// --- ret-carrying event assertions ---
//
// Every event type whose kernel struct has a `ret` field must satisfy
// RetCarrier, because streamrow.New reads RetVal/IsError through that
// interface. The GetRet accessor is emitted by the types generator, so a newly
// generated ret-carrying struct is covered automatically; these assertions
// pin the current set, and TestGeneratedRetCarriersExposeGetRet in
// internal/types guards the generator-level invariant.

var (
	// *types.RetEvent is the generic syscall exit payload.
	_ RetCarrier = (*types.RetEvent)(nil)

	// *types.SocketpairEvent is the socketpair exit payload (sv0/sv1 + ret).
	_ RetCarrier = (*types.SocketpairEvent)(nil)

	// *types.AcceptEvent is the accept/accept4 exit payload (accepted fd in ret).
	_ RetCarrier = (*types.AcceptEvent)(nil)

	// *types.PipeEvent is the pipe/pipe2 exit payload (fd0/fd1 + ret).
	_ RetCarrier = (*types.PipeEvent)(nil)

	// *types.EventfdEvent is the eventfd/pidfd-family exit payload (flags + ret).
	_ RetCarrier = (*types.EventfdEvent)(nil)
)
