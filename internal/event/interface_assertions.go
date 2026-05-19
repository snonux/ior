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

	// *types.RetEvent is the exit-side event for all syscalls; it carries the
	// kernel return value.
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
)
