package generate

// kindMeta holds static metadata for a TracepointKind. Adding a new kind
// only requires registering an entry here — no switch statements need to be
// updated elsewhere (Open/Closed Principle).
type kindMeta struct {
	// structName is the C struct name used in generated BPF handlers, e.g. "fd_event".
	structName string
	// enterAccepted reports whether this kind is valid for a syscall-enter tracepoint.
	// Kinds that are exit-only (e.g. KindRet) must not appear on enter.
	enterAccepted bool
}

// kindRegistry maps every known TracepointKind to its static metadata.
// To add a new syscall classification, add a single entry here; the rest of
// the code (isEnterRejected, eventStructName, eventTypeConstant) picks it up
// automatically via lookupKind.
var kindRegistry = map[TracepointKind]kindMeta{
	KindFd:             {structName: "fd_event", enterAccepted: true},
	KindOpen:           {structName: "open_event", enterAccepted: true},
	KindPathname:       {structName: "path_event", enterAccepted: true},
	KindName:           {structName: "name_event", enterAccepted: true},
	KindRet:            {structName: "ret_event", enterAccepted: false},
	KindFcntl:          {structName: "fcntl_event", enterAccepted: true},
	KindNull:           {structName: "null_event", enterAccepted: true},
	KindDup3:           {structName: "dup3_event", enterAccepted: true},
	KindOpenByHandleAt: {structName: "open_by_handle_at_event", enterAccepted: true},
	// KindNone is intentionally absent: it represents "unclassified" and is
	// never enter-accepted. lookupKind returns the zero kindMeta (enterAccepted=false)
	// for any unregistered kind, so KindNone is implicitly rejected.
}

// lookupKind returns the metadata for kind. If kind is not registered (e.g.
// KindNone or an unknown value), it returns a zero kindMeta whose structName
// is "unknown_event" and enterAccepted is false.
func lookupKind(kind TracepointKind) kindMeta {
	if m, ok := kindRegistry[kind]; ok {
		return m
	}
	return kindMeta{structName: "unknown_event", enterAccepted: false}
}
