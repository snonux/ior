package types

import "encoding/binary"

const (
	// Sizes below are the kernel ringbuf payload sizes, i.e. sizeof(struct ...)
	// from internal/c/types.h compiled for the BPF/LP64 target. The kernel
	// reserves sizeof(struct) via bpf_ringbuf_reserve, which for structs whose
	// last field is 32-bit but that also contain a __u64 includes trailing
	// padding to the struct's 8-byte alignment. The fast path must therefore
	// gate on sizeof, not on the sum of field widths, or it silently falls back
	// to the slow binary.Read path on the hot events (open/read/write/ret/...).
	//
	// The *V1 constants are the historical, unpadded field-sum sizes still
	// produced by Go's binary.Write (used by tests and by Bytes()); the fast
	// decoders accept both so test payloads and kernel payloads both hit the
	// fast path. The trailing pad bytes carry no data and are ignored.
	openEventSize             = 304
	openEventSizeV1           = 300
	execEventSize             = 304
	nullEventSize             = 24
	fdEventSize               = 32
	fdEventSizeV1             = 28
	retEventSize              = 40
	retEventSizeV1            = 36
	nameEventSize             = 536
	pathEventSize             = 280
	fcntlEventSize            = 40
	dup3EventSize             = 32
	openByHandleAtEventSize   = 32
	openByHandleAtEventSizeV1 = 28
	socketEventSize           = 40
	socketEventSizeV1         = 36
	socketpairEventSize       = 56
	socketpairEventSizeV1     = 52
	acceptEventSize           = 40
	acceptEventSizeV1         = 36
	pipeEventSize             = 48
	pipeEventSizeV1           = 44
	eventfdEventSize          = 40
	eventfdEventSizeV1        = 36
	epollCtlEventSize         = 40
	twoFdEventSize            = 40
	pollEventSize             = 40
	pollEventSizeV1           = 36
	memEventSize              = 56
	sleepEventSize            = 32
	keyctlEventSize           = 40
	ptraceEventSize           = 48
	perfOpenEventSize         = 56
)

func NewOpenEventFast(raw []byte) *OpenEvent {
	if len(raw) < openEventSizeV1 {
		return nil
	}
	if len(raw) != openEventSize && len(raw) != openEventSizeV1 {
		return NewOpenEvent(raw)
	}
	o := poolOfOpenEvents.Get().(*OpenEvent)
	o.EventType = EventType(binary.LittleEndian.Uint32(raw[0:4]))
	o.TraceId = TraceId(binary.LittleEndian.Uint32(raw[4:8]))
	o.Time = binary.LittleEndian.Uint64(raw[8:16])
	o.Pid = binary.LittleEndian.Uint32(raw[16:20])
	o.Tid = binary.LittleEndian.Uint32(raw[20:24])
	o.Flags = int32(binary.LittleEndian.Uint32(raw[24:28]))
	copy(o.Filename[:], raw[28:284])
	copy(o.Comm[:], raw[284:300])
	return o
}

func NewExecEventFast(raw []byte) *ExecEvent {
	if len(raw) < execEventSize {
		return nil
	}
	if len(raw) != execEventSize {
		return NewExecEvent(raw)
	}
	e := poolOfExecEvents.Get().(*ExecEvent)
	e.EventType = EventType(binary.LittleEndian.Uint32(raw[0:4]))
	e.TraceId = TraceId(binary.LittleEndian.Uint32(raw[4:8]))
	e.Time = binary.LittleEndian.Uint64(raw[8:16])
	e.Pid = binary.LittleEndian.Uint32(raw[16:20])
	e.Tid = binary.LittleEndian.Uint32(raw[20:24])
	e.Dirfd = int32(binary.LittleEndian.Uint32(raw[24:28]))
	e.Flags = int32(binary.LittleEndian.Uint32(raw[28:32]))
	copy(e.Filename[:], raw[32:288])
	copy(e.Comm[:], raw[288:304])
	return e
}

func NewNullEventFast(raw []byte) *NullEvent {
	if len(raw) < nullEventSize {
		return nil
	}
	if len(raw) != nullEventSize {
		return NewNullEvent(raw)
	}
	n := poolOfNullEvents.Get().(*NullEvent)
	n.EventType = EventType(binary.LittleEndian.Uint32(raw[0:4]))
	n.TraceId = TraceId(binary.LittleEndian.Uint32(raw[4:8]))
	n.Time = binary.LittleEndian.Uint64(raw[8:16])
	n.Pid = binary.LittleEndian.Uint32(raw[16:20])
	n.Tid = binary.LittleEndian.Uint32(raw[20:24])
	return n
}

func NewFdEventFast(raw []byte) *FdEvent {
	if len(raw) < fdEventSizeV1 {
		return nil
	}
	if len(raw) != fdEventSize && len(raw) != fdEventSizeV1 {
		return NewFdEvent(raw)
	}
	f := poolOfFdEvents.Get().(*FdEvent)
	f.EventType = EventType(binary.LittleEndian.Uint32(raw[0:4]))
	f.TraceId = TraceId(binary.LittleEndian.Uint32(raw[4:8]))
	f.Time = binary.LittleEndian.Uint64(raw[8:16])
	f.Pid = binary.LittleEndian.Uint32(raw[16:20])
	f.Tid = binary.LittleEndian.Uint32(raw[20:24])
	f.Fd = int32(binary.LittleEndian.Uint32(raw[24:28]))
	return f
}

func NewRetEventFast(raw []byte) *RetEvent {
	if len(raw) < retEventSizeV1 {
		return nil
	}
	if len(raw) != retEventSize && len(raw) != retEventSizeV1 {
		return NewRetEvent(raw)
	}
	r := poolOfRetEvents.Get().(*RetEvent)
	r.EventType = EventType(binary.LittleEndian.Uint32(raw[0:4]))
	r.TraceId = TraceId(binary.LittleEndian.Uint32(raw[4:8]))
	r.Time = binary.LittleEndian.Uint64(raw[8:16])
	r.Ret = int64(binary.LittleEndian.Uint64(raw[16:24]))
	r.Pid = binary.LittleEndian.Uint32(raw[24:28])
	r.Tid = binary.LittleEndian.Uint32(raw[28:32])
	r.RetType = binary.LittleEndian.Uint32(raw[32:36])
	return r
}

func NewNameEventFast(raw []byte) *NameEvent {
	if len(raw) < nameEventSize {
		return nil
	}
	if len(raw) != nameEventSize {
		return NewNameEvent(raw)
	}
	n := poolOfNameEvents.Get().(*NameEvent)
	n.EventType = EventType(binary.LittleEndian.Uint32(raw[0:4]))
	n.TraceId = TraceId(binary.LittleEndian.Uint32(raw[4:8]))
	n.Time = binary.LittleEndian.Uint64(raw[8:16])
	n.Pid = binary.LittleEndian.Uint32(raw[16:20])
	n.Tid = binary.LittleEndian.Uint32(raw[20:24])
	copy(n.Oldname[:], raw[24:280])
	copy(n.Newname[:], raw[280:536])
	return n
}

func NewPathEventFast(raw []byte) *PathEvent {
	if len(raw) < pathEventSize {
		return nil
	}
	if len(raw) != pathEventSize {
		return NewPathEvent(raw)
	}
	p := poolOfPathEvents.Get().(*PathEvent)
	p.EventType = EventType(binary.LittleEndian.Uint32(raw[0:4]))
	p.TraceId = TraceId(binary.LittleEndian.Uint32(raw[4:8]))
	p.Time = binary.LittleEndian.Uint64(raw[8:16])
	p.Pid = binary.LittleEndian.Uint32(raw[16:20])
	p.Tid = binary.LittleEndian.Uint32(raw[20:24])
	copy(p.Pathname[:], raw[24:280])
	return p
}

func NewFcntlEventFast(raw []byte) *FcntlEvent {
	if len(raw) < fcntlEventSize {
		return nil
	}
	if len(raw) != fcntlEventSize {
		return NewFcntlEvent(raw)
	}
	f := poolOfFcntlEvents.Get().(*FcntlEvent)
	f.EventType = EventType(binary.LittleEndian.Uint32(raw[0:4]))
	f.TraceId = TraceId(binary.LittleEndian.Uint32(raw[4:8]))
	f.Time = binary.LittleEndian.Uint64(raw[8:16])
	f.Pid = binary.LittleEndian.Uint32(raw[16:20])
	f.Tid = binary.LittleEndian.Uint32(raw[20:24])
	f.Fd = binary.LittleEndian.Uint32(raw[24:28])
	f.Cmd = binary.LittleEndian.Uint32(raw[28:32])
	f.Arg = binary.LittleEndian.Uint64(raw[32:40])
	return f
}

func NewDup3EventFast(raw []byte) *Dup3Event {
	if len(raw) < dup3EventSize {
		return nil
	}
	if len(raw) != dup3EventSize {
		return NewDup3Event(raw)
	}
	d := poolOfDup3Events.Get().(*Dup3Event)
	d.EventType = EventType(binary.LittleEndian.Uint32(raw[0:4]))
	d.TraceId = TraceId(binary.LittleEndian.Uint32(raw[4:8]))
	d.Time = binary.LittleEndian.Uint64(raw[8:16])
	d.Pid = binary.LittleEndian.Uint32(raw[16:20])
	d.Tid = binary.LittleEndian.Uint32(raw[20:24])
	d.Fd = int32(binary.LittleEndian.Uint32(raw[24:28]))
	d.Flags = int32(binary.LittleEndian.Uint32(raw[28:32]))
	return d
}

func NewOpenByHandleAtEventFast(raw []byte) *OpenByHandleAtEvent {
	if len(raw) < openByHandleAtEventSizeV1 {
		return nil
	}
	if len(raw) != openByHandleAtEventSize && len(raw) != openByHandleAtEventSizeV1 {
		return NewOpenByHandleAtEvent(raw)
	}
	o := poolOfOpenByHandleAtEvents.Get().(*OpenByHandleAtEvent)
	o.EventType = EventType(binary.LittleEndian.Uint32(raw[0:4]))
	o.TraceId = TraceId(binary.LittleEndian.Uint32(raw[4:8]))
	o.Time = binary.LittleEndian.Uint64(raw[8:16])
	o.Pid = binary.LittleEndian.Uint32(raw[16:20])
	o.Tid = binary.LittleEndian.Uint32(raw[20:24])
	o.Flags = int32(binary.LittleEndian.Uint32(raw[24:28]))
	return o
}

func NewSocketEventFast(raw []byte) *SocketEvent {
	if len(raw) < socketEventSizeV1 {
		return nil
	}
	if len(raw) != socketEventSize && len(raw) != socketEventSizeV1 {
		return NewSocketEvent(raw)
	}
	s := poolOfSocketEvents.Get().(*SocketEvent)
	s.EventType = EventType(binary.LittleEndian.Uint32(raw[0:4]))
	s.TraceId = TraceId(binary.LittleEndian.Uint32(raw[4:8]))
	s.Time = binary.LittleEndian.Uint64(raw[8:16])
	s.Pid = binary.LittleEndian.Uint32(raw[16:20])
	s.Tid = binary.LittleEndian.Uint32(raw[20:24])
	s.Family = int32(binary.LittleEndian.Uint32(raw[24:28]))
	s.Type = int32(binary.LittleEndian.Uint32(raw[28:32]))
	s.Protocol = int32(binary.LittleEndian.Uint32(raw[32:36]))
	return s
}

func NewSocketpairEventFast(raw []byte) *SocketpairEvent {
	if len(raw) < socketpairEventSizeV1 {
		return nil
	}
	if len(raw) != socketpairEventSize && len(raw) != socketpairEventSizeV1 {
		return NewSocketpairEvent(raw)
	}
	s := poolOfSocketpairEvents.Get().(*SocketpairEvent)
	s.EventType = EventType(binary.LittleEndian.Uint32(raw[0:4]))
	s.TraceId = TraceId(binary.LittleEndian.Uint32(raw[4:8]))
	s.Time = binary.LittleEndian.Uint64(raw[8:16])
	s.Pid = binary.LittleEndian.Uint32(raw[16:20])
	s.Tid = binary.LittleEndian.Uint32(raw[20:24])
	s.Family = int32(binary.LittleEndian.Uint32(raw[24:28]))
	s.Type = int32(binary.LittleEndian.Uint32(raw[28:32]))
	s.Protocol = int32(binary.LittleEndian.Uint32(raw[32:36]))
	s.Sv0 = int32(binary.LittleEndian.Uint32(raw[36:40]))
	s.Sv1 = int32(binary.LittleEndian.Uint32(raw[40:44]))
	retOffset := 44
	if len(raw) == socketpairEventSize {
		retOffset = 48
	}
	s.Ret = int64(binary.LittleEndian.Uint64(raw[retOffset : retOffset+8]))
	return s
}

func NewAcceptEventFast(raw []byte) *AcceptEvent {
	if len(raw) < acceptEventSizeV1 {
		return nil
	}
	if len(raw) != acceptEventSize && len(raw) != acceptEventSizeV1 {
		return NewAcceptEvent(raw)
	}
	a := poolOfAcceptEvents.Get().(*AcceptEvent)
	a.EventType = EventType(binary.LittleEndian.Uint32(raw[0:4]))
	a.TraceId = TraceId(binary.LittleEndian.Uint32(raw[4:8]))
	a.Time = binary.LittleEndian.Uint64(raw[8:16])
	a.Pid = binary.LittleEndian.Uint32(raw[16:20])
	a.Tid = binary.LittleEndian.Uint32(raw[20:24])
	a.Fd = int32(binary.LittleEndian.Uint32(raw[24:28]))
	retOffset := 28
	if len(raw) == acceptEventSize {
		retOffset = 32
	}
	a.Ret = int64(binary.LittleEndian.Uint64(raw[retOffset : retOffset+8]))
	return a
}

func NewPipeEventFast(raw []byte) *PipeEvent {
	if len(raw) < pipeEventSizeV1 {
		return nil
	}
	if len(raw) != pipeEventSize && len(raw) != pipeEventSizeV1 {
		return NewPipeEvent(raw)
	}
	p := poolOfPipeEvents.Get().(*PipeEvent)
	p.EventType = EventType(binary.LittleEndian.Uint32(raw[0:4]))
	p.TraceId = TraceId(binary.LittleEndian.Uint32(raw[4:8]))
	p.Time = binary.LittleEndian.Uint64(raw[8:16])
	p.Pid = binary.LittleEndian.Uint32(raw[16:20])
	p.Tid = binary.LittleEndian.Uint32(raw[20:24])
	p.Flags = int32(binary.LittleEndian.Uint32(raw[24:28]))
	p.Fd0 = int32(binary.LittleEndian.Uint32(raw[28:32]))
	p.Fd1 = int32(binary.LittleEndian.Uint32(raw[32:36]))
	retOffset := 36
	if len(raw) == pipeEventSize {
		retOffset = 40
	}
	p.Ret = int64(binary.LittleEndian.Uint64(raw[retOffset : retOffset+8]))
	return p
}

func NewEventfdEventFast(raw []byte) *EventfdEvent {
	if len(raw) < eventfdEventSizeV1 {
		return nil
	}
	if len(raw) != eventfdEventSize && len(raw) != eventfdEventSizeV1 {
		return NewEventfdEvent(raw)
	}
	e := poolOfEventfdEvents.Get().(*EventfdEvent)
	e.EventType = EventType(binary.LittleEndian.Uint32(raw[0:4]))
	e.TraceId = TraceId(binary.LittleEndian.Uint32(raw[4:8]))
	e.Time = binary.LittleEndian.Uint64(raw[8:16])
	e.Pid = binary.LittleEndian.Uint32(raw[16:20])
	e.Tid = binary.LittleEndian.Uint32(raw[20:24])
	e.Flags = int32(binary.LittleEndian.Uint32(raw[24:28]))
	retOffset := 28
	if len(raw) == eventfdEventSize {
		retOffset = 32
	}
	e.Ret = int64(binary.LittleEndian.Uint64(raw[retOffset : retOffset+8]))
	return e
}

func NewEpollCtlEventFast(raw []byte) *EpollCtlEvent {
	if len(raw) < epollCtlEventSize {
		return nil
	}
	if len(raw) != epollCtlEventSize {
		return NewEpollCtlEvent(raw)
	}
	e := poolOfEpollCtlEvents.Get().(*EpollCtlEvent)
	e.EventType = EventType(binary.LittleEndian.Uint32(raw[0:4]))
	e.TraceId = TraceId(binary.LittleEndian.Uint32(raw[4:8]))
	e.Time = binary.LittleEndian.Uint64(raw[8:16])
	e.Pid = binary.LittleEndian.Uint32(raw[16:20])
	e.Tid = binary.LittleEndian.Uint32(raw[20:24])
	e.Epfd = int32(binary.LittleEndian.Uint32(raw[24:28]))
	e.Op = int32(binary.LittleEndian.Uint32(raw[28:32]))
	e.Fd = int32(binary.LittleEndian.Uint32(raw[32:36]))
	e.Events = binary.LittleEndian.Uint32(raw[36:40])
	return e
}

func NewTwoFdEventFast(raw []byte) *TwoFdEvent {
	if len(raw) < twoFdEventSize {
		return nil
	}
	if len(raw) != twoFdEventSize {
		return NewTwoFdEvent(raw)
	}
	t := poolOfTwoFdEvents.Get().(*TwoFdEvent)
	t.EventType = EventType(binary.LittleEndian.Uint32(raw[0:4]))
	t.TraceId = TraceId(binary.LittleEndian.Uint32(raw[4:8]))
	t.Time = binary.LittleEndian.Uint64(raw[8:16])
	t.Pid = binary.LittleEndian.Uint32(raw[16:20])
	t.Tid = binary.LittleEndian.Uint32(raw[20:24])
	t.FdA = int32(binary.LittleEndian.Uint32(raw[24:28]))
	t.FdB = int32(binary.LittleEndian.Uint32(raw[28:32]))
	t.Extra = binary.LittleEndian.Uint64(raw[32:40])
	return t
}

func NewPollEventFast(raw []byte) *PollEvent {
	if len(raw) < pollEventSizeV1 {
		return nil
	}
	if len(raw) != pollEventSize && len(raw) != pollEventSizeV1 {
		return NewPollEvent(raw)
	}
	p := poolOfPollEvents.Get().(*PollEvent)
	p.EventType = EventType(binary.LittleEndian.Uint32(raw[0:4]))
	p.TraceId = TraceId(binary.LittleEndian.Uint32(raw[4:8]))
	p.Time = binary.LittleEndian.Uint64(raw[8:16])
	p.Pid = binary.LittleEndian.Uint32(raw[16:20])
	p.Tid = binary.LittleEndian.Uint32(raw[20:24])
	p.Nfds = int32(binary.LittleEndian.Uint32(raw[24:28]))
	timeoutOffset := 28
	if len(raw) == pollEventSize {
		timeoutOffset = 32
	}
	p.TimeoutNs = int64(binary.LittleEndian.Uint64(raw[timeoutOffset : timeoutOffset+8]))
	return p
}

func NewMemEventFast(raw []byte) *MemEvent {
	if len(raw) < memEventSize {
		return nil
	}
	if len(raw) != memEventSize {
		return NewMemEvent(raw)
	}
	m := poolOfMemEvents.Get().(*MemEvent)
	m.EventType = EventType(binary.LittleEndian.Uint32(raw[0:4]))
	m.TraceId = TraceId(binary.LittleEndian.Uint32(raw[4:8]))
	m.Time = binary.LittleEndian.Uint64(raw[8:16])
	m.Pid = binary.LittleEndian.Uint32(raw[16:20])
	m.Tid = binary.LittleEndian.Uint32(raw[20:24])
	m.Addr = binary.LittleEndian.Uint64(raw[24:32])
	m.Length = binary.LittleEndian.Uint64(raw[32:40])
	m.Length2 = binary.LittleEndian.Uint64(raw[40:48])
	m.Flags = binary.LittleEndian.Uint64(raw[48:56])
	return m
}

func NewSleepEventFast(raw []byte) *SleepEvent {
	if len(raw) < sleepEventSize {
		return nil
	}
	if len(raw) != sleepEventSize {
		return NewSleepEvent(raw)
	}
	s := poolOfSleepEvents.Get().(*SleepEvent)
	s.EventType = EventType(binary.LittleEndian.Uint32(raw[0:4]))
	s.TraceId = TraceId(binary.LittleEndian.Uint32(raw[4:8]))
	s.Time = binary.LittleEndian.Uint64(raw[8:16])
	s.Pid = binary.LittleEndian.Uint32(raw[16:20])
	s.Tid = binary.LittleEndian.Uint32(raw[20:24])
	s.RequestedNs = int64(binary.LittleEndian.Uint64(raw[24:32]))
	return s
}

func NewKeyctlEventFast(raw []byte) *KeyctlEvent {
	if len(raw) < keyctlEventSize {
		return nil
	}
	if len(raw) != keyctlEventSize {
		return NewKeyctlEvent(raw)
	}
	k := poolOfKeyctlEvents.Get().(*KeyctlEvent)
	k.EventType = EventType(binary.LittleEndian.Uint32(raw[0:4]))
	k.TraceId = TraceId(binary.LittleEndian.Uint32(raw[4:8]))
	k.Time = binary.LittleEndian.Uint64(raw[8:16])
	k.Pid = binary.LittleEndian.Uint32(raw[16:20])
	k.Tid = binary.LittleEndian.Uint32(raw[20:24])
	k.Option = int32(binary.LittleEndian.Uint32(raw[24:28]))
	k.KeySerial = int32(binary.LittleEndian.Uint32(raw[28:32]))
	k.Value = binary.LittleEndian.Uint64(raw[32:40])
	return k
}

func NewPtraceEventFast(raw []byte) *PtraceEvent {
	if len(raw) < ptraceEventSize {
		return nil
	}
	if len(raw) != ptraceEventSize {
		return NewPtraceEvent(raw)
	}
	p := poolOfPtraceEvents.Get().(*PtraceEvent)
	p.EventType = EventType(binary.LittleEndian.Uint32(raw[0:4]))
	p.TraceId = TraceId(binary.LittleEndian.Uint32(raw[4:8]))
	p.Time = binary.LittleEndian.Uint64(raw[8:16])
	p.Pid = binary.LittleEndian.Uint32(raw[16:20])
	p.Tid = binary.LittleEndian.Uint32(raw[20:24])
	p.Request = int64(binary.LittleEndian.Uint64(raw[24:32]))
	p.TargetPid = int32(binary.LittleEndian.Uint32(raw[32:36]))
	p.Pad = int32(binary.LittleEndian.Uint32(raw[36:40]))
	p.Data = binary.LittleEndian.Uint64(raw[40:48])
	return p
}

func NewPerfOpenEventFast(raw []byte) *PerfOpenEvent {
	if len(raw) < perfOpenEventSize {
		return nil
	}
	if len(raw) != perfOpenEventSize {
		return NewPerfOpenEvent(raw)
	}
	p := poolOfPerfOpenEvents.Get().(*PerfOpenEvent)
	p.EventType = EventType(binary.LittleEndian.Uint32(raw[0:4]))
	p.TraceId = TraceId(binary.LittleEndian.Uint32(raw[4:8]))
	p.Time = binary.LittleEndian.Uint64(raw[8:16])
	p.Pid = binary.LittleEndian.Uint32(raw[16:20])
	p.Tid = binary.LittleEndian.Uint32(raw[20:24])
	p.AttrType = binary.LittleEndian.Uint32(raw[24:28])
	p.AttrSize = binary.LittleEndian.Uint32(raw[28:32])
	p.Config = binary.LittleEndian.Uint64(raw[32:40])
	p.TargetPid = int32(binary.LittleEndian.Uint32(raw[40:44]))
	p.Cpu = int32(binary.LittleEndian.Uint32(raw[44:48]))
	p.GroupFd = int32(binary.LittleEndian.Uint32(raw[48:52]))
	p.Flags = binary.LittleEndian.Uint32(raw[52:56])
	return p
}
